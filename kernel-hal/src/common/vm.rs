use crate::{addr::is_aligned, MMUFlags, PhysAddr, VirtAddr};

/// Errors may occur during address translation.
#[derive(Debug)]
pub enum PagingError {
    NoMemory,
    NotMapped,
    AlreadyMapped,
}

/// Address translation result.
pub type PagingResult<T = ()> = Result<T, PagingError>;

/// The [`PagingError::NotMapped`] can be ignored.
pub trait IgnoreNotMappedErr {
    /// If self is `Err(PagingError::NotMapped`, ignores the error and returns
    /// `Ok(())`, otherwise remain unchanged.
    fn ignore(self) -> PagingResult;
}

impl<T> IgnoreNotMappedErr for PagingResult<T> {
    fn ignore(self) -> PagingResult {
        match self {
            Ok(_) | Err(PagingError::NotMapped) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Possible page size (4K, 2M, 1G).
#[repr(usize)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PageSize {
    Size4K = 0x1000,
    Size2M = 0x20_0000,
    Size1G = 0x4000_0000,
}

/// A 4K, 2M or 1G size page.
#[derive(Debug, Copy, Clone)]
pub struct Page {
    pub vaddr: VirtAddr,
    pub size: PageSize,
}

impl PageSize {
    pub const fn is_aligned(self, addr: usize) -> bool {
        self.page_offset(addr) == 0
    }

    pub const fn align_down(self, addr: usize) -> usize {
        addr & !(self as usize - 1)
    }

    pub const fn page_offset(self, addr: usize) -> usize {
        addr & (self as usize - 1)
    }

    pub const fn is_huge(self) -> bool {
        matches!(self, Self::Size1G | Self::Size2M)
    }
}

impl Page {
    pub fn new_aligned(vaddr: VirtAddr, size: PageSize) -> Self {
        debug_assert!(size.is_aligned(vaddr));
        Self { vaddr, size }
    }
}

/// A generic page table abstraction.
pub trait GenericPageTable: Sync + Send {
    /// Get the physical address of root page table.
    fn table_phys(&self) -> PhysAddr;

    /// Map the `page` to the frame of `paddr` with `flags`.
    fn map(&mut self, page: Page, paddr: PhysAddr, flags: MMUFlags) -> PagingResult;

    /// Unmap the page of `vaddr`.
    fn unmap(&mut self, vaddr: VirtAddr) -> PagingResult<(PhysAddr, PageSize)>;

    /// Change the `flags` of the page of `vaddr`.
    fn update(
        &mut self,
        vaddr: VirtAddr,
        paddr: Option<PhysAddr>,
        flags: Option<MMUFlags>,
    ) -> PagingResult<PageSize>;

    /// Query the physical address which the page of `vaddr` maps to.
    fn query(&self, vaddr: VirtAddr) -> PagingResult<(PhysAddr, MMUFlags, PageSize)>;

    ///将一段连续的虚拟内存地址映射到对应的物理内存地址。
    /// 它会根据页的大小（4K、2M、1G）选择最合适的页大小来进行映射，同时支持大页（huge page）模式。
    fn map_cont(
        &mut self,
        start_vaddr: VirtAddr,
        size: usize,
        start_paddr: PhysAddr,
        flags: MMUFlags,
    ) -> PagingResult {
        //先通过 assert! 语句来确保 start_vaddr、start_paddr 和 size 都是按页大小对齐的
        assert!(is_aligned(start_vaddr));
        assert!(is_aligned(start_vaddr));
        assert!(is_aligned(size));
        //使用 debug! 打印调试信息，显示虚拟地址到物理地址的映射范围以及映射标志
        debug!(
            "map_cont: {:#x?} => {:#x}, flags={:?}",
            start_vaddr..start_vaddr + size,
            start_paddr,
            flags
        );

        let mut vaddr = start_vaddr;
        let mut paddr = start_paddr;
        let end_vaddr = vaddr + size;
        // 如果含有huge_page标志位
        if flags.contains(MMUFlags::HUGE_PAGE) {
            //函数通过 while 循环遍历虚拟地址范围，将每一段虚拟内存映射到相应的物理内存。
            while vaddr < end_vaddr {
                let remains = end_vaddr - vaddr;
                //当剩余内存大小大于等于 1G 且虚拟地址和物理地址都对齐到 1G 边界时，使用 1G 页进行映射。
                let page_size = if remains >= PageSize::Size1G as usize
                    && PageSize::Size1G.is_aligned(vaddr)
                    && PageSize::Size1G.is_aligned(paddr)
                {
                    PageSize::Size1G
                //当剩余内存大小大于等于 2M 且虚拟地址和物理地址都对齐到 2M 边界时，使用 2M 页。
                } else if remains >= PageSize::Size2M as usize
                    && PageSize::Size2M.is_aligned(vaddr)
                    && PageSize::Size2M.is_aligned(paddr)
                {
                    PageSize::Size2M
                } else {
                    PageSize::Size4K
                };
                let page = Page::new_aligned(vaddr, page_size);
                //通过 self.map 函数来进行页表的具体映射。这个操作是将 page（虚拟页）映射到 paddr（物理地址），并应用 flags 标志
                self.map(page, paddr, flags)?;
                vaddr += page_size as usize;
                paddr += page_size as usize;
            }
        } else {
        //如果没有huge_page标记，就不启用大页模式，始终使用 4K 页映射
            while vaddr < end_vaddr {
                let page_size = PageSize::Size4K;
                let page = Page::new_aligned(vaddr, page_size);
                self.map(page, paddr, flags)?;
                vaddr += page_size as usize;
                paddr += page_size as usize;
            }
        }
        Ok(())
    }

    fn unmap_cont(&mut self, start_vaddr: VirtAddr, size: usize) -> PagingResult {
        assert!(is_aligned(start_vaddr));
        assert!(is_aligned(size));
        debug!(
            "{:#x?} unmap_cont: {:#x?}",
            self.table_phys(),
            start_vaddr..start_vaddr + size
        );
        let mut vaddr = start_vaddr;
        let end_vaddr = vaddr + size;
        while vaddr < end_vaddr {
            let page_size = match self.unmap(vaddr) {
                Ok((_, s)) => {
                    assert!(s.is_aligned(vaddr));
                    s as usize
                }
                Err(PagingError::NotMapped) => PageSize::Size4K as usize,
                Err(e) => return Err(e),
            };
            vaddr += page_size;
            assert!(vaddr <= end_vaddr);
        }
        Ok(())
    }
}
