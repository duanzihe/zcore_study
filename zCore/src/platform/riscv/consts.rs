// RISCV

/// 内核每个硬件线程的栈页数。
pub const STACK_PAGES_PER_HART: usize = 32;

/// 最大的对称多核硬件线程数量。
pub const MAX_HART_NUM: usize = 5;

#[inline]
pub fn phys_to_virt_offset() -> usize {
    kernel_mem_info().offset()
}

use spin::Once;

/// 内核位置信息
pub struct KernelMemInfo {
    /// 内核在物理地址空间的起始地址。
    pub paddr_base: usize,

    /// 内核所在虚拟地址空间的起始地址。
    ///
    /// 实际上是虚地址空间的最后一个 GiB 页的起始地址，
    /// 并与物理内存保持 2 MiB 页内偏移对齐。
    /// 与链接时设定的地址保持一致。
    pub vaddr_base: usize,

    /// 内核链接区域长度。
    pub size: usize,
}

impl KernelMemInfo {
    /// 初始化物理内存信息。
    ///
    /// # Safety
    ///
    /// 为了获取内核的物理地址，
    /// 这个函数必须在 `pc` 仍在物理地址空间时调用！
    unsafe fn new() -> Self {
        extern "C" {
            fn start();
            fn end();
        }
        let paddr_base = start as usize;        //qemu把内核加载到模拟板上时，就会给start这个在linker.ld中定义的符号分配一个在模拟板上的物理地址，这里用paddr_base获取它。
        // 从启动后的输出信息来看内核的物理地址应该是Domain0 Next Address      : 0x0000000080200000
        let vaddr_base = 0xffff_ffc0_8020_0000; //内核虚拟地址 ，一般来说，虚拟地址在高地址， 物理地址在低地址
        Self {
            paddr_base,
            vaddr_base,
            size: end as usize - paddr_base, //end也是在linker.ld中定义的符号，相减得到内核大小（从这里可以推测内核代码的各个段应当是连续的）
        }
    }

    /// 计算内核虚存空间到物理地址空间的偏移。
    #[inline]
    pub fn offset(&self) -> usize {
        self.vaddr_base - self.paddr_base
    }
}

static KERNEL_MEM_INFO: Once<KernelMemInfo> = Once::new();

#[inline]
pub fn kernel_mem_info() -> &'static KernelMemInfo {
    KERNEL_MEM_INFO.wait()
}

#[inline]
pub(super) unsafe fn kernel_mem_probe() -> &'static KernelMemInfo {
    KERNEL_MEM_INFO.call_once(|| KernelMemInfo::new())
}
