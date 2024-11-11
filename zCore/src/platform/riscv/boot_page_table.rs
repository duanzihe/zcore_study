use super::consts::{kernel_mem_info, kernel_mem_probe};
use core::arch::asm;
use page_table::{MmuMeta, Pte, Sv39, VAddr, VmFlags, VmMeta, PPN}; //疑惑：这里用的是page-table0.06,而非项目自带的，但create.io中并没有Sv39

/// 启动页表。
#[repr(align(4096))]
pub(super) struct BootPageTable([Pte<Sv39>; 512]);

impl BootPageTable {
    /// 初始化为全零的启动页表。
    pub const ZERO: Self = Self([Pte::ZERO; 512]);  //创建了一个包含 512 个页表条目（page table entry）的数组，每个元素都是 Pte::ZERO

    /// 根据内核实际位置初始化启动页表。
    /// 为页表项配置标志位，确保内核虚实地址1GiB对齐，映射跳板页，映射物理地址空间的前 128 GiB
    pub fn init(&mut self) {
        cfg_if! {
            if #[cfg(feature = "thead-maee")] {   // 华山派特性，cvitek.cr1825会启用这个特性。
                const FLAGS: VmFlags<Sv39> = unsafe {
                    VmFlags::from_raw(VmFlags::<Sv39>::build_from_str("DAG_XWRV").val() | (1 << 62))
                };
            } else {
                const FLAGS: VmFlags<Sv39> = VmFlags::build_from_str("DAG_XWRV");//为sv39页表结构的页表项设置标志位(注意，只是设置标记位本身，并没有打开或者关闭它们)
                //疑惑：这里的build_from_str具体是怎么实现的？page-table的create.io里没有啊？
                //解答：据说因为crates.io里的是x64版本编译的，所以没有riscv64对应的文档。
            }
        }

        // 启动页表初始化之前 pc 必定在物理地址空间
        // 因此可以安全地定位内核地址信息
        //这里的mem_info包含了内核的物理起始地址、虚拟起始地址和内核大小。
        let mem_info = unsafe { kernel_mem_probe() };
        // 确保虚实地址在 1 GiB 内对齐（意思就是内核的虚拟地址与内核的物理地址的偏移量是1GiB的倍数）
        // 疑惑：这里为什么要这样做？大页的映射究竟是怎么回事？
        assert!(mem_info.offset().trailing_zeros() >= 30);//至少要有30个0
        // 映射跳板页
        let base = VAddr::<Sv39>::new(mem_info.paddr_base)  //修剪物理地址，这一步只是裁剪掉了高于虚拟地址空间位宽的部分，并不涉及复杂的映射过程。
            .floor() // 获取对应页号类型为VPN。（在分页机制中，floor的含义是将地址向下取整到页号级别，也就是舍弃掉页内的偏移量部分，只留下页号。这通常用于地址映射等场景，在映射页表时需要处理页而不是具体的字节）
            //注意：这个时候页表还没创建，但floor已经知道页表结构是sv39,所以知道该怎么取虚拟索引页号。不过也正因页表还没创建，这个页号并没有指向物理地址。只是“纸上谈兵”而已。
            .index_in(Sv39::MAX_LEVEL);//保留MAX_LEVEL的索引，对于SV39来说就是保存高位的对应一级索引的9位。
        //根据上面三行，得知base是内核物理地址0x8020 0000 经过裁剪和选取得到的高9位，也 就是000 0000 10。
        self.0[base] = FLAGS.build_pte(PPN::new(base << 18)); //在这个一级页表项中保存这个大页的第一个小页。（这里的大页是000 0000 10这个大页）
        //疑惑：跳板页具体有什么用？
        // 映射物理地址空间的前 128 GiB
        let base = VAddr::<Sv39>::new(mem_info.offset()) //获取内核虚实地址偏移量0xffff_ffc0_0000_0000，将其转化成虚拟地址 
            .floor() //获取对应的页号
            .index_in(Sv39::MAX_LEVEL); //裁剪到只剩一级索引
        for i in 0..128 {  //用100 0000 00 到 101 1111 11的一级页表项来映射物理地址的前128G
            self.0[base + i] = FLAGS.build_pte(PPN::new(i << 18));  //这些一级页表项里都放着对应大页的第一个小页表项
        }
        //一级页表中直接放置了物理页的映射（三级页表项），在这种情况下，系统不需要创建完整的二级和三级页表，而是直接通过一级页表项指向物理页的基地址。
        //目的：这种映射方式可以在启动阶段快速设置内核空间，使得内核能够访问并初始化其页表和其他关键数据结构。
    }

    /// 启动地址转换，跃迁到高地址，并设置线程指针和内核对用户页的访问权限。
    ///
    /// # Safety
    ///
    /// 调用前后位于不同的地址空间，必须内联。
    #[inline(always)]
    pub unsafe fn launch(&self) -> usize {
        use riscv::register::satp;
        // 利用“启动页表”来启动地址转换
        satp::set(  //satp（超级地址转换寄存器）用于设置 RISC-V 中的地址转换模式。
            satp::Mode::Sv39,  //satp::Mode::Sv39 指定使用 SV39（64 位虚拟地址和物理地址）模式。
            //ASID（Address Space Identifier）：这个参数是 0。
            //ASID 用于区分不同的地址空间，在多任务系统中，ASID 允许处理器同时处理多个进程的地址映射而无需重新加载页表。
            //如果系统只使用一个地址空间或者没有使用 ASID，那么这个值可以设置为 0
            0, 
            //self.0.as_ptr() 返回指向“启动页表”的指针，指向页表的起始位置，因为此时还没有建立虚拟内存机制，指针指向的就是物理地址
            //as usize将指针转换为整数方便运算，
            //>> sv39::page_bits就是右移12位,传递给 satp 的参数应该是页表的物理页号.
            self.0.as_ptr() as usize >> Sv39::PAGE_BITS,
        );

        //注意！在satp被set之后，所有的地址操作和计算都是基于虚拟地址的。
        // 因为启动页表用了虚拟高地址0xffff_ffc0_0000_0000 之后的128个一级页表项来映射物理地址的前128G，
        // 所以这里设置了satp之后要用jump_higher跳转到高地址，才能映射到原本的物理低地址。

        // 此时原本的地址空间还在，所以不用刷快表 
        // riscv::asm::sfence_vma_all();
        // 跳到高页面对应位置 
        Self::jump_higher(kernel_mem_info().offset());

        // 设置内核可访问用户内存
        //sstatus 寄存器的第 18 位是与 SUM（Supervisor User Memory access） 位对应的。
        //将 SUM 位设置为 1 的作用是允许内核（超级模式）访问用户空间的内存
        let mut sstatus = 1usize << 18; //将rust变量sstatus的18位 置一。
        asm!("csrrs {0}, sstatus, {0}", inlateout(reg) sstatus);  //这里的{0}是占位符，其实就是rust变量sstatus，这里让rust变量的sstatus和当前sstatus寄存器进行或运算
        sstatus | (1usize << 18)  //疑惑：这里为什么又置1一次？一开始定义的这里不已经置1了吗？
    }

    /// 向上跳到距离为 `offset` 的新地址然后继续执行。
    ///
    /// # Safety
    ///
    /// 裸函数。
    ///
    /// 导致栈重定位，栈上的指针将失效！
    #[naked]
    unsafe extern "C" fn jump_higher(offset: usize) {
        asm!("add sp, sp, a0", "add ra, ra, a0", "ret", options(noreturn))
    }
}
