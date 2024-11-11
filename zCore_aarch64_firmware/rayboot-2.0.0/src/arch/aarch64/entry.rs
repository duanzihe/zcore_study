use super::page_table::{MemFlags, PageTableEntry};
use core::time::Duration;
use cortex_a::{asm, asm::barrier, registers::*}; //提高对arm架构寄存器的高级抽象包装，这样在代码中可以之间操作寄存器。
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
//修改！为方便调试，在这里也用log
use log::*;

#[repr(align(4096))]
struct PageTable([PageTableEntry; 512]);

#[repr(align(4096))]
pub struct NormalMem(pub [u8; 0x4000]);

#[no_mangle]
pub static mut STACK: NormalMem = NormalMem([0; 0x4000]);
#[no_mangle]
static mut BOOT_PT0: PageTable = PageTable([PageTableEntry::empty(); 512]);
#[no_mangle]
static mut BOOT_PT1: PageTable = PageTable([PageTableEntry::empty(); 512]);

/*
   函数：uptime
   传入参数：无
   返回值类型：时间Duration
   作用：获取从上电到现在经历的时间
*/
pub fn uptime() -> Duration {
    unsafe { barrier::isb(barrier::SY) }
    let cur_cnt = CNTPCT_EL0.get() * 1_000_000_000;
    let freq = CNTFRQ_EL0.get() as u64;
    Duration::from_nanos(cur_cnt / freq)
}

/*
   函数:switch_to_el1
   传入参数：无
   返回值类型：无
   作用：切换到EL1特权级
*/
pub unsafe fn switch_to_el1() {
    // use super::bsp::Pl011Uart;
    // let uart = Pl011Uart::new(0x0900_0000);
    // uart.write(format_args!("\n########## switch_to_el1 ##########\n\n"));
   
    SPSel.write(SPSel::SP::ELx); //SP_Select,告诉 ARM 处理器，在当前异常级别下（例如 EL3、EL2 等），使用当前级别的堆栈指针
                                //其实就是在start_qemu里我们指定的临时栈boot_pt0。
    let current_el = CurrentEL.read(CurrentEL::EL); //获取当前异常级别
    if current_el >= 2 { //如果是更高el，就执行如下操作
        if current_el == 3 { //如果是EL3，
            // Set EL2 to 64bit and enable the HVC instruction.
            // 设置el2是64位的，且允许hypervisor。
            SCR_EL3.write(
                SCR_EL3::NS::NonSecure + SCR_EL3::HCE::HvcEnabled + SCR_EL3::RW::NextELIsAarch64,
                //SCR_EL3::NS::NonSecure设置寄存器的 NS（Non-Secure）位为 NonSecure，表示在 EL3 下，当前的执行环境被配置为非安全环境。
                //这意味着，处理器将允许非安全代码（如用户程序）执行。
                //SCR_EL3::HCE::HvcEnabled设置 HCE（Hyp Exception Enable）位为 HvcEnabled，允许 Hypervisor Call（HVC）指令的处理。
                //这使得处理器可以进入虚拟化模式，以便支持 Hypervisor 和虚拟机的管理。
                //SCR_EL3::RW::NextELIsAarch64：这一部分设置 RW（Root of Trust Write）位为 NextELIsAarch64，
                //指定在下一个异常级别（Next EL）中使用 AArch64 状态。这意味着在进入下一个异常级别时，处理器将使用 AArch64 体系结构。
            );
            // Set the return address and exception level.
            // 这段代码整体的功能是准备将处理器从 EL3 切换到 EL1，并且配置了相应的状态寄存器和返回地址
                
            SPSR_EL3.write(  //Saved Program Status Register，程序状态保存寄存器
                SPSR_EL3::M::EL1h  //这行代码将状态寄存器的模式位 (M) 设置为 EL1h，表示将处理器的异常级别切换到 EL1 (异常级别 1) 的高半部。
                //将调试 (D)、异步 (A)、中断 (I) 和快速中断 (F) 的标志位掩码
                    + SPSR_EL3::D::Masked
                    + SPSR_EL3::A::Masked
                    + SPSR_EL3::I::Masked
                    + SPSR_EL3::F::Masked,
            );
            ELR_EL3.set(LR.get());  //通过将 LR 的值存储到 ELR_EL3，该系统确保在返回到 EL3 时能够正确恢复上下文
        }
        // Disable EL1 timer traps and the timer offset.
        CNTHCTL_EL2.modify(CNTHCTL_EL2::EL1PCEN::SET + CNTHCTL_EL2::EL1PCTEN::SET);
        CNTVOFF_EL2.set(0);
        // Set EL1 to 64bit.
        HCR_EL2.write(HCR_EL2::RW::EL1IsAarch64);
        // Set the return address and exception level.
        SPSR_EL2.write(
            SPSR_EL2::M::EL1h
                + SPSR_EL2::D::Masked
                + SPSR_EL2::A::Masked
                + SPSR_EL2::I::Masked
                + SPSR_EL2::F::Masked,
        );
        SP_EL1.set(STACK.0.as_ptr_range().end as u64); //将EL1模式下的SP设置为STACK顶
        ELR_EL2.set(LR.get()); //用于设置异常链接寄存器（ELR）在 EL2（Exception Level 2）中的值为当前链接寄存器（LR）的值。这个过程在切换异常级别时非常重要，具体来说，它用于保存返回到 EL2 时的地址。
        asm::eret();
    }
}

/*
   函数：init_mmu
   传入参数：无
   返回值类型：无
   作用：初始化MMU
*/
pub unsafe fn init_mmu() {
    use super::bsp::Pl011Uart;
    let uart = Pl011Uart::new(0x0900_0000);
    uart.write(format_args!("\n########## init_mmu ##########\n\n"));
    // Device-nGnRE memory
    let attr0 = MAIR_EL1::Attr0_Device::nonGathering_nonReordering_EarlyWriteAck;
        //MAIR是Memory Attribute Indirection Register 内存属性指数寄存器
        //nonGathering：表示该设备内存不会进行数据聚合（gathering），这意味着数据访问将逐个地址处理，而不是将多个地址的访问合并为一个访问。
        //这通常在涉及到设备寄存器时很重要，以确保每次访问都能即时反映到硬件状态中。
        //nonReordering：表示该内存访问不会被重排（reordering）。设备内存通常要求严格的顺序访问，以确保正确的操作顺序，特别是在涉及到状态寄存器和控制寄存器时。
        //EarlyWriteAck：这一部分表示写操作的确认在写入数据后会尽早进行。设备在处理写请求时，通常会在写操作完成后立即返回确认，而不是等待内存访问完成。这有助于提高设备的响应速度。
    // Normal memory
    let attr1 = MAIR_EL1::Attr1_Normal_Inner::WriteBack_NonTransient_ReadWriteAlloc
        + MAIR_EL1::Attr1_Normal_Outer::WriteBack_NonTransient_ReadWriteAlloc;
    MAIR_EL1.write(attr0 + attr1); // 把这两个属性条目存入MAIR

    // Enable TTBR0 and TTBR1 walks, page size = 4K, vaddr size = 48 bits, paddr size = 40 bits.
    let tcr_flags0 = TCR_EL1::EPD0::EnableTTBR0Walks  //启用 TTBR0 的页表遍历。TTBR0 用于管理低虚拟地址空间的页表映射。
    //如果虚拟地址属于低地址空间（如用户态），处理器会从 TTBR0_EL1 寄存器中获取页表的基地址
        + TCR_EL1::TG0::KiB_4 //设置 TTBR0 所对应的第一级页表的页大小为 4KB
        + TCR_EL1::SH0::Inner //设置 TTBR0 相关的内存共享属性为“内部共享”。
        + TCR_EL1::ORGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable //设置 TTBR0 管理的虚拟地址空间的缓存策略为“写回缓存，读写时分配”。
        + TCR_EL1::IRGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable //设置 TTBR0 管理的虚拟地址空间的指令缓存策略为“写回缓存，读写时分配”。
        + TCR_EL1::T0SZ.val(16); //设置 TTBR0 管理的虚拟地址空间大小
    let tcr_flags1 = TCR_EL1::EPD1::EnableTTBR1Walks
    //如果虚拟地址属于高地址空间（如内核态），处理器会从 TTBR1_EL1 寄存器中获取页表的基地址。
        + TCR_EL1::TG1::KiB_4
        + TCR_EL1::SH1::Inner
        + TCR_EL1::ORGN1::WriteBack_ReadAlloc_WriteAlloc_Cacheable
        + TCR_EL1::IRGN1::WriteBack_ReadAlloc_WriteAlloc_Cacheable
        + TCR_EL1::T1SZ.val(16);

    TCR_EL1.write(TCR_EL1::IPS::Bits_40 + tcr_flags0 + tcr_flags1); //Bits_40 表示支持 40 位的物理地址，也就是说系统最多支持 1TB 的物理地址空间
    // uart.write(format_args!("\n########## init_mmu_step 1##########\n\n"));  //从uart输出来看，这里之后没有正常的反馈输出
    
    barrier::isb(barrier::SY);                                        //从日志来看，在isb之后就会out of bounds

    // uart.write(format_args!("\n########## init_mmu_step 1##########\n\n"));  //从uart输出来看，这里之后没有正常的反馈输出

    // Set both TTBR0 and TTBR1

    let root_paddr = BOOT_PT0.0.as_ptr() as u64;
    
  //设置 TTBR0_EL1 确实意味着低地址空间的虚拟地址映射已启用
    TTBR0_EL1.set(root_paddr);   
  //设置 TTBR1_EL1 确实意味着高地址空间的虚拟地址映射已启用
    TTBR1_EL1.set(root_paddr);

    // uart.write(format_args!("\n########## init_mmu_step 1##########\n\n"));  //从uart输出来看，这里之后没有正常的反馈输出

    core::arch::asm!("tlbi vmalle1; dsb sy; isb"); // flush tlb all
                                                //    Enable the MMU and turn on I-cache and D-cache
    
    
    SCTLR_EL1.modify(SCTLR_EL1::M::Enable + SCTLR_EL1::I::Cacheable + SCTLR_EL1::C::Cacheable);
    // uart.write(format_args!("\n########## init_mmu_step 2##########\n\n"));  //从uart输出来看，这里之后没有正常的反馈输出

    barrier::isb(barrier::SY);
    // uart.write(format_args!("\n########## init_mmu_finish ##########\n\n"));
}

/*
   函数：init_qemu_boot_page_table
   传入参数：无
   返回值类型：无
   作用：初始化qemu启动时页表
*/
pub unsafe fn init_qemu_boot_page_table() {
    // 0x0000_0000_0000 ~ 0x0080_0000_0000, table
    //将 BOOT_PT0 页表的第一个条目设置为指向 BOOT_PT1 页表
    BOOT_PT0.0[0] = PageTableEntry::new_table(BOOT_PT1.0.as_ptr() as u64);
    //将 BOOT_PT1 的第一个条目设置为一个映射从物理地址 0x0000_0000_0000 到 0x0000_4000_0000 的内存块，并将其标记为设备内存。
    BOOT_PT1.0[0] =
        PageTableEntry::new_page(0, MemFlags::READ | MemFlags::WRITE | MemFlags::DEVICE, true);
    //将从物理地址 0x4000_0000 开始的 1GB 内存块映射为可读、可写、可执行的普通内存区域
    BOOT_PT1.0[1] = PageTableEntry::new_page(
        0x4000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    //纠错修改！因为系统在跳转到内核之前的执行流会达到0xbxxx xxxx这个级别，所以需要再扩展2G的页表映射范围，
    BOOT_PT1.0[2] = PageTableEntry::new_page(
        0x8000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    BOOT_PT1.0[3] = PageTableEntry::new_page(
        0xb000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );

}

/*
   函数：init_raspi4_boot_page_table
   传入参数：无
   返回值类型：无
   作用：初始化树莓派4b启动时页表
*/
pub unsafe fn init_raspi4_boot_page_table() {



    // 0x0000_0000_0000 ~ 0x0080_0000_0000, table
    BOOT_PT0.0[0] = PageTableEntry::new_table(BOOT_PT1.0.as_ptr() as u64);

    // 0x0000_0000_0000..0x0000_4000_0000, block, normal memory
    BOOT_PT1.0[0] = PageTableEntry::new_page(
        0,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    // 0x0000_4000_0000..0x0000_8000_0000, block, normal memory
    BOOT_PT1.0[1] = PageTableEntry::new_page(
        0x4000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    // 0x0000_8000_0000..0x0000_c000_0000, block, normal memory
    BOOT_PT1.0[2] = PageTableEntry::new_page(
        0x8000_0000,
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE,
        true,
    );
    // 0x0000_c000_0000..0x0001_0000_0000, block, device
    BOOT_PT1.0[3] = PageTableEntry::new_page(
        0xc000_0000,
        // 在树莓派4b平台上uart输出会乱码
        // MemFlags::READ | MemFlags::WRITE | MemFlags::DEVICE
        // 改成下面的就不会
        MemFlags::READ | MemFlags::WRITE | MemFlags::EXECUTE | MemFlags::DEVICE,
        true,
    );
}

/*
   函数：start_raspi4
   传入参数：无
   返回值类型：!
   作用：初始化树莓派4b内存环境
*/
#[naked]
#[no_mangle]
pub unsafe extern "C" fn start_raspi4() -> ! {
    // PC = 0x4008_0000
    //修改，这里用的本来是asm,这里改成了naked_asm
    core::arch::naked_asm!("                  
        adrp    x8, BOOT_PT0
        mov     sp, x8
        bl      {switch_to_el1}
        bl      {init_boot_page_table}
        bl      {init_mmu}
        adrp    x8, BOOT_PT0
        mov     sp, x8
        adrp    x9, STACK
        ldr     x10, [x9]
        ldr     x0, [x9, #8]
        br      x10
        ",
        switch_to_el1 = sym switch_to_el1,
        init_boot_page_table = sym init_raspi4_boot_page_table,
        init_mmu = sym init_mmu,
        //options(noreturn),      //修改！移除了这一行，因为noreturn这个option对于global-scoped inline assembly是无意义的。
    )
}

/*
   函数：start_qemu
   传入参数：无
   返回值类型：!
   作用：初始化qemu内存环境
*/
#[naked]
#[no_mangle]
pub unsafe extern "C" fn start_qemu() -> ! {
    // PC = 0x4008_0000   //修改！将asm改为naked_asm
    core::arch::naked_asm!("        
        adrp    x8, BOOT_PT0             //# 使用adrp指令加载一个页表基地址BOOT_PT0到x8寄存器中
        mov     sp, x8                      //# 将当前栈指针设置为页表的起始地址。
                                        //这是一个很聪明的设计，boot_pt0作为页表基地址，页表项只会向上增长，下面正好用来做临时找。

        bl      {switch_to_el1}           //# 跳转到switch_to_el1函数并将返回地址保存到lr（链接寄存器）中
        bl      {init_boot_page_table}   //# 跳转到init_boot_page_table，该函数初始化引导页表，设置虚拟地址与物理地址的映射规则。
        bl      {init_mmu}              //#启用虚拟内存机制
        adrp    x8, BOOT_PT0  
        mov     sp, x8
        adrp    x9, STACK
        ldr     x10, [x9]
        ldr     x0, [x9, #8]
        br      x10
        ",
    switch_to_el1 = sym switch_to_el1,
    init_boot_page_table = sym init_qemu_boot_page_table,
    init_mmu = sym init_mmu,
    // options(noreturn),
    )
}
