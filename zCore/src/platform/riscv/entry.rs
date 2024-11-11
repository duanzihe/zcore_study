use super::{
    boot_page_table::BootPageTable,
    consts::{kernel_mem_info, MAX_HART_NUM, STACK_PAGES_PER_HART},
};
use core::arch::asm;
use dtb_walker::{Dtb, DtbObj, HeaderError::*, Property, Str, WalkOperation::*};
use kernel_hal::KernelConfig;

/// 内核入口。
/// # Safety
///
/// 裸函数。
#[naked]
#[no_mangle] //指示编译器不要对函数名进行改编（mangle），以便在链接时可以按原名引用该函数
#[link_section = ".text.entry"] //将函数放置在链接器脚本指定的 .text.entry 段中 
//extern C 保证此函数与C和汇编的兼容性。因为其会被opensbi调用
unsafe extern "C" fn _start(hartid: usize, device_tree_paddr: usize) -> ! { //hartid和device_tree_padder会由opensbi传递
    asm!(
        "call {select_stack}", // 设置启动栈
        "j    {main}",         // 进入 rust
        select_stack = sym select_stack,
        main         = sym primary_rust_main,
        options(noreturn)
    )
}

/// 副核入口。此前副核被 bootloader/see 阻塞。
///
/// # Safety
///
/// 裸函数。
#[naked]
unsafe extern "C" fn secondary_hart_start(hartid: usize) -> ! {
    asm!(
        "call {select_stack}", // 设置启动栈
        "j    {main}",         // 进入 rust
        select_stack = sym select_stack,
        main         = sym secondary_rust_main,
        options(noreturn)
    )
}

/// 启动页表
static mut BOOT_PAGE_TABLE: BootPageTable = BootPageTable::ZERO; //初始化一个全零的启动页表

/// 主核启动。
extern "C" fn primary_rust_main(hartid: usize, device_tree_paddr: usize) -> ! {
    // 清零 bss 段
    extern "C" {
        static mut sbss: u64;
        static mut ebss: u64;
    }
    unsafe { r0::zero_bss(&mut sbss, &mut ebss) };
    // 使能启动页表
    let sstatus = unsafe {
        BOOT_PAGE_TABLE.init();  //初始化
        BOOT_PAGE_TABLE.launch()  //使能 ，进入虚拟空间，此后所有地址操作都是虚拟地址了。
    };
    let mem_info = kernel_mem_info();
    // 检查设备树
    let dtb = unsafe {
        //from_raw_parts_filtered是一个用于从原始内存数据创建 Dtb 对象的函数。它会解析内存中的设备树数据，生成相应的结构。
        Dtb::from_raw_parts_filtered((device_tree_paddr + mem_info.offset()) as _, |e| { //传入的设备书虚拟地址的指针，和一个闭包函数e。
            matches!(e, Misaligned(4) | LastCompVersion(_)) //这个闭包会过滤掉 Misaligned(4) 和 LastCompVersion(_) 两种非致命错误，使得解析过程可以继续。
        })
    }
    .unwrap();
    // 打印启动信息
    println!(
        "
boot page table launched, sstatus = {sstatus:#x}
kernel (physical): {:016x}..{:016x}
kernel (remapped): {:016x}..{:016x}
device tree:       {device_tree_paddr:016x}..{:016x}
",
        mem_info.paddr_base,
        mem_info.paddr_base + mem_info.size,
        mem_info.vaddr_base,
        mem_info.vaddr_base + mem_info.size,
        device_tree_paddr + dtb.total_size(),
    );
    // 启动副核
    boot_secondary_harts(
        hartid, //当前核心的硬件线程 ID，表示当前执行的主核。
        &dtb, //设备树（Device Tree）的地址，设备树中包含了系统的硬件信息，比如有多少个核心、每个核心的 hart ID 
        secondary_hart_start as usize - mem_info.offset(), //副核启动代码所在位置的偏移，用于告诉副核从哪里开始执行代码。
    );
    // 转交控制权
    crate::primary_main(KernelConfig {
        phys_to_virt_offset: mem_info.offset(), //返回物理内存地址和虚拟内存地址之间的偏移量
        dtb_paddr: device_tree_paddr, //设备树（Device Tree Blob, DTB）在物理内存中的起始地址
        dtb_size: dtb.total_size() as _, //返回设备树的总大小，表示整个设备树的字节数
    });
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
    unreachable!()
}

/// 副核启动。
extern "C" fn secondary_rust_main() -> ! {
    let _ = unsafe { BOOT_PAGE_TABLE.launch() }; //主核已经完成了启动页表的init,这里只需launch到虚拟地址空间
    crate::secondary_main()
}

/// 根据硬件线程号设置启动栈。
///
/// # Safety
///
/// 裸函数。
#[naked]
unsafe extern "C" fn select_stack(hartid: usize) {
    const STACK_LEN_PER_HART: usize = 4096 * STACK_PAGES_PER_HART; //每个硬件线程（hart）分配的栈大小为32个页，每页4KB
    const STACK_LEN_TOTAL: usize = STACK_LEN_PER_HART * MAX_HART_NUM; //整个栈数组的大小，为所有 hart 分配的栈空间总和，等于每个 hart 的栈大小乘以最大支持的硬件线程数量
    #[link_section = ".bss.bootstack"]  //这是用于存储栈的静态数组，大小为 STACK_LEN_TOTAL，存储在 .bss.bootstack 段中（通常用于未初始化的全局变量）。
    static mut BOOT_STACK: [u8; STACK_LEN_TOTAL] = [0u8; STACK_LEN_TOTAL];  //这里为可能存在的最多五个 hart 分配了栈空间。

    asm!(
        "   mv   tp, a0",     //将传入的 hartid（在 a0 寄存器中）存入线程指针寄存器 tp，这是 RISC-V 的线程指针寄存器，用于表示当前线程的 ID
        "   addi t0, a0,  1     #  将 hartid 加 1，结果存入 t0 寄存器
            la   sp, {stack}    #  将栈顶指针 sp 设置为 BOOT_STACK 的起始地址
            li   t1, {len_per_hart}  #将每个 hart 的栈长度存入 t1 寄存器
         1: add  sp, sp, t1  #将栈顶指针 sp 向上移动 t1 字节，指向下一个栈的起始位置
            addi t0, t0, -1 #将 t0 减 1
            bnez t0, 1b #如果 t0 不为零，则跳回标签 1，继续寻找
            ret
        ",
        stack        =   sym BOOT_STACK,
        len_per_hart = const STACK_LEN_PER_HART,
        options(noreturn)
    )
}

// 遍历设备树，并启动所有副核
fn boot_secondary_harts(boot_hartid: usize, dtb: &Dtb, start_addr: usize) {
    //检查 HSM SBI 扩展支持
    if sbi_rt::probe_extension(sbi_rt::Hsm).is_unavailable() {
        println!("HSM SBI extension is not supported for current SEE.");
        return;
    }
    // 解析设备树（设备树的节点i其实就像是目录一样。）
    let mut cpus = false;
    let mut cpu: Option<usize> = None;
        //遍历设备树，然后将其中的obj按模式匹配
    dtb.walk(|path, obj| match obj {
        //如果传入的是 SubNode，代码会进入 DtbObj::SubNode { name } 分支，name 会被绑定到 SubNode 的 name 字段值上。
        DtbObj::SubNode { name } => {
            if path.is_root() {  //如果在根目录
                if name == Str::from("cpus") {  //且在cpus节点下
                    // 进入 cpus 节点
                    cpus = true;
                    StepInto //这个就像是cd命令，cpus就像是一个目录
                } else if cpus { //如果在根目录，且已经进入过cpus目录
                    // 说明现在已经离开了 cpus 节点，这里是为了启动最后一个遍历到的hart
                    if let Some(hartid) = cpu.take() {   //如果cpu中有值，就取出，并清空cpu原本的值
                        hart_start(boot_hartid, hartid, start_addr); //启动对应的hart
                    }
                    Terminate //停止对当前目录的遍历，返回上级目录
                } else {
                    // 其他节点
                    StepOver //跳过，正常遍历下一个
                }
            //如果在cpus目录
            } else if path.name() == Str::from("cpus") {
                // 如果没有 cpu 序号，肯定是单核的
                if name == Str::from("cpu") {
                    return Terminate; //那就没必要在启动什么副核了，直接return就完事了。
                }
                //如果当前节点的名称以 "cpu@" 开头，表示这是一个具体的 CPU 节点
                if name.starts_with("cpu@") {
                    //使用 from_str_radix 将名称中的 CPU ID 部分（去掉 "cpu@" 后的部分）转换为 usize 类型。
                    let id: usize = usize::from_str_radix(
                        unsafe { core::str::from_utf8_unchecked(&name.as_bytes()[4..]) },
                        16,
                    )
                    .unwrap();
                    //使用 cpu.replace(id) 将 cpu 中的值替换为新的 CPU ID，如果成功替换，就用hartid来获取cpu中之前保存的值
                    //所以这里会启动替换前的核，最后一次替换的核心在这启动不了，需要在上面的cpu.take那里才能取出来启动。
                    if let Some(hartid) = cpu.replace(id) {
                        hart_start(boot_hartid, hartid, start_addr); //然后启动对应id的hart.
                    }
                    StepInto  //疑惑：这里为什么要用stepinto？此时不是已经在cpu节点了吗？再进入具体的cpu节点有什么意义？
                //都不是，就遍历cpus中的下一个节点
                } else {
                    StepOver
                }
            //如果既不是根目录，也不是cpus目录，就直接跳过。
            } else {
                StepOver
            }
        }
        //只有当当前节点是一个以 cpu@ 开头的 CPU 节点，且它的 status 属性不是 "okay" 时，这个分支才会被执行。
        // 状态不是 "okay" 的 cpu 不能启动
        DtbObj::Property(Property::Status(status))
            if path.name().starts_with("cpu@") && status != Str::from("okay") =>
        {
            if let Some(id) = cpu.take() {
                println!("hart{id} has status: {status}");
            }
            StepOut
        }
        //其他属性：无需处理，直接跳过。
        DtbObj::Property(_) => StepOver,
    });
    println!();
}
//打印此hart的启动信息，并跳转到secondary_hart_start，副核开始执行
fn hart_start(boot_hartid: usize, hartid: usize, start_addr: usize) {
    if hartid != boot_hartid {
        println!("hart{hartid} is booting...");
        //利用sbi_rto提供的hart_start将这个hartid对应hart的pci设置为start_addr，
        //这里意味着副核将从secondary_hart_start函数开始执行。
        let ret = sbi_rt::hart_start(hartid, start_addr, 0); //（从这里继续）
        if ret.is_err() {
            panic!("start hart{hartid} failed. error: {ret:?}");
        }
    } else {
        println!("hart{hartid} is the primary hart.");
    }
}
