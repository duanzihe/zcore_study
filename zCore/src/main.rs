#![cfg_attr(not(feature = "libos"), no_std)]
#![deny(warnings)]
#![no_main]
#![feature(naked_functions, asm_sym, asm_const)]
#![feature(default_alloc_error_handler)]

use core::sync::atomic::{AtomicBool, Ordering};

extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate cfg_if;

#[macro_use]
mod logging;

#[cfg(not(feature = "libos"))]
mod lang;

mod fs;
mod handler;
mod platform;
mod utils;

cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        #[path = "memory_x86_64.rs"]
        mod memory;
    } else {
        mod memory;
    }
}

static STARTED: AtomicBool = AtomicBool::new(false);

#[cfg(all(not(any(feature = "libos")), feature = "mock-disk"))]
static MOCK_CORE: AtomicBool = AtomicBool::new(false);

fn primary_main(config: kernel_hal::KernelConfig) {
    logging::init();// 初始化日志系统。设置日志级别为warn和error。
    memory::init();// 初始化一个堆分配器，并将预定义的 MEMORY 内存块注册到堆分配器中，供操作系统在启动时进行动态内存管理
    //执行早期初始化步骤(从设备树获取物理地址并将其转化为虚拟地址以生成设备树对象，获取并设置内核命令行参数，获取并设置CPU时钟频率，获取并设置 initrd 的内存区域，获取并设置系统的内存区域)
    kernel_hal::primary_init_early(config, &handler::ZcoreKernelHandler); 
    let options = utils::boot_options(); // 获取启动选项，包括cmdline,log_level和root_proc（在linux模式下就是/bin/busybox?sh）
    logging::set_max_level(&options.log_level); //根据启动选项设置日志级别。
    warn!("Boot options: {:#?}", options); //打印启动选项的详细信息。
    memory::insert_regions(&kernel_hal::mem::free_pmem_regions());//将空闲的物理内存区域经过offset转换成空闲的虚拟地址区域， 然后注册到分配器。

    kernel_hal::primary_init();//执行进一步的初始化步骤，可能包括启动核心服务、设置中断处理程序等。

    //这里的ordering：：seqcst确保顺序一致性，保证了在设置started为true的时候前面的初始化指令已经完成
    STARTED.store(true, Ordering::SeqCst);//设置一个标志，指示系统已经启动。这个标志用于同步或通知其他部分的代码。

    //这个宏用于根据不同的编译特性（linux 或 zircon）来选择不同的代码路径。
    cfg_if! { 
        if #[cfg(all(feature = "linux", feature = "zircon"))] {
            panic!("Feature `linux` and `zircon` cannot be enabled at the same time!");
        //如果启用了 linux，则从启动选项中获取命令行参数和环境变量，加载根文件系统，然后调用 zcore_loader::linux::run 来启动 Linux 环境。
        } else if #[cfg(feature = "linux")] {
            //这行代码将根进程的路径和参数从字符串中解析出来，使用 ? 作为分隔符，并将其转换为一个 Vec<String>。
            //(其实就是在上面boot_options函数设置的root_proc，就是/bin/busybox?sh，在l这里按？分割)
            let args = options.root_proc.split('?').map(Into::into).collect(); // parse "arg0?arg1?arg2"
            //定义了一个环境变量 PATH，指定了可执行文件的搜索路径。
            let envs = alloc::vec!["PATH=/usr/sbin:/usr/bin:/sbin:/bin".into()];
            // 调用 fs::rootfs() 获取根文件系统的相关信息，以便后续的进程可以访问文件。
            // 在xtask阶段制作好了rootfs，并将它的路径作为参数传递给了qemu，qemu就将它当做设备写入了设备树，现在内核再通过rootfs()打开这个设备来访问根文件系统
            let rootfs = fs::rootfs();
            //传入args=[/bin/busy/box,sh],envs="PATH=/usr/sbin:/usr/bin:/sbin:/bin",rootfs就是之前xtask阶段用rcore的simple_file_system制作的根文件系统
            let proc = zcore_loader::linux::run(args, envs, rootfs);
            //上面这个过程完成后，用户空间的 sh 进程将运行，并可以执行相应的命令。此时，内核成功地将控制权交给用户空间，实现了用户与操作系统的交互。
            //接下来只需要等待它退出就可以了。
            utils::wait_for_exit(Some(proc))
        } else if #[cfg(feature = "zircon")] {

            let zbi = fs::zbi();      //这里就是用我们的user-link-img指定的bringup.zbi做init_ram_disk

            let proc = zcore_loader::zircon::run_userboot(zbi, &options.cmdline); 
            warn!("finished!");
            utils::wait_for_exit(Some(proc))
        } else {
            panic!("One of the features `linux` or `zircon` must be specified!");
        }
    }
}
//似乎目前aarch64并不支持多核启动？
#[cfg(not(any(feature = "libos", target_arch = "aarch64")))]
fn secondary_main() -> ! {
    //这是一个自旋锁的实现，副核会反复检查 STARTED 的值，直到它变为 true 才继续执行。
    while !STARTED.load(Ordering::SeqCst) {
        core::hint::spin_loop(); //这是一个 CPU 指令级的提示，告诉处理器当前处于自旋状态（空循环），优化性能。
    }
    //获取到started信号后执行
    kernel_hal::secondary_init();
    info!("hart{} inited", kernel_hal::cpu::cpu_id());
    #[cfg(feature = "mock-disk")]
    {
        if MOCK_CORE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            utils::mock_disk();
        }
    }
    utils::wait_for_exit(None)
}
