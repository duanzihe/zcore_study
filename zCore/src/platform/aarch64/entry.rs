use super::consts::save_offset;
use kernel_hal::KernelConfig;
use rayboot::Aarch64BootInfo;
core::arch::global_asm!(include_str!("space.s"));

#[naked]
#[no_mangle]
#[link_section = ".text.entry"]
unsafe extern "C" fn _start() -> ! {
    core::arch::asm!(
        "
        adrp    x19, boot_stack_top  //将 boot_stack_top 地址的页框部分加载到 x19 中，因此适用于加载4KB对齐的地址
        mov     sp, x19              //设置栈指针
        b rust_main",                //跳转去执行rust_main
        options(noreturn),
    )
}

#[no_mangle]
extern "C" fn rust_main(boot_info: &'static Aarch64BootInfo) -> ! {  //注意，这里的Aarch64BootInfo是由作为引导固件的rayboot提供的
    let config = KernelConfig {                 //具体的配置可以从boot.json里得到
        cmdline: boot_info.cmdline,             //"cmdline": "LOG=warn:ROOTPROC=/bin/busybox?sh",
        firmware_type: boot_info.firmware_type, // "firmware_type": "QEMU",
        uart_base: boot_info.uart_base,         // "uart_base": 150994944,
        gic_base: boot_info.gic_base,           // "gic_base": 134217728,
        phys_to_virt_offset: boot_info.offset,  // "offset": 18446462598732840960
    };
    save_offset(boot_info.offset);   //用惰性的全局线程安全的变量OFFSET
    crate::primary_main(config); //进入
    unreachable!()
}
