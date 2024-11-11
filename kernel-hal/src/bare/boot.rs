//! Bootstrap and initialization.

use crate::{KernelConfig, KernelHandler, KCONFIG, KHANDLER};

//公用的有参数的函数调用对应arch的具体的没有参数的函数！
hal_fn_impl! {
    impl mod crate::hal_fn::boot {
        fn cmdline() -> alloc::string::String {
            super::arch::cmdline()
        }

        fn init_ram_disk() -> Option<&'static mut [u8]> {
            super::arch::init_ram_disk()
        }
        
        fn primary_init_early(cfg: KernelConfig, handler: &'static impl KernelHandler) {
            info!("Primary CPU {} init early...", crate::cpu::cpu_id());
            KCONFIG.init_once_by(cfg);  //初始化KCONFIG，在aarch64下就是zCore/disk/EFI/Boot/Boot.json中的信息。
            KHANDLER.init_once_by(handler);
            super::arch::primary_init_early();
        }

        fn primary_init() {
            info!("Primary CPU {} init...", crate::cpu::cpu_id());
            unsafe { trapframe::init() };
            super::arch::primary_init();
        }

        fn secondary_init() {
            // info!("Secondary CPU {} init...", crate::cpu::cpu_id());
            // we can't print anything here, see reason: zcore/main.rs::secondary_main()
            unsafe { trapframe::init() };
            super::arch::secondary_init();
            // now can print
        }
    }
}
