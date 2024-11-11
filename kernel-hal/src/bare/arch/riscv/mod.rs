mod drivers;
mod trap;

pub mod config;
pub mod cpu;
pub mod interrupt;
pub mod mem;
pub mod sbi;
pub mod timer;
pub mod vm;

use crate::{mem::phys_to_virt, utils::init_once::InitOnce, PhysAddr};
use alloc::{string::String, vec::Vec};
use core::ops::Range;
use zcore_drivers::utils::devicetree::Devicetree;

static CMDLINE: InitOnce<String> = InitOnce::new_with_default(String::new());
static INITRD_REGION: InitOnce<Option<Range<PhysAddr>>> = InitOnce::new_with_default(None);
static MEMORY_REGIONS: InitOnce<Vec<Range<PhysAddr>>> = InitOnce::new_with_default(Vec::new());

pub const fn timer_interrupt_vector() -> usize {
    trap::SUPERVISOR_TIMER_INT_VEC
}

pub fn cmdline() -> String {
    CMDLINE.clone()
}

pub fn init_ram_disk() -> Option<&'static mut [u8]> {
    INITRD_REGION.as_ref().map(|range| unsafe {
        core::slice::from_raw_parts_mut(phys_to_virt(range.start) as *mut u8, range.len())
    })
}

pub fn primary_init_early() {
    // 从设备树获取物理地址并将其转化为虚拟地址，生成设备树对象
    let dt = Devicetree::from(phys_to_virt(crate::KCONFIG.dtb_paddr)).unwrap();
    // 获取并设置内核命令行参数 （注意！这个内核命令行参数并不是我们输入的，而是设备树提供的）
    if let Some(cmdline) = dt.bootargs() {
        info!("Load kernel cmdline from DTB: {:?}", cmdline);
        CMDLINE.init_once_by(cmdline.into());
    }
    // 获取并设置CPU时钟频率
    if let Some(time_freq) = dt.timebase_frequency() {
        info!("Load CPU clock frequency from DTB: {} Hz", time_freq);
        super::cpu::CPU_FREQ_MHZ.init_once_by((time_freq / 1_000_000) as u16);
    }
    // 获取并设置 initrd 的内存区域
    //initrd 是 "initial ramdisk" 的缩写，表示初始内存盘。
    //它在系统启动时作为临时文件系统被加载，包含了一些基本的系统文件，帮助内核完成进一步的启动过程。initrd 中通常存放一些初始化脚本或必要的驱动程序。
    if let Some(initrd_region) = dt.initrd_region() {
        info!("Load initrd regions from DTB: {:#x?}", initrd_region);
        INITRD_REGION.init_once_by(Some(initrd_region));
    }
    // 获取并设置系统的内存区域
    if let Ok(regions) = dt.memory_regions() {
        info!("Load memory regions from DTB: {:#x?}", regions);
        MEMORY_REGIONS.init_once_by(regions);
    }
}

pub fn primary_init() {
    vm::init();
    drivers::init().unwrap();
}

pub fn timer_init() {
    timer::init();
}
//从这里继续
pub fn secondary_init() {
    vm::init(); //
    info!("cpu {} drivers init ...", crate::cpu::cpu_id());
    drivers::intc_init().unwrap(); //查找对于cpuid的中断控制器，为他注册软中断和时间中断的处理程序
    let plic = crate::drivers::all_irq() //查找riscv的平台级中断控制器
        .find("riscv-plic")
        .expect("IRQ device 'riscv-plic' not initialized!");
    info!(
        "cpu {} enable plic: {:?}",
        crate::cpu::cpu_id(),
        plic.name()
    );
    //riscv_plic的详情请见drivers/src/irq/riscv_plic.rs
    plic.init_hart(); //为当前核心设置中断优先级的处理规则，确保它能够根据设定的阈值响应适当的中断。 
}
