use alloc::boxed::Box;
use alloc::format;

use zcore_drivers::builder::{DevicetreeDriverBuilder, IoMapper};
use zcore_drivers::irq::riscv::ScauseIntCode;
use zcore_drivers::uart::BufferedUart;
use zcore_drivers::{Device, DeviceResult};

use crate::common::vm::GenericPageTable;
use crate::{drivers, mem::phys_to_virt, CachePolicy, MMUFlags, PhysAddr, VirtAddr};

struct IoMapperImpl;

impl IoMapper for IoMapperImpl {
    fn query_or_map(&self, paddr: PhysAddr, size: usize) -> Option<VirtAddr> {
        let vaddr = if paddr > (1 << 39) {
            // To retrieve avaliable sv39 vaddr
            paddr | (0x1ffffff << 39)
        } else {
            phys_to_virt(paddr)
        };
        let mut pt = super::vm::kernel_page_table().lock();
        if let Ok((paddr_mapped, _, _)) = pt.query(vaddr) {
            if paddr_mapped == paddr {
                Some(vaddr)
            } else {
                warn!(
                    "IoMapper::query_or_map: not linear mapping: vaddr={:#x}, paddr={:#x}",
                    vaddr, paddr_mapped
                );
                None
            }
        } else {
            let size = crate::addr::align_up(size);
            let flags = MMUFlags::READ
                | MMUFlags::WRITE
                | MMUFlags::HUGE_PAGE
                | MMUFlags::DEVICE
                | MMUFlags::from_bits_truncate(CachePolicy::UncachedDevice as usize);
            if let Err(err) = pt.map_cont(vaddr, size, paddr, flags) {
                warn!(
                    "IoMapper::query_or_map: failed to map {:#x?} => {:#x}, flags={:?}: {:?}",
                    vaddr..vaddr + size,
                    paddr,
                    flags,
                    err
                );
                None
            } else {
                Some(vaddr)
            }
        }
    }
}

/// Initialize device drivers.
pub(super) fn init() -> DeviceResult {
    // prase DTB and probe devices
    let dev_list =
    //使用 DevicetreeDriverBuilder 来解析设备树，获取设备列表。这里 phys_to_virt 函数用于将物理地址转换为虚拟地址，以便访问设备树数据。
        DevicetreeDriverBuilder::new(phys_to_virt(crate::KCONFIG.dtb_paddr), IoMapperImpl)?
            .build()?; //build会根据设备的类型和属性创建相应的结构体实例
    //遍历解析到的设备列表，判断设备类型,并添加到驱动中。
    for dev in dev_list.into_iter() {
        //如果是 UART 设备，则将其封装为 BufferedUart 后再添加到驱动中
        if let Device::Uart(uart) = dev {
            drivers::add_device(Device::Uart(BufferedUart::new(uart)));
        } else {
            drivers::add_device(dev);
        }
    }
    // 如果未禁用 PCI 支持，调用 PCI 初始化，获取并添加所有 PCI 设备。
    #[cfg(not(feature = "no-pci"))]
    {
        use alloc::sync::Arc;
        use zcore_drivers::bus::pci;
        let pci_devs = pci::init(Some(Arc::new(IoMapperImpl)))?;
        for d in pci_devs.into_iter() {
            drivers::add_device(d);
        }
    }
    // 初始化中断控制器，以便处理硬件中断
    intc_init()?;

    //如果启用了图形功能，初始化图形控制台，并根据需要创建渲染线程
    #[cfg(feature = "graphic")]
    if let Some(display) = drivers::all_display().first() {
        crate::console::init_graphic_console(display.clone());
        if display.need_flush() {
            // TODO: support nested interrupt to render in time
            crate::thread::spawn(crate::common::future::DisplayFlushFuture::new(display, 30));
        }
    }
    //如果启用了环回功能，初始化网络模块。
    #[cfg(feature = "loopback")]
    {
        use crate::net;
        net::init();
    }

    Ok(())
}
//查找对于cpuid的中断控制器，为他注册软中断和时间中断的处理程序
pub(super) fn intc_init() -> DeviceResult {
    //找到与当前 CPU 相关的中断控制器
    let irq = drivers::all_irq()
        .find(format!("riscv-intc-cpu{}", crate::cpu::cpu_id()).as_str())
        .expect("IRQ device 'riscv-intc' not initialized!");
    // 为中断控制器注册了一个处理程序，用于处理软中断。当发生软中断时，控制器会调用 super::trap::super_soft 函数来处理该中断。
    irq.register_handler(
        ScauseIntCode::SupervisorSoft as _,
        Box::new(super::trap::super_soft),
    )?;
    // 同上，注册一个处理时间中断的程序
    irq.register_handler(
        ScauseIntCode::SupervisorTimer as _,
        Box::new(super::trap::super_timer),
    )?;
    irq.unmask(ScauseIntCode::SupervisorSoft as _)?;
    irq.unmask(ScauseIntCode::SupervisorTimer as _)?;

    Ok(())
}
