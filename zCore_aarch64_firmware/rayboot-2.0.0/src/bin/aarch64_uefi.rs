#![no_std]
#![no_main]
#![feature(abi_efiapi)]
#![feature(default_alloc_error_handler)]
#![feature(slice_pattern)]
#![allow(dead_code)]
#![allow(unused_imports)]

#[macro_use]
extern crate alloc;

use acpi::AcpiTables;
use alloc::boxed::Box;
use alloc::vec::*;
use core::arch::global_asm;
use core::borrow::{Borrow, BorrowMut};
use core::fmt::Write;
use core::mem::transmute;
use core::ops::DerefMut;
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::slice::SlicePattern;
use core::time::Duration;
use cortex_a::registers::CurrentEL;
use cortex_a::registers::*;
use irsa::{RsaPublicKey, Sha256};
use log::*;
use rayboot::arch::aarch64::entry::{start_qemu, start_raspi4};
use rayboot::arch::aarch64::{
    config::*,
    entry::{
        init_mmu, init_qemu_boot_page_table, init_raspi4_boot_page_table, switch_to_el1, uptime,
        STACK,
    },
};
use rayboot::boot_info::{MemoryRegions, Optional};
use rayboot::{Aarch64BootInfo, FirmwareType};
use rsdp::Rsdp;
use serde_json;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use uefi::prelude::*;
use uefi::proto::console::serial::Serial;
use uefi::proto::device_path::DevicePath;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::table::boot::{
    AllocateType, MemoryDescriptor, MemoryType, OpenProtocolAttributes, OpenProtocolParams,
};
use uefi::table::Runtime;
use uefi::{
    prelude::{entry, Boot, SystemTable},
    CStr16, Handle, ResultExt, Status,
};
use uefi_test_runner::poweron_check;
use xmas_elf::program::Type;
use xmas_elf::sections::SectionData::SymbolTable64;
use xmas_elf::symbol_table::Entry;
 //修改！这里一开始是true,意味着启用了树梅派开发板，但实际上我们是在qemu上做的，所以先关闭这个特性。
static mut IS_RASPI4: bool = false;

#[entry]
//这里的image和st都是由uefi运行环境提供的，可以理解为是fd提供的
fn efi_main(image: Handle, mut st: SystemTable<Boot>) -> Status {
    // Initialize utilities (logging, memory allocation...)
    //初始化与日志，内存分配相关的工具
    uefi_services::init(&mut st).expect("Failed to initialize utilities");

    // Set and detect firmware environment
    //设置并检查固件环境
    st.stdout().clear().expect("unable to clear screen");

    info!("Current EL: {}", CurrentEL.get() >> 2);

    // Locale ACPI table info
    let rsdp_addr = {
        use uefi::table::cfg;
        let mut config_entries = st.config_table().iter();
        // look for an ACPI2 RSDP first
        let acpi2_rsdp = config_entries.find(|entry| matches!(entry.guid, cfg::ACPI2_GUID));
        // if no ACPI2 RSDP is found, look for a ACPI1 RSDP
        let rsdp = acpi2_rsdp
            .or_else(|| config_entries.find(|entry| matches!(entry.guid, cfg::ACPI_GUID)));
        rsdp.map(|entry| entry.address as u64)
    }
    .expect("rsdp not found");
    info!("rsdp_addr: 0x{:x}", rsdp_addr);

    //这里会检查并反馈信息 Detect QEMU device
    detect_device_type(st.boot_services());

    // Load and verify kernel
    // 一个名为kernel_entry，类型是接受aarch64bootinfow为参数的回调函数。
    //这个函数指针是通过分析内核的elf找到的内核入口点地址，最后再类型转换得到的。
    let kernel_entry: extern "C" fn(&Aarch64BootInfo) = {
        let fs = st
            .boot_services()
            .get_image_file_system(image.clone())  //这里的这个image其实是UEFI环境提供的用来“访问其他文件系统的”文件系统镜像。
            .expect("cannot get image file system");
        let fs = unsafe { fs.interface.get().as_mut().unwrap() };
        let kernel_elf = verify_kernel(fs);
        info!("loading dzh_kernel to memory...");
        let kernel_entry = load_kernel(st.boot_services(), kernel_elf); //这里反馈输出了三个可加载段的物理地址
        info!("kernel entry: 0x{:x}", kernel_entry);  //这里反馈输出了0xffff000040080000 （疑惑：似乎一开始就启用了虚拟地址？或许问题就出在这里）
        unsafe { transmute(kernel_entry) } //这一步transmute(kernel_entry) 的作用是将这个地址（u64）转换成一个函数指针 extern "C" fn(&Aarch64BootInfo)。
    };

    let fs = {
        let fs = st
            .boot_services()
            .get_image_file_system(image.clone())
            .expect("cannot get image file system");
        unsafe { fs.interface.get().as_mut().unwrap() }
    };

    let mut file = open_file(
        fs,
        "\\EFI\\Boot\\Boot.json",
        FileMode::Read,
        FileAttribute::READ_ONLY,
    );
    let file_info: Box<FileInfo> = file.get_boxed_info().unwrap();
    let mut buf = vec![0 as u8; file_info.file_size() as usize];
    let buf = buf.as_mut_slice();
    assert_eq!(file_info.file_size() as usize, file.read(buf).unwrap());
    let info = serde_json::from_slice(buf).unwrap();
    info!("Boot info from json: {:#x?}", info);

    //修改！地址测试
    info!("Address of info: {:p}", &info);

    // check memory mapping info
    let max_mmap_size = st.boot_services().memory_map_size().map_size;
    let mmap_storage = Box::leak(vec![0; max_mmap_size].into_boxed_slice());
    // exit boot service and switch to kernel
    info!("exit boot services");
    let (_system_table, _memory_map) = st
        .exit_boot_services(image, mmap_storage)
        .expect("Failed to exit boot services");
    unsafe {
        switch_to_kernel(kernel_entry, &info);
    }

    Status::SUCCESS
}
//switch_to_kernel把在load_kernel时获取的kernel_entry和用来获取的boot.json中的info，把他们俩的地址压入了stack。
//但需要注意的是，这里压入的kernel_entry的地址是0xffff 0000 4008 0000
unsafe fn switch_to_kernel(kernel_entry: extern "C" fn(&Aarch64BootInfo), _info: &Aarch64BootInfo) {
    use rayboot::arch::aarch64::bsp::Pl011Uart;
    let uart = Pl011Uart::new(if IS_RASPI4 { 0xfe20_1000 } else { 0x0900_0000 });
    uart.write(format_args!("\n########## jump to kernel ##########\n\n"));
    let mut index = 0;
    for i in (kernel_entry as usize).to_le_bytes() {
        STACK.0[index] = i;
        index += 1;
    }
    for i in (_info as *const Aarch64BootInfo as usize).to_le_bytes() { //疑惑：这里压入的地址我认为应当s 和kernel_entry一样的虚拟地址，但其实这里是物理地址。
        STACK.0[index] = i; 
        index += 1;
    }


    if IS_RASPI4 {
        start_raspi4();
    } else {
        // uart.write(format_args!("\n########## finish ##########\n\n"));
        // 通过在这里反馈，可以得知直到这里都是执行了的。

        start_qemu();
    }

}
//将 ELF 格式内核映像的可加载段从输入缓冲区加载到分配的内存中，以便在后续步骤中可以执行该内核。
fn load_kernel(boot_services: &BootServices, kernel_elf: Vec<u8>) -> u64 {
    //首先，使用 xmas_elf 库解析内核 ELF 文件，确保其头部的魔数正确（0x7f 45 4c 46，即 ".ELF"）。
    let kernel_elf = xmas_elf::ElfFile::new(kernel_elf.as_slice()).unwrap();
    let elf_header = kernel_elf.header;
    assert_eq!(elf_header.pt1.magic, [0x7f, 0x45, 0x4c, 0x46]);
    //遍历 ELF 文件的每一个程序头表，找到那些类型为 Type::Load 的段，这些段通常包含要加载到内存中的代码或数据。
    for ph in kernel_elf.program_iter() {
        if ph.get_type().unwrap() == Type::Load {
            //在每个可加载段，代码会从 ELF 中读取该段的虚拟地址范围，计算该段占据的内存页数，
            //并调用 EFI 的 allocate_pages 来分配内存。这里的 start_va 和 end_va 都是虚拟地址。
            let start_va = ph.virtual_addr() as usize & 0x0000ffffffffffff;
            let end_va = (ph.virtual_addr() + ph.mem_size()) as usize & 0x0000ffffffffffff;
            let pages = (end_va >> ARM64_PAGE_SIZE_BITS) - (start_va >> ARM64_PAGE_SIZE_BITS) + 1;
            info!("load header to address: 0x{:x}", start_va);
            boot_services
                .allocate_pages(
                    AllocateType::Address(start_va),
                    MemoryType::CONVENTIONAL,
                    pages,
                )
                .ok();
            let dst = unsafe {
                core::slice::from_raw_parts_mut(start_va as *mut u8, ph.file_size() as usize)
            };
            let src =
                &kernel_elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize];
            dst.copy_from_slice(src);
        }
    }

    kernel_elf.header.pt2.entry_point() //通过程序头表获取入口点的虚拟地址
}
///在hda里寻找os,并返回相关的信息
fn verify_kernel(fs: &mut SimpleFileSystem) -> Vec<u8> {
    // load packaged kernel and hashed public key from disk and reset cursor to use behind
    let mut kernel_img = open_file(
        fs,
        KERNEL_LOCATION,   //这儿用的其实就是disk里的os,也就是zcore的elf文件
        FileMode::Read,
        FileAttribute::READ_ONLY,
    );
    let kernel_info: Box<FileInfo> = kernel_img.get_boxed_info().unwrap();
    let mut kernel_data = vec![0 as u8; kernel_info.file_size() as usize];
    let kernel_data = kernel_data.as_mut_slice(); //这个就是最后返回的内核信息
    kernel_img.read(kernel_data).expect("failed to read kernel");  

    match option_env!("SECURE_BOOT") {
        Some("ON") => {
            info!("running kernel integrity check...");
            info!("start integrity check at: {:?}", uptime());
            let mut pk_hash_data =
                open_file(fs, "pk_hash", FileMode::Read, FileAttribute::READ_ONLY);
            let mut pk_hash = vec![0 as u8; 32];
            let pk_hash = pk_hash.as_mut_slice();
            assert_eq!(pk_hash_data.read(pk_hash).unwrap(), 32);

            // Split the signed kernel image
            let header = unsafe {
                (kernel_data.as_ptr() as *const KernelHeader)
                    .as_ref()
                    .unwrap()
            };
            let header_size = core::mem::size_of::<KernelHeader>();
            let pk_from_image = &kernel_data[header_size..(header_size + header.pk_size)];
            let sign_from_image = &kernel_data
                [(header_size + header.pk_size)..(header_size + header.pk_size + header.sign_size)];
            let kernel_from_image =
                &kernel_data[(header_size + header.pk_size + header.sign_size)..];

            // verify public key
            let mut pk_hasher = Sha256::new();
            pk_hasher
                .input(pk_from_image)
                .expect("failed to input public key to hasher");
            assert_eq!(
                pk_hasher
                    .finalize()
                    .expect("hash pub key failed")
                    .as_slice(),
                pk_hash,
                "verify pub key failed"
            );
            info!("public key verification pass!");

            // verify signature, hash kernel data and verify kernel
            let pk = RsaPublicKey::from_raw(pk_from_image.to_vec());
            let hashed_kernel_from_sign = pk
                .verify(sign_from_image.as_slice())
                .expect("failed to verify signature");
            let mut kernel_hasher = Sha256::new();
            kernel_hasher
                .input(kernel_from_image)
                .expect("fail to input kernel to hasher");
            assert_eq!(
                kernel_hasher.finalize().expect("hash kernel data failed"),
                hashed_kernel_from_sign.as_slice(),
                "verify kernel failed"
            );
            info!("kernel verification pass!");
            info!("end integrity check at: {:?}", uptime());
            return kernel_from_image.to_vec();
        }
        _ => {}
    }

    kernel_data.to_vec()
}

fn open_file(
    fs: &mut SimpleFileSystem,
    name: &str,
    mode: FileMode,
    attribute: FileAttribute,
) -> RegularFile {
    let mut root_dir = fs.open_volume().expect("cannot get root dir");
    use uefi::CStr16;
    let mut name_buf: [u16; 100] = [0; 100];
    let kernel_img = root_dir
        .open(
            CStr16::from_str_with_buf(name, &mut name_buf).unwrap(),
            mode,
            attribute,
        )
        .expect(format!("open file {} failed", name).as_str());
    unsafe { RegularFile::new(kernel_img) }
}

fn detect_device_type(bt: &BootServices) {
    if let Ok(serial) = bt.locate_protocol::<Serial>() {
        let serial = unsafe { &*serial.get() };
        unsafe {
            match serial.io_mode().baud_rate {
                115200 => {
                    info!("Detect raspi4 device");
                    IS_RASPI4 = true;
                }
                38400 => {
                    info!("Detect QEMU device");
                    IS_RASPI4 = false;
                }
                _ => {
                    panic!("Unknown device");
                }
            }
        }
    } else {
        panic!("Get serial info failed");
    }
}
