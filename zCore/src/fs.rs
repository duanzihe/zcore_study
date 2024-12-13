cfg_if! {
    if #[cfg(feature = "linux")] {
        use alloc::sync::Arc;
        use rcore_fs::vfs::FileSystem;

        #[cfg(feature = "libos")]
        pub fn rootfs() -> Arc<dyn FileSystem> {
            let  rootfs = if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
                std::path::Path::new(&dir).parent().unwrap().to_path_buf()
            } else {
                std::env::current_dir().unwrap()
            };
            rcore_fs_hostfs::HostFS::new(rootfs.join("rootfs").join("libos"))
        }

        #[cfg(not(feature = "libos"))]
        pub fn rootfs() -> Arc<dyn FileSystem> {
            use rcore_fs::dev::Device;

            let device: Arc<dyn Device> = {
                #[cfg(feature = "mock-disk")]{
                    let block = linux_object::fs::mock_block();
                    Arc::new(block)
                }
                #[cfg(not(feature = "mock-disk"))] {
                //在xtask阶段制作好了rootfs，并将它的路径作为参数传递给了qemu，qemu就将它当做设备写入了设备树，现在内核再通过rootfs()打开这个设备来访问根文件系统
                    use linux_object::fs::rcore_fs_wrapper::*;
                    if let Some(initrd) = init_ram_disk() {
                        Arc::new(MemBuf::new(initrd))
                    } else {
                        let block = kernel_hal::drivers::all_block().first_unwrap();
                        Arc::new(BlockCache::new(Block::new(block), 0x100))
                    }
                }
            };
            warn!("Opening the rootfs...");
            rcore_fs_sfs::SimpleFileSystem::open(device).expect("failed to open device SimpleFS")
        }
    } else if #[cfg(feature = "zircon")] {

        #[cfg(feature = "libos")]
        pub fn zbi() -> impl AsRef<[u8]> {
            let path = std::env::args().nth(1).unwrap();
            std::fs::read(path).expect("failed to read zbi file")
        }

        #[cfg(not(feature = "libos"))]
        pub fn zbi() -> impl AsRef<[u8]> {
            init_ram_disk().expect("failed to get the init RAM disk")
        }
    }
}

#[cfg(not(feature = "libos"))]
pub(crate) fn init_ram_disk() -> Option<&'static mut [u8]> {
    //获取嵌入到内核中的zbi的起始和结束地址，并将其作为一个字节切片返回，供后续run_userboot使用
    if cfg!(feature = "link-user-img") {
        extern "C" {
            fn _user_img_start();
            fn _user_img_end();
        }
        //Z修改！定位
        {
            let start = _user_img_start as usize;
            let end = _user_img_end as usize;
            warn!("_user_img_start: 0x{:x}, _user_img_end: 0x{:x}", start, end);
        }
        Some(unsafe {
            core::slice::from_raw_parts_mut(
                _user_img_start as *mut u8,
                _user_img_end as usize - _user_img_start as usize,
            )
        })
    } else {
        kernel_hal::boot::init_ram_disk()
    }
}

// Hard link rootfs img
// 这里在编译时就把link-user-img嵌入到内核空间新建的.data.img数据段中。
#[cfg(not(feature = "libos"))]
#[cfg(feature = "link-user-img")]
core::arch::global_asm!(concat!(
    r#"
    .section .data.img
    .global _user_img_start
    .global _user_img_end
_user_img_start:
    .incbin ""#,
    env!("USER_IMG"),
    r#""
_user_img_end:
"#
));
