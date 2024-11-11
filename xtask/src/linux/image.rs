use crate::{commands::wget, Arch, PROJECT_DIR};
use os_xtask_utils::{dir, CommandExt, Qemu, Tar};
use std::{fs, path::Path};

impl super::LinuxRootfs {
    /// 在zCore/riscv64.img生成镜像,此镜像包含busybox。
    pub fn image(&self) {
        // 递归 rootfs，制作根文件系统的“内容”，也就是busybox.
        self.make(false);
        // 镜像路径
        let inner = PROJECT_DIR.join("zCore");//inner就是zCore/
        let image = inner.join(format!("{arch}.img", arch = self.0.name()));//image就是zCore/架构名.img
        // aarch64 还需要下载 firmware到ignored/origin/archs/aarch64,因为aarch64的情况比riscv64更复杂。
        //这一段代码下载并解压，复制又重命名，最终在zCore/disk/EFI/Boot 目录下，新建了boot.json和bootaa64.efi。

    //修改！
        if let Arch::Aarch64 = self.0 {
            const URL:&str = "https://github.com/Luchangcheng2333/rayboot/releases/download/2.0.0/aarch64_firmware.tar.gz";
            let aarch64_tar = self.0.origin().join("Aarch64_firmware.zip");
            wget(URL, &aarch64_tar);

            let fw_dir = self.0.target().join("firmware");
            dir::clear(&fw_dir).unwrap();
            Tar::xf(&aarch64_tar, Some(&fw_dir)).invoke();

            let boot_dir = inner.join("disk").join("EFI").join("Boot");
            dir::clear(&boot_dir).unwrap();
            //原版
            // fs::copy(
            //     fw_dir.join("aarch64_uefi.efi"),
            //     boot_dir.join("bootaa64.efi"),
            // )
            // .unwrap();

            //修改！虽然个人认为rayboot这个制作efi的文件也应该在zcore项目里管理，但暂时还是先用本地目录来测试吧
            fs::copy(
                "/home/dzh/everything/daima/rust/zCore_aarch64_firmware/rayboot-2.0.0/target/aarch64-unknown-uefi/release/aarch64_uefi.efi",
                boot_dir.join("bootaa64.efi"),
            )
            .unwrap();

            fs::copy(fw_dir.join("Boot.json"), boot_dir.join("Boot.json")).unwrap();
        }


        // 将make方法制作的”内容“填入fuse方法制作的”框架“，得到根文件系统的镜像。
        fuse(self.path(), &image);
        // 扩充一些额外空间，供某些测试使用
        Qemu::img()
            .arg("resize")
            .args(&["-f", "raw"])
            .arg(image)
            .arg("+5M")
            .invoke();
    }
}

/// 利用传入dir路径中的根文件系统”内容“，搭配rcore的文件系统”框架“，制作根文件系统镜像并存放到传入的image路径中。
fn fuse(dir: impl AsRef<Path>, image: impl AsRef<Path>) {
    use rcore_fs::vfs::FileSystem;
    use rcore_fs_fuse::zip::zip_dir;
    use rcore_fs_sfs::SimpleFileSystem;
    use std::sync::{Arc, Mutex};

    // 这一步是创建空的zCore/riscv64.img
    let file = fs::OpenOptions::new() //创建一个新的 OpenOptions 实例。OpenOptions 提供了多种选项来控制文件的打开或创建方式。
        .read(true)  //可读
        .write(true)//可写
        .create(true)//没有就新建
        .truncate(true) //如果文件已经存在，就清空其中内容
        .open(image) //尝试打开名为 image 的文件。image 是一个实现了 AsRef<Path> 的类型，通常是一个文件路径。如果文件路径存在且可以被打开，则返回一个 File 对象。
        .expect("failed to open image");
    //定义了文件系统的最大空间为 1 GiB
    const MAX_SPACE: usize = 1024 * 1024 * 1024; // 1GiB
    //使用 SimpleFileSystem::create 创建一个新的文件系统实例, 这里用到了rcore_fs_sfs
    let fs = SimpleFileSystem::create(Arc::new(Mutex::new(file)), MAX_SPACE)
        .expect("failed to create sfs");
    zip_dir(dir.as_ref(), fs.root_inode()).expect("failed to zip fs");
}
