//! 支持架构的定义。

use crate::{commands::wget, LinuxRootfs, XError, ARCHS, TARGET};
use os_xtask_utils::{dir, CommandExt, Tar};
use std::{path::PathBuf, str::FromStr};

/// 支持的 CPU 架构。
#[derive(Clone, Copy)]
pub(crate) enum Arch {
    Riscv64,
    X86_64,
    Aarch64,
}

impl Arch {
    /// Returns the name of Arch.
    #[inline]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Riscv64 => "riscv64",
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// Returns the path to store arch-dependent files from network.
    #[inline]
    pub fn origin(&self) -> PathBuf {
        ARCHS.join(self.name())
    }

    /// Returns the path to cache arch-dependent generated files durning processes.
    #[inline]
    pub fn target(&self) -> PathBuf {
        TARGET.join(self.name())
    }

    /// Downloads linux musl toolchain, and returns its path.
    /// 
    /// musl是Minimalist User-space Library的缩写，它是一个轻量级的更小更精简的C标准库
    /// 
    /// 此函数会从网络上下载工具链压缩包，解压并返回解压后的交叉编译工具链目录路径（也就是ignored/target/架构名/架构名-linux-musl-cross，供后续操作使用。
    pub fn linux_musl_cross(&self) -> PathBuf {
        //根据当前对象的名称生成工具链的名称
        let name = format!("{}-linux-musl-cross", self.name().to_lowercase());
        //// 获取源和目标目录的路径
        let origin = self.origin();//这里的origin就是ignored/origin/archs/架构名
        let target = self.target();//这里的target就是ignored/target/架构名

        let tgz = origin.join(format!("{name}.tgz")); //tgz 是工具链压缩包的完整路径。
        let dir = target.join(&name);//dir 是工具链解压后的目录路径。

        dir::create_parent(&dir).unwrap(); //确保解压目录的父目录存在，
        dir::rm(&dir).unwrap();//然后删除可能已经存在的旧目录。这样可以确保每次都从干净的状态开始解压。

        //从指定的 URL 下载工具链压缩包到本地的 tgz 路径。wget 是一个用来下载文件的工具函数。
        wget(
            format!("https://github.com/YdrMaster/zCore/releases/download/musl-cache/{name}.tgz"),
            &tgz,
        );
        //使用 Tar 工具将下载的压缩包解压到目标目录 target。Tar::xf 是解压 .tgz 文件的操作。
        Tar::xf(&tgz, Some(target)).invoke();
        //返回解压后的交叉编译工具链目录路径（也就是ignored/target/架构名/架构名-linux-musl-cross，供后续操作使用。
        dir
    }
}

impl FromStr for Arch {
    type Err = XError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "riscv64" => Ok(Self::Riscv64),
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            _ => Err(XError::EnumParse {
                type_name: "Arch",
                value: s.into(),
            }),
        }
    }
}

#[derive(Clone, Copy, Args)]
pub(crate) struct ArchArg {
    /// Build architecture, `riscv64` or `x86_64`.
    #[clap(short, long)]
    pub arch: Arch,
}
// 为archarg实现linux_rootfs方法
impl ArchArg {
    /// linux_rootfs 方法的作用就是为不同的架构创建对应的 Linux 根文件系统  
    /// 
    /// Returns the [`LinuxRootfs`] object related to selected architecture.
    #[inline]
    pub fn linux_rootfs(&self) -> LinuxRootfs {
        LinuxRootfs::new(self.arch)  //具体怎么创建先不看
    }
}
