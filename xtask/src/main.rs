#![deny(warnings)]

#[macro_use]
extern crate clap;

#[cfg(not(target_arch = "riscv64"))]
mod dump;

mod arch;
mod build;
mod commands;
mod errors;
mod linux;

use arch::{Arch, ArchArg};
use build::{GdbArgs, OutArgs, QemuArgs};
use clap::Parser;
use errors::XError;
use linux::LinuxRootfs;
use once_cell::sync::Lazy;
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use crate::build::{BuildArgs, BuildConfig};

/// The path of zCore project.
/// std::env!("CARGO_MANIFEST_DIR") 是一个编译时宏，用于获取当前 Cargo.toml 文件所在的目录路径，
/// 不过因为xtask被包含到根目录的cargo.toml里，所以这里获得的其实是项目根目录
static PROJECT_DIR: Lazy<&'static Path> =
    Lazy::new(|| Path::new(std::env!("CARGO_MANIFEST_DIR")).parent().unwrap());
/// The path to store arch-dependent files from network.
/// ARCHS代表了从网络中获取到的，现在存放在项目根目录下ignored/origin/archs的架构路径
static ARCHS: Lazy<PathBuf> =
    Lazy::new(|| PROJECT_DIR.join("ignored").join("origin").join("archs"));
/// The path to store third party repos from network.
/// 存储从网络上获取的第三方代码仓库或依赖
static REPOS: Lazy<PathBuf> =
    Lazy::new(|| PROJECT_DIR.join("ignored").join("origin").join("repos"));
/// The path to cache generated files during processes.
/// 用于存储缓存生成的文件路径,其实就是ignored/target
static TARGET: Lazy<PathBuf> = Lazy::new(|| PROJECT_DIR.join("ignored").join("target"));

/// Build or test zCore.
/// Command Line Interface（命令行接口）
#[derive(Parser)]  //通过实现 Parser trait，Cli 结构体将能够处理命令行输入，将其解析为结构体的字段，并提供错误处理、帮助信息等功能。
#[clap(name = "zCore configure")] //这个属性设置了生成的命令行工具的名称。这里的 "zCore configure" 是命令行工具的名称，它会出现在命令行帮助信息中。
//version：这个属性会自动将版本号添加到命令行工具的帮助信息中。clap 会从 Cargo.toml 文件中提取版本号，或者你可以在 Cargo.toml 中定义版本号。
//about：这个属性会将工具的简要描述添加到帮助信息中。这是对工具的简要说明，帮助用户理解其功能。
//long_about = None：这是一个可选的属性，用于设置更详细的描述信息。如果设置为 None，则不会提供更详细的描述。如果需要详细描述，可以提供一个字符串。
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)] //表明command 字段是用来存储命令行子命令的。
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 设置 git 代理。Sets git proxy.
    ///
    /// 通过 `--port` 传入代理端口，或者不传入端口以清除代理设置。
    ///
    /// Input your proxy port through `--port`,
    /// or leave blank to unset it.
    ///
    /// 设置 `--global` 修改全局设置。
    ///
    /// Set `--global` for global configuration.
    ///
    /// ## Example
    ///
    /// ```bash
    /// cargo git-proxy --global --port 12345
    /// ```
    ///
    /// ```bash
    /// cargo git-proxy --global
    /// ```
    GitProxy(ProxyPort),

    /// 打印构建信息。Dumps build config.
    ///
    /// ## Example
    ///
    /// ```bash
    /// cargo dump
    /// ```
    #[cfg(not(target_arch = "riscv64"))]
    Dump,

    /// 下载 zircon 模式需要的二进制文件。Download zircon binaries.
    ///
    /// ## Example
    ///
    /// ```bash
    /// cargo zircon-init
    /// ```
    ZirconInit,

    /// 更新工具链、依赖和子项目。Updates toolchain, dependencies and submodules.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo update-all
    /// ```
    UpdateAll,

    /// 静态检查。Checks code without running.
    ///
    /// 设置多种编译选项，检查代码能否编译。
    ///
    /// Try to compile the project with various different features.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo check-style
    /// ```
    CheckStyle,

    /// 生成内核反汇编文件。Dumps the asm of kernel.
    ///
    /// 默认保存到 `target/zcore.asm`。
    ///
    /// The default output is `target/zcore.asm`.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo asm --arch riscv64 --output riscv64.asm
    /// ```
    Asm(OutArgs),

    /// 生成内核 raw 镜像到指定位置。Strips kernel binary for specific architecture.
    ///
    /// 默认输出到 `target/{arch}/release/zcore.bin`。
    ///
    /// The default output is `target/{arch}/release/zcore.bin`.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo bin --arch riscv64 --output zcore.bin
    /// ```
    Bin(OutArgs),

    /// 在 qemu 中启动 zCore。Runs zCore in qemu.
    /// 表示一个名为 qemu 的子命令，它接收并解析 QemuArgs 类型的参数
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo qemu --arch riscv64 --smp 4
    /// ```
    Qemu(QemuArgs),  

    /// 启动 gdb 并连接到指定端口。Launches gdb and connects to a port.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo gdb --arch riscv64 --port 1234
    /// ```
    Gdb(GdbArgs),

    /// 重建 Linux rootfs。Rebuilds the linux rootfs.
    ///
    /// 这个命令会清除已有的为此架构构造的 rootfs 目录，重建最小的 rootfs。
    ///
    /// This command will remove the existing rootfs directory for this architecture,
    /// and rebuild the minimum rootfs.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo rootfs --arch riscv64
    /// ```
    Rootfs(ArchArg),

    /// 将 musl 动态库拷贝到 rootfs 目录对应位置。Copies musl so files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo musl-libs --arch riscv64
    /// ```
    MuslLibs(ArchArg),

    /// 将 ffmpeg 动态库拷贝到 rootfs 目录对应位置。Copies ffmpeg so files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo ffmpeg --arch riscv64
    /// ```
    Ffmpeg(ArchArg),

    /// 将 opencv 动态库拷贝到 rootfs 目录对应位置。Copies opencv so files to rootfs directory.
    ///
    /// 如果 ffmpeg 已经放好了，opencv 将会编译出包含 ffmepg 支持的版本。
    ///
    /// If ffmpeg is already there, this opencv will build with ffmpeg support.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo opencv --arch riscv64
    /// ```
    Opencv(ArchArg),

    /// 将 libc 测试集拷贝到 rootfs 目录对应位置。Copies libc test files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo libc-test --arch riscv64
    /// ```
    LibcTest(ArchArg),

    /// 将其他测试集拷贝到 rootfs 目录对应位置。Copies other test files to rootfs directory.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo other-test --arch riscv64
    /// ```
    OtherTest(ArchArg),

    /// 构造 Linux rootfs 镜像文件。Builds the linux rootfs image file.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo image --arch riscv64
    /// ```
    Image(ArchArg),

    /// 构造 libos 需要的 rootfs 并放入 libc test。Builds the libos rootfs and puts it into libc test.
    ///
    /// > **注意** 这可能不是这个命令的最终形态，因此这个命令没有别名。
    /// >
    /// > **NOTICE** This may not be the final form of this command, so this command has no alias.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo xtask libos-libc-test
    /// ```
    LibosLibcTest,

    /// 在 linux libos 模式下启动 zCore 并执行位于指定路径的应用程序。Runs zCore in linux libos mode and runs the executable at the specified path.
    ///
    /// > **注意** libos 模式只能执行单个应用程序，完成就会退出。
    /// >
    /// > **NOTICE** zCore can only run a single executable in libos mode, and it will exit after finishing.
    ///
    /// # Example
    ///
    /// ```bash
    /// cargo linux-libos --args /bin/busybox
    /// ```
    LinuxLibos(LinuxLibosArg),
}

#[derive(Args)]
struct ProxyPort {
    /// Proxy port.
    #[clap(long)]
    port: Option<u16>,
    /// Global config.
    #[clap(short, long)]
    global: bool,
}

#[derive(Args)]
struct LinuxLibosArg {
    /// Command for busybox.
    #[clap(short, long)]
    pub args: String,
}

fn main() {
    use Commands::*;
    // 通过Cli::parse()解析命令行参数，得到一个 Cli的实例，它的command成员是一个Commands 枚举类型，并且这个枚举中的变体会解析输入命令的相关参数。
    //在这里进行匹配，command获取到哪个命令就执行对应的代码
    match Cli::parse().command {
        //这个变体处理 GitProxy 命令。如果 port 有值，就设置代理；否则取消代理。
        GitProxy(ProxyPort { port, global }) => {
            if let Some(port) = port {
                set_git_proxy(global, port);
            } else {
                unset_git_proxy(global);
            }
        }
        //只有在非 riscv64 架构上才会执行 Dump 命令，调用 dump_config 函数。
        #[cfg(not(target_arch = "riscv64"))]
        Dump => dump::dump_config(),
        //这些命令直接调用各自的函数。
        ZirconInit => install_zircon_prebuilt(),
        UpdateAll => update_all(),
        CheckStyle => check_style(),
        //这些命令通常会接受一个参数 arg，并调用 arg.linux_rootfs() 的相关方法。
        Rootfs(arg) => arg.linux_rootfs().make(true),
        MuslLibs(arg) => {
            // 丢弃返回值
            arg.linux_rootfs().put_musl_libs();
        }
        Opencv(arg) => arg.linux_rootfs().put_opencv(),
        Ffmpeg(arg) => arg.linux_rootfs().put_ffmpeg(),
        LibcTest(arg) => arg.linux_rootfs().put_libc_test(),
        OtherTest(arg) => arg.linux_rootfs().put_other_test(),
        Image(arg) => arg.linux_rootfs().image(),
        
        //这些命令调用传入的参数的相应方法，执行任务。
        Asm(args) => args.asm(),
        Bin(args) => {
            // 丢弃返回值
            args.bin();
        }
        //qemu命令只会解析：arch,smp,debug，gdb.
        Qemu(args) => args.qemu(),
        Gdb(args) => args.gdb(),

        LibosLibcTest => {
            libos::rootfs(true);
            libos::put_libc_test();
        }
        LinuxLibos(arg) => libos::linux_run(arg.args),
    }
}

/// 更新子项目。
fn git_submodule_update(init: bool) {
    use os_xtask_utils::{CommandExt, Git};
    Git::submodule_update(init).invoke();
}

/// 下载 zircon 模式所需的测例和库
fn install_zircon_prebuilt() {
    use commands::wget;
    use os_xtask_utils::{dir, CommandExt, Tar};
    const URL: &str =
        "https://github.com/rcore-os/zCore/releases/download/prebuilt-2208/prebuilt-all.tar.xz";  //修改！要获取arm64的prebuilt而不只是x86的
    
    //原版：let tar = Arch::X86_64.origin().join("prebuilt.tar.xz"); // 其实就是在/ignored/origin/archs/x86_64/prebuilt.tar.xz
    let tar = Arch::Aarch64.origin().join("prebuilt-all.tar.xz"); // 修改！在/ignored/origin/archs/aarch64/prebuilt-all.tar.xz
   
    wget(URL, &tar);
    // 解压到目标路径
    let dir = PROJECT_DIR.join("prebuilt");
    let target = TARGET.join("zircon");
    dir::rm(&dir).unwrap(); //删除zcore/prebuilt
    dir::rm(&target).unwrap(); //删除ignored/target/zircon
    fs::create_dir_all(&target).unwrap();
    Tar::xf(&tar, Some(&target)).invoke();  //把下载得到的prebuilt-all.tar.xz解压到ignored/target/zircon
    dircpy::copy_dir(target.join("prebuilt"), dir).unwrap(); //ignored/target/zircon/prebuilt/...复制到prebuilt/...
    

}

/// 更新工具链和依赖。
fn update_all() {
    use os_xtask_utils::{Cargo, CommandExt, Ext};
    git_submodule_update(false);
    Ext::new("rustup").arg("update").invoke();
    Cargo::update().invoke();
}

/// 设置 git 代理。
fn set_git_proxy(global: bool, port: u16) {
    use os_xtask_utils::{CommandExt, Git};
    let dns = fs::read_to_string("/etc/resolv.conf")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("nameserver ")
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
        })
        .expect("FAILED: detect DNS");
    let proxy = format!("socks5://{dns}:{port}");
    Git::config(global).args(&["http.proxy", &proxy]).invoke();
    Git::config(global).args(&["https.proxy", &proxy]).invoke();
    println!("git proxy = {proxy}");
}

/// 移除 git 代理。
fn unset_git_proxy(global: bool) {
    use os_xtask_utils::{CommandExt, Git};
    Git::config(global)
        .args(&["--unset", "http.proxy"])
        .invoke();
    Git::config(global)
        .args(&["--unset", "https.proxy"])
        .invoke();
    println!("git proxy =");
}

/// 风格检查。
fn check_style() {
    use os_xtask_utils::{Cargo, CommandExt};
    println!("Check workspace");
    Cargo::fmt().arg("--all").arg("--").arg("--check").invoke();
    Cargo::clippy().all_features().invoke();
    Cargo::doc().all_features().arg("--no-deps").invoke();

    println!("Check libos");
    // println!("    Checks zircon libos");
    // Cargo::clippy()
    //     .package("zcore")
    //     .features(false, &["zircon", "libos"])
    //     .invoke();
    println!("    Checks linux libos");
    Cargo::clippy()
        .package("zcore")
        .features(false, &["linux", "libos"])
        .invoke();

    println!("Check bare-metal");
    for arch in [Arch::Riscv64, Arch::X86_64, Arch::Aarch64] {
        println!("    Checks {} bare-metal", arch.name());
        BuildConfig::from_args(BuildArgs {
            machine: format!("virt-{}", arch.name()),
            debug: false,
        })
        .invoke(Cargo::clippy);
    }
}

mod libos {
    use crate::{arch::Arch, commands::wget, linux::LinuxRootfs, ARCHS, TARGET};
    use os_xtask_utils::{dir, Cargo, CommandExt, Tar};
    use std::fs;

    /// 部署 libos 使用的 rootfs。
    pub(super) fn rootfs(clear: bool) {
        // 下载
        const URL: &str =
            "https://github.com/YdrMaster/zCore/releases/download/musl-cache/rootfs-libos.tar.gz";
        let origin = ARCHS.join("libos").join("rootfs-libos.tar.gz");
        dir::create_parent(&origin).unwrap();
        wget(URL, &origin);
        // 解压
        let target = TARGET.join("libos");
        fs::create_dir_all(&target).unwrap();
        Tar::xf(origin.as_os_str(), Some(&target)).invoke();
        // 拷贝
        const ROOTFS: &str = "rootfs/libos";
        if clear {
            dir::clear(ROOTFS).unwrap();
        }
        dircpy::copy_dir(target.join("rootfs"), ROOTFS).unwrap();
    }

    /// 将 x86_64 的 libc-test 复制到 libos。
    pub(super) fn put_libc_test() {
        const TARGET: &str = "rootfs/libos/libc-test";
        let x86_64 = LinuxRootfs::new(Arch::X86_64);
        x86_64.put_libc_test();
        dir::clear(TARGET).unwrap();
        dircpy::copy_dir(x86_64.path().join("libc-test"), TARGET).unwrap();
    }

    /// libos 模式执行应用程序。
    pub(super) fn linux_run(args: String) {
        println!("{}", std::env!("OUT_DIR"));  //这里报错 Rust 项目中使用了构建脚本（build scripts），但 VS Code 的 Rust Analyzer 或 Cargo 没有正确配置以处理这些构建脚本
        rootfs(false);
        // 启动！
        Cargo::run()
            .package("zcore")
            .release()
            .features(true, ["linux", "libos"])
            .arg("--")
            .args(args.split_whitespace())
            .invoke()
    }
}
