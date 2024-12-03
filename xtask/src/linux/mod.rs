mod image;
mod opencv;
mod test;

use crate::{commands::fetch_online, Arch, PROJECT_DIR, REPOS};
use os_xtask_utils::{dir, CommandExt, Ext, Git, Make};
use std::{
    env,
    ffi::OsString,
    fs,
    os::unix,
    path::{Path, PathBuf},
};

pub(crate) struct LinuxRootfs(Arch);

impl LinuxRootfs {
    /// 生成指定架构的 linux rootfs 操作对象。
    #[inline]
    pub const fn new(arch: Arch) -> Self {
        Self(arch)
    }

    /// 构造启动内存文件系统 rootfs，间接产物在ignored目录下,最终产物在rootfs目录下。
    /// 对于 x86_64，这个文件系统可用于 libos 启动。
    /// 若设置 `clear`，将清除已存在的目录。
    pub fn make(&self, _clear: bool) {
        // 若已存在且不需要清空，可以直接退出
        let dir = self.path();//这里的path就是/rootfs/架构

        //测试修改，在这里取消重用，让每次修改都被编译
        // if dir.is_dir() && !clear {
        //     return;
        // }

        // 如果没制作，就准备最小系统需要的资源，交叉编译工具链和busybox的可执行文件
        let musl = self.0.linux_musl_cross(); //这里的0是图方便，反正这linuxrootfs是元组结构体，也就一个arch成员
        let busybox = self.busybox(&musl);
        // 先清空，再创建目标目录，就是rootfs/架构名/bin和rootfs/架构名/lib
        let bin = dir.join("bin");
        let lib = dir.join("lib");
        let lib_test = dir.join("libc-test");
        let functional = lib_test.join("src/functional");
        dir::clear(&dir).unwrap();
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&lib).unwrap();
        fs::create_dir(&lib_test).unwrap();
        fs::create_dir_all(&functional).unwrap();

        // 从ignored/target/架构名/busybox将 busybox的可执行文件拷贝到rootfs/架构名/bin中
        fs::copy(busybox, bin.join("busybox")).unwrap();
        // 拷贝 libc.so
        // 这部分代码从交叉编译工具链中拷贝了 libc.so 动态库，并将其重命名为 ld-musl-{arch}.so.1，以适配特定的架构
        let from = musl //这里的from就是ignored/target/架构名/架构名-linux-musl-cross/架构名-linux-musl/lib/libc.so
            .join(format!("{}-linux-musl", self.0.name()))
            .join("lib")
            .join("libc.so");
        let to = lib.join(format!("ld-musl-{arch}.so.1", arch = self.0.name()));//这里的to就是rootfs/架构名/lib/ld-musl-riscv64.so.1
        fs::copy(from, &to).unwrap();


        // 新增：将 /libc-test/src/functional 下的所有 .exe 文件复制到 /rootfs/aarch64/libc-test/src/functional 中
        let source_dir = Path::new("./libc-test/src/functional");
        if source_dir.exists() {
            for entry in fs::read_dir(source_dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();

                // 如果是 .exe 文件
                if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("exe") {
                    let dest_path = functional.join(path.file_name().unwrap());
                    fs::copy(&path, &dest_path).unwrap();
                }
            }
        }



        //裁剪指定文件的大小
        Ext::new(self.strip(musl)).arg("-s").arg(to).invoke();
        // 为常用功能建立符号链接
        const SH: &[&str] = &[
            "cat", "cp", "echo", "false", "grep", "gzip", "kill", "ln", "ls", "mkdir", "mv",
            "pidof", "ping", "ping6", "printenv", "ps", "pwd", "rm", "rmdir", "sh", "sleep",
            "stat", "tar", "touch", "true", "uname", "usleep", "watch",
        ];
        let bin = dir.join("bin"); //这就是为什么可以在rootfs里看到ls,cat等命令的二进制文件
        for sh in SH {
            unix::fs::symlink("busybox", bin.join(sh)).unwrap();//这些二进制文件其实都是指向busybox的软链接，仔细看的话右边还能看到一个“符号链接”呢。
        }
    }

    /// 将 musl 动态库放入 rootfs。
    pub fn put_musl_libs(&self) -> PathBuf {
        // 递归 rootfs
        self.make(false);
        let dir = self.0.linux_musl_cross();
        self.put_libs(&dir, dir.join(format!("{}-linux-musl", self.0.name())));
        dir
    }

    /// 指定架构的 rootfs 路径，就是rootfs/架构名。
    #[inline]
    pub fn path(&self) -> PathBuf {
        PROJECT_DIR.join("rootfs").join(self.0.name())
    }

    /// 从网络第三方仓库下载并编译 busybox，返回busybox可执行文件本身的路径，也就是ignored/target/jiagoum/busybox/busybox。
    fn busybox(&self, musl: impl AsRef<Path>) -> PathBuf {
        // 最终文件目录路径在ignored/target/架构名/busybox
        let target = self.0.target().join("busybox");
        // 如果busybox目录下，可执行的busybox文件存在，直接退出
        let executable = target.join("busybox");
        if executable.is_file() {
            return executable;
        }
        // 从网络上的第三方仓库获得源码，并存放在ignored/origin/repos/busybox中
        let source = REPOS.join("busybox");
        if !source.is_dir() {
            fetch_online!(source, |tmp| {
                Git::clone("https://git.busybox.net/busybox.git")
                    .dir(tmp)
                    .single_branch()
                    .depth(1)
                    .done()
            });
        }
        // 先移除可能的旧文件，再然后将源码从 source 目录复制到 target 目录。
        dir::rm(&target).unwrap();
        dircpy::copy_dir(source, &target).unwrap();
        // 配置，这里为 make 命令添加了一个参数 "defconfig"，这是 BusyBox 提供的一个默认配置目标。
        // 执行 make defconfig 是为了生成一个默认的配置文件（通常名为 .config），这个配置文件定义了 BusyBox 应该包含哪些功能。
        Make::new().current_dir(&target).arg("defconfig").invoke();
        // 编译
        let musl = musl.as_ref();
        Make::new()
            .current_dir(&target)
            .arg(format!(
                "CROSS_COMPILE={musl}/{arch}-linux-musl-",
                musl = musl.canonicalize().unwrap().join("bin").display(),
                arch = self.0.name(),
            ))
            .invoke();
        // 裁剪
        Ext::new(self.strip(musl))
            .arg("-s")
            .arg(&executable)
            .invoke();
        executable
    }

    fn strip(&self, musl: impl AsRef<Path>) -> PathBuf {
        musl.as_ref()
            .join("bin")
            .join(format!("{}-linux-musl-strip", self.0.name()))
    }

    /// 从安装目录拷贝所有 so 和 so 链接到 rootfs
    fn put_libs(&self, musl: impl AsRef<Path>, dir: impl AsRef<Path>) {
        let lib = self.path().join("lib");
        let musl_libc_protected = format!("ld-musl-{}.so.1", self.0.name());
        let musl_libc_ignored = "libc.so";
        let strip = self.strip(musl);
        dir.as_ref()
            .join("lib")
            .read_dir()
            .unwrap()
            .filter_map(|res| res.map(|e| e.path()).ok())
            .filter(|path| check_so(path))
            .for_each(|source| {
                let name = source.file_name().unwrap();
                let target = lib.join(name);
                if source.is_symlink() {
                    if name != musl_libc_protected.as_str() {
                        dir::rm(&target).unwrap();
                        // `fs::copy` 会拷贝文件内容
                        unix::fs::symlink(source.read_link().unwrap(), target).unwrap();
                    }
                } else if name != musl_libc_ignored {
                    dir::rm(&target).unwrap();
                    fs::copy(source, &target).unwrap();
                    Ext::new(&strip).arg("-s").arg(target).status();
                }
            });
    }
}

/// 为 PATH 环境变量附加路径。
fn join_path_env<I, S>(paths: I) -> OsString
where
    I: IntoIterator<Item = S>,
    S: AsRef<Path>,
{
    let mut path = OsString::new();
    let mut first = true;
    if let Ok(current) = env::var("PATH") {
        path.push(current);
        first = false;
    }
    for item in paths {
        if first {
            first = false;
        } else {
            path.push(":");
        }
        path.push(item.as_ref().canonicalize().unwrap().as_os_str());
    }
    path
}

/// 判断一个文件是动态库或动态库的符号链接。
fn check_so<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();
    // 是符号链接或文件
    // 对于符号链接，`is_file` `exist` 等函数都会针对其指向的真实文件判断
    if !path.is_symlink() && !path.is_file() {
        return false;
    }
    // 对文件名分段
    let name = path.file_name().unwrap().to_string_lossy();
    let mut seg = name.split('.');
    // 不能以 . 开头
    if matches!(seg.next(), Some("") | None) {
        return false;
    }
    // 扩展名的第一项是 so
    if !matches!(seg.next(), Some("so")) {
        return false;
    }
    // so 之后全是纯十进制数字
    !seg.any(|it| !it.chars().all(|ch| ch.is_ascii_digit()))
}
