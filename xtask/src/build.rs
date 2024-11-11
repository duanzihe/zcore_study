use crate::{linux::LinuxRootfs, Arch, ArchArg, PROJECT_DIR};
use once_cell::sync::Lazy;
use os_xtask_utils::{dir, BinUtil, Cargo, CommandExt, Ext, Qemu};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs,
    path::PathBuf,
    str::FromStr,
};
use z_config::MachineConfig;

#[derive(Clone, Args)]
pub(crate) struct BuildArgs {
    /// Which machine is build for.
    #[clap(long, short)]
    pub machine: String,
    /// Build as debug mode.
    #[clap(long)]
    pub debug: bool,
}

#[derive(Args)]
pub(crate) struct OutArgs {
    #[clap(flatten)]
    build: BuildArgs,
    /// The file to save asm.
    #[clap(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct QemuArgs {
    #[clap(flatten)] //这里的flatten起到展平结构体的左右，可以理解为把archarg这个结构体的成员直接放到当前结构体里，而不是用结构体成员再包裹一次.
    arch: ArchArg,
    /// Build as debug mode.
    #[clap(long)]
    debug: bool,
    /// Number of hart (SMP for Symmetrical Multiple Processor).
    #[clap(long)]
    smp: Option<u8>,
    /// Port for gdb to connect. If set, qemu will block and wait gdb to connect.
    #[clap(long)]
    gdb: Option<u16>,
}

#[derive(Args)]
pub(crate) struct GdbArgs {
    #[clap(flatten)]
    arch: ArchArg,
    #[clap(long)]
    port: u16,
}
///inner其实就是zcore/
static INNER: Lazy<PathBuf> = Lazy::new(|| PROJECT_DIR.join("zCore"));

pub(crate) struct BuildConfig {
    arch: Arch,
    debug: bool,
    env: HashMap<OsString, OsString>,
    features: HashSet<String>,
}

impl BuildConfig {
    ///根据传入的机器类型（args.machine）从config/machine-features.toml中选择相应的机器配置
    pub fn from_args(args: BuildArgs) -> Self {
        //根据传入的机器类型（args.machine）从config/machine-features.toml中选择相应的机器配置。
        let machine = MachineConfig::select(args.machine).expect("Unknown target machine");
        //创建一个 HashSet 用于存储特性，从 machine.features 中获取特性列表，并将其克隆到 features 集合中。
        let mut features = HashSet::from_iter(machine.features.iter().cloned());
        //创建一个 HashMap 用于存储环境变量。
        let mut env = HashMap::new();
        //从 machine.arch 字符串中解析出架构类型 Arch，如果解析失败，则触发 panic。
        let arch = Arch::from_str(&machine.arch)
            .unwrap_or_else(|_| panic!("Unknown arch {} for machine", machine.arch));
        // 递归 image， 处理用户镜像
        if let Some(path) = &machine.user_img { //如果 machine.user_img 包含用户镜像路径，就把path解构出来，然后执行花括号
            features.insert("link-user-img".into()); //将 "link-user-img" 特性添加到 features 集合中。
            // env 环境变量中，路径处理为绝对路径。
            env.insert(
                "USER_IMG".into(),
                if path.is_absolute() {
                    path.as_os_str().to_os_string()
                } else {
                    PROJECT_DIR.join(path).as_os_str().to_os_string()
                },
            );
            LinuxRootfs::new(arch).image();
        }
        // 不支持 pci
        if !machine.pci_support {
            features.insert("no-pci".into());
        }
        //不以zircon启动,就是以linux启动
        if !features.contains("zircon") {
            features.insert("linux".into()); 
            //修改！如果没有zircon特性，就添加zircon特性！强制以zircon模式启动
            // features.insert("zircon".into()); 


        }
        Self {
            arch,
            debug: args.debug,
            env,
            features,
        }
    }

    #[inline]
    /// 就是/target/架构名/release/zcore
    fn target_file_path(&self) -> PathBuf {
        PROJECT_DIR
            .join("target")
            .join(self.arch.name())
            .join(if self.debug { "debug" } else { "release" })
            .join("zcore")
    }

    pub fn invoke(&self, cargo: impl FnOnce() -> Cargo) {
        let mut cargo = cargo();
        cargo
            .package("zcore")                //构建package指定为zcore
            .features(false, &self.features) //特性设置
            //设置目标配置文件。从zcore/架构名.json的目标配置文件中获取构建目标的详细信息，如编译器配置、目标平台等。
            .target(INNER.join(format!("{}.json", self.arch.name())))

            //下面两个args的配置是e针对”no-std"环境的，通过 build-std 参数包含了 core 和 alloc 库，
            //并且启用了标准库的一些特性。这种配置允许在没有完整标准库支持的环境中构建应用，同时保证必要的功能和特性得到支持。

            //添加编译参数 -Z build-std=core,alloc，指定构建时需要包含标准库 core 和 alloc。
            .args(&["-Z", "build-std=core,alloc"])
            //添加编译参数 -Z build-std-features=compiler-builtins-mem，指定标准库特性，以支持内存操作的编译器内建功能。
            .args(&["-Z", "build-std-features=compiler-builtins-mem"])
            //根据 self.debug 的值决定是否将构建配置为发布模式。如果 self.debug 为 false，则调用 cargo.release()，将构建设置为发布模式（优化过的构建）。
            .conditional(!self.debug, |cargo| {
                cargo.release();
            });
        //遍历 self.env 中的环境变量，并将这些变量设置到 cargo 对象中。println! 用于输出正在设置的环境变量及其值。
        for (key, val) in &self.env {
            println!("set build env: {key:?} : {val:?}");
            cargo.env(key, val);
        }
        //通过 cargo.invoke() 来执行配置好的 Cargo 构建命令。这会触发实际的构建过程，根据之前的配置生成最终的构建产物。
        cargo.invoke();
    }
    /// 在target/riscv64/release/zcore.bin这个位置生成zcore的bin文件
    pub fn bin(&self, output: Option<PathBuf>) -> PathBuf {
        // 递归 build,按照invoke传递的各种配置参数，在“target_file_path（也就是target/riscv64/release/zcore)"这个位置生成zcore的elf文件。
        self.invoke(Cargo::build);
        // 这里的obj其实就是elf文件的位置
        let obj = self.target_file_path();



        let out = output.unwrap_or_else(|| obj.with_extension("bin")); //修改成bin_error，再试试看，居然还能跑！看来是格式不敏感的。
        println!("strip zcore to {}", out.display());
        dir::create_parent(&out).unwrap();
        BinUtil::objcopy()
            .arg("--binary-architecture=riscv64")        //疑惑：为什么这里硬编码是riscv64？我来把他修改成aarch64试试。别说修改了，注释了都一样跑，难绷。
            .arg(obj)
            .args(["--strip-all", "-O", "binary"])            
            .arg(&out)
            .invoke();
        out
    }
}

impl OutArgs {
    /// 打印 asm。
    pub fn asm(self) {
        let Self { build, output } = self;
        let build = BuildConfig::from_args(build);
        // 递归 build
        build.invoke(Cargo::build);
        // 确定目录
        let obj = build.target_file_path();
        let out = output.unwrap_or_else(|| PROJECT_DIR.join("target/zcore.asm"));
        // 生成
        println!("Asm file dumps to '{}'.", out.display());
        dir::create_parent(&out).unwrap();
        fs::write(out, BinUtil::objdump().arg(obj).arg("-d").output().stdout).unwrap();
    }

    /// 生成 bin 文件。
    #[inline]
    pub fn bin(self) -> PathBuf {
        let Self { build, output } = self;
        BuildConfig::from_args(build).bin(output)
    }
}

impl QemuArgs {
    /// 在 qemu 中启动
    /// 进行了制作根文件系统镜像、生成内核二进制bin文件、设置qemu参数等操作
    pub fn qemu(self) {
        // 递归 image， linux_rootfs() 方法创建了适用于特定架构的根文件系统"实例"，但这个文件系统本身并不具备启动能力，只是个空实例罢了。
        // 使用 image() 方法，用make制作”内容“（busybox），再用fuse将其压入”框架“，(rcore_sys),将他们打包成镜像文件，使其能够被识别和加载。
        self.arch.linux_rootfs().image();
        // 构造各种字符串
        let arch = self.arch.arch;
        let arch_str = arch.name();
        //对于cargo qemu --arch riscv64这个命令来说，obj代表的就是target/riscv64/release/zcore
        let obj = PROJECT_DIR
            .join("target")
            .join(self.arch.arch.name())
            .join(if self.debug { "debug" } else { "release" })
            .join("zcore");
        // 递归生成内核二进制， 这里会先根据buildargs生成一个buildconfig,然后通过这个buildconfig执行bin方法
        // bin方法先生成了elf,在转换成bin输出
        let bin = BuildConfig::from_args(BuildArgs {
            machine: format!("virt-{}", self.arch.arch.name()), //machine名
            debug: self.debug, //是否debug
        })
        .bin(None);

//在执行完bin的from_args之后，就已经启用了zircon特性！

        // 设置 Qemu 参数，这个arg的具体实现会一直追溯到工具链提供的部分，暂时不深究，知道是用来添加参数就行。
        let mut qemu = Qemu::system(arch_str);
        qemu.args(&["-m", "2G"]) //设置虚拟机的内存为 2GB
            //指定内核镜像文件。bin 是之前构建的内核二进制文件的路径。
            .arg("-kernel")
            .arg(&bin)
            //指定初始 RAM 磁盘（initrd）镜像的路径(就是zCore/riscv64.img)，用于提供根文件系统。
            .arg("-initrd")
            .arg(INNER.join(format!("{arch_str}.img")))
            //传递内核启动参数，设置日志级别为警告。
            .args(&["-append", "\"LOG=warn\""])
            //禁用显示输出。
            .args(&["-display", "none"])
            //禁用虚拟机重启功能。
            .arg("-no-reboot")
            //禁用图形界面，使用控制台输出
            .arg("-nographic")

            //修改！增加-d asm 按汇编命令调试，并把执行情况保存到qemu.log中
            .args(&["-d", "in_asm"])
            .args(&["-D", "qemu_aarch64_debug.log"]) //似乎有缺陷，识别不了arm的currentEL寄存器，会报unknown,可以查命令编号来确认具体命令。


            //（optional会判断第一个参数是否存在，如果存在，就执行后面的闭包）在这里就是如果 self.smp 有值，则添加 SMP 选项，指定虚拟机的 CPU 核心数。
            .optional(&self.smp, |qemu, smp| {
                qemu.args(&["-smp", &smp.to_string()]);
            });
        match arch {
            //RISC-V 的架构设计相对简单统一，因此在 QEMU 的 virt 机器类型中，很多常见的硬件配置都已经默认设置好了。这使得在虚拟化 RISC-V 时，只需要进行最少的配置即可启动系统。
            Arch::Riscv64 => {
                qemu.args(&["-machine", "virt"])//指定虚拟机的机器类型为 virt。
                    .args(&["-bios", "default"])//使用默认 BIOS,其实就是opensbi。
                    .args(&["-serial", "mon:stdio"]);//将串行端口重定向到标准输入/输出。
            }
            Arch::X86_64 => todo!(),
            //ARM（aarch64）架构由于支持的硬件种类繁多且复杂，QEMU 中的 virt 机器类型并没有办法涵盖所有可能的配置需求。
            //因此，需要手动指定更多的硬件参数（如 EFI 固件、CPU 类型、设备映射等）来确保虚拟机能够准确模拟特定的硬件环境
            Arch::Aarch64 => {
                fs::copy(obj, INNER.join("disk").join("os")).unwrap();//将构建的二进制elf文件复制到虚拟机的磁盘映像。
                qemu.args(&["-machine", "virt"])//指定机器类型为 virt
                    .args(&["-cpu", "cortex-a72"])//指定 CPU 类型为 cortex-a72
                    //指定 EFI 固件。
                    .arg("-bios")
                    //这里其实就是ignored/target/aarch64/firmware/QEMU_EFI.fd
                    .arg(arch.target().join("firmware").join("QEMU_EFI.fd"))
                    //将一个 FAT 文件系统映射为虚拟硬盘。
                    //这里其实就是把zCore/disk给制作成了自由读写的fat文件系统，然后把他当作虚拟硬盘hda
                    .args(&["-hda", &format!("fat:rw:{}/disk", INNER.display())])
                    //指定一个原始格式的磁盘映像
                    .args(&[
                        "-drive",
                        &format!(
                            "file={}/aarch64.img,if=none,format=raw,id=x0",
                            INNER.display()
                        ),
                    ])
                    //使用 VirtIO 磁盘设备，drive=x0 指向之前定义的 aarch64.img 磁盘映像，
                    //bus=virtio-mmio-bus.0 表示它将连接到虚拟的 MMIO（内存映射输入输出）总线上。这种设置通常用于提高虚拟设备的性能和效率。
                    .args(&[
                        "-device",
                        "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
                    ]);
            }
        }
        //检查是否需要开启 GDB 调试
        qemu.optional(&self.gdb, |qemu, port| {
            //如果需要，就添加 -S 和 -gdb tcp::{port} 参数
            qemu.args(&["-S", "-gdb", &format!("tcp::{port}")]);
        })
        .invoke();//.invoke() 启动配置好的 QEMU 虚拟机
    }
}

impl GdbArgs {
    pub fn gdb(&self) {
        match self.arch.arch {
            Arch::Riscv64 => {
                Ext::new("riscv64-unknown-elf-gdb")
                    .args(&["-ex", &format!("target remote localhost:{}", self.port), 
                            "-ex", "file target/riscv64/release/zcore"])  //修改！在这里预输入一下，省的每次都要再输一遍。从elf文件里获取调试信息
                    .invoke();
            }
            //修改：因为找不着所谓的aarch64-none-linux-gnu-gdb 这个gdb版本，所以用了别的版本
            // Arch::Aarch64 => {
            //     Ext::new("aarch64-none-linux-gnu-gdb")
            //         .args(&["-ex", &format!("target remote localhost:{}", self.port)])
            //         .invoke();
            // }
            Arch::Aarch64 => {
                Ext::new("gdb-multiarch") //修改了gdb版本！
                    .args(&["-ex", &format!("target remote localhost:{}", self.port),
                            "-ex", "zCore_aarch64_firmware/rayboot-2.0.0/src/bin/aarch64_uefi.rs"]) //修改！尝试调试efi！
                    .invoke();
            }
            Arch::X86_64 => todo!(),
        }
    }
}
