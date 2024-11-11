use argh::FromArgs;
use std::process::Command;
use std::{fs, path::Path};

#[derive(FromArgs)]
/// run bootloader
struct BuildArgs {
    /// run or debug
    #[argh(option)]
    debug: bool,
}

fn main() {
    let args: BuildArgs = argh::from_env();
    let mut cmd = Command::new("qemu-system-aarch64");
    cmd.args([
        "-machine",
        "virt,secure=on,virtualization=on,kernel_irqchip=on,gic-version=2",
    ]);
    cmd.args(["-cpu", "cortex-a72"]);
    cmd.args(["-smp", "4"]);
    cmd.args(["-netdev", "user,id=user0,hostfwd=tcp::5000-:22"]);
    cmd.args(["-device", "e1000,netdev=user0"]);
    cmd.args(["-m", "1024"]);

    // Only support UEFI aarch64 for test
    if !Path::new("out_dir/EFI/Boot").exists() {
        fs::create_dir_all("out_dir/EFI/Boot").expect("Failed to create directory");
    }
    fs::copy(
        "target/aarch64-unknown-uefi/release/aarch64_uefi.efi",
        "out_dir/EFI/Boot/bootaa64.efi",
    )
    .expect("copy file failed");

    cmd.args(["-bios", "trusted_edk2.bin"]);
    cmd.args(["-hda", "fat:rw:out_dir/"]);
    cmd.args(["-device", "VGA"]);
    cmd.args(["-serial", "stdio"]);

    println!("args: {:?}", args.debug);
    if args.debug {
        cmd.args(["-S", "-s"]);
    }
    cmd.spawn().expect("Run qemu failed");
}
