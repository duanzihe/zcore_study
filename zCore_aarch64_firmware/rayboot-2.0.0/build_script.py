import argparse
import os

print("本构建脚本基于Python的argparse库，使用参数--help查看详细使用方法")

parser = argparse.ArgumentParser()
parser.description = '输入参数，准备开始编译x86_64或aarch64架构的bootloader（请事先配置好Linux Rust环境）'
parser.add_argument("-m", "--kernel_manifest",
                    help="（可选）指定内核的依赖配置Cargo.toml（aarch64架构不需要配置）",
                    type=str)
parser.add_argument("-b", "--kernel_binary",
                    help="（可选）指定生成内核的ELF文件（aarch64架构不需要配置）",
                    type=str)
parser.add_argument("-a", "--arch",
                    help="（必选）指定目标架构",
                    type=str,
                    choices=["aarch64", "x86_64"])
parser.add_argument("-f", "--firmware",
                    help="（可选）指定固件类型（UEFI和BIOS均需要则不填）",
                    type=str,
                    choices=["UEFI", "BIOS"])

build_command = "cargo builder --out-dir out_dir"
args = parser.parse_args()

if args.arch is None:
    assert "目标架构不能为空"
    
build_command += " --arch " + args.arch

if args.firmware is not None:
    build_command += " --firmware " + args.firmware

if args.arch == "x86_64":
    assert args.kernel_manifest is not None and args.kernel_binary is not None
    build_command += " --kernel-manifest " + args.kernel_manifest
    build_command += " --kernel-binary " + args.kernel_binary

os.system(build_command)
