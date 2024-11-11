#[cfg(target_arch = "riscv64")]
fn main() {}

#[cfg(not(target_arch = "riscv64"))]
fn main() -> shadow_rs::SdResult<()> {
    shadow_rs::new() //调用 shadow_rs 的 new 函数，以便在编译时生成与项目配置相关的代码，从而帮助开发者更轻松地管理和使用这些信息
}
