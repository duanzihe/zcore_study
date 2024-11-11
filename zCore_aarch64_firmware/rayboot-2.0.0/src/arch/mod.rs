/// Docs here
#[cfg(feature = "x64")]
pub mod x86_64;

#[cfg(feature = "arm64")]
#[macro_use]
pub mod aarch64;
