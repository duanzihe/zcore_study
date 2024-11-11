use super::Pl011Uart;
use core::fmt::Arguments;

/// print to uart
pub fn print(args: Arguments) {
    let uart = Pl011Uart::new(0x0900_0000);
    for i in args.as_str().unwrap().chars() {
        uart.putchar(i as u8);
    }
}

#[macro_export]
/// print
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::arch::aarch64::bsp::serial::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
/// println
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::arch::aarch64::bsp::serial::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
