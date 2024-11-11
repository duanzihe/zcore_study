use crate::{print, println};
use log::{Level, LevelFilter, Log, Metadata, Record};

static LOGGER: Logger = Logger;

/// init logger
pub fn logger_init() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Trace);
}

struct Logger;
impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        print!("\x1b[{}m", level_to_color_code(record.level()));
        println!("[{}] {}", record.level(), record.args());
        print!("\x1b[0m");
    }

    fn flush(&self) {}
}

fn level_to_color_code(level: Level) -> u8 {
    match level {
        Level::Error => 31, // red
        Level::Warn => 93,  // yellow
        Level::Info => 34,  // blue
        Level::Debug => 32, // green
        Level::Trace => 90, // black
    }
}
