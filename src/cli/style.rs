use colored::*;
use std::sync::OnceLock;

static STATUS_ON: OnceLock<String> = OnceLock::new();
static STATUS_OFF: OnceLock<String> = OnceLock::new();
static STATUS_YES: OnceLock<String> = OnceLock::new();
static STATUS_NO: OnceLock<String> = OnceLock::new();

fn get_status_on() -> &'static str {
    STATUS_ON.get_or_init(|| "on".green().to_string()).as_str()
}

fn get_status_off() -> &'static str {
    STATUS_OFF.get_or_init(|| "off".red().to_string()).as_str()
}

fn get_status_yes() -> &'static str {
    STATUS_YES
        .get_or_init(|| "yes".green().to_string())
        .as_str()
}

fn get_status_no() -> &'static str {
    STATUS_NO.get_or_init(|| "no".red().to_string()).as_str()
}

pub fn title(s: &str) -> colored::ColoredString {
    s.cyan().bold()
}

pub fn success(s: &str) -> colored::ColoredString {
    s.green()
}

pub fn error(s: &str) -> colored::ColoredString {
    s.red()
}

pub fn warning(s: &str) -> colored::ColoredString {
    s.yellow()
}

pub fn version(s: &str) -> colored::ColoredString {
    s.green()
}

pub fn status_flag(flag: bool) -> &'static str {
    if flag {
        get_status_on()
    } else {
        get_status_off()
    }
}

pub fn yes_no(flag: bool) -> &'static str {
    if flag {
        get_status_yes()
    } else {
        get_status_no()
    }
}

pub fn help_line(key: &str, desc: &str) {
    println!("  {:<10} {}", key.green(), desc);
}

pub fn settings_line(key: &str, value: &str) {
    println!("  {:<15} {}", key, value);
}
