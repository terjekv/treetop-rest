use colored::*;

lazy_static::lazy_static! {
    static ref STATUS_ON: String = "on".green().to_string();
    static ref STATUS_OFF: String = "off".red().to_string();
    static ref STATUS_YES: String = "yes".green().to_string();
    static ref STATUS_NO: String = "no".red().to_string();
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
        STATUS_ON.as_str()
    } else {
        STATUS_OFF.as_str()
    }
}

pub fn yes_no(flag: bool) -> &'static str {
    if flag {
        STATUS_YES.as_str()
    } else {
        STATUS_NO.as_str()
    }
}

pub fn help_line(key: &str, desc: &str) {
    println!("  {:<10} {}", key.green(), desc);
}

pub fn settings_line(key: &str, value: &str) {
    println!("  {:<15} {}", key, value);
}
