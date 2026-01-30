use std::path::PathBuf;

use dirs::{config_dir, data_dir};

const APP_DIR: &str = "treetop-cli";

pub fn cli_data_dir() -> Option<PathBuf> {
    data_dir().map(|data_dir| data_dir.join(APP_DIR))
}

pub fn cli_config_path() -> Option<PathBuf> {
    config_dir().map(|config_dir| config_dir.join(APP_DIR).join("config.toml"))
}

pub fn cli_history_path() -> Option<PathBuf> {
    cli_data_dir().map(|data_dir| data_dir.join("history"))
}
