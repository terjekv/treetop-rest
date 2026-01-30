//! CLI configuration management
//!
//! This module handles loading and saving CLI configuration, including table style preferences,
//! from the platform-standard config directory:
//! - Unix: `~/.config/treetop-cli/config.toml`
//! - Windows: `%APPDATA%/treetop-cli/config.toml`
//! - macOS: `~/Library/Application Support/treetop-cli/config.toml`
//!
//! Configuration hierarchy (highest to lowest priority):
//! 1. Command line arguments
//! 2. Environment variables (e.g., TREETOP_TABLE_STYLE)
//! 3. Config file (~/.config/treetop-cli/config.toml)
//! 4. Built-in defaults

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::cli::paths::cli_config_path;

use crate::cli::models::TableStyle;

/// CLI configuration that can be persisted to disk
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Default server host to connect to
    pub host: Option<String>,
    /// Default server port to connect to
    pub port: Option<u16>,
    /// Default JSON output toggle
    pub json: Option<bool>,
    /// Default debug output toggle
    pub debug: Option<bool>,
    /// Default timing output toggle
    pub timing: Option<bool>,
    /// Default table style for output
    pub table_style: Option<TableStyle>,
}

impl CliConfig {
    /// Get the path to the config file using platform-standard directories
    fn config_path() -> Option<PathBuf> {
        cli_config_path()
    }

    /// Load configuration from disk, or return defaults if not found
    /// Returns (config, was_loaded_from_file)
    pub fn load() -> (Self, bool) {
        match Self::config_path() {
            Some(path) if path.exists() => match fs::read_to_string(&path) {
                Ok(content) => match toml::from_str::<Self>(&content) {
                    Ok(config) => (config, true),
                    Err(_) => (Self::default(), false),
                },
                Err(_) => (Self::default(), false),
            },
            _ => (Self::default(), false),
        }
    }

    /// Save configuration to disk
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::config_path().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unable to determine config directory",
            )
        })?;

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize and write the config
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CliConfig::default();
        assert!(config.host.is_none());
        assert!(config.port.is_none());
        assert!(config.json.is_none());
        assert!(config.debug.is_none());
        assert!(config.timing.is_none());
        assert!(config.table_style.is_none());
    }

    #[test]
    fn test_load_defaults_when_missing() {
        let (config, _loaded) = CliConfig::load();
        // If no config file exists, defaults to "rounded"
        // If config file exists, uses the value from file
        // Either way, loading should succeed
        if let Some(style) = config.table_style {
            assert!(matches!(
                style,
                TableStyle::Ascii
                    | TableStyle::Rounded
                    | TableStyle::Unicode
                    | TableStyle::Markdown
            ));
        }
    }

    #[test]
    fn test_config_path_uses_config_dir() {
        let path = CliConfig::config_path();
        assert!(path.is_some());
        if let Some(p) = path {
            println!("Config path: {:?}", p);
            assert!(p.to_string_lossy().contains("treetop-cli"));
            assert!(p.ends_with("config.toml"));
        }
    }

    #[test]
    fn test_toml_serialization() {
        let config = CliConfig {
            table_style: Some(TableStyle::Unicode),
            ..Default::default()
        };
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("table_style"));
        // TOML enums are serialized as strings
        assert!(toml_str.contains("Unicode") || toml_str.contains("unicode"));
    }
}
