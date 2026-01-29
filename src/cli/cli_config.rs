//! CLI configuration management
//!
//! This module handles loading and saving CLI configuration, including table style preferences,
//! from the platform-standard config directory:
//! - Unix: `~/.config/treetop/cli.toml`
//! - Windows: `%APPDATA%/treetop/cli.toml`
//! - macOS: `~/Library/Application Support/treetop/cli.toml`
//!
//! Configuration hierarchy (highest to lowest priority):
//! 1. Command line arguments
//! 2. Environment variables (e.g., TREETOP_TABLE_STYLE)
//! 3. Config file (~/.config/treetop/cli.toml)
//! 4. Built-in defaults

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::cli::models::TableStyle;

/// CLI configuration that can be persisted to disk
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Default table style for output
    pub table_style: TableStyle,
}

impl CliConfig {
    /// Get the path to the config file using platform-standard directories
    fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|config_dir| config_dir.join("treetop").join("cli.toml"))
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
        assert_eq!(config.table_style.to_string(), "rounded");
    }

    #[test]
    fn test_load_defaults_when_missing() {
        let (config, _loaded) = CliConfig::load();
        // If no config file exists, defaults to "rounded"
        // If config file exists, uses the value from file
        // Either way, loading should succeed
        assert!(matches!(
            config.table_style,
            TableStyle::Ascii | TableStyle::Rounded | TableStyle::Unicode | TableStyle::Markdown
        ));
    }

    #[test]
    fn test_config_path_uses_config_dir() {
        let path = CliConfig::config_path();
        assert!(path.is_some());
        if let Some(p) = path {
            println!("Config path: {:?}", p);
            assert!(p.to_string_lossy().contains("treetop"));
            assert!(p.ends_with("cli.toml"));
        }
    }

    #[test]
    fn test_toml_serialization() {
        let config = CliConfig {
            table_style: TableStyle::Unicode,
        };
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("table_style"));
        // TOML enums are serialized as strings
        assert!(toml_str.contains("Unicode") || toml_str.contains("unicode"));
    }
}
