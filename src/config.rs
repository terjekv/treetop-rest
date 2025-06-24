use clap::Parser;

use crate::models::Endpoint;

/// Application configuration (host and port).
#[derive(Parser, Debug)]
pub struct Config {
    /// IP address to bind to
    #[clap(long, default_value = "127.0.0.1", env = "APP_HOST")]
    pub host: String,

    /// Port to listen on
    #[clap(long, default_value = "9999", env = "APP_PORT")]
    pub port: u16,

    /// Nnumber of worker threads
    #[clap(long, default_value = "4", env = "APP_WORKERS")]
    pub workers: usize,

    /// Allow upload of policy (otherwise only support of fetching from a URL)
    #[clap(long, default_value = "false", env = "APP_ALLOW_UPLOAD")]
    pub allow_upload: bool,

    /// URL to fetch policies from
    #[clap(long, default_value = None, env = "APP_POLICY_URL")]
    pub policy_url: Option<Endpoint>,

    /// Update frequency in seconds for fetching APP_POLICY_URL (default is 60 seconds)
    #[clap(long, default_value = None, env = "APP_POLICY_UPDATE_FREQUENCY")]
    pub update_frequency: Option<u32>,

    /// Optional URL to fetch host labels from
    #[clap(long, default_value = None, env = "APP_HOST_LABELS_URL")]
    pub host_labels_url: Option<Endpoint>,

    /// Update frequency in seconds for fetching host labels (default is 60 seconds)
    #[clap(long, default_value = None, env = "APP_HOST_LABELS_UPDATE_FREQUENCY")]
    pub host_labels_refresh: Option<u32>,
}
