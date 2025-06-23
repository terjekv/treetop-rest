use clap::Parser;

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
}
