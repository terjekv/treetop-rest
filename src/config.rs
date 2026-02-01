use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::IpAddr;
use std::str::FromStr;

use crate::errors::ServiceError;

use crate::models::Endpoint;

/// Application configuration (host and port).
#[derive(Parser, Debug, Clone)]
pub struct Config {
    /// IP address to bind to
    #[clap(long, default_value = "127.0.0.1", env = "TREETOP_LISTEN")]
    pub host: String,

    /// Port to listen on
    #[clap(long, default_value = "9999", env = "TREETOP_PORT")]
    pub port: u16,

    /// Number of Actix worker threads (default: auto based on available CPU)
    #[clap(long, env = "TREETOP_WORKERS")]
    pub workers: Option<usize>,

    /// Number of Rayon worker threads used for batch evaluation (default: auto based on available CPU)
    #[clap(long, env = "TREETOP_RAYON_THREADS")]
    pub rayon_threads: Option<usize>,

    /// Batch parallel threshold (0 or unset = auto)
    #[clap(long, env = "TREETOP_PAR_THRESHOLD")]
    pub par_threshold: Option<usize>,

    /// Allow upload of policy (otherwise only support of fetching from a URL)
    #[clap(long, default_value = "false", env = "TREETOP_ALLOW_UPLOAD")]
    pub allow_upload: bool,

    /// URL to fetch policies from
    #[clap(long, default_value = None, env = "TREETOP_POLICY_URL")]
    pub policy_url: Option<Endpoint>,

    /// Update frequency in seconds for fetching TREETOP_POLICY_URL (default is 60 seconds)
    #[clap(long, default_value = None, env = "TREETOP_POLICY_UPDATE_FREQUENCY")]
    pub update_frequency: Option<u32>,

    /// Optional URL to fetch host labels from
    #[clap(long, default_value = None, env = "TREETOP_LABELS_URL")]
    pub labels_url: Option<Endpoint>,

    /// Update frequency in seconds for fetching host labels (default is 60 seconds)
    #[clap(long, default_value = None, env = "TREETOP_LABELS_UPDATE_FREQUENCY")]
    pub labels_refresh: Option<u32>,

    /// Trust proxy IP headers (X-Forwarded-For/Forwarded). If false, use peer address only.
    #[clap(long, default_value = "true", env = "TREETOP_TRUST_IP_HEADERS")]
    pub trust_ip_headers: bool,

    /// Whitelist of client IPs or CIDRs ("*" allows all)
    #[clap(
        long,
        default_value = "127.0.0.1,::1",
        env = "TREETOP_CLIENT_ALLOWLIST"
    )]
    pub client_allowlist: ClientAllowlist,

    #[clap(long)]
    /// Print version information and exit
    pub version: bool,
}

#[derive(Debug, Clone)]
pub enum ClientAllowlist {
    Any,
    Nets(Vec<IpNet>),
}

impl ClientAllowlist {
    pub fn parse_cli(input: &str) -> Result<Self, ServiceError> {
        let trimmed = input.trim();

        if trimmed == "*" {
            return Ok(Self::Any);
        }

        let nets: Vec<IpNet> = trimmed
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(Self::parse_net)
            .collect::<Result<_, _>>()?;

        if nets.is_empty() {
            return Err(ServiceError::ValidationError(
                "client allowlist cannot be empty".into(),
            ));
        }

        Ok(Self::Nets(nets))
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        match self {
            ClientAllowlist::Any => true,
            ClientAllowlist::Nets(nets) => nets.iter().any(|net| match (net, ip) {
                (IpNet::V4(net), IpAddr::V4(addr)) => net.contains(&addr),
                (IpNet::V6(net), IpAddr::V6(addr)) => net.contains(&addr),
                _ => false,
            }),
        }
    }

    fn parse_net(raw: &str) -> Result<IpNet, ServiceError> {
        IpNet::from_str(raw)
            .or_else(|_| Self::ip_to_host_net(raw))
            .map_err(|_| ServiceError::InvalidIp)
    }

    fn ip_to_host_net(raw: &str) -> Result<IpNet, ()> {
        let ip: IpAddr = raw.parse().map_err(|_| ())?;
        match ip {
            IpAddr::V4(addr) => Ipv4Net::new(addr, 32).map(IpNet::from).map_err(|_| ()),
            IpAddr::V6(addr) => Ipv6Net::new(addr, 128).map(IpNet::from).map_err(|_| ()),
        }
    }
}

impl FromStr for ClientAllowlist {
    type Err = ServiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_cli(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn parses_any() {
        let allowlist = ClientAllowlist::from_str("*").unwrap();
        assert!(allowlist.allows(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn parses_default_hosts() {
        let allowlist = ClientAllowlist::from_str("127.0.0.1,::1").unwrap();
        assert!(allowlist.allows(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(allowlist.allows(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_outside_network() {
        let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
        assert!(!allowlist.allows(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn errors_on_empty() {
        assert!(matches!(
            ClientAllowlist::from_str(""),
            Err(ServiceError::ValidationError(_))
        ));
        assert!(matches!(
            ClientAllowlist::from_str(",,,"),
            Err(ServiceError::ValidationError(_))
        ));
    }

    #[test]
    fn errors_on_invalid_ip() {
        assert!(matches!(
            ClientAllowlist::from_str("not-an-ip"),
            Err(ServiceError::InvalidIp)
        ));
    }
}
