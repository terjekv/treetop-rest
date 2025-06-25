use clap::{Parser, Subcommand};
use reqwest::Client;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use treetop_core::Resource;
use treetop_rest::models::Endpoint;

// Top-level commands
const COMMANDS_MAIN: &[&str] = &[
    "status",
    "check",
    "get-policies",
    "upload",
    "list-policies",
    "help",
    "exit",
];
// Flags per command (use kebab-case to match clap defaults)
const CHECK_FLAGS: &[&str] = &[
    "--principal",
    "--action",
    "--resource-type",
    "--resource-data",
];
const GET_POLICIES_FLAGS: &[&str] = &["--raw"];
const UPLOAD_FLAGS: &[&str] = &["--file", "--raw", "--token"];

struct CLIHelper;
impl Helper for CLIHelper {}
impl Validator for CLIHelper {}
impl Highlighter for CLIHelper {}
impl Hinter for CLIHelper {
    type Hint = String;
}

impl Completer for CLIHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        // Determine start of current token
        let start = line[..pos].rfind(' ').map_or(0, |i| i + 1);
        let word = &line[start..pos];
        // Split the input into tokens before the current word
        let prefix = &line[..start].trim();
        let tokens: Vec<&str> = if prefix.is_empty() {
            vec![]
        } else {
            prefix.split_whitespace().collect()
        };

        // Decide suggestions based on first token
        let base = if tokens.is_empty() {
            COMMANDS_MAIN
        } else {
            match tokens[0] {
                "check" => CHECK_FLAGS,
                "get-policies" => GET_POLICIES_FLAGS,
                "upload" => UPLOAD_FLAGS,
                _ => &[],
            }
        };

        // Filter out flags/commands that have already been used
        let used = tokens.to_vec();
        let candidates = base
            .iter()
            .filter(|&&item| !used.contains(&item))
            .cloned()
            .collect::<Vec<&str>>();

        // Build completion pairs matching the current word
        let mut matches = Vec::new();
        for s in candidates {
            if s.starts_with(word) {
                matches.push(Pair {
                    display: s.to_string(),
                    replacement: s.to_string(),
                });
            }
        }
        Ok((start, matches))
    }
}

#[derive(Parser, Debug)]
#[clap(name = "policy-cli", about = "CLI (and REPL) for Policy Service API")]
struct Cli {
    #[clap(long, default_value = "127.0.0.1")]
    host: String,
    #[clap(long, default_value = "9999")]
    port: u16,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch interactive REPL
    Repl,
    /// Get service status
    Status,
    /// Check a request against policies
    Check {
        #[clap(long)]
        principal: String,
        #[clap(long)]
        action: String,
        #[clap(long = "resource-type")]
        resource_type: String,
        #[clap(long = "resource-data")]
        resource_data: String,
    },
    /// Download policies (JSON by default, use --raw for plain text)
    GetPolicies {
        #[clap(long)]
        raw: bool,
    },
    /// Upload new policies from a file
    Upload {
        #[clap(long)]
        file: std::path::PathBuf,
        #[clap(long)]
        raw: bool,
        #[clap(long)]
        token: String,
    },
    /// List policies relevant to a user
    ListPolicies { user: String },
}

trait CliDisplay {
    fn display(&self) -> String;
}

#[derive(Deserialize)]
struct StatusResponse {
    policies_sha256: String,
    policies_uploaded_at: String,
    policies_size: usize,
    policies_allow_upload: bool,
    policies_url: Option<Endpoint>,
    policies_refresh_frequency: Option<u32>,
    host_labels_url: Option<Endpoint>,
    host_labels_refresh_frequency: Option<u32>,
}
impl CliDisplay for StatusResponse {
    fn display(&self) -> String {
        let refresh = match self.policies_refresh_frequency {
            Some(freq) => format!("{} seconds", freq),
            None => "N/A".to_string(),
        };
        let url = match self.policies_url.as_ref().map(|u| u.to_string()) {
            Some(url) => url,
            None => "None".to_string(),
        };

        let hrefresh = match self.host_labels_refresh_frequency {
            Some(freq) => format!("{} seconds", freq),
            None => "N/A".to_string(),
        };
        let hurl = match self.host_labels_url.as_ref().map(|u| u.to_string()) {
            Some(url) => url,
            None => "None".to_string(),
        };

        format!(
            "**Policies**\n  SHA256: {}\n  Timestamp: {}\n  Size: {} bytes\n  Allow Upload: {}\n  URL: {}\n  Refresh: {}\n**Host labels**\n  URL: {}\n  Refresh: {}",
            self.policies_sha256,
            self.policies_uploaded_at,
            self.policies_size,
            self.policies_allow_upload,
            url,
            refresh,
            hurl,
            hrefresh
        )
    }
}

#[derive(Serialize)]
struct CheckRequest {
    principal: String,
    action: String,
    resource: Resource,
}

#[derive(Deserialize)]
struct CheckResponse {
    decision: String,
}
impl CliDisplay for CheckResponse {
    fn display(&self) -> String {
        self.decision.clone()
    }
}

#[derive(Deserialize)]
struct PoliciesDownload {
    policies: String,
    sha256: String,
    uploaded_at: String,
}
impl CliDisplay for PoliciesDownload {
    fn display(&self) -> String {
        format!(
            "Policies SHA256: {}\nUploaded at: {}\nPolicies:\n{}",
            self.sha256, self.uploaded_at, self.policies
        )
    }
}

#[derive(Deserialize, Clone)]
struct UserPolicies(serde_json::Value);
impl CliDisplay for UserPolicies {
    fn display(&self) -> String {
        serde_json::to_string_pretty(&self.0).unwrap()
    }
}

#[derive(Deserialize, Clone)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let base_url = format!("http://{}:{}/api/v1", cli.host, cli.port);
    let client = Client::new();

    if let Commands::Repl = cli.command {
        let mut rl = Editor::new()?;
        rl.set_helper(Some(CLIHelper));
        println!("Policy CLI REPL. Type 'help' for commands, 'exit' to quit.");
        loop {
            match rl.readline("policy> ") {
                Ok(input) => {
                    rl.add_history_entry(input.as_str())?;
                    let parts: Vec<&str> = input.split_whitespace().collect();
                    match parts.first().copied() {
                        Some("exit") | Some("quit") => break,
                        Some("help") => print_help(),
                        Some(_) => {
                            let args = std::iter::once("policy-cli").chain(parts.into_iter());
                            if let Ok(parsed) = Cli::try_parse_from(args) {
                                execute_command(parsed.command, &base_url, &client).await?;
                            } else {
                                eprintln!("Unknown or invalid command");
                            }
                        }
                        None => {}
                    }
                }
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    break;
                }
            }
        }
    } else {
        execute_command(cli.command, &base_url, &client).await?;
    }
    Ok(())
}

fn print_help() {
    println!(
        "Available commands:\n  status\n  check --principal <P> --action <A> --resource-type <N> --resource-data <DATA>\n  get-policies [--raw]\n  upload --file <PATH> [--raw]\n  list-policies <USER>\n  help\n  exit"
    );
}

async fn execute_command(
    command: Commands,
    base_url: &str,
    client: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Repl => {
            // REPL is handled in the main function
            unreachable!();
        }
        Commands::Status => {
            let resp = client.get(format!("{}/status", base_url)).send().await?;
            handle_response::<StatusResponse>(resp).await;
        }
        Commands::Check {
            principal,
            action,
            resource_type,
            resource_data,
        } => {
            let resource = match resource_type.to_lowercase().as_str() {
                "host" => {
                    let name = resource_data.split(':').next().unwrap_or("").to_string();
                    let ip: IpAddr = match resource_data
                        .split(':')
                        .nth(1)
                        .unwrap_or("")
                        .to_string()
                        .parse()
                    {
                        Ok(ip) => ip,
                        Err(_) => {
                            eprintln!(
                                "Invalid IP address format in resource data: {}",
                                resource_data
                            );
                            return Ok(());
                        }
                    };

                    Resource::Host { name, ip }
                }
                "photo" => Resource::Photo {
                    id: resource_data.to_string(),
                },
                _ => {
                    eprintln!("Unsupported resource type: {}", resource_type);
                    return Ok(());
                }
            };

            let req = CheckRequest {
                principal,
                action,
                resource,
            };
            let resp = client
                .post(format!("{}/check", base_url))
                .json(&req)
                .send()
                .await?;
            handle_response::<CheckResponse>(resp).await;
        }
        Commands::GetPolicies { raw } => {
            let url = if raw {
                format!("{}/policies?format=raw", base_url)
            } else {
                format!("{}/policies", base_url)
            };
            let resp = client.get(&url).send().await?;
            if raw && resp.status().is_success() {
                println!("{}", resp.text().await?);
            } else {
                handle_response::<PoliciesDownload>(resp).await;
            }
        }
        Commands::Upload { file, raw, token } => {
            let content = fs::read_to_string(&file)?;
            let resp = if raw {
                client
                    .post(format!("{}/policies", base_url))
                    .header("Content-Type", "text/plain")
                    .header("X-Upload-Token", token)
                    .body(content)
                    .send()
                    .await?
            } else {
                #[derive(Serialize)]
                struct Upload {
                    policies: String,
                }
                client
                    .post(format!("{}/policies", base_url))
                    .json(&Upload { policies: content })
                    .send()
                    .await?
            };
            handle_response::<StatusResponse>(resp).await;
        }
        Commands::ListPolicies { user } => {
            let resp = client
                .get(format!("{}/policies/{}", base_url, user))
                .send()
                .await?;
            handle_response::<UserPolicies>(resp).await;
        }
    }
    Ok(())
}

async fn handle_response<T: serde::de::DeserializeOwned + CliDisplay>(resp: reqwest::Response) {
    if resp.status().is_success() {
        if let Ok(data) = resp.json::<T>().await {
            println!("{}", data.display());
        }
    } else {
        handle_error(resp).await;
    }
}

async fn handle_error(resp: reqwest::Response) {
    let status = resp.status();
    if let Ok(err) = resp.json::<ErrorResponse>().await {
        eprintln!("Error: {}", err.error);
    } else {
        eprintln!("Unexpected error: {}", status);
    }
}
