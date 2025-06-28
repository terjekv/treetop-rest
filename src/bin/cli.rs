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
use treetop_core::{Resource, ResourceKind};
use treetop_rest::models::PoliciesMetadata;
use treetop_rest::state::{Metadata, OfPolicies};

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
    "--detailed",
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
    /// Check a request against policies.     
    Check {
        #[clap(long)]
        principal: String,
        #[clap(long)]
        action: String,
        #[clap(long = "resource-type")]
        resource_type: String,
        #[clap(long = "resource-data")]
        resource_data: String,
        #[clap(long = "detailed")]
        detailed: Option<bool>,
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

impl CliDisplay for PoliciesMetadata {
    fn display(&self) -> String {
        format!(
            "Allow upload: {}
 Policies:
{}
 Host labels:
{}",
            self.allow_upload, self.policies, self.host_labels,
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
struct CheckResponseDetailed {
    decision: treetop_core::Decision,
}

impl CliDisplay for CheckResponseDetailed {
    fn display(&self) -> String {
        match &self.decision {
            treetop_core::Decision::Allow { policy } => {
                format!("Allow\n--- Matching policy ---\n{}\n---", policy.literal)
            }
            treetop_core::Decision::Deny => "Deny".to_string(),
        }
    }
}

#[derive(Deserialize)]
struct PoliciesDownload {
    policies: Metadata<OfPolicies>,
}
impl CliDisplay for PoliciesDownload {
    fn display(&self) -> String {
        format!(
            "Metadata:\n{}\nContent:\n{}",
            self.policies, self.policies.content
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

trait FromColonString {
    fn from_colon_string(s: &str) -> Result<Resource, String>;
}

impl FromColonString for Resource {
    fn from_colon_string(s: &str) -> Result<Resource, String> {
        let (tag, data) = s
            .split_once(':')
            .ok_or_else(|| format!("expected `<kind>:<payload>`, got {s:?}"))?;

        let kind = tag
            .parse::<ResourceKind>()
            .map_err(|_| format!("unknown resource kind {tag:?}"))?;

        match kind {
            ResourceKind::Host => {
                let (name, ip_str) = data
                    .split_once(':')
                    .ok_or_else(|| format!("host needs `name:ip`, got {data:?}"))?;
                let ip = ip_str
                    .parse::<IpAddr>()
                    .map_err(|e| format!("invalid IP `{ip_str}`: {e}"))?;
                Ok(Resource::Host {
                    name: name.to_string(),
                    ip,
                })
            }
            ResourceKind::Photo => Ok(Resource::Photo {
                id: data.to_string(),
            }),
            ResourceKind::Generic => Ok(Resource::Generic {
                kind: tag.to_string(),
                id: data.to_string(),
            }),
        }
    }
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
                    eprintln!("Error: {err}");
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
            let resp = client.get(format!("{base_url}/status")).send().await?;
            handle_response::<PoliciesMetadata>(resp).await;
        }
        Commands::Check {
            principal,
            action,
            resource_type,
            resource_data,
            detailed,
        } => {
            let resource = match Resource::from_colon_string(&format!(
                "{resource_type}:{resource_data}"
            )) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("Error parsing resource: {e}");
                    return Ok(());
                }
            };

            let req = CheckRequest {
                principal,
                action,
                resource,
            };
            if let Some(detailed) = detailed
                && detailed {
                    let resp = client
                        .post(format!("{base_url}/check_detailed"))
                        .json(&req)
                        .send()
                        .await?;
                    handle_response::<CheckResponseDetailed>(resp).await;
                    return Ok(());
                }
            let resp = client
                .post(format!("{base_url}/check"))
                .json(&req)
                .send()
                .await?;
            handle_response::<CheckResponse>(resp).await;
        }
        Commands::GetPolicies { raw } => {
            let url = if raw {
                format!("{base_url}/policies?format=raw")
            } else {
                format!("{base_url}/policies")
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
                    .post(format!("{base_url}/policies"))
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
                    .post(format!("{base_url}/policies"))
                    .json(&Upload { policies: content })
                    .send()
                    .await?
            };
            handle_response::<PoliciesMetadata>(resp).await;
        }
        Commands::ListPolicies { user } => {
            let resp = client
                .get(format!("{base_url}/policies/{user}"))
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
        eprintln!("Unexpected error: {status}");
    }
}
