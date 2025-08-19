use anyhow::{Context as AnyContext, Result};
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
use std::str::FromStr;
use treetop_core::{Action, AttrValue, Principal, Request, Resource, User};
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
    "--resource-id",
    "--resource-attribute",
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
    #[clap(long, default_value = "127.0.0.1", env = "CLI_HOST")]
    host: String,
    #[clap(long, default_value = "9999", env = "CLI_PORT")]
    port: u16,
    /// Print raw JSON responses
    #[arg(long)]
    json: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum InputAttrValue {
    Ip(IpAddr),
    Long(i64),
    Bool(bool),
    String(String),
}

impl From<InputAttrValue> for AttrValue {
    fn from(v: InputAttrValue) -> Self {
        match v {
            InputAttrValue::Ip(ip) => AttrValue::Ip(ip.to_string()),
            InputAttrValue::Long(i) => AttrValue::Long(i),
            InputAttrValue::Bool(b) => AttrValue::Bool(b),
            InputAttrValue::String(s) => AttrValue::String(s),
        }
    }
}

impl FromStr for InputAttrValue {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Ok(i) = s.parse::<i64>() {
            return Ok(Self::Long(i));
        }
        if let Ok(b) = s.parse::<bool>() {
            return Ok(Self::Bool(b));
        }
        // allow wrapping quotes to keep commas/spaces intact
        let unquoted = s
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .unwrap_or(s);
        Ok(Self::String(unquoted.to_string()))
    }
}

fn parse_kv(s: &str) -> Result<(String, InputAttrValue), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("missing '=' in `{s}`"))?;
    let k = k.trim();
    if k.is_empty() {
        return Err("attribute key is empty".into());
    }
    Ok((k.to_string(), v.parse()?))
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
        /// Repeatable: --resource-attribute key=value (quotes allowed around value)
        #[arg(long = "resource-attribute", value_parser = parse_kv)]
        attrs: Vec<(String, InputAttrValue)>,
        #[clap(long = "resource-id")]
        resource_id: String,
        #[clap(long = "detailed")]
        detailed: bool,
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
            self.allow_upload, self.policies, self.labels,
        )
    }
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let base_url = format!("http://{}:{}/api/v1", cli.host, cli.port);
    let client = Client::new();
    let json = cli.json;

    if let Commands::Repl = cli.command {
        let mut rl = Editor::new()?;
        rl.set_helper(Some(CLIHelper));
        println!("Policy CLI REPL. Type 'help' for commands, 'exit' to quit.");
        loop {
            match rl.readline(&format!("{}@{}> ", cli.host, cli.port)) {
                Ok(input) => {
                    rl.add_history_entry(input.as_str())?;
                    let parts: Vec<&str> = input.split_whitespace().collect();
                    match parts.first().copied() {
                        Some("exit") | Some("quit") => break,
                        Some("help") | None => print_help(),
                        Some(_) => {
                            let args = std::iter::once("policy-cli").chain(parts.into_iter());
                            match Cli::try_parse_from(args) {
                                Ok(parsed) => {
                                    match execute_command(parsed.command, &base_url, &client, json)
                                        .await
                                    {
                                        Ok(_) => {}
                                        Err(e) => eprintln!("Error executing command: {e}"),
                                    }
                                }
                                Err(e) => eprintln!("Error parsing command: {e}"),
                            }
                        }
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
        execute_command(cli.command, &base_url, &client, json).await?;
    }
    Ok(())
}

fn print_help() {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    cmd.print_long_help().ok();
    println!();
}
async fn execute_command(
    command: Commands,
    base_url: &str,
    client: &Client,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Repl => {
            // REPL is handled in the main function
            unreachable!();
        }
        Commands::Status => {
            let resp = client.get(format!("{base_url}/status")).send().await?;
            handle_response::<PoliciesMetadata>(resp, json).await?;
        }
        Commands::Check {
            principal,
            action,
            resource_type,
            resource_id,
            attrs,
            detailed,
        } => {
            let mut resource = Resource::new(&resource_type, &resource_id);
            for (k, v) in attrs {
                resource = resource.with_attr(k, AttrValue::from(v));
            }

            let principal = Principal::User(
                User::from_str(&principal)
                    .with_context(|| format!("invalid --principal `{principal}`"))?,
            );

            let action = Action::from_str(&action)
                .with_context(|| format!("invalid --action `{action}`"))?;

            let req = Request {
                principal,
                action,
                resource,
            };

            if detailed {
                let resp = client
                    .post(format!("{base_url}/check_detailed"))
                    .json(&req)
                    .send()
                    .await?;
                handle_response::<CheckResponseDetailed>(resp, json).await?;
                return Ok(());
            }
            let resp = client
                .post(format!("{base_url}/check"))
                .json(&req)
                .send()
                .await?;
            handle_response::<CheckResponse>(resp, json).await?;
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
                handle_response::<PoliciesDownload>(resp, json).await?;
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
            handle_response::<PoliciesMetadata>(resp, json).await?;
        }
        Commands::ListPolicies { user } => {
            let resp = client
                .get(format!("{base_url}/policies/{user}"))
                .send()
                .await?;
            handle_response::<UserPolicies>(resp, json).await?;
        }
    }
    Ok(())
}

async fn handle_response<T>(resp: reqwest::Response, json: bool) -> Result<()>
where
    T: serde::de::DeserializeOwned + CliDisplay,
{
    let status = resp.status();
    if status.is_success() {
        if json {
            let v = resp.json::<serde_json::Value>().await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            let data = resp
                .json::<T>()
                .await
                .with_context(|| format!("Failed to parse successful response ({status})"))?;
            println!("{}", data.display());
        }
        Ok(())
    } else {
        handle_error(resp).await;
        // Make non-2xx fail the command:
        anyhow::bail!("request failed with status {status}")
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
