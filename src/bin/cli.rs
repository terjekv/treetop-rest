use anyhow::{Context as AnyContext, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use rustyline::completion::{Completer, Pair};
use rustyline::config::Configurer;
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
use treetop_rest::models::{CheckResponse, CheckResponseBrief, DecisionBrief, PoliciesMetadata};
use treetop_rest::state::{Metadata, OfPolicies};

// Re-export the completion logic from the library
use treetop_rest::cli::*;

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
        let (start, matches) = complete_line(line, pos);
        let pairs = matches
            .into_iter()
            .map(|s| Pair {
                display: s.clone(),
                replacement: s,
            })
            .collect();
        Ok((start, pairs))
    }
}

#[derive(Parser, Debug)]
#[clap(name = "policy-cli", about = "CLI (and REPL) for Policy Service API")]
struct Cli {
    #[clap(long, default_value = "127.0.0.1", env = "CLI_HOST")]
    host: String,
    #[clap(long, default_value = "9999", env = "CLI_PORT")]
    port: u16,
    /// Print JSON responses
    #[arg(long)]
    json: bool,
    /// Print JSON requests and responses (superset of --json)
    #[arg(long)]
    debug: bool,
    /// Print command execution timing
    #[arg(long)]
    timing: bool,
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
    /// Toggle display of JSON responses
    Json,
    /// Toggle debug mode - shows both requests and responses
    Debug,
    /// Toggle command execution timing display
    Timing,
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

impl CliDisplay for CheckResponseBrief {
    fn display(&self) -> String {
        match self.decision {
            DecisionBrief::Allow => format!("Allow ({})", self.version.hash),
            DecisionBrief::Deny => format!("Deny ({})", self.version.hash),
        }
    }
}

impl CliDisplay for CheckResponse {
    fn display(&self) -> String {
        match &self.policy {
            Some(policy) => format!(
                "Allow ({})\n--- Matching policy ---\n{}\n---",
                self.version.hash, policy.literal
            ),
            None => format!("Deny ({})", self.version.hash),
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
    let mut show_json = cli.json || cli.debug;
    let mut show_debug = cli.debug;
    let mut show_timing = cli.timing;

    if let Commands::Repl = cli.command {
        let mut rl = Editor::new()?;
        rl.set_helper(Some(CLIHelper));

        // Set up history file in data directory
        let history_path = dirs::data_dir()
            .map(|p| p.join("treetop-rest"))
            .unwrap_or_else(|| "treetop-rest".into())
            .join("cli_history");

        // Ensure the data directory exists
        if let Some(parent) = history_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Load existing history (ignore errors if file doesn't exist)
        let _ = rl.load_history(&history_path);

        // Set maximum history size (1000 entries)
        rl.set_max_history_size(1000)?;

        println!("Policy CLI REPL. Type 'help' for commands, 'exit' to quit.");
        loop {
            match rl.readline(&format!("{}@{}> ", cli.host, cli.port)) {
                Ok(input) => {
                    rl.add_history_entry(input.as_str())?;
                    let parts: Vec<&str> = input.split_whitespace().collect();
                    match parts.first().copied() {
                        Some("exit") | Some("quit") => break,
                        Some("help") | None => print_help(),
                        Some("history") => {
                            for (idx, entry) in rl.history().iter().enumerate() {
                                println!("{:4}: {}", idx + 1, entry);
                            }
                        }
                        Some(_) => {
                            let args = std::iter::once("policy-cli").chain(parts.into_iter());
                            match Cli::try_parse_from(args) {
                                Ok(parsed) => {
                                    match execute_command(
                                        parsed.command,
                                        &base_url,
                                        &client,
                                        &mut show_json,
                                        &mut show_debug,
                                        &mut show_timing,
                                    )
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

        // Save history before exiting
        if let Err(e) = rl.save_history(&history_path) {
            eprintln!("Warning: Failed to save command history: {}", e);
        }
    } else {
        execute_command(
            cli.command,
            &base_url,
            &client,
            &mut show_json,
            &mut show_debug,
            &mut show_timing,
        )
        .await?;
    }
    Ok(())
}

fn print_help() {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    cmd.print_long_help().ok();
    println!();
    println!("REPL-only commands:");
    println!("  history       Show command history");
    println!("  exit, quit    Exit the REPL");
}

async fn execute_command(
    command: Commands,
    base_url: &str,
    client: &Client,
    show_json: &mut bool,
    show_debug: &mut bool,
    show_timing: &mut bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = std::time::Instant::now();
    match command {
        Commands::Repl => {
            // REPL is handled in the main function
            unreachable!();
        }
        Commands::Status => {
            let resp = client.get(format!("{base_url}/status")).send().await?;
            handle_response::<PoliciesMetadata>(resp, *show_json, *show_debug).await?;
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

            if *show_debug {
                match serde_json::to_string_pretty(&req) {
                    Ok(body) => eprintln!("DEBUG request:\n{}", body),
                    Err(err) => eprintln!("Failed to serialize request: {err}"),
                }
            }
            if detailed {
                let resp = client
                    .post(format!("{base_url}/check_detailed"))
                    .json(&req)
                    .send()
                    .await?;
                handle_response::<CheckResponse>(resp, *show_json, *show_debug).await?;
            } else {
                let resp = client
                    .post(format!("{base_url}/check"))
                    .json(&req)
                    .send()
                    .await?;
                handle_response::<CheckResponseBrief>(resp, *show_json, *show_debug).await?;
            }
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
                handle_response::<PoliciesDownload>(resp, *show_json, *show_debug).await?;
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
            handle_response::<PoliciesMetadata>(resp, *show_json, *show_debug).await?;
        }
        Commands::ListPolicies { user } => {
            let resp = client
                .get(format!("{base_url}/policies/{user}"))
                .send()
                .await?;
            handle_response::<UserPolicies>(resp, *show_json, *show_debug).await?;
        }
        Commands::Json => {
            *show_json = !*show_json;
            println!("JSON responses: {}", if *show_json { "on" } else { "off" });
        }
        Commands::Debug => {
            *show_debug = !*show_debug;
            println!(
                "Debug mode (requests + responses): {}",
                if *show_debug { "on" } else { "off" }
            );
        }
        Commands::Timing => {
            *show_timing = !*show_timing;
            println!(
                "Timing display: {}",
                if *show_timing { "on" } else { "off" }
            );
        }
    }

    if *show_timing {
        println!("Time: {:?} microseconds", now.elapsed().as_micros());
    }
    Ok(())
}

async fn handle_response<T>(
    resp: reqwest::Response,
    show_json: bool,
    show_debug: bool,
) -> Result<()>
where
    T: serde::de::DeserializeOwned + CliDisplay,
{
    let status = resp.status();
    let body = resp.text().await?;

    if show_debug {
        eprintln!("DEBUG response status: {status}");
        eprintln!("DEBUG response body:\n{}", body);
    }

    if status.is_success() {
        if show_json {
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
                Err(_) => println!("{}", body),
            }
            return Ok(());
        }

        match serde_json::from_str::<T>(&body) {
            Ok(data) => {
                println!("{}", data.display());
                Ok(())
            }
            Err(parse_err) => {
                eprintln!("Failed to parse successful response ({status}): {parse_err}");
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    println!("{}", body);
                }
                anyhow::bail!("failed to parse successful response ({status})")
            }
        }
    } else {
        // Best-effort error handling using the already-consumed body
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            eprintln!("Error: {}", err.error);
        } else {
            eprintln!("Unexpected error: {status}");
            if !body.trim().is_empty() {
                eprintln!("Body: {body}");
            }
        }
        // Make non-2xx fail the command:
        anyhow::bail!("request failed with status {status}")
    }
}
