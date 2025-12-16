use anyhow::{Context as AnyContext, Result};
use clap::{Parser, Subcommand};
use colored::*;
use reqwest::Client;
use rustyline::completion::{Completer, Pair};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::str::FromStr;
use treetop_core::{Action, AttrValue, Principal, Request, Resource, User};
use treetop_rest::models::{CheckResponse, CheckResponseBrief, DecisionBrief, PoliciesMetadata};
use treetop_rest::state::{Metadata, OfPolicies};

// Re-export the completion logic from the library
use treetop_rest::cli::*;

// Colored status strings for toggle commands
lazy_static::lazy_static! {
    static ref STATUS_ON: String = "on".green().to_string();
    static ref STATUS_OFF: String = "off".red().to_string();
    static ref STATUS_YES: String = "yes".green().to_string();
    static ref STATUS_NO: String = "no".red().to_string();
}

// Helper to format section titles
fn title(s: &str) -> colored::ColoredString {
    s.cyan().bold()
}

// Semantic color helpers
fn success(s: &str) -> colored::ColoredString {
    s.green()
}

fn error(s: &str) -> colored::ColoredString {
    s.red()
}

fn warning(s: &str) -> colored::ColoredString {
    s.yellow()
}

fn version(s: &str) -> colored::ColoredString {
    s.green()
}

// Structure to hold last used values
#[derive(Default, Clone)]
struct LastUsedValues {
    principal: Option<String>,
    action: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    attrs: Vec<(String, InputAttrValue)>,
}

// Consolidated execution context for commands
struct ExecContext {
    base_url: String,
    client: Client,
    show_json: bool,
    show_debug: bool,
    show_timing: bool,
    last_used: LastUsedValues,
    host: String,
    port: u16,
}

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
#[clap(name = "treetop-cli", about = "CLI (and REPL) for the Treeptop API")]
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

impl fmt::Display for InputAttrValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputAttrValue::Ip(ip) => write!(f, "{ip}"),
            InputAttrValue::Long(i) => write!(f, "{i}"),
            InputAttrValue::Bool(b) => write!(f, "{b}"),
            InputAttrValue::String(s) => write!(f, "{s}"),
        }
    }
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
        /// Principal to evaluate (falls back to last used in REPL)
        #[clap(long)]
        principal: Option<String>,
        /// Action to evaluate (falls back to last used in REPL)
        #[clap(long)]
        action: Option<String>,
        /// Resource type (falls back to last used in REPL)
        #[clap(long = "resource-type")]
        resource_type: Option<String>,
        /// Repeatable: --resource-attribute key=value (quotes allowed around value)
        #[arg(long = "resource-attribute", value_parser = parse_kv)]
        attrs: Vec<(String, InputAttrValue)>,
        /// Resource ID (falls back to last used in REPL)
        #[clap(long = "resource-id")]
        resource_id: Option<String>,
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
    /// Show current settings and connection info
    Show,
    /// Show version information
    Version,
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
            DecisionBrief::Allow => {
                format!("{} ({})", success("Allow"), self.version.hash)
            }
            DecisionBrief::Deny => {
                format!("{} ({})", error("Deny"), self.version.hash)
            }
        }
    }
}

impl CliDisplay for CheckResponse {
    fn display(&self) -> String {
        match &self.policy {
            Some(policy) => format!(
                "{} ({})\n{}\n{}\n{}",
                success("Allow"),
                self.version.hash,
                "--- Matching policy ---".cyan(),
                policy.literal,
                "---".cyan()
            ),
            None => format!("{} ({})", error("Deny"), self.version.hash),
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
    let mut ctx = ExecContext {
        base_url,
        client,
        show_json: cli.json || cli.debug,
        show_debug: cli.debug,
        show_timing: cli.timing,
        last_used: LastUsedValues::default(),
        host: cli.host.clone(),
        port: cli.port,
    };

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
                                    match execute_command(parsed.command, &mut ctx).await {
                                        Ok(_) => {}
                                        Err(e) => eprintln!("{}: {}", error("Error"), e),
                                    }
                                }
                                Err(e) => eprintln!("{}: {}", error("Error"), e),
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
        execute_command(cli.command, &mut ctx).await?;
    }
    Ok(())
}

fn print_help() {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    cmd.print_long_help().ok();
    println!();
    println!("{}:", title("REPL-only commands"));
    println!("  {:<10}  Toggle JSON response output", "json".green());
    println!(
        "  {:<10}  Toggle debug mode (requests + responses)",
        "debug".green()
    );
    println!("  {:<10}  Toggle command timing display", "timing".green());
    println!("  {:<10}  Show command history", "history".green());
    println!("  {:<10}  Show current settings", "show".green());
    println!("  {:<10}  Show version information", "version".green());
    println!("  {:<10}  Exit the REPL", "exit, quit".green());
    println!("  {:<10}  Show this help", "help".green());
}

async fn execute_command(
    command: Commands,
    ctx: &mut ExecContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = std::time::Instant::now();
    match command {
        Commands::Repl => {
            // REPL is handled in the main function
            unreachable!();
        }
        Commands::Status => {
            show_status_and_version(ctx).await?;
        }
        Commands::Check {
            principal,
            action,
            resource_type,
            resource_id,
            attrs,
            detailed,
        } => {
            let principal = principal
                .or_else(|| ctx.last_used.principal.clone())
                .ok_or_else(|| anyhow::anyhow!("--principal is required (no previous value)"))?;
            let action = action
                .or_else(|| ctx.last_used.action.clone())
                .ok_or_else(|| anyhow::anyhow!("--action is required (no previous value)"))?;
            let resource_type = resource_type
                .or_else(|| ctx.last_used.resource_type.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!("--resource-type is required (no previous value)")
                })?;
            let resource_id = resource_id
                .or_else(|| ctx.last_used.resource_id.clone())
                .ok_or_else(|| anyhow::anyhow!("--resource-id is required (no previous value)"))?;

            // Prefer current attrs; if none provided, reuse last ones
            let resolved_attrs = if attrs.is_empty() {
                ctx.last_used.attrs.clone()
            } else {
                attrs
            };

            // Store last used values
            ctx.last_used.principal = Some(principal.clone());
            ctx.last_used.action = Some(action.clone());
            ctx.last_used.resource_type = Some(resource_type.clone());
            ctx.last_used.resource_id = Some(resource_id.clone());
            ctx.last_used.attrs = resolved_attrs.clone();

            let mut resource = Resource::new(&resource_type, &resource_id);
            for (k, v) in &resolved_attrs {
                resource = resource.with_attr(k.clone(), AttrValue::from(v.clone()));
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

            if ctx.show_debug {
                match serde_json::to_string_pretty(&req) {
                    Ok(body) => eprintln!("{}\n{}", warning("DEBUG request:"), body),
                    Err(err) => eprintln!("{}: {}", "Failed to serialize request".red(), err),
                }
            }
            if detailed {
                let resp = ctx
                    .client
                    .post(format!("{}/check_detailed", ctx.base_url))
                    .json(&req)
                    .send()
                    .await?;
                handle_response::<CheckResponse>(resp, ctx.show_json, ctx.show_debug).await?;
            } else {
                let resp = ctx
                    .client
                    .post(format!("{}/check", ctx.base_url))
                    .json(&req)
                    .send()
                    .await?;
                handle_response::<CheckResponseBrief>(resp, ctx.show_json, ctx.show_debug).await?;
            }
        }
        Commands::GetPolicies { raw } => {
            let url = if raw {
                format!("{}/policies?format=raw", ctx.base_url)
            } else {
                format!("{}/policies", ctx.base_url)
            };
            let resp = ctx.client.get(&url).send().await?;
            if raw && resp.status().is_success() {
                println!("{}", resp.text().await?);
            } else {
                handle_response::<PoliciesDownload>(resp, ctx.show_json, ctx.show_debug).await?;
            }
        }
        Commands::Upload { file, raw, token } => {
            let content = fs::read_to_string(&file)?;
            let resp = if raw {
                ctx.client
                    .post(format!("{}/policies", ctx.base_url))
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
                ctx.client
                    .post(format!("{}/policies", ctx.base_url))
                    .json(&Upload { policies: content })
                    .send()
                    .await?
            };
            handle_response::<PoliciesMetadata>(resp, ctx.show_json, ctx.show_debug).await?;
        }
        Commands::ListPolicies { user } => {
            let resp = ctx
                .client
                .get(format!("{}/policies/{user}", ctx.base_url))
                .send()
                .await?;
            handle_response::<UserPolicies>(resp, ctx.show_json, ctx.show_debug).await?;
        }
        Commands::Json => {
            ctx.show_json = !ctx.show_json;
            println!(
                "JSON responses: {}",
                if ctx.show_json {
                    &*STATUS_ON
                } else {
                    &*STATUS_OFF
                }
            );
        }
        Commands::Debug => {
            ctx.show_debug = !ctx.show_debug;
            println!(
                "Debug mode (requests + responses): {}",
                if ctx.show_debug {
                    &*STATUS_ON
                } else {
                    &*STATUS_OFF
                }
            );
        }
        Commands::Timing => {
            ctx.show_timing = !ctx.show_timing;
            println!(
                "Timing display: {}",
                if ctx.show_timing {
                    &*STATUS_ON
                } else {
                    &*STATUS_OFF
                }
            );
        }
        Commands::Show => {
            println!("\n{}", title("Current Settings:"));
            println!("  {:<15} {}:{}", "Server:", ctx.host, ctx.port);
            println!(
                "  {:<15} {}",
                "JSON output:",
                if ctx.show_json {
                    &*STATUS_ON
                } else {
                    &*STATUS_OFF
                }
            );
            println!(
                "  {:<15} {}",
                "Debug mode:",
                if ctx.show_debug {
                    &*STATUS_ON
                } else {
                    &*STATUS_OFF
                }
            );
            println!(
                "  {:<15} {}",
                "Timing:",
                if ctx.show_timing {
                    &*STATUS_ON
                } else {
                    &*STATUS_OFF
                }
            );

            if ctx.last_used.principal.is_some() || ctx.last_used.action.is_some() {
                println!("\n{}", title("Last Used Values:"));
                if let Some(p) = &ctx.last_used.principal {
                    println!("  {:<15} {}", "Principal:", p);
                }
                if let Some(a) = &ctx.last_used.action {
                    println!("  {:<15} {}", "Action:", a);
                }
                if let Some(rt) = &ctx.last_used.resource_type {
                    println!("  {:<15} {}", "Resource Type:", rt);
                }
                if let Some(rid) = &ctx.last_used.resource_id {
                    println!("  {:<15} {}", "Resource ID:", rid);
                }
                if !ctx.last_used.attrs.is_empty() {
                    println!("  {:<15} {}", "Attributes:", "");
                    for (k, v) in &ctx.last_used.attrs {
                        println!("  {:<15} {}", "", format!("{k}={v}"));
                    }
                }
            }

            if let Some(data_dir) = dirs::data_dir() {
                let history_path = data_dir.join("treetop-rest").join("cli_history");
                println!("\n{}", title("Files:"));
                println!(
                    "  {:<15} {}",
                    "History:",
                    history_path.display().to_string()
                );
            }
        }
        Commands::Version => {
            show_status_and_version(ctx).await?;
        }
    }

    if ctx.show_timing {
        println!("{} {:?} microseconds", "Time:", now.elapsed().as_micros());
    }
    Ok(())
}

async fn show_status_and_version(ctx: &ExecContext) -> Result<()> {
    let status_url = format!("{}/status", ctx.base_url);
    let status_resp = ctx.client.get(&status_url).send().await?;
    let status_code = status_resp.status();
    let status_body = status_resp.text().await?;

    if ctx.show_debug {
        eprintln!("{} {}", warning("DEBUG status code:"), status_code);
        eprintln!("{}\n{}", warning("DEBUG status body:"), status_body);
    }

    if !status_code.is_success() {
        if let Ok(err) = serde_json::from_str::<ErrorResponse>(&status_body) {
            anyhow::bail!("status failed: {}", err.error);
        }
        anyhow::bail!("status failed with {status_code}");
    }

    if ctx.show_json {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&status_body) {
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            println!("{}", status_body);
        }
    }

    let metadata: PoliciesMetadata =
        serde_json::from_str(&status_body).with_context(|| "failed to parse /status response")?;

    let version_url = format!("{}/version", ctx.base_url);
    let version_info = match ctx.client.get(&version_url).send().await {
        Ok(resp) if resp.status().is_success() => resp
            .json::<treetop_rest::handlers::VersionInfo>()
            .await
            .ok(),
        _ => None,
    };

    println!("\n{}", title("treetop-cli"));
    println!(
        "  {:<15} {}",
        "Version:",
        version(env!("CARGO_PKG_VERSION"))
    );
    println!("  {:<15} {}", "Built:", env!("VERGEN_BUILD_TIMESTAMP"));
    println!("  {:<15} {}", "Git:", env!("VERGEN_GIT_DESCRIBE"));

    println!("\n{}", title("Server"));
    if let Some(info) = version_info {
        println!("  {:<15} {}", "Version:", version(&info.version));
        println!("  {:<15} {}", "Core:", info.core.version);
        println!("  {:<15} {}", "Cedar:", info.core.cedar);
    } else {
        println!("  {}", warning("Version: unavailable"));
    }

    println!("\n{}", title("Policies"));
    println!("  {:<15} {}", "Hash:", metadata.policies.sha256);
    println!(
        "  {:<15} {}",
        "Updated:",
        metadata.policies.timestamp.to_string()
    );
    println!("  {:<15} {}", "Entries:", metadata.policies.entries);
    println!(
        "  {:<15} {}",
        "Size:",
        format!("{} bytes", metadata.policies.size).white()
    );

    if let Some(src) = &metadata.policies.source {
        println!("  {:<15} {}", "Source:", src.to_string());
    }
    if let Some(freq) = metadata.policies.refresh_frequency {
        println!("  {:<15} every {}s", "Refresh:", freq);
    }

    println!(
        "  {:<15} {}",
        "Allow upload:",
        if metadata.allow_upload {
            &*STATUS_YES
        } else {
            &*STATUS_NO
        }
    );

    println!("\n{}", title("Labels"));
    println!("  {:<15} {}", "Hash:", metadata.labels.sha256);
    println!(
        "  {:<15} {}",
        "Updated:",
        metadata.labels.timestamp.to_string()
    );
    println!("  {:<15} {}", "Entries:", metadata.labels.entries);
    println!(
        "  {:<15} {}",
        "Size:",
        format!("{} bytes", metadata.labels.size).white()
    );
    if let Some(src) = &metadata.labels.source {
        println!("  {:<15} {}", "Source:", src.to_string());
    }
    if let Some(freq) = metadata.labels.refresh_frequency {
        println!("  {:<15} every {}s", "Refresh:", freq);
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
        eprintln!("{} {}", warning("DEBUG response status:"), status);
        eprintln!("{}\n{}", warning("DEBUG response body:"), body);
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
                eprintln!(
                    "{}: {}",
                    "Failed to parse successful response".red(),
                    parse_err
                );
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
            eprintln!("{}: {}", error("Error"), err.error);
        } else {
            eprintln!("{}: {}", "Unexpected error".red(), status);
            if !body.trim().is_empty() {
                eprintln!("{}: {body}", warning("Body"));
            }
        }
        // Make non-2xx fail the command:
        anyhow::bail!("request failed with status {status}")
    }
}
