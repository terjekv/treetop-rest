use anyhow::{Context as AnyContext, Result};
use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use treetop_core::{Action, AttrValue, Principal, Request, Resource, User};
use treetop_rest::cli::style::{
    error, help_line, settings_line, status_flag, title, version, warning, yes_no,
};
use treetop_rest::cli::{
    ApiClient, AuthorizeResult, CliConfig, CliDisplay, ErrorResponse, InputAttrValue,
    LastUsedValues, PoliciesDownload, UserPolicies, matrix::expand_matrix, models::TableStyle,
    repl::run_repl,
};
use treetop_rest::models::{AuthRequest, AuthorizeRequest, PoliciesMetadata};
use uuid::Uuid;

// Completion is handled inside the REPL module now

// Consolidated execution context for commands
struct ExecContext {
    api: ApiClient,
    show_json: bool,
    show_debug: bool,
    show_timing: bool,
    last_used: LastUsedValues,
    host: String,
    port: u16,
    correlation_id: String,
    table_style: TableStyle,
}

// REPL logic moved to treetop_rest::cli::repl

#[derive(Parser, Debug)]
#[clap(name = "treetop-cli", about = "CLI (and REPL) for the Treeptop API")]
struct Cli {
    #[clap(long, default_value = "127.0.0.1", env = "TREETOP_CLI_SERVER_ADDRESS")]
    host: String,
    #[clap(long, default_value = "9999", env = "TREETOP_CLI_SERVER_PORT")]
    port: u16,
    /// Print JSON responses
    #[arg(long, env = "TREETOP_CLI_JSON")]
    json: bool,
    /// Print JSON requests and responses (superset of --json)
    #[arg(long, env = "TREETOP_CLI_DEBUG")]
    debug: bool,
    /// Print command execution timing
    #[arg(long, env = "TREETOP_CLI_TIMING")]
    timing: bool,
    /// Table style: rounded (default), ascii, unicode, or markdown
    #[arg(long, value_parser = clap::value_parser!(TableStyle), env = "TREETOP_CLI_TABLE_STYLE", default_value = "rounded")]
    table_style: Option<TableStyle>,
    #[clap(subcommand)]
    command: Commands,
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

fn sanitize_command(cmd: &str) -> String {
    cmd.chars()
        .filter_map(|c| {
            if !c.is_ascii() {
                None
            } else if c.is_whitespace() {
                Some('_')
            } else {
                Some(c)
            }
        })
        .collect()
}

fn make_correlation_id(cmd: &str) -> String {
    let sanitized = sanitize_command(cmd);
    let uuid = Uuid::new_v4();
    if sanitized.is_empty() {
        uuid.to_string()
    } else {
        format!("{}-{}", uuid, sanitized)
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch interactive REPL
    Repl,
    /// Get service status
    Status,
    /// Check a request against policies. Supports matrix expansion: use 'alice|bob' for alternatives, 'User::alice[admins|viewers]' for Cedar groups
    Check {
        /// Principal to evaluate (falls back to last used in REPL). Supports alternatives: alice|bob
        #[clap(long)]
        principal: Option<String>,
        /// Action to evaluate (falls back to last used in REPL). Supports alternatives: create|delete
        #[clap(long)]
        action: Option<String>,
        /// Resource type (falls back to last used in REPL). Supports alternatives: Host|Document
        #[clap(long = "resource-type")]
        resource_type: Option<String>,
        /// Repeatable: --resource-attribute key=value (quotes allowed around value). Values support alternatives
        #[arg(long = "resource-attribute", value_parser = parse_kv)]
        attrs: Vec<(String, InputAttrValue)>,
        /// Resource ID (falls back to last used in REPL). Supports alternatives: host1.com|host2.com
        #[clap(long = "resource-id")]
        resource_id: Option<String>,
        #[clap(long = "detailed")]
        detailed: bool,
        /// Display results in table format instead of default format
        #[clap(long = "table")]
        table: bool,
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
    /// Fetch Prometheus metrics from the server
    Metrics,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Load configuration hierarchy: CLI > ENV > Config file > Built-in defaults
    // At this point, clap has already handled CLI args and environment variables
    // Now fill in any missing values from the config file
    let (config, config_loaded_from_file) = CliConfig::load();

    // For table style: if not provided via CLI/ENV, use config file value
    let table_style = if let Some(style) = cli.table_style {
        style
    } else if config_loaded_from_file {
        config.table_style
    } else {
        TableStyle::default()
    };

    let cli_command = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let correlation_id = make_correlation_id(&cli_command);

    let mut api = ApiClient::from_host_port(&cli.host, cli.port);
    api.set_correlation_id(correlation_id.clone());

    let mut ctx = ExecContext {
        api,
        show_json: cli.json || cli.debug,
        show_debug: cli.debug,
        show_timing: cli.timing,
        last_used: LastUsedValues::default(),
        host: cli.host.clone(),
        port: cli.port,
        correlation_id,
        table_style,
    };

    if let Commands::Repl = cli.command {
        let ctx_arc = Arc::new(tokio::sync::Mutex::new(ctx));
        run_repl(
            &cli.host,
            cli.port,
            {
                let ctx_arc = ctx_arc.clone();
                move |input: String| {
                    let ctx_arc_inner = ctx_arc.clone();
                    async move {
                        let parts: Vec<&str> = input.split_whitespace().collect();
                        let args = std::iter::once("policy-cli").chain(parts.into_iter());
                        match Cli::try_parse_from(args) {
                            Ok(parsed) => {
                                let correlation_id = make_correlation_id(&input);
                                let mut guard = ctx_arc_inner.lock().await;
                                guard.api.set_correlation_id(correlation_id.clone());
                                guard.correlation_id = correlation_id;
                                execute_command(parsed.command, &mut guard).await
                            }
                            Err(e) => {
                                eprintln!("{}: {}", error("Error"), e);
                                Ok(())
                            }
                        }
                    }
                }
            },
            print_help,
        )
        .await?;
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
    help_line("json", "Toggle JSON response output");
    help_line("debug", "Toggle debug mode (requests + responses)");
    help_line("timing", "Toggle command timing display");
    help_line("history", "Show command history");
    help_line("show", "Show current settings");
    help_line("version", "Show version information");
    help_line("metrics", "Fetch Prometheus metrics");
    help_line("exit, quit", "Exit the REPL");
    help_line("help", "Show this help");
}

struct CheckParams {
    principal: Option<String>,
    action: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    attrs: Vec<(String, InputAttrValue)>,
    detailed: bool,
    table: bool,
}

async fn handle_check(ctx: &mut ExecContext, params: CheckParams) -> Result<()> {
    let principal = params
        .principal
        .or_else(|| ctx.last_used.principal.clone())
        .ok_or_else(|| anyhow::anyhow!("--principal is required (no previous value)"))?;
    let action = params
        .action
        .or_else(|| ctx.last_used.action.clone())
        .ok_or_else(|| anyhow::anyhow!("--action is required (no previous value)"))?;
    let resource_type = params
        .resource_type
        .or_else(|| ctx.last_used.resource_type.clone())
        .ok_or_else(|| anyhow::anyhow!("--resource-type is required (no previous value)"))?;
    let resource_id = params
        .resource_id
        .or_else(|| ctx.last_used.resource_id.clone())
        .ok_or_else(|| anyhow::anyhow!("--resource-id is required (no previous value)"))?;

    let resolved_attrs = if params.attrs.is_empty() {
        ctx.last_used.attrs.clone()
    } else {
        params.attrs
    };

    ctx.last_used.principal = Some(principal.clone());
    ctx.last_used.action = Some(action.clone());
    ctx.last_used.resource_type = Some(resource_type.clone());
    ctx.last_used.resource_id = Some(resource_id.clone());
    ctx.last_used.attrs = resolved_attrs.clone();

    // Convert resolved_attrs to string pairs for matrix expansion
    let attrs_tuples: Vec<(String, String)> = resolved_attrs
        .iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect();

    // Expand matrix to generate all query permutations
    let matrix_queries = expand_matrix(
        &principal,
        &action,
        &resource_type,
        &resource_id,
        attrs_tuples,
    );

    // Show preview for matrix queries
    if matrix_queries.len() > 1 {
        let mut dimensions = Vec::new();
        let principals_count = principal.split('|').count();
        let actions_count = action.split('|').count();
        let resource_types_count = resource_type.split('|').count();
        let resource_ids_count = resource_id.split('|').count();

        if principals_count > 1 {
            dimensions.push(format!("{} principals", principals_count));
        }
        if actions_count > 1 {
            dimensions.push(format!("{} actions", actions_count));
        }
        if resource_types_count > 1 {
            dimensions.push(format!("{} resource-types", resource_types_count));
        }
        if resource_ids_count > 1 {
            dimensions.push(format!("{} resource-ids", resource_ids_count));
        }

        println!(
            "{} Generating {} permutations: {}",
            title("Matrix:"),
            matrix_queries.len(),
            dimensions.join(" × ")
        );
    }

    // Build authorization requests with query IDs
    let mut auth_requests = Vec::new();
    for matrix_query in &matrix_queries {
        let mut resource = Resource::new(&matrix_query.resource_type, &matrix_query.resource_id);
        for (k, v) in &matrix_query.attrs {
            // Parse the attribute value as a Cedar value
            if let Ok(attr_val) = InputAttrValue::from_str(v) {
                resource = resource.with_attr(k.clone(), AttrValue::from(attr_val));
            } else {
                resource = resource.with_attr(k.clone(), AttrValue::String(v.clone()));
            }
        }

        let principal = Principal::User(
            User::from_str(&matrix_query.principal)
                .with_context(|| format!("invalid principal `{}`", matrix_query.principal))?,
        );

        let action = Action::from_str(&matrix_query.action)
            .with_context(|| format!("invalid action `{}`", matrix_query.action))?;

        let req = Request {
            principal,
            action,
            resource,
        };

        auth_requests.push(AuthRequest {
            id: Some(matrix_query.query_id.clone()),
            request: req,
        });
    }

    if ctx.show_debug {
        for (idx, auth_req) in auth_requests.iter().enumerate() {
            match serde_json::to_string_pretty(&auth_req.request) {
                Ok(body) => eprintln!("{}\n{}", warning(&format!("DEBUG request {}:", idx)), body),
                Err(err) => eprintln!("{}: {}", error("Failed to serialize request"), err),
            }
        }
    }

    // Use the unified authorize endpoint with all queries
    let auth_request_full = AuthorizeRequest {
        requests: auth_requests,
    };
    let resp = ctx
        .api
        .post_authorize(&auth_request_full, params.detailed)
        .await?;

    // Auto-enable table mode for multiple queries
    let use_table = params.table || matrix_queries.len() > 1;
    handle_response_authorize(
        resp,
        ctx.show_json,
        ctx.show_debug,
        use_table,
        ctx.table_style,
    )
    .await?;

    Ok(())
}

async fn handle_get_policies(ctx: &ExecContext, raw: bool) -> Result<()> {
    let resp = ctx.api.get_policies(raw).await?;
    if raw && resp.status().is_success() {
        println!("{}", resp.text().await?);
    } else {
        handle_response::<PoliciesDownload>(resp, ctx.show_json, ctx.show_debug).await?;
    }
    Ok(())
}

async fn handle_upload(
    ctx: &ExecContext,
    file: std::path::PathBuf,
    raw: bool,
    token: String,
) -> Result<()> {
    let content = fs::read_to_string(&file)?;
    let resp = if raw {
        ctx.api.post_policies_raw(&token, content).await?
    } else {
        ctx.api.post_policies_json(content).await?
    };
    handle_response::<PoliciesMetadata>(resp, ctx.show_json, ctx.show_debug).await?;
    Ok(())
}

async fn handle_list_policies(ctx: &ExecContext, user: &str) -> Result<()> {
    let resp = ctx.api.get_user_policies(user).await?;
    handle_response::<UserPolicies>(resp, ctx.show_json, ctx.show_debug).await?;
    Ok(())
}

fn toggle_json(ctx: &mut ExecContext) {
    ctx.show_json = !ctx.show_json;
    println!("JSON responses: {}", status_flag(ctx.show_json));
}

fn toggle_debug(ctx: &mut ExecContext) {
    ctx.show_debug = !ctx.show_debug;
    println!(
        "Debug mode (requests + responses): {}",
        status_flag(ctx.show_debug)
    );
}

fn toggle_timing(ctx: &mut ExecContext) {
    ctx.show_timing = !ctx.show_timing;
    println!("Timing display: {}", status_flag(ctx.show_timing));
}

async fn handle_metrics(ctx: &ExecContext) -> Result<()> {
    let resp = ctx.api.get_metrics().await?;
    let status = resp.status();
    let body = resp.text().await?;

    if ctx.show_debug {
        eprintln!("{} {}", warning("DEBUG response status:"), status);
        eprintln!("{}\n{}", warning("DEBUG response body:"), body);
    }

    if !status.is_success() {
        anyhow::bail!("metrics request failed with status {}", status);
    }

    // Just print the raw Prometheus metrics
    println!("{}", body);
    Ok(())
}

fn show_settings(ctx: &ExecContext) {
    println!("\n{}", title("Current Settings:"));

    settings_line("Server:", &format!("{}:{}", ctx.host, ctx.port));
    settings_line("JSON output:", status_flag(ctx.show_json));
    settings_line("Debug mode:", status_flag(ctx.show_debug));
    settings_line("Timing:", status_flag(ctx.show_timing));
    settings_line("Table style:", &ctx.table_style.to_string());

    if ctx.last_used.principal.is_some() || ctx.last_used.action.is_some() {
        println!("\n{}", title("Last Used Values:"));
        if let Some(p) = &ctx.last_used.principal {
            settings_line("Principal:", p);
        }
        if let Some(a) = &ctx.last_used.action {
            settings_line("Action:", a);
        }
        if let Some(rt) = &ctx.last_used.resource_type {
            settings_line("Resource Type:", rt);
        }
        if let Some(rid) = &ctx.last_used.resource_id {
            settings_line("Resource ID:", rid);
        }
        if !ctx.last_used.attrs.is_empty() {
            settings_line("Attributes:", "");
            for (k, v) in &ctx.last_used.attrs {
                settings_line("", &format!("{k}={v}"));
            }
        }
    }

    if let Some(data_dir) = dirs::data_dir() {
        let history_path = data_dir.join("treetop-rest").join("cli_history");
        println!("\n{}", title("Files:"));
        settings_line("History:", &history_path.display().to_string());
    }
}

async fn execute_command(command: Commands, ctx: &mut ExecContext) -> Result<()> {
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
            table,
        } => {
            handle_check(
                ctx,
                CheckParams {
                    principal,
                    action,
                    resource_type,
                    resource_id,
                    attrs,
                    detailed,
                    table,
                },
            )
            .await?;
        }
        Commands::GetPolicies { raw } => {
            handle_get_policies(ctx, raw).await?;
        }
        Commands::Upload { file, raw, token } => {
            handle_upload(ctx, file, raw, token).await?;
        }
        Commands::ListPolicies { user } => {
            handle_list_policies(ctx, &user).await?;
        }
        Commands::Json => {
            toggle_json(ctx);
        }
        Commands::Debug => {
            toggle_debug(ctx);
        }
        Commands::Timing => {
            toggle_timing(ctx);
        }
        Commands::Show => {
            show_settings(ctx);
        }
        Commands::Version => {
            show_status_and_version(ctx).await?;
        }
        Commands::Metrics => {
            handle_metrics(ctx).await?;
        }
    }

    if ctx.show_timing {
        println!("Time: {:?} microseconds", now.elapsed().as_micros());
    }
    Ok(())
}

async fn show_status_and_version(ctx: &ExecContext) -> Result<()> {
    let status_resp = ctx.api.get_status().await?;
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

    let version_info = match ctx.api.get_version().await {
        Ok(resp) if resp.status().is_success() => resp
            .json::<treetop_rest::handlers::VersionInfo>()
            .await
            .ok(),
        _ => None,
    };

    println!("\n{}", title("treetop-cli"));
    settings_line("Version", &version(env!("CARGO_PKG_VERSION")));
    settings_line("Built:", env!("VERGEN_BUILD_TIMESTAMP"));
    settings_line("Git:", env!("VERGEN_GIT_DESCRIBE"));

    println!("\n{}", title("Server"));
    if let Some(info) = version_info {
        settings_line("Version:", &version(&info.version));
        settings_line("Core:", &info.core.version);
        settings_line("Cedar:", &info.core.cedar);
    } else {
        settings_line("Version:", &warning("unavailable"));
    }

    let p = &metadata.policies;
    println!("\n{}", title("Policies"));
    settings_line("Hash:", &p.sha256);
    settings_line("Updated:", &p.timestamp.to_string());
    settings_line("Entries:", &p.entries.to_string());
    settings_line("Size:", &format!("{} bytes", p.size).white());

    if let Some(src) = &p.source {
        settings_line("Source:", &src.to_string());
    }
    if let Some(freq) = p.refresh_frequency {
        settings_line("Refresh:", &format!("every {}s", freq));
    }

    settings_line("Allow upload:", yes_no(metadata.allow_upload));

    let l = &metadata.labels;
    println!("\n{}", title("Labels"));
    settings_line("Hash:", &l.sha256);
    settings_line("Updated:", &l.timestamp.to_string());
    settings_line("Entries:", &l.entries.to_string());
    settings_line("Size:", &format!("{} bytes", l.size).white());
    if let Some(src) = &l.source {
        settings_line("Source:", &src.to_string());
    }
    if let Some(freq) = l.refresh_frequency {
        settings_line("Refresh:", &format!("every {}s", freq));
    }

    Ok(())
}

/// Generic response handler that takes a closure for display logic
async fn handle_response_impl<T, F>(
    resp: reqwest::Response,
    show_json: bool,
    show_debug: bool,
    display_fn: F,
) -> Result<()>
where
    T: serde::de::DeserializeOwned,
    F: Fn(T) -> String,
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
                println!("{}", display_fn(data));
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

async fn handle_response_authorize(
    resp: reqwest::Response,
    show_json: bool,
    show_debug: bool,
    use_table: bool,
    table_style: TableStyle,
) -> Result<()> {
    handle_response_impl(resp, show_json, show_debug, |data: AuthorizeResult| {
        if use_table {
            data.display_as_table_with_style(table_style)
        } else {
            data.display()
        }
    })
    .await
}

async fn handle_response<T>(
    resp: reqwest::Response,
    show_json: bool,
    show_debug: bool,
) -> Result<()>
where
    T: serde::de::DeserializeOwned + CliDisplay,
{
    handle_response_impl(resp, show_json, show_debug, |data: T| data.display()).await
}
