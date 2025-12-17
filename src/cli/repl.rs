use anyhow::Result;
use rustyline::completion::{Completer, Pair};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use super::completion::complete_line;

pub struct CLIHelper;
impl Helper for CLIHelper {}
impl Validator for CLIHelper {}
impl Highlighter for CLIHelper {}
impl Hinter for CLIHelper { type Hint = String; }

impl Completer for CLIHelper {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> std::result::Result<(usize, Vec<Pair>), ReadlineError> {
        let (start, matches) = complete_line(line, pos);
        let pairs = matches
            .into_iter()
            .map(|s| Pair { display: s.clone(), replacement: s })
            .collect();
        Ok((start, pairs))
    }
}

pub async fn run_repl<F, Fut, H>(host: &str, port: u16, mut handle_line: F, mut show_help: H) -> Result<()>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
    H: FnMut(),
{
    let mut rl = Editor::new()?;
    rl.set_helper(Some(CLIHelper));

    let history_path = dirs::data_dir()
        .map(|p| p.join("treetop-rest"))
        .unwrap_or_else(|| "treetop-rest".into())
        .join("cli_history");

    if let Some(parent) = history_path.parent() { std::fs::create_dir_all(parent)?; }
    let _ = rl.load_history(&history_path);
    rl.set_max_history_size(1000)?;

    println!("Policy CLI REPL. Type 'help' for commands, 'exit' to quit.");
    loop {
        match rl.readline(&format!("{}@{}> ", host, port)) {
            Ok(input) => {
                rl.add_history_entry(input.as_str())?;
                let parts: Vec<&str> = input.split_whitespace().collect();
                match parts.first().copied() {
                    Some("exit") | Some("quit") => break,
                    Some("help") | None => show_help(),
                    Some("history") => {
                        for (idx, entry) in rl.history().iter().enumerate() {
                            println!("{:4}: {}", idx + 1, entry);
                        }
                    }
                    Some(_) => {
                        if let Err(e) = handle_line(input.clone()).await {
                            eprintln!("Error: {}", e);
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(err) => { eprintln!("Error: {err}"); break; }
        }
    }

    if let Err(e) = rl.save_history(&history_path) {
        eprintln!("Warning: Failed to save command history: {}", e);
    }

    Ok(())
}
