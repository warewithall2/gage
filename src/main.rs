//! ctx -- hand context between agents, with a trust boundary.
//!
//! Transport-agnostic on purpose. A bundle is a directory, so it moves over
//! anything you already have: a shared folder for two agents on one machine,
//! git, email, a file drop. No server is required, and none is included,
//! because agents are invoked rather than online -- presence is the part of
//! the instant-messenger model that does not transfer.

mod bundle;
mod identity;
mod manifest;
mod open;
mod trust;

use clap::{Parser, Subcommand};
use manifest::{AgentInfo, ItemKind};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ctx", about = "Hand context between agents, with provenance")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your identity keypair
    Init { handle: String },
    /// Print your public handle and key, to give to someone else
    Whoami,
    /// Add someone's key to your buddy list
    Add { name: String, key: String },
    /// List your contacts and groups
    Contacts,
    /// Build a bundle
    Send {
        #[arg(long)] to: Vec<String>,
        #[arg(long)] subject: String,
        #[arg(long)] out: PathBuf,
        #[arg(long)] file: Vec<PathBuf>,
        #[arg(long)] prompt: Vec<PathBuf>,
        #[arg(long)] decision: Vec<PathBuf>,
        #[arg(long)] agent: Option<String>,
        #[arg(long)] model: Option<String>,
    },
    /// Summarise a bundle without putting its contents in context
    Inspect { dir: PathBuf },
    /// Render a bundle for an agent to read, inside a trust frame
    Open {
        dir: PathBuf,
        /// Show contents even when the signature does not verify
        #[arg(long)] reveal: bool,
    },
    /// Re-sign a bundle for someone else, appending to its chain
    Forward {
        dir: PathBuf,
        #[arg(long)] to: Vec<String>,
        #[arg(long)] out: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ctx: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Init { handle } => {
            let id = identity::Identity::create(&handle)?;
            println!("identity created in {}", identity::home().display());
            println!("handle : {handle}");
            println!("key    : {}", id.public_b64());
            println!("\nGive the line above to anyone who should be able to send to you.");
        }
        Cmd::Whoami => {
            let id = identity::Identity::load()?;
            println!("{}\t{}", id.handle, id.public_b64());
        }
        Cmd::Add { name, key } => {
            if !bundle::b64_decode_ok(&key) {
                return Err("that key is not valid base64".into());
            }
            let mut c = trust::Contacts::load();
            c.keys.insert(key.trim().to_string(), name.clone());
            c.save()?;
            println!("added {name}");
        }
        Cmd::Contacts => {
            let c = trust::Contacts::load();
            if c.keys.is_empty() {
                println!("no contacts yet");
            }
            for (k, n) in &c.keys {
                println!("{n}\t{}…", k.chars().take(16).collect::<String>());
            }
            for (g, members) in &c.groups {
                println!("group:{g}\t{} member(s)", members.len());
            }
        }
        Cmd::Send { to, subject, out, file, prompt, decision, agent, model } => {
            let id = identity::Identity::load()?;
            let mut specs: Vec<(ItemKind, PathBuf)> = Vec::new();
            specs.extend(file.into_iter().map(|p| (ItemKind::File, p)));
            specs.extend(prompt.into_iter().map(|p| (ItemKind::Prompt, p)));
            specs.extend(decision.into_iter().map(|p| (ItemKind::Decision, p)));
            if specs.is_empty() {
                return Err("nothing to send: pass --file, --prompt or --decision".into());
            }
            if to.is_empty() {
                return Err("no recipient: pass --to <handle|group:name>".into());
            }
            let ag = agent.map(|name| AgentInfo { name, model });
            let m = bundle::create(&out, &id, &subject, &to, ag, &specs)?;
            println!("bundle {} written to {}", m.id, out.display());
            println!("  {} item(s), signed by {}", m.items.len(), m.from.handle);
            println!("\nMove that directory however you like: shared folder, git, email.");
        }
        Cmd::Inspect { dir } => {
            let l = bundle::load(&dir)?;
            let m = &l.manifest;
            println!("id       : {}", m.id);
            println!("subject  : {}", m.subject);
            println!("trust    : {}", l.trust.label());
            println!("from     : {} ({}…)", m.from.handle, m.from.key.chars().take(16).collect::<String>());
            println!("forwarded: {}", if m.is_forwarded() { "yes" } else { "no" });
            println!("to       : {}", m.to.join(", "));
            for it in &m.items {
                println!("  {:?}\t{}\t{} bytes", it.kind, it.path, it.bytes);
            }
            if !l.tampered.is_empty() {
                println!("TAMPERED : {}", l.tampered.join(", "));
                return Ok(ExitCode::FAILURE);
            }
        }
        Cmd::Open { dir, reveal } => {
            let l = bundle::load(&dir)?;
            print!("{}", open::render(&l, reveal));
            // Non-zero when the content could not be attributed, so a script
            // or agent harness can branch on it instead of parsing prose.
            if !l.tampered.is_empty() || matches!(l.trust, trust::Trust::Unverified) {
                return Ok(ExitCode::from(2));
            }
        }
        Cmd::Forward { dir, to, out } => {
            let id = identity::Identity::load()?;
            if to.is_empty() {
                return Err("no recipient: pass --to".into());
            }
            let m = bundle::forward(&dir, &out, &id, &to)?;
            println!("forwarded {} as {} hop(s) to {}", m.id, m.chain.len(), to.join(", "));
        }
    }
    Ok(ExitCode::SUCCESS)
}
