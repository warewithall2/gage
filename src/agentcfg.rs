//! Connecting an LLM or a bot to this machine's gage, from the viewer.
//!
//! Every agent gets its own identity, in its own home under `agents/`. That
//! is the whole point rather than a detail: `SENDER VERIFIED` means *a key
//! signed this*, so agents sharing one home are one identity on the wire.
//! The verdict could not say which agent sent something, the journal could
//! not either, and a grant naming one agent would really be a grant for
//! anything running as that user. Per-agent keys are what make a per-agent
//! grant mean anything.
//!
//! ## Why this drives the CLI instead of calling the library
//!
//! `identity::Identity::create` resolves the home from the environment, as
//! does everything else that writes to a home. Creating an identity
//! *somewhere else* from inside a running server would mean either mutating
//! process-wide environment (which races every other request this server is
//! serving) or a second, home-explicit path through identity handling that
//! exists only for this feature. Both are worse than spawning the binary
//! that is already installed, with `GAGE_HOME` set for that child alone.
//!
//! It is the same reason `gage mcp` is described as a front door rather than
//! a second implementation: if this disagreed with the CLI, that would be a
//! bug here, not a second opinion.
//!
//! ## The one ceremony that is skipped, and the line under it
//!
//! Adding a contact normally requires comparing word-pairs read off the
//! other machine, because a key arriving from elsewhere might not belong to
//! whoever it claims. A key *this process just generated*, in a home it just
//! created, for the human sitting in front of it, has no second party to
//! impersonate. There is nothing to compare it against except itself.
//!
//! So these two identities are added to each other's lists here. The
//! boundary is hard and narrow: only a key generated in this call, in this
//! process, qualifies. Nothing here gives a key that arrived over a network,
//! a relay, a clipboard or a QR code any way to skip the compare.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A name is the one piece of untrusted input here that becomes a path, so
/// it is checked as a path component rather than sanitised into one.
/// Sanitising invites "what did it turn into?"; refusing does not.
pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Where this machine keeps the identities it made for agents.
pub fn agents_dir() -> PathBuf {
    crate::identity::home().join("agents")
}

fn home_for(name: &str) -> PathBuf {
    agents_dir().join(name)
}

/// Run the installed gage with a home of its own, and give back stdout.
///
/// `current_exe` rather than a PATH lookup: the agent must be created by the
/// same build that is serving this page, and a `gage` earlier in PATH could
/// be any version or anything at all.
fn run_in(home: &Path, args: &[&str]) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this binary: {e}"))?;
    let out = Command::new(exe)
        .args(args)
        // Set, not appended to: the child must not inherit a GAGE_HOME, a
        // COUNTERSIGN_HOME or a CTX_HOME from this server's environment,
        // because `identity::home` takes the first of the three that is set
        // and any of them would silently win over this one.
        .env("GAGE_HOME", home)
        .env_remove("COUNTERSIGN_HOME")
        .env_remove("CTX_HOME")
        .output()
        .map_err(|e| format!("could not run gage {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        return Err(if err.is_empty() {
            format!("gage {} failed", args.join(" "))
        } else {
            err.to_string()
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// `gage whoami` prints `handle<TAB>signpub.boxpub` on stdout.
fn whoami_in(home: &Path) -> Result<(String, String), String> {
    let out = run_in(home, &["whoami"])?;
    let line = out.lines().next().unwrap_or("");
    match line.split_once('\t') {
        Some((h, k)) if !k.trim().is_empty() => Ok((h.trim().to_string(), k.trim().to_string())),
        _ => Err("could not read the new identity's key".into()),
    }
}

/// An agent that exists on this machine.
pub struct Agent {
    pub name: String,
    pub handle: String,
    pub key: String,
    pub home: PathBuf,
}

impl Agent {
    pub fn fingerprint(&self) -> String {
        let (sign, boxpub) = crate::identity::split_key(&self.key);
        crate::words::fingerprint_of(&sign, boxpub.as_deref())
    }
}

/// Every agent identity this machine has made, oldest name order.
///
/// A directory without a readable identity is skipped rather than reported
/// as broken: this lists what can be used, and `whoami` failing is the same
/// answer as the directory not being an agent home at all.
pub fn list() -> Vec<Agent> {
    let dir = agents_dir();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| name_ok(n))
        .collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|name| {
            let home = home_for(&name);
            let (handle, key) = whoami_in(&home).ok()?;
            Some(Agent {
                name,
                handle,
                key,
                home,
            })
        })
        .collect()
}

/// Create an agent identity and introduce it to this machine's own.
///
/// Refuses an existing name outright. Overwriting here would destroy an
/// identity key, which is the one file in gage whose loss cannot be undone,
/// and "create" is not a word that should ever mean "replace".
pub fn create(name: &str) -> Result<Agent, String> {
    if !name_ok(name) {
        return Err("A name is 1 to 40 characters: letters, digits, - and _.".into());
    }
    let home = home_for(name);
    if home.exists() {
        return Err(format!("An agent called {name} already exists."));
    }
    let me = crate::identity::Identity::load()
        .map_err(|_| "This machine has no identity yet.".to_string())?;

    std::fs::create_dir_all(&home).map_err(|e| format!("could not make {}: {e}", home.display()))?;
    // From here on a failure leaves a directory behind. It is removed rather
    // than left for the next attempt to trip over, because `create` refuses
    // a name that exists and a half-made agent would make that name
    // permanently unusable from the page.
    let built = (|| -> Result<Agent, String> {
        run_in(&home, &["init", name])?;
        let (handle, key) = whoami_in(&home)?;

        let my_key = me.full_key();
        let my_home = crate::identity::home();
        let my_home = my_home.to_string_lossy().to_string();
        let home_str = home.to_string_lossy().to_string();

        // Each side adds the other, and each records the confirmation as
        // what it is: both keys came out of a keygen this process ran
        // seconds ago, in two directories on one disk. There is no other
        // party, no channel for anybody to sit on, and nothing a word-pair
        // comparison could establish that this code does not already know.
        //
        // `--same-machine` says exactly that and records it in `how`, so
        // somebody reading `gage contacts` later can tell this apart from a
        // confirmation a human performed. Leaving it unconfirmed instead
        // would have been the other defensible choice and is the worse one:
        // it would put an UNCONFIRMED verdict on every bundle from your own
        // agents, which teaches people that the verdict is noise.
        run_in(
            &crate::identity::home(),
            &["add", name, &key, "--same-machine"],
        )?;
        run_in(&home, &["add", &me.handle, &my_key, "--same-machine"])?;
        // And a local route each way, so `--to` delivers into the other
        // home directly. An agent on this machine has no reason to go out
        // over a relay to reach the identity sitting beside it.
        run_in(&crate::identity::home(), &["route", name, &home_str])?;
        run_in(&home, &["route", &me.handle, &my_home])?;

        Ok(Agent {
            name: name.to_string(),
            handle,
            key,
            home: home.clone(),
        })
    })();

    if built.is_err() {
        let _ = std::fs::remove_dir_all(&home);
    }
    built
}

/// What `remove` took out of service, so the caller can say it precisely.
#[derive(Debug)]
pub struct Removed {
    pub name: String,
    /// The agent's signing key, retired rather than forgotten. `None` only
    /// when the home was too broken to read one out of.
    pub key: Option<String>,
    pub route_removed: bool,
    pub home: PathBuf,
}

/// Take an agent out of service: retire its key, drop its route, delete its
/// home.
///
/// ## Retired, not forgotten
///
/// The contact entry is **retired**, not deleted. An agent that existed has
/// signed things, and those bundles are still on disk. Deleting the key from
/// `contacts.json` would turn every one of them from `SENDER VERIFIED` into
/// `SENDER UNVERIFIABLE` -- rewriting the past rather than ending the
/// present -- and it would let the same key be silently re-added later as if
/// it had never been judged. `trust::Contacts::retire` is the operation that
/// already means "this key stops counting from here", and it is the right
/// one. The tombstone is the point of it.
///
/// ## Why the order is this order
///
/// Trust first, then the route, then the home. Each step is the fail-closed
/// one: if removing the directory fails, an agent whose key is already
/// retired is harmless, whereas a deleted home whose key is still trusted
/// leaves a live grant naming an identity nobody can account for. It is the
/// same reasoning as `keychange` -- a window in which the key is still
/// trusted is a window opened by the act of revoking it.
///
/// ## What it does not touch
///
/// Nothing outside `<home>/agents/<name>/`, and no other application's
/// configuration. gage shows an MCP host config and never writes one, so it
/// cannot un-write one either; the caller prints the line to run instead.
pub fn remove(name: &str) -> Result<Removed, String> {
    if !name_ok(name) {
        return Err("A name is 1 to 40 characters: letters, digits, - and _.".into());
    }
    let home = home_for(name);
    if !home.is_dir() {
        return Err(format!("No agent called {name} on this machine."));
    }

    // Prefer the key the home actually holds; fall back to the one the
    // contact list has under this name. A home too broken to answer `whoami`
    // must still be removable, or a half-made agent is permanent.
    let key_from_home = whoami_in(&home).ok().map(|(_, k)| k);
    let mut c = crate::trust::Contacts::load();
    let sign = key_from_home
        .as_deref()
        .map(|k| crate::identity::split_key(k).0)
        .or_else(|| c.key_for_name(name));

    if let Some(sign) = &sign {
        let now = crate::bundle::now_rfc3339();
        // Two steps, exactly as `gage retire` and `gage keychange` do it, and
        // for the reason spelled out in `state::observe_and_cut`.
        //
        // The first `retire` takes the cut at 0, which is fail-closed: until
        // the real cut is known, EVERY bundle this key signed reads as
        // rejected. Then the inbox is observed and the cut reserved above
        // that batch in one locked step, and `retired_seq` is relaxed to it.
        // The order matters because the window between the two is the only
        // window in which an old-key arrival could land below the line, and
        // closing it the other way round would open it.
        //
        // Getting this wrong is not subtle in its effect: with the cut left
        // at 0, nothing can be `seq < retired_seq`, so every bundle the agent
        // ever sent turns from SENDER VERIFIED into SENDER KEY REJECTED --
        // which is the retroactive condemnation that plain retirement exists
        // NOT to do. `--compromised` is the operation that condemns history.
        //
        // `retire` returns false when the key was not a live contact, which
        // is not an error here: an agent whose contact entry was already
        // retired by hand still has a home to remove.
        if c.retire(sign, &now, 0, false, None) {
            c.save().map_err(|e| format!("could not save contacts: {e}"))?;
            let seq = crate::state::LocalState::observe_and_cut(crate::routes::scan_inbox_knowing)
                .map_err(|e| format!("could not take the retirement cut: {e}"))?;
            if let Some(r) = c.retired.get_mut(sign) {
                r.retired_seq = seq;
            }
            c.save().map_err(|e| format!("could not save contacts: {e}"))?;
        }
    }

    let mut r = crate::routes::Routes::load();
    let route_removed = r.local.remove(name).is_some();
    if route_removed {
        r.save().map_err(|e| format!("could not save routes: {e}"))?;
    }

    std::fs::remove_dir_all(&home)
        .map_err(|e| format!("could not remove {}: {e}", home.display()))?;

    Ok(Removed {
        name: name.to_string(),
        key: sign,
        route_removed,
        home,
    })
}

/// The MCP host configurations for an agent, ready to paste.
///
/// Absolute paths throughout: an MCP host is started by a desktop
/// application whose PATH and working directory are not the shell's, and
/// "command not found" inside a host that logs nowhere is a bad afternoon.
pub fn configs(agent: &Agent) -> serde_json::Value {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "gage".into());
    let home = agent.home.to_string_lossy().to_string();
    let json_block = format!(
        "{{\n  \"mcpServers\": {{\n    \"gage\": {{\n      \"command\": {exe:?},\n      \
         \"args\": [\"mcp\"],\n      \"env\": {{ \"GAGE_HOME\": {home:?} }}\n    }}\n  }}\n}}"
    );
    serde_json::json!({
        // One line, and the only form that needs no file editing at all.
        "claude_code": format!(
            "GAGE_HOME={} claude mcp add gage -- {} mcp",
            shell_quote(&home), shell_quote(&exe)),
        "claude_desktop": json_block,
        // Codex reads the same shape; named separately because telling
        // somebody "use the Claude block" in a Codex setup is how a config
        // ends up in the wrong file.
        "codex": json_block,
        "generic": format!("{} mcp   # with GAGE_HOME={}", exe, home),
    })
}

/// A single-quoted shell word. Only used for display, never executed here:
/// nothing in this module runs a shell, and the one command that is run is
/// an argv with no shell between it and the kernel.
fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The `authority` line that would let this agent's messages be accepted
/// without a human, and the words that say what it does.
///
/// Returned as text to paste, never written. There is no command in gage
/// that writes this file, for the reason given in `src/authority.rs`: a
/// documented path that grants authority by being asked is reachable by
/// anything that can talk an agent into asking.
pub fn grant_line(agent: &Agent) -> String {
    format!("allow {} answer auto-accept max-exchanges 200", agent.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The name becomes a directory under the home, so these are the cases
    // that decide whether a request can write outside it.
    #[test]
    fn a_name_that_could_leave_the_agents_directory_is_refused() {
        for bad in [
            "..",
            ".",
            "../escape",
            "a/b",
            "a\\b",
            "/abs",
            "",
            ".hidden",
            "has space",
            "semi;colon",
            "nul\0byte",
            "new\nline",
            "quote'name",
            "dollar$name",
            "tilde~name",
        ] {
            assert!(!name_ok(bad), "accepted a dangerous agent name: {bad:?}");
        }
        let long = "a".repeat(41);
        assert!(!name_ok(&long), "accepted a 41-character name");
    }

    #[test]
    fn ordinary_agent_names_are_accepted() {
        for good in ["codex", "grok", "claude-code", "bot_2", "a", &"a".repeat(40)] {
            assert!(name_ok(good), "refused an ordinary agent name: {good:?}");
        }
    }

    // `remove` deletes a directory derived from this name, so the name check
    // has to happen before anything touches the filesystem -- and it has to
    // be the same check `create` uses, or the two doors disagree about what
    // a name is.
    #[test]
    fn remove_refuses_a_dangerous_name_before_touching_anything() {
        for bad in ["..", ".", "../escape", "a/b", "/abs", "", ".hidden", "nul\0byte"] {
            let e = remove(bad).unwrap_err();
            assert!(
                e.contains("1 to 40 characters"),
                "remove({bad:?}) refused for the wrong reason: {e}"
            );
        }
    }

    // The displayed command is for a human to copy into a shell, so a path
    // with a space in it has to come back as one word.
    #[test]
    fn a_path_with_a_space_is_quoted_for_the_shell() {
        assert_eq!(shell_quote("/home/o/.ctx"), "/home/o/.ctx");
        assert_eq!(
            shell_quote("/home/o/My Home/.ctx"),
            "'/home/o/My Home/.ctx'"
        );
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
