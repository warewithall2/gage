//! `gage quickstart` -- the shortest honest path from nothing to a first
//! verified handoff.
//!
//! Composition only. Every step here is an existing command's own code path:
//! `Identity::create_named`, `words::fingerprint_of`, `trust::add_contact`,
//! `outbound::send_bundle`. No new state, no new file formats, no crypto. If
//! you delete this module nothing else changes behaviour, which is the point
//! -- it is a guided tour, not a second way to do things.
//!
//! Written because walking the documented path as a stranger took five
//! commands across two documents, and the first line it told you to send a
//! colleague did not run.
//!
//! Every step is skippable, an empty answer is always the safe answer, and
//! EOF (a closed stdin, or a script that ran out of input) is treated as
//! "skip the rest" rather than an error -- so this can be driven by a pipe
//! without pretending to be non-interactive.

use std::io::{self, BufRead, Write};

/// A line from the user, or `None` at EOF.
fn ask(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

/// A yes/no where empty means no. The default is always the one that does
/// nothing.
fn yes(prompt: &str) -> bool {
    matches!(
        ask(prompt).as_deref().map(str::trim),
        Some("y") | Some("Y") | Some("yes") | Some("YES")
    )
}

fn rule() {
    println!("\n----------------------------------------------------------------\n");
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("gage quickstart");
    println!("Three things: who you are, who you trust, and one handoff.");
    println!("Press Ctrl-C at any point, or leave an answer empty to skip it.");
    rule();

    // ---- 1. an identity, or the one that is already here
    let id = match crate::identity::Identity::load() {
        Ok(id) => {
            println!("You already have an identity, so this leaves it alone.");
            id
        }
        Err(_) => {
            println!("First, an identity. This makes a keypair on this machine.");
            println!("A name is just a label for you; leave it empty and gage");
            println!("derives two words from the key itself.");
            let name = ask("\n  a name for yourself (or empty): ").unwrap_or_default();
            let chosen = if name.is_empty() { None } else { Some(name) };
            let id = crate::identity::Identity::create_named(chosen.as_deref())?;
            println!(
                "\nmade you an identity in {}",
                crate::identity::home().display()
            );
            id
        }
    };

    let token = id.full_key();
    let fp = crate::words::fingerprint_of(&id.public_b64(), Some(&id.box_public_b64()));
    println!("\n  you are   : {}", crate::manifest::one_line(&id.handle));
    println!("  this key says : {fp}");
    println!();
    println!("  Those four word-pairs come from your key, so nobody picks their");
    println!("  own. They are what a colleague reads back to you out loud, on a");
    println!("  call, to check the key they got is really yours. That one human");
    println!("  moment is what makes SENDER VERIFIED mean anything later.");
    println!("\n  Send them this line (it is public, so any channel will do):");
    println!(
        "\n    gage add {} {}",
        crate::manifest::one_line(&crate::manifest::shell_word(&id.handle)),
        token
    );
    rule();

    // ---- 2. a contact, from the line they send back
    println!("Second, their key. When they run `gage connect` or");
    println!("`gage quickstart`, they get a line like the one above.");
    let mut added: Option<String> = None;
    if yes("\n  do you have their line to paste now? [y/N] ") {
        println!("\n  Paste the whole `gage add ...` line, or just the key.");
        let pasted = ask("  > ").unwrap_or_default();
        if pasted.is_empty() {
            println!("  nothing pasted -- skipping. `gage add <name> <key>` later.");
        } else {
            // Accept the whole line they were told to run, or a bare key.
            // Parsing what the other side was handed is friendlier than
            // asking a person to take it apart themselves.
            let (name, key) = parse_add(&pasted);
            let key = match key {
                Some(k) => k,
                None => {
                    println!("  that does not look like a key -- skipping.");
                    String::new()
                }
            };
            if !key.is_empty() {
                let name = match name {
                    Some(n) => n,
                    None => ask("  what do you want to call them? ").unwrap_or_default(),
                };
                if name.is_empty() {
                    println!("  no name given -- skipping.");
                } else {
                    match crate::trust::add_contact(&name, &key) {
                        // `add_contact` returns the lines `gage add` prints,
                        // word-pairs and all -- so they are printed, not
                        // reformatted. Joining them was my bug, and it put a
                        // whole paragraph on the "this key says" line.
                        Ok(lines) => {
                            println!();
                            for l in lines {
                                println!("{l}");
                            }
                            println!();
                            println!("  NOW the part nothing can do for you: ask them to read");
                            println!("  those four pairs back, on a call or in person -- not in");
                            println!("  the channel the line came through. If one word differs,");
                            println!("  it is not their key and somebody is in between.");
                            added = Some(name);
                        }
                        Err(e) => println!("\n  not added: {e}"),
                    }
                }
            }
        }
    } else {
        println!("  skipped. `gage add <name> <key>` when you have it.");
    }
    rule();

    // ---- 3. one handoff
    println!("Third, a handoff. This builds a signed bundle addressed to them.");
    if !yes("\n  send one now? [y/N] ") {
        println!("  skipped.");
        finish(added.as_deref());
        return Ok(());
    }
    let to = match added.clone() {
        Some(n) => {
            println!("\n  sending to {}", crate::manifest::one_line(&n));
            n
        }
        None => ask("\n  who to (a name on your list): ").unwrap_or_default(),
    };
    if to.is_empty() {
        println!("  no recipient -- skipping.");
        finish(added.as_deref());
        return Ok(());
    }
    let subject = {
        let s = ask("  subject: ").unwrap_or_default();
        if s.is_empty() {
            "hello from gage".to_string()
        } else {
            s
        }
    };
    let path = ask("  a file to send (empty writes a short note for you): ").unwrap_or_default();
    let out_dir = std::env::current_dir()?.join("gage-first-handoff");
    let file = if path.is_empty() {
        // An empty answer must not be a dead end: the point of this step is
        // that a first handoff completes.
        let tmp = std::env::temp_dir().join(format!("gage-hello-{}.md", std::process::id()));
        std::fs::write(&tmp, "Hello -- this is my first gage handoff.\n")?;
        println!("  (no file given, so sending a one-line note)");
        tmp
    } else {
        std::path::PathBuf::from(path)
    };

    let args = crate::outbound::SendArgs {
        to: vec![to.clone()],
        subject,
        out: Some(out_dir.clone()),
        file: vec![file],
        prompt: vec![],
        decision: vec![],
        memory: vec![],
        dir: vec![],
        allow_secrets: false,
        reply_to: None,
        msg_type: "share".to_string(),
        allow_findings: false,
        lan: false,
        agent: None,
        model: None,
        record_send: true,
    };
    let mut say = Vec::new();
    let sent = crate::outbound::send_bundle(args, &mut say);
    for l in &say {
        println!("{l}");
    }
    match sent {
        // The summary `send_bundle` collected is printed above, so this does
        // not restate where the bundle landed.
        Ok(_) => {
            println!();
            println!("  To get it to them, pick whichever you have:");
            println!(
                "    gage push {} --to {} --yes      (through a relay, if you joined one)",
                out_dir.display(),
                crate::manifest::shell_word(&to)
            );
            println!("    or hand that directory over any way you like -- a shared");
            println!("    folder, git, email. It is signed; the transport is not");
            println!("    trusted with anything.");
            println!();
            println!("  On their side, one command:  gage open <that directory>");
            println!("  which is where they see who signed it and that nothing");
            println!("  inside it carries any authority. That screen is the product.");
        }
        Err(e) => println!("\n  not sent: {e}"),
    }
    finish(added.as_deref());
    Ok(())
}

/// Pull a name and a key out of whatever was pasted: the whole
/// `gage add NAME KEY` line, a quoted name, or a bare key.
///
/// Shared with the viewer's paste path (`ui::parse_invite`) rather than
/// copied into it. Two parsers for one format drift, and the one that
/// drifts is the one a person is pasting an attacker's line into.
pub(crate) fn parse_add(s: &str) -> (Option<String>, Option<String>) {
    let looks_like_key = |t: &str| t.len() > 40 && t.contains('=');
    let rest = s
        .trim()
        .strip_prefix("gage add")
        .map(str::trim)
        .unwrap_or_else(|| s.trim());
    // A quoted name, which is what a derived two-word handle is printed as.
    if let Some(after) = rest.strip_prefix('\'')
        && let Some((name, tail)) = after.split_once('\'')
    {
        let key = tail.split_whitespace().find(|t| looks_like_key(t));
        return (Some(name.to_string()), key.map(str::to_string));
    }
    let toks: Vec<&str> = rest.split_whitespace().collect();
    let key = toks
        .iter()
        .find(|t| looks_like_key(t))
        .map(|t| t.to_string());
    let name = match (&key, toks.len()) {
        // `NAME KEY`, the unquoted single-word form.
        (Some(_), 2) if !looks_like_key(toks[0]) => Some(toks[0].to_string()),
        _ => None,
    };
    (name, key)
}

fn finish(added: Option<&str>) {
    rule();
    println!("That is the whole of it. Worth knowing:");
    // The page first, and named for what it does rather than what it is. It
    // opens on a checklist derived from this machine's own state, which is
    // the question somebody who has just finished this has -- "am I set up?"
    // -- and the list below is the terminal answer to a question they have
    // not asked yet.
    println!("  gage ui             a local page that says which steps are done");
    println!("  gage inbox          what is waiting, unread");
    println!("  gage open <dir>     read one, inside the trust frame");
    println!("  gage whoami         your line, and your word-pairs again");
    if added.is_none() {
        println!("  gage add <name> <key>   put someone on your list");
    }
    println!("\nThe full tour is in README.md; driving this from a script is in");
    println!("docs/agents.md.");
}

#[cfg(test)]
mod tests {
    use super::parse_add;

    const K: &str =
        "3cEWfCOaxNwnYWOgB2wAQ4FotbAFBwC12ta7GRcsde4=.l64eR5VCbVPJycmQft4DTbePRDrFaMa+bHfybn0QZxU=";

    #[test]
    fn a_pasted_add_line_is_taken_apart() {
        // The three shapes a person can plausibly paste.
        assert_eq!(
            parse_add(&format!("gage add alice {K}")),
            (Some("alice".into()), Some(K.into()))
        );
        // A derived handle, which `connect` prints quoted because it has a
        // space in it. This is the case that made the quoting necessary.
        assert_eq!(
            parse_add(&format!("gage add 'crisp beetle' {K}")),
            (Some("crisp beetle".into()), Some(K.into()))
        );
        assert_eq!(parse_add(K), (None, Some(K.into())));
        // And the shapes that are not a key at all.
        assert_eq!(parse_add("nonsense"), (None, None));
        assert_eq!(parse_add(""), (None, None));
    }
}
