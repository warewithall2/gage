//! Per-service run records, so something outside gage can tell which services
//! are already serving *this* home.
//!
//! The desktop app needs to answer one question before it starts anything:
//! is `lan` (or `ui`, or `watch`) already running **for the home I resolved**?
//! Getting that wrong in either direction is a visible failure. Start a
//! duplicate and the second `ui` cannot bind its port, so the app reports
//! "could not start" while gage is running perfectly. Adopt the wrong one and
//! the app shows an identity that is not the user's, which is worse.
//!
//! The obvious place to look is the process table, and that is where this
//! started. It does not work. A process's argv says `gage lan` but not whose
//! home it serves, and the home lives in the environment, which **macOS will
//! not show you for another process** -- measured, not assumed: `ps eww -p
//! <pid>` and `ps eww -p <pid> -o command=` both return the command with no
//! environment on macOS 15. Linux answers through `/proc/<pid>/environ`, so an
//! implementation built and tested only on Linux passes and then fails on the
//! one platform the app ships to.
//!
//! So the record lives in the home instead, because **the home is the
//! identity**. A file under `<home>/run/` can only have been written by a
//! service started against that home, which makes "whose service is this"
//! answerable by looking at the right directory rather than by interrogating a
//! process.
//!
//! The file is a hint and the liveness check is authoritative. Nothing here
//! trusts a file to mean a service is up:
//!
//! - A service killed with a signal never runs `Drop`, so a stale record is
//!   normal, not exceptional. `running` treats a record whose process is gone
//!   as absent, which is what makes a crash self-healing instead of a state
//!   that needs clearing by hand.
//! - A dead service's pid can be reused by something unrelated. So a live pid
//!   is not enough: the process must also still *be* that gage service, which
//!   is checked from its argv. Argv is readable on both platforms; only the
//!   environment is not.
//!
//! This deliberately does not lock. An advisory lock held for the process
//! lifetime would make liveness exact, but it needs `flock`, which means a C
//! dependency this tree does not have and would not add for a convenience.

use std::path::{Path, PathBuf};

/// Where the records live. A directory rather than files loose in the home, so
/// a home listing still reads as the user's own data.
///
/// The home is a parameter all the way down, and only the two public wrappers
/// call `identity::home()`. That is not ceremony: `identity::home()` reads
/// process-global environment variables, and the first version of these tests
/// set `GAGE_HOME` to a fixture, which silently overrode the `CTX_HOME` the
/// seal tests set and broke five of them. Threading the path through means the
/// tests here touch no global state and cannot collide with anyone else's.
fn run_dir_in(home: &Path) -> PathBuf {
    home.join("run")
}

fn path_for_in(home: &Path, service: &str) -> PathBuf {
    run_dir_in(home).join(format!("{service}.pid"))
}

/// Where this home's record for `service` lives, so a message about a stale
/// one can name the file to delete rather than leaving the reader to find it.
pub fn path_for(service: &str) -> PathBuf {
    path_for_in(&crate::identity::home(), service)
}

/// The argv of a live process, or `None` if it is gone.
///
/// Linux first, because `/proc` costs nothing and needs no child process. The
/// `ps` fallback is for macOS, where argv *is* available even though the
/// environment is not -- which is the whole reason this module reads argv and
/// not the environment.
fn argv_of(pid: u32) -> Option<String> {
    let proc_path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    if let Ok(raw) = std::fs::read(&proc_path) {
        // NUL-separated. Join with spaces so one matcher serves both sources.
        return Some(
            raw.split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    let out = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Does this argv belong to the named gage service?
///
/// Matched on the subcommand following an executable whose name starts with
/// `gage` -- the binary has been called `ctx` and `countersign` in earlier
/// eras and a service from one of those is still that service, so the prefix
/// is checked rather than the whole name. A record is only ever consulted from
/// the home it sits in, so this does not have to identify the home as well.
fn argv_is_service(argv: &str, service: &str) -> bool {
    let mut parts = argv.split_whitespace();
    let Some(exe) = parts.next() else {
        return false;
    };
    let base = exe.rsplit('/').next().unwrap_or(exe);
    if !(base.starts_with("gage") || base.starts_with("ctx") || base.starts_with("countersign")) {
        return false;
    }
    parts.next() == Some(service)
}

/// Is `service` already running for this home?
///
/// False whenever the answer is not certain: no record, an unreadable or
/// malformed record, a process that has exited, or a pid now belonging to
/// something else. Erring toward "not running" means the caller starts a
/// service it did not need to rather than adopting a stranger's, and a
/// duplicate is a smaller failure than a wrong identity.
pub fn running(service: &str) -> bool {
    running_in(&crate::identity::home(), service)
}

fn running_in(home: &Path, service: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path_for_in(home, service)) else {
        return false;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return false;
    };
    if pid == 0 {
        return false;
    }
    // A process is not the thing already running instead of itself. Without
    // this, a record holding our own pid -- which a container restarted on
    // the same volume produces, since it comes back as pid 1 and writes 1 --
    // reports the starting process as the one already serving.
    if pid == std::process::id() {
        return false;
    }
    match argv_of(pid) {
        Some(argv) => argv_is_service(&argv, service),
        None => false,
    }
}

/// A service's claim on this home, released when dropped.
///
/// Held by value for the lifetime of the service so the record disappears on a
/// normal exit, including a panic unwind. A signal skips `Drop` and leaves the
/// record behind on purpose: `running` is what decides, and it reads a stale
/// record as absent.
pub struct RunFile {
    path: PathBuf,
}

impl RunFile {
    /// Record that this process is serving `service` for this home.
    ///
    /// Best effort by design. A home on a read-only mount, or one this user
    /// cannot write, must not stop the service from running -- the record is
    /// an optimisation for a second process, never a precondition for this
    /// one. The caller gets `None` and carries on.
    pub fn claim(service: &str) -> Option<RunFile> {
        Self::claim_in(&crate::identity::home(), service)
    }

    fn claim_in(home: &Path, service: &str) -> Option<RunFile> {
        // Never take a record that belongs to a live process of this
        // service. A start that is about to fail -- a second `gage ui` on a
        // port already bound -- used to overwrite the running server's
        // record on the way past, and then delete it on the way out. The
        // server kept serving with no record, so the macOS launcher's
        // adoption check and the viewer's background-pull check both went on
        // believing nothing was running. Measured, not theorised: it is what
        // happened the first time the warning below was tested.
        if running_in(home, service) {
            return None;
        }
        let dir = run_dir_in(home);
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join(format!("{service}.pid"));
        std::fs::write(&path, format!("{}\n", std::process::id())).ok()?;
        Some(RunFile { path })
    }
}

impl Drop for RunFile {
    fn drop(&mut self) {
        // Only if it is still ours. Belt to `claim_in`'s braces: whatever
        // else has happened to the file in between, this process removes a
        // record only while that record names this process.
        let mine = std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
            == Some(std::process::id());
        if mine {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disposable home per test, passed explicitly. Nothing here sets an
    /// environment variable, so these tests cannot disturb -- or be disturbed
    /// by -- any other test in the binary.
    fn fixture_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gage-runfile-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // A record holding the pid of the process doing the asking must not be
    // read as "something else is already running". A container restarted on
    // the same volume comes back as pid 1, writes 1, and then matches its
    // own stale record. While the caller refused a start rather than warning
    // about one, that made gage unstartable with no way out but deleting a
    // file nobody had been told about.
    #[test]
    fn a_record_holding_our_own_pid_is_not_something_else_running() {
        let home = fixture_home("own-pid");
        std::fs::create_dir_all(home.join("run")).unwrap();
        std::fs::write(
            home.join("run").join("ui.pid"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        assert!(
            !running_in(&home, "ui"),
            "a process reported itself as the one already serving"
        );
    }

    #[test]
    fn a_claim_is_written_and_removed_again() {
        let home = fixture_home("claim");
        let p = home.join("run/lan.pid");
        {
            let _claim = RunFile::claim_in(&home, "lan").expect("the home is writable");
            assert!(p.exists(), "the record was not written");
            assert_eq!(
                std::fs::read_to_string(&p).unwrap().trim(),
                std::process::id().to_string()
            );
        }
        assert!(!p.exists(), "dropping the claim left the record behind");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The case that makes a crash recoverable without anyone clearing state:
    /// a record naming a pid that is gone must read as absent, not as running.
    #[test]
    fn a_record_for_a_dead_process_is_not_running() {
        let home = fixture_home("dead");
        std::fs::create_dir_all(home.join("run")).unwrap();
        // Spawn and reap, so the pid is known to be finished rather than
        // guessed at. A hardcoded "unlikely" pid is a test that passes until
        // the day it does not.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        std::fs::write(home.join("run/lan.pid"), format!("{pid}\n")).unwrap();
        assert!(
            !running_in(&home, "lan"),
            "a dead pid was reported as a running service"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Pid reuse. The record names a process that is very much alive -- this
    /// test binary -- which is not a gage service, so the argv check has to
    /// reject it. Without that check this is how the app adopts something that
    /// merely inherited a number.
    #[test]
    fn a_live_pid_that_is_not_the_service_is_not_running() {
        let home = fixture_home("reuse");
        std::fs::create_dir_all(home.join("run")).unwrap();
        std::fs::write(home.join("run/ui.pid"), format!("{}\n", std::process::id())).unwrap();
        assert!(
            !running_in(&home, "ui"),
            "a live pid belonging to something else was reported as the service"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn no_record_means_not_running() {
        let home = fixture_home("absent");
        assert!(!running_in(&home, "watch"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_malformed_record_is_not_running() {
        let home = fixture_home("junk");
        std::fs::create_dir_all(home.join("run")).unwrap();
        for junk in ["", "   ", "not-a-pid", "0", "-1", "99999999999999999999"] {
            std::fs::write(home.join("run/lan.pid"), junk).unwrap();
            assert!(
                !running_in(&home, "lan"),
                "a record of {junk:?} was read as running"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Each service answers for itself. A running `lan` must not make `ui`
    /// look up, or the app would skip starting the one thing it came for.
    #[test]
    fn one_services_record_says_nothing_about_another() {
        let home = fixture_home("perservice");
        let _claim = RunFile::claim_in(&home, "lan").unwrap();
        assert!(!home.join("run/ui.pid").exists());
        assert!(!running_in(&home, "ui"), "lan's record answered for ui");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Two homes, one machine. A service running for another identity must not
    /// show up here -- this is the whole reason the record lives in the home.
    #[test]
    fn a_record_in_another_home_is_invisible() {
        let mine = fixture_home("mine");
        let theirs = fixture_home("theirs");
        let _claim = RunFile::claim_in(&theirs, "lan").unwrap();
        assert!(
            !running_in(&mine, "lan"),
            "another home's running service was reported as mine"
        );
        let _ = std::fs::remove_dir_all(&mine);
        let _ = std::fs::remove_dir_all(&theirs);
    }

    #[test]
    fn argv_matching_is_about_the_subcommand_not_a_substring() {
        // The eras of the binary's name, all still that service.
        assert!(argv_is_service("/usr/local/bin/gage lan --port 7791", "lan"));
        assert!(argv_is_service("gage lan", "lan"));
        assert!(argv_is_service("/home/o/.local/bin/ctx lan", "lan"));
        assert!(argv_is_service("countersign watch --every 120", "watch"));
        // Not this service.
        assert!(!argv_is_service("gage ui --port 7777", "lan"));
        // The word appears, but not as the subcommand. A naive `contains`
        // would call each of these a running service.
        assert!(!argv_is_service("gage send --file lan", "lan"));
        assert!(!argv_is_service("gage open /tmp/lan", "lan"));
        assert!(!argv_is_service("vim src/lan.rs", "lan"));
        assert!(!argv_is_service("grep lan src/main.rs", "lan"));
        // Something else entirely that happens to take the same subcommand.
        assert!(!argv_is_service("/usr/bin/other lan", "lan"));
        assert!(!argv_is_service("", "lan"));
    }
}
