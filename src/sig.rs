//! `signal(2)`, declared once for the whole crate.
//!
//! It used to be declared twice, in `main.rs` and in `lan.rs`, with
//! incompatible handler types -- one `usize`, one `extern "C" fn(i32)` --
//! because one call restores a default and the other installs a handler. That
//! worked only because both are pointer-sized on this target, and
//! `clashing_extern_declarations` was right to complain: two declarations of
//! one symbol with different types is the kind of thing that stays harmless
//! until a target or a compiler version disagrees.
//!
//! The handler is `usize`, which is what C's `sighandler_t` actually is in
//! practice and what the `libc` crate uses for it. Not
//! `Option<extern "C" fn(i32)>`, which looks tidier and is wrong for this
//! function: the special values are `SIG_DFL` (0), `SIG_IGN` (1) and
//! `SIG_ERR` (-1), and only the first is a null pointer. `signal` also
//! *returns* the previous disposition, so a function-pointer return type
//! would have us constructing a value of 1 or -1 as though it were a function
//! -- which nothing here would call, but which is a worse thing to have
//!  written down than a cast at the one site that installs a handler.
//!
//! Declared by hand rather than taking a `libc` dependency, as before: this
//! is two constants and one function, and the whole crate's other seven
//! dependencies are cryptographic primitives.

#![cfg(unix)]

pub const SIGINT: i32 = 2;
pub const SIGPIPE: i32 = 13;

/// `SIG_DFL`: the default disposition for the signal.
const SIG_DFL: usize = 0;

unsafe extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
}

/// Restore the default disposition, so the next occurrence does what it would
/// have done if nothing had ever been installed.
pub fn restore_default(sig: i32) {
    // The previous disposition is returned and deliberately dropped: neither
    // caller has anything to restore it to, and `SIG_ERR` would only tell us
    // a signal number was invalid, which these are not.
    unsafe { signal(sig, SIG_DFL) };
}

/// Install a handler. The cast is what `sighandler_t` being an integer costs,
/// and it is confined to this one line.
pub fn install(sig: i32, handler: extern "C" fn(i32)) {
    unsafe { signal(sig, handler as usize) };
}
