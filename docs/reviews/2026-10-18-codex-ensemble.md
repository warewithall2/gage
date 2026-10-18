I found one confirmed security issue: a remote party can make the relay hold its global state mutex during filesystem work.

In `/register`, the successful proof path serializes and writes the full owners map while holding the state lock:

> `let mut g = STATE.lock().unwrap();`  
> `let st = g.as_mut().unwrap();`  
> `let data = serde_json::to_vec_pretty(&st.owners).unwrap_or_default();`  
> `let _ = std::fs::write(path, data);`  
> — [src/relay.rs](/home/owenware/Projects/ctx/src/relay.rs:471), [src/relay.rs](/home/owenware/Projects/ctx/src/relay.rs:517)

The first leg of registration is unauthenticated, and the pending-claim cap is 10,000. An attacker can generate many claims, prove them by generating the matching box keys, and register many distinct mailboxes. Each registration grows `owners.json`; serializing and rewriting it under the global lock makes concurrent requests wait behind increasingly expensive disk work. This is a real remote denial-of-service path. There is no per-party mailbox cap: the registration check only rejects a box key already bound to a different signing key. The unauthenticated rate limit raises the cost but does not remove the issue.

The other points:

- **`owners.json` torn write:** real integrity weakness, but the destructive failure described is theoretical under ordinary remote attack. A kill or power loss during `fs::write` can leave invalid JSON, and startup silently turns that into an empty map at lines 227–230. A remote party can trigger registrations but cannot directly cause the process or host to be killed mid-write; this is primarily a crash/power-loss recovery risk.
- **`do_fetch` response size and lock:** the concern is real, but bounded by configured mailbox limits (default 64 MiB and 500 envelopes). It does hold the mutex while reading, building the JSON response, and writing it, so a full mailbox can stall other requests for a long time. That makes it a secondary availability issue, not unbounded memory growth.
- **`trust::add_contact`:** its `key` input is split and both key components are checked as 32-byte base64. Names are not validated inside `add_contact`, but the remote UI callers validate names before calling it, and the CLI caller is local. I did not find a demonstrated remote injection path through this function.

I did not find a remote mailbox-count limit in the reviewed code.
