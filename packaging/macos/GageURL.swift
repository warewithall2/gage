// The two decisions the window makes about URLs, in a file with no AppKit in
// it, so a test can compile and run them without a window server.
//
// They were inline in GageApp.swift, which also holds the top-level
// `app.run()` -- so nothing could link them, and the only coverage was a
// person opening the app and looking. Both are security decisions: one keeps
// the bundle from becoming a browser pointed anywhere, the other keeps a
// link on the page from navigating a chromeless window off-origin.

import Foundation

/// The URL the launcher passes, accepted only when it is this machine's own
/// loopback http. A bundle that could be pointed at an arbitrary origin
/// would be a browser wearing the app's icon, with no address bar to say so.
public func loopbackURL(from args: [String]) -> URL? {
    guard let raw = args.dropFirst().first, let url = URL(string: raw) else { return nil }
    guard url.scheme == "http", let host = url.host else { return nil }
    guard host == "127.0.0.1" || host == "localhost" else { return nil }
    return url
}

/// Whether a navigation stays inside the window. Only the exact origin the
/// window was opened on does; everything else is handed to the real browser,
/// where the address bar is.
///
/// `port` is compared as the URL reports it, which is nil for a default
/// port -- and http's default is 80, never a gage port, so a nil on one side
/// and 80 on the other cannot name the same service here.
public func staysInWindow(_ target: URL, origin: URL) -> Bool {
    return target.host == origin.host
        && target.port == origin.port
        && target.scheme == origin.scheme
}
