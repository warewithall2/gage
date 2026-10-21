// The window. Route A: Gage in its own window with its own dock icon,
// rather than a tab in whatever browser happened to be default.
//
// It is deliberately thin. The page, the routes and every decision live in
// the gage binary and are served over loopback; this process holds a
// WKWebView pointed at that URL and nothing else. No bridge to native code,
// no injected script, no local file access -- so there is no new surface
// here to get wrong, and the browser path stays a working fallback rather
// than a second implementation.
//
// Built by packaging/macos/make-app.sh against an EXPLICITLY PINNED SDK.
// That is not fussiness: the Command Line Tools ship a Swift 6.1.2 compiler
// next to a MacOSX26 SDK built with Swift 6.2, and swiftc reaches for the
// newest SDK by default, which fails with "this SDK is not supported by the
// compiler". Nothing is missing when that happens and installing Xcode is
// not the fix -- naming the SDK is.

import Cocoa
import WebKit

// The URL comes from the launcher, which has already waited for the port to
// answer. Only loopback is accepted: this window exists to show this
// machine's own gage, and a bundle that could be pointed at an arbitrary
// origin would be a browser wearing the app's icon.
func loopbackURL(from args: [String]) -> URL? {
    guard let raw = args.dropFirst().first, let url = URL(string: raw) else { return nil }
    guard url.scheme == "http", let host = url.host else { return nil }
    guard host == "127.0.0.1" || host == "localhost" else { return nil }
    return url
}

class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    let url: URL
    var window: NSWindow!
    var web: WKWebView!

    init(url: URL) {
        self.url = url
        super.init()
    }

    func applicationDidFinishLaunching(_ note: Notification) {
        let config = WKWebViewConfiguration()
        web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = self

        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false)
        window.title = "Gage"
        // Below this the two-column layout stops being usable.
        window.minSize = NSSize(width: 720, height: 480)
        window.center()
        window.setFrameAutosaveName("GageMain")
        web.frame = window.contentView!.bounds
        web.autoresizingMask = [.width, .height]
        window.contentView!.addSubview(web)
        window.makeKeyAndOrderFront(nil)
        web.load(URLRequest(url: url))
        NSApp.activate(ignoringOtherApps: true)
    }

    // Closing the window quits, which runs the launcher's cleanup and stops
    // the services this app started. A window the user closed that leaves a
    // process in the dock is the behaviour the packaging brief asked to have
    // an explicit answer for.
    func applicationShouldTerminateAfterLastWindowClosed(_ app: NSApplication) -> Bool {
        return true
    }

    // Anything that is not this loopback page opens in the real browser
    // instead of inside the app. The page links outward (documentation, a
    // relay address someone pasted), and following those in here would turn
    // a one-page app into an unlabelled browser with no address bar.
    func webView(_ w: WKWebView,
                 decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let target = action.request.url else {
            decisionHandler(.cancel)
            return
        }
        if target.host == url.host && target.port == url.port && target.scheme == url.scheme {
            decisionHandler(.allow)
        } else {
            decisionHandler(.cancel)
            NSWorkspace.shared.open(target)
        }
    }

    // A loopback page that will not load means the services died under us.
    // Say so in the window rather than showing a blank rectangle.
    func webView(_ w: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        showFailure(error)
    }

    func webView(_ w: WKWebView,
                 didFailProvisionalNavigation navigation: WKNavigation!,
                 withError error: Error) {
        showFailure(error)
    }

    private func showFailure(_ error: Error) {
        let message = error.localizedDescription
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
        let html = """
            <html><head><meta name="viewport" content="width=device-width,initial-scale=1">
            <style>
              :root { color-scheme: light dark; }
              body { font: 15px -apple-system, system-ui, sans-serif; margin: 0;
                     display: flex; align-items: center; justify-content: center;
                     height: 100vh; background: Canvas; color: CanvasText; }
              div { max-width: 34em; padding: 2em; }
              h1 { font-size: 1.2em; }
              code { font-family: ui-monospace, monospace; }
            </style></head>
            <body><div>
            <h1>Gage is not answering on this machine</h1>
            <p>The local service stopped or never started. Quit Gage and open it again.</p>
            <p>From a terminal, <code>gage ui</code> shows what it says on start-up.</p>
            <p>\(message)</p>
            </div></body></html>
            """
        web.loadHTMLString(html, baseURL: nil)
    }
}

let app = NSApplication.shared
guard let url = loopbackURL(from: CommandLine.arguments) else {
    FileHandle.standardError.write(
        "usage: GageWindow http://127.0.0.1:<port>/  (loopback only)\n".data(using: .utf8)!)
    exit(2)
}
let delegate = AppDelegate(url: url)
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
