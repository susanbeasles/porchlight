import AppKit
import SwiftUI

/// M2 status screen: is the extension running, and is it seeing processes. The full
/// plain-language activation flow is M8.
struct StatusView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Porchlight").font(.largeTitle).bold()

            GroupBox("Extension") {
                VStack(alignment: .leading, spacing: 6) {
                    row("Installation", model.activation)
                    row("Connected", (model.stats?.connected ?? false) ? "Yes" : "No")
                    row("State", stateText(model.stats?.extensionStatus?.state))
                    row("Streaming", (model.stats?.extensionStatus?.streaming ?? false) ? "Yes" : "No")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("Collection") {
                VStack(alignment: .leading, spacing: 6) {
                    row("Events recorded", "\(model.stats?.eventsIngested ?? 0)")
                    row("Programs running (seen)", "\(model.stats?.liveProcesses ?? 0)")
                    row("Missed events", droppedText(model.stats))
                    row("Exec changed pidversion", pidversionText(model.stats?.live))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack {
                Button("Install extension") { model.activate() }
                Button("Open Login Items & Extensions") {
                    open("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
                }
                Button("Open Full Disk Access") {
                    open("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
                }
            }

            if let error = model.coreError ?? model.stats?.lastError {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            }
            Spacer()
        }
        .padding(20)
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary).frame(width: 210, alignment: .leading)
            Text(value).monospacedDigit().textSelection(.enabled)
            Spacer()
        }
    }

    private func stateText(_ state: String?) -> String {
        switch state {
        case "running": return "Running"
        case "starting": return "Starting"
        case "not_permitted": return "Needs Full Disk Access"
        case "not_entitled": return "Not entitled (see docs/development.md)"
        case "not_privileged": return "Not running as root"
        case "too_many_clients": return "Too many security tools running"
        case .some(let other): return other
        case .none: return "Unknown"
        }
    }

    /// The end-to-end count is the headline: it catches loss anywhere between the kernel and
    /// the store. The causes are detail.
    private func droppedText(_ stats: AppStats?) -> String {
        guard let stats else { return "Unknown" }
        let missing = stats.endToEnd.missing + stats.drops.storeFailed
        if missing == 0 { return "None" }
        return "\(missing) (queue full: \(stats.drops.ringFull), app closed: \(stats.drops.appDisconnected), not saved: \(stats.drops.storeFailed))"
    }

    private func pidversionText(_ live: LiveStats?) -> String {
        guard let live, live.execs > 0 else { return "No exec seen yet" }
        return "\(live.execPidversionChanged) of \(live.execs)"
    }

    private func open(_ url: String) {
        if let u = URL(string: url) {
            NSWorkspace.shared.open(u)
        }
    }
}
