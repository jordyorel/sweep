// Background persistence watch: runs the bundled `sweep` CLI (Contents/Helpers/sweep), which owns the LaunchAgent.
import AppKit
import Observation
import SwiftUI

struct WatchAlert: Codable, Sendable, Identifiable {
    let timeUnix: UInt64
    let change: String
    let plist: String
    let label: String?
    let program: String?
    let risk: String
    let flags: [String]
    var id: String { "\(timeUnix)-\(plist)" }
}

private struct WatchStatus: Codable, Sendable {
    let installed: Bool
    let alerts: [WatchAlert]
}

@MainActor @Observable
final class WatchModel {
    var installed = false
    var alerts: [WatchAlert] = []
    var busy = false
    var error: String?

    /// Alerts from the last 7 days, newest first.
    var recent: [WatchAlert] {
        let cutoff = UInt64(Date().timeIntervalSince1970) - 7 * 86_400
        return alerts.filter { $0.timeUnix >= cutoff }.reversed()
    }

    private static var helper: URL { Foundation.Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/sweep") }

    func refresh() async {
        do {
            let s: WatchStatus = try await Self.run(["--json", "watch", "--status"])
            installed = s.installed
            alerts = s.alerts
        } catch {
            self.error = error.localizedDescription
        }
    }

    func set(_ on: Bool) async {
        busy = true
        error = nil
        defer { busy = false }
        do {
            _ = try await Self.output(["watch", on ? "--install" : "--uninstall"])
        } catch {
            self.error = error.localizedDescription
        }
        await refresh()
    }

    private static func run<T: Decodable & Sendable>(_ args: [String]) async throws -> T {
        let data = try await output(args)
        let dec = JSONDecoder()
        dec.keyDecodingStrategy = .convertFromSnakeCase
        return try dec.decode(T.self, from: data)
    }

    /// Run the helper off the main thread and return its stdout.
    private static func output(_ args: [String]) async throws -> Data {
        let url = helper
        return try await Task.detached {
            guard FileManager.default.isExecutableFile(atPath: url.path) else {
                throw CoreError(message: "the sweep helper is missing from the app bundle")
            }
            let p = Process()
            p.executableURL = url
            p.arguments = args
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            try p.run()
            let data = out.fileHandleForReading.readDataToEndOfFile()
            let errData = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            guard p.terminationStatus == 0 else {
                throw CoreError(message: String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
            }
            return data
        }.value
    }
}

struct WatchButton: View {
    @Environment(WatchModel.self) private var watch
    private let showing = State(initialValue: false) // no @State macro with the Command Line Tools

    var body: some View {
        Button { showing.wrappedValue = true } label: {
            Label("Watch", systemImage: watch.recent.isEmpty ? "shield.lefthalf.filled" : "exclamationmark.shield.fill")
                .foregroundStyle(watch.recent.isEmpty ? (watch.installed ? Color.green : .secondary) : .red)
        }
        .help(watch.installed ? "Background watch is on" : "Background watch is off")
        .popover(isPresented: showing.projectedValue, arrowEdge: .bottom) { WatchPanel() }
        .task { await watch.refresh() }
    }
}

struct WatchPanel: View {
    @Environment(WatchModel.self) private var watch

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Toggle(isOn: Binding(get: { watch.installed }, set: { on in Task { await watch.set(on) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Background watch").font(.headline)
                    Text("Checks launch agents and daemons whenever they change and every 6 hours, and notifies you when a suspicious one appears.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            .toggleStyle(.switch)
            .disabled(watch.busy)
            if let e = watch.error {
                Text(e).font(.caption).foregroundStyle(.red)
            }
            Divider()
            if watch.recent.isEmpty {
                Label("No alerts in the last 7 days", systemImage: "checkmark.shield").foregroundStyle(.secondary)
            } else {
                Text("Alerts (last 7 days)").font(.subheadline.weight(.semibold))
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(watch.recent) { a in AlertRow(alert: a) }
                    }
                }
                .frame(maxHeight: 260)
            }
        }
        .padding(14)
        .frame(width: 400)
        .task { await watch.refresh() }
    }
}

struct AlertRow: View {
    let alert: WatchAlert

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(alert.risk.uppercased()).font(.caption2.weight(.bold))
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(alert.risk == "high" ? Color.red.opacity(0.25) : Color.orange.opacity(0.25), in: Capsule())
                Text((alert.change == "new" ? "New: " : "Changed: ") + (alert.label ?? Format.tilde(alert.plist)))
                    .lineLimit(1).truncationMode(.middle)
            }
            ForEach(alert.flags, id: \.self) { f in
                Text("• " + f).font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Text(Date(timeIntervalSince1970: TimeInterval(alert.timeUnix)), style: .relative).font(.caption2).foregroundStyle(.tertiary)
                Spacer()
                Button("Show in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: alert.plist)])
                }
                .buttonStyle(.link).font(.caption)
            }
        }
        .textSelection(.enabled)
    }
}
