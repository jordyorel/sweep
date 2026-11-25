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
    let intervalHours: UInt64?
    let lastRunUnix: UInt64?
    let alerts: [WatchAlert]
}

@MainActor @Observable
final class WatchModel {
    var installed = false
    /// Hours between checks when nothing changes (the agent also runs on every change of the launch folders).
    var intervalHours: UInt64?
    var lastRun: Date?
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
            intervalHours = s.intervalHours
            lastRun = s.lastRunUnix.map { Date(timeIntervalSince1970: TimeInterval($0)) }
            alerts = s.alerts
        } catch {
            self.error = error.localizedDescription
        }
    }

    static let frequencies: [UInt64] = [1, 6, 12, 24]

    /// Turn the watch on (with `everyHours`, default: current or 6) or off.
    func set(_ on: Bool, everyHours: UInt64? = nil) async {
        busy = true
        error = nil
        defer { busy = false }
        let hours = everyHours ?? intervalHours ?? 6
        do {
            _ = try await Self.output(on ? ["watch", "--install", "--every-hours", String(hours)] : ["watch", "--uninstall"])
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

/// Always visible at the bottom of the sidebar. Lives in the main window on purpose: content in popovers and
/// inspectors stopped updating in this app (the toolbar popover looked like the button vanished).
struct WatchSidebarRow: View {
    @Environment(WatchModel.self) private var watch

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Divider()
            HStack {
                Image(systemName: watch.recent.isEmpty ? "shield.lefthalf.filled" : "exclamationmark.shield.fill")
                    .foregroundStyle(watch.recent.isEmpty ? (watch.installed ? Color.green : .secondary) : .red)
                Text("Background watch")
                Spacer()
                if watch.busy { ProgressView().controlSize(.small) }
                Toggle("Background watch", isOn: Binding(get: { watch.installed }, set: { on in Task { await watch.set(on) } }))
                    .labelsHidden().toggleStyle(.switch).controlSize(.mini)
                    .disabled(watch.busy)
            }
            .padding(.horizontal, 12)
            Group {
                if !watch.recent.isEmpty {
                    Text("\(watch.recent.count) alert\(watch.recent.count == 1 ? "" : "s") this week: see the home screen")
                        .foregroundStyle(.red)
                } else if watch.installed {
                    HStack(spacing: 4) {
                        Menu {
                            ForEach(WatchModel.frequencies, id: \.self) { h in
                                Button { Task { await watch.set(true, everyHours: h) } } label: {
                                    Text(Self.label(h)) + Text(h == watch.intervalHours ? "  ✓" : "")
                                }
                            }
                        } label: {
                            Text("Every \(Self.label(watch.intervalHours ?? 6).lowercased())")
                        }
                        .menuStyle(.borderlessButton).fixedSize()
                        .help("Also runs right away whenever a launch agent or daemon is added or changed.")
                        Text("+ on every change").foregroundStyle(.secondary)
                    }
                    if let last = watch.lastRun {
                        (Text("Last check ") + Text(last, style: .relative) + Text(" ago")).foregroundStyle(.secondary)
                    } else {
                        Text("Not run yet").foregroundStyle(.secondary)
                    }
                } else {
                    Text("Off: turn on to be alerted about new launch items").foregroundStyle(.secondary)
                }
            }
            .font(.caption)
            .padding(.horizontal, 12)
            if let e = watch.error {
                Text(e).font(.caption).foregroundStyle(.red).padding(.horizontal, 12)
            }
        }
        .padding(.bottom, 8)
        .help("Checks launch agents and daemons whenever they change and on a schedule, and notifies you when a suspicious one appears.")
        .task {
            // Keep "last check" current while the app is open.
            while !Task.isCancelled {
                await watch.refresh()
                try? await Task.sleep(for: .seconds(60))
            }
        }
    }

    static func label(_ hours: UInt64) -> String {
        hours == 1 ? "Hour" : hours == 24 ? "Day" : "\(hours) hours"
    }
}

/// Recent alerts, on the home screen (shown when no app is selected).
struct WatchAlertsList: View {
    @Environment(WatchModel.self) private var watch

    var body: some View {
        if !watch.recent.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Label("Suspicious launch items (last 7 days)", systemImage: "exclamationmark.shield.fill")
                    .font(.headline).foregroundStyle(.red)
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(watch.recent) { a in AlertRow(alert: a) }
                    }
                }
                .frame(maxHeight: 240)
            }
            .padding(16)
            .background(Color.red.opacity(0.06))
        }
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
