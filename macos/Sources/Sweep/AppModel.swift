import AppKit
import Observation

@MainActor @Observable
final class AppModel {
    var apps: [AppBundle] = []
    var search = ""
    var selectedApp: String?

    var report: Report?
    /// Paths the user wants removed. Starts as the scanner's default selection.
    var chosen: Set<String> = []

    var busy = false
    var error: String?
    /// Last removal, shown in a banner with an Undo button.
    var lastOutcome: Outcome?
    var undoMessage: String?
    /// Set when removal was refused because the app is running.
    var runningConflict: String?
    let hasFullDiskAccess = Core.hasFullDiskAccess()

    var filteredApps: [AppBundle] {
        search.isEmpty ? apps : apps.filter { $0.name.localizedCaseInsensitiveContains(search) || ($0.rawId ?? "").localizedCaseInsensitiveContains(search) }
    }

    var chosenSize: UInt64 {
        report?.findings.filter { isChosen($0) && !isImplied($0) }.reduce(0) { $0 + $1.size } ?? 0
    }

    var chosenCount: Int { report?.findings.filter { isChosen($0) }.count ?? 0 }

    func loadApps() async {
        apps = (try? await Task.detached { try Core.listApps() }.value) ?? []
    }

    func scan(_ path: String) async {
        busy = true
        error = nil
        report = nil
        defer { busy = false }
        do {
            let r = try await Task.detached { try Core.scan(path) }.value
            report = r
            chosen = Set(r.findings.filter(\.selected).map(\.path))
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Inside a folder that is already being removed: goes with it, cannot be unticked on its own.
    func isImplied(_ f: Finding) -> Bool {
        chosen.contains { $0 != f.path && f.path.hasPrefix($0 + "/") }
    }

    func isChosen(_ f: Finding) -> Bool { chosen.contains(f.path) || isImplied(f) }

    func toggle(_ f: Finding) {
        if chosen.contains(f.path) { chosen.remove(f.path) } else { chosen.insert(f.path) }
    }

    func remove(allowRunning: Bool = false) async {
        guard let r = report, chosenCount > 0 else { NSSound.beep(); return }
        busy = true
        error = nil
        defer { busy = false }
        let app = r.bundle.path
        let paths = Array(chosen)
        do {
            let out = try await Task.detached { try Core.remove(app, chosen: paths, allowRunning: allowRunning) }.value
            lastOutcome = out
            undoMessage = nil
            if !out.moved.isEmpty { NSSound(named: "Purr")?.play() }
            report = nil
            selectedApp = nil
            await loadApps()
        } catch {
            let msg = error.localizedDescription
            if msg.contains("is running") { runningConflict = msg } else { self.error = msg }
        }
    }

    func undo() async {
        busy = true
        defer { busy = false }
        let id = lastOutcome?.journal
        do {
            let u = try await Task.detached { try Core.undo(id) }.value
            var parts = ["Restored \(u.restored.count) item\(u.restored.count == 1 ? "" : "s")."]
            if !u.conflicts.isEmpty { parts.append("\(u.conflicts.count) kept in the Trash because something already exists at the original place.") }
            if !u.gone.isEmpty { parts.append("\(u.gone.count) no longer in the Trash.") }
            if !u.failed.isEmpty { parts.append("\(u.failed.count) failed: \(u.failed[0].reason)") }
            undoMessage = parts.joined(separator: " ")
            lastOutcome = nil
            await loadApps()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

enum Format {
    static func size(_ n: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
    }

    static func tilde(_ p: String) -> String {
        let home = NSHomeDirectory()
        return p.hasPrefix(home + "/") ? "~" + p.dropFirst(home.count) : p
    }

    static func category(_ c: String) -> String {
        switch c {
        case "bundle": "App"
        case "parent_folder": "Parent folder"
        case "application_support": "Application Support"
        case "group_containers": "Group Containers"
        case "application_scripts": "Application Scripts"
        case "saved_state": "Saved State"
        case "launch_agents": "Launch Agent"
        case "launch_daemons": "Launch Daemon"
        case "privileged_helpers": "Privileged Helper"
        case "crash_reports": "Crash Reports"
        case "web_data": "Web Data"
        default: c.prefix(1).uppercased() + c.dropFirst().replacingOccurrences(of: "_", with: " ")
        }
    }
}
