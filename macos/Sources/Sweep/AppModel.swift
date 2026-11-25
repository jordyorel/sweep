import AppKit
import Observation

enum Section: String, CaseIterable { case apps = "Apps", security = "Security" }

@MainActor @Observable
final class AppModel {
    var section: Section = ProcessInfo.processInfo.arguments.contains("--security") ? .security : .apps
    var apps: [AppBundle] = []
    var search = ""
    var selectedApp: String?

    var report: Report?
    /// Paths the user wants removed. Starts as the scanner's default selection.
    var chosen: Set<String> = []

    /// Security check of the selected app, run in the background while the leftovers are shown.
    var check: AppCheck?
    var checkError: String?
    var checking = false
    var showCheckDetails = false
    private var checkPath: String?

    var busy = false
    var error: String?
    /// Last removal, shown in a banner with an Undo button.
    var lastOutcome: Outcome?
    /// App of the last removal, and the undo journal covering it (also set when only the administrator part moved
    /// something).
    private var lastApp: String?
    private var undoJournal: String?
    /// Result of the administrator part of the last removal.
    var privilegedMessage: String?
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
        startCheck(path)
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

    private func startCheck(_ path: String) {
        check = nil
        checkError = nil
        showCheckDetails = false
        checking = true
        checkPath = path
        let token = Core.beginCheck() // makes the previous app's check stop
        Task {
            let result = await Task.detached { Result { try Core.check(path, token: token) } }.value
            guard checkPath == path else { return } // the user moved on
            checking = false
            switch result {
            case .success(let c): check = c
            case .failure(let e): checkError = e.localizedDescription
            }
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
            lastApp = app
            undoJournal = out.journal
            privilegedMessage = nil
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

    /// Move the items the last removal could not (owned by root) behind macOS's administrator prompt.
    func removeWithPassword() async {
        guard let out = lastOutcome, !out.needsPrivileges.isEmpty else { return }
        busy = true
        error = nil
        defer { busy = false }
        let app = lastApp
        let paths = out.needsPrivileges.map(\.path)
        let journal = undoJournal
        do {
            let r = try await Task.detached { try Core.trashPrivileged(kind: "leftovers", app: app, paths: paths, journal: journal) }.value
            undoJournal = r.journal ?? undoJournal
            var msg = "Moved \(r.response.moved.count) system item\(r.response.moved.count == 1 ? "" : "s") to the Trash with administrator rights."
            if !r.response.failed.isEmpty { msg += " \(r.response.failed.count) failed: \(r.response.failed[0].reason)" }
            privilegedMessage = msg
            if !r.response.moved.isEmpty { NSSound(named: "Purr")?.play() }
            // The banner no longer offers the password button: those items are handled.
            lastOutcome = Outcome(journal: undoJournal, moved: out.moved + r.response.moved, missing: out.missing,
                                  needsPrivileges: [], failed: out.failed + r.response.failed)
        } catch {
            let msg = error.localizedDescription
            self.error = msg == "cancelled" ? nil : msg
        }
    }

    func undo() async {
        busy = true
        defer { busy = false }
        let id = undoJournal ?? lastOutcome?.journal
        do {
            let u = try await Task.detached { try Core.undo(id) }.value
            var restored = u.restored.count
            var failed = u.failed.map(\.reason)
            if !u.needsPrivileges.isEmpty {
                // Items moved with the administrator password: macOS asks for it again.
                let journal = u.journal
                do {
                    let r = try await Task.detached { try Core.undoPrivileged(journal) }.value
                    restored += r.restored.count
                    failed += r.failed.map(\.reason)
                } catch {
                    let msg = error.localizedDescription
                    failed.append(msg == "cancelled" ? "system items left in the Trash (password cancelled)" : msg)
                }
            }
            var parts = ["Restored \(restored) item\(restored == 1 ? "" : "s")."]
            if !u.conflicts.isEmpty { parts.append("\(u.conflicts.count) kept in the Trash because something already exists at the original place.") }
            if !u.gone.isEmpty { parts.append("\(u.gone.count) no longer in the Trash.") }
            if !failed.isEmpty { parts.append("\(failed.count) failed: \(failed[0])") }
            undoMessage = parts.joined(separator: " ")
            lastOutcome = nil
            privilegedMessage = nil
            await loadApps()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

enum Format {
    /// "6 min ago", "2 hr ago": coarser than SwiftUI's `.relative` style ("6 min, 32 sec").
    static func ago(_ d: Date, now: Date = Date()) -> String {
        if now.timeIntervalSince(d) < 60 { return "just now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: d, relativeTo: now)
    }

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
