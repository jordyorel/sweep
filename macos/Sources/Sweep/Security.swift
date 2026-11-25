// Security section: launch-item audit and on-demand XProtect scans of a folder.
import AppKit
import Observation
import SwiftUI

enum SecurityPage: String, CaseIterable, Identifiable {
    case launchItems = "Launch Items"
    case malwareScan = "Malware Scan"
    var id: String { rawValue }
    var icon: String { self == .launchItems ? "gearshape.2" : "magnifyingglass.circle" }
}

@MainActor @Observable
final class SecurityModel {
    var page: SecurityPage? = .launchItems

    // Launch items
    var jobs: [LaunchJob] = []
    var auditing = false
    var auditedAt: Date?
    var showAllJobs = false

    // Folder scan
    var scanning = false
    var scanTarget: String?
    var progress: UInt64 = 0
    var scan: FolderScan?

    var error: String?
    /// Last move to the Trash from this section, with Undo.
    var outcome: Outcome?
    var undoMessage: String?

    var flaggedJobs: [LaunchJob] { jobs.filter { $0.risk != "info" } }
    var visibleJobs: [LaunchJob] { showAllJobs ? jobs : flaggedJobs }

    func audit() async {
        auditing = true
        error = nil
        defer { auditing = false }
        do {
            jobs = try await Task.detached { try Core.persistence() }.value
            auditedAt = Date()
        } catch {
            self.error = error.localizedDescription
        }
    }

    init() {
        // Dev hook: `--scan-folder <path>` opens the Malware Scan page and scans it (checked by screenshot).
        let args = ProcessInfo.processInfo.arguments
        if let i = args.firstIndex(of: "--scan-folder"), i + 1 < args.count {
            page = .malwareScan
            let p = args[i + 1]
            Task { await scanFolder(p) }
        }
    }

    func scanFolder(_ path: String) async {
        scanning = true
        scanTarget = path
        scan = nil
        error = nil
        progress = 0
        let token = Core.beginFolderScan()
        let poll = Task {
            while !Task.isCancelled {
                progress = Core.folderScanProgress()
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        defer {
            poll.cancel()
            scanning = false
        }
        do {
            scan = try await Task.detached { try Core.scanFolder(path, token: token) }.value
        } catch {
            self.error = error.localizedDescription
        }
    }

    func cancelScan() { Core.cancelFolderScan() }

    func trash(kind: String, paths: [String]) async {
        error = nil
        do {
            let out = try await Task.detached { try Core.trashFindings(kind: kind, paths: paths) }.value
            outcome = out
            undoMessage = nil
            await refreshAfterChange()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func undo() async {
        guard let id = outcome?.journal else { return }
        do {
            let u = try await Task.detached { try Core.undo(id) }.value
            undoMessage = "Restored \(u.restored.count) item\(u.restored.count == 1 ? "" : "s")."
                + (u.conflicts.isEmpty ? "" : " \(u.conflicts.count) kept in the Trash (something already exists there).")
            outcome = nil
            await refreshAfterChange()
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func refreshAfterChange() async {
        if !jobs.isEmpty { await audit() }
        if let s = scan { await scanFolder(s.path) }
    }

    static func chooseFolder() -> String? {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Scan"
        panel.message = "Choose a folder or file to scan with Apple's XProtect signatures"
        return panel.runModal() == .OK ? panel.url?.path : nil
    }
}

/// Sidebar content in Security mode.
struct SecuritySidebar: View {
    @Environment(SecurityModel.self) private var sec

    var body: some View {
        List(SecurityPage.allCases, selection: Binding(get: { sec.page }, set: { sec.page = $0 })) { p in
            HStack {
                Label(p.rawValue, systemImage: p.icon)
                Spacer()
                if p == .launchItems, !sec.flaggedJobs.isEmpty {
                    Text("\(sec.flaggedJobs.count)").font(.caption.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Color.orange.opacity(0.3), in: Capsule())
                }
            }
            .padding(.vertical, 4)
            .tag(p)
        }
    }
}

/// Detail content in Security mode.
struct SecurityDetail: View {
    @Environment(SecurityModel.self) private var sec

    var body: some View {
        VStack(spacing: 0) {
            if let e = sec.error {
                Banner(icon: "exclamationmark.triangle", tint: .red, text: e) { Button("Dismiss") { sec.error = nil } }
            }
            if let o = sec.outcome {
                Banner(icon: "trash", tint: .accentColor, text: summary(o)) {
                    if o.journal != nil { Button("Undo") { Task { await sec.undo() } } }
                    Button("Dismiss") { sec.outcome = nil }
                }
            }
            if let m = sec.undoMessage {
                Banner(icon: "arrow.uturn.backward", tint: .green, text: m) { Button("Dismiss") { sec.undoMessage = nil } }
            }
            switch sec.page ?? .launchItems {
            case .launchItems: LaunchItemsView()
            case .malwareScan: MalwareScanView()
            }
        }
    }

    private func summary(_ o: Outcome) -> String {
        var s = "Moved \(o.moved.count) item\(o.moved.count == 1 ? "" : "s") to the Trash."
        if !o.needsPrivileges.isEmpty { s += " \(o.needsPrivileges.count) need admin rights and were left in place (not supported yet)." }
        if !o.failed.isEmpty { s += " \(o.failed.count) failed: \(o.failed[0].reason)" }
        return s
    }
}

struct LaunchItemsView: View {
    @Environment(SecurityModel.self) private var sec

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Launch Items").font(.title2.weight(.semibold))
                    Text("Programs macOS starts on its own (launch agents and daemons). Malware uses them to come back after a restart.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("Show all", isOn: Binding(get: { sec.showAllJobs }, set: { sec.showAllJobs = $0 }))
                    .toggleStyle(.checkbox)
                Button { Task { await sec.audit() } } label: { Label("Check Again", systemImage: "arrow.clockwise") }
                    .disabled(sec.auditing)
            }
            .padding(14)
            Divider()
            if sec.auditing && sec.jobs.isEmpty {
                ProgressView("Checking launch items…").frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if sec.visibleJobs.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield").font(.system(size: 40, weight: .light)).foregroundStyle(.green)
                    Text("No launch item with red flags").font(.title3)
                    Text("\(sec.jobs.count) launch items checked. Tick “Show all” to see them.").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(sec.visibleJobs) { j in LaunchJobRow(job: j) }
            }
            Divider()
            HStack {
                if let t = sec.auditedAt {
                    (Text("Checked ") + Text(t, style: .relative) + Text(" ago")).foregroundStyle(.secondary)
                }
                if sec.auditing { ProgressView().controlSize(.small) }
                Spacer()
                Text("\(sec.jobs.count) launch items · \(sec.flaggedJobs.count) with red flags").foregroundStyle(.secondary)
            }
            .font(.callout)
            .padding(10)
        }
        .task { if sec.jobs.isEmpty { await sec.audit() } }
    }
}

struct LaunchJobRow: View {
    @Environment(SecurityModel.self) private var sec
    let job: LaunchJob
    private let confirming = State(initialValue: false) // no @State macro with the Command Line Tools

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            RiskTag(risk: job.risk)
            VStack(alignment: .leading, spacing: 3) {
                Text(job.label ?? (job.plist as NSString).lastPathComponent).font(.body.weight(.medium))
                Text(Format.tilde(job.plist)).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if let p = job.program {
                    Text("runs " + Format.tilde(p)).font(.caption).lineLimit(1).truncationMode(.middle)
                }
                Text(signer).font(.caption).foregroundStyle(.secondary)
                ForEach(job.flags, id: \.self) { f in
                    Text("• " + f).font(.caption).foregroundStyle(job.risk == "high" ? .red : .orange)
                }
                ForEach(job.detections, id: \.rule) { d in
                    Text("• XProtect: " + d.rule).font(.caption.weight(.semibold)).foregroundStyle(.red)
                }
                Text(job.daemon ? "System daemon (runs as root)" : "Agent (runs as you)")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            Spacer()
            if isOwn {
                Text("Sweep").font(.caption).foregroundStyle(.secondary)
            } else {
            VStack(alignment: .trailing, spacing: 6) {
                Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: job.plist)]) }
                Button("Move to Trash", role: .destructive) { confirming.wrappedValue = true }
                    .confirmationDialog("Move \(job.label ?? "this launch item") to the Trash?", isPresented: confirming.projectedValue) {
                        Button("Move to Trash", role: .destructive) { Task { await sec.trash(kind: "launch_item", paths: [job.plist]) } }
                    } message: {
                        Text("It is stopped first and will not start again. You can put it back with Undo. Only its plist is moved: check the program it runs too.")
                    }
            }
            .controlSize(.small)
            }
        }
        .padding(.vertical, 4)
        .textSelection(.enabled)
    }

    /// Sweep's own watch agent: shown, but not offered for removal (use the sidebar switch).
    private var isOwn: Bool {
        job.plist.hasSuffix("/LaunchAgents/dev.sweep.watch.plist")
            && job.program == Foundation.Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/sweep").path
    }

    private var signer: String {
        guard let s = job.signature else { return "program not found or not checked" }
        if s.apple { return "Signed by Apple" }
        if s.adhoc { return "Ad-hoc signature (no developer identity)" }
        return s.authority.first.map { "Signed by " + $0 } ?? "Not signed"
    }
}

struct RiskTag: View {
    let risk: String

    var body: some View {
        Text(risk.uppercased())
            .font(.caption2.weight(.bold))
            .frame(width: 58)
            .padding(.vertical, 2)
            .background(color.opacity(0.25), in: Capsule())
            .foregroundStyle(color)
    }

    private var color: Color {
        switch risk {
        case "high": .red
        case "medium": .orange
        case "low": .yellow
        default: .secondary
        }
    }
}

struct MalwareScanView: View {
    @Environment(SecurityModel.self) private var sec
    private let confirming = State(initialValue: false)

    private var downloads: String { FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first?.path ?? NSHomeDirectory() + "/Downloads" }

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Malware Scan").font(.title2.weight(.semibold))
                    Text("Checks files against Apple's XProtect signatures, on demand. This is not real-time protection.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if sec.scanning {
                    Button("Stop") { sec.cancelScan() }
                } else {
                    Button { Task { await sec.scanFolder(downloads) } } label: { Label("Scan Downloads", systemImage: "arrow.down.circle") }
                    Button { if let p = SecurityModel.chooseFolder() { Task { await sec.scanFolder(p) } } } label: {
                        Label("Choose…", systemImage: "folder")
                    }
                }
            }
            .padding(14)
            Divider()
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    @ViewBuilder private var content: some View {
        if sec.scanning {
            VStack(spacing: 10) {
                ProgressView()
                Text("Scanning \(Format.tilde(sec.scanTarget ?? ""))…")
                Text("\(sec.progress) items checked").monospacedDigit().foregroundStyle(.secondary)
            }
        } else if let s = sec.scan, s.summary.filesScanned == 0, s.summary.detections.isEmpty, let err = s.summary.errors.first {
            VStack(spacing: 10) {
                Image(systemName: "questionmark.folder").font(.system(size: 44, weight: .light)).foregroundStyle(.orange)
                Text("Nothing could be scanned").font(.title3)
                Text(err).foregroundStyle(.secondary).textSelection(.enabled)
                Text("Check that it still exists. For protected folders, give Sweep Full Disk Access.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        } else if let s = sec.scan {
            let sum = s.summary
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Image(systemName: sum.detections.isEmpty ? "checkmark.shield.fill" : "xmark.shield.fill")
                        .font(.system(size: 32)).foregroundStyle(sum.detections.isEmpty ? Color.green : .red)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(sum.detections.isEmpty ? "No known malware found" : "\(sum.detections.count) file\(sum.detections.count == 1 ? "" : "s") match known malware")
                            .font(.title3.weight(.semibold))
                        Text("\(Format.tilde(s.path)) · \(sum.filesScanned) files scanned, \(sum.filesSkipped) skipped (empty or over 128 MB) · XProtect \(s.xprotectVersion)"
                             + (sum.cancelled ? " · stopped before the end" : "")
                             + (sum.errors.isEmpty ? "" : " · \(sum.errors.count) unreadable"))
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if !sum.detections.isEmpty {
                        Button("Move All to Trash", role: .destructive) { confirming.wrappedValue = true }
                            .confirmationDialog("Move \(Set(sum.detections.map(\.path)).count) files to the Trash?", isPresented: confirming.projectedValue) {
                                Button("Move to Trash", role: .destructive) {
                                    Task { await sec.trash(kind: "malware", paths: Array(Set(sum.detections.map(\.path)))) }
                                }
                            } message: { Text("You can put them back with Undo.") }
                    }
                }
                if !sum.detections.isEmpty {
                    List(sum.detections, id: \.path) { d in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(Format.tilde(d.path)).lineLimit(1).truncationMode(.middle)
                            Text(d.rule + (d.description.map { " · " + $0 } ?? "")).font(.caption).foregroundStyle(.red)
                        }
                        .contextMenu {
                            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: d.path)]) }
                        }
                    }
                }
                if sum.errors.count > 0 && sum.detections.isEmpty && !sec.scanning {
                    Text("Some files could not be read. Giving Sweep Full Disk Access lets it scan everything.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(16)
        } else {
            VStack(spacing: 10) {
                Image(systemName: "magnifyingglass.circle").font(.system(size: 44, weight: .light)).foregroundStyle(.secondary)
                Text("Scan your Downloads, a disk image, or any folder").font(.title3)
                Text("Uses the malware signatures Apple ships with macOS. Nothing leaves your Mac.").foregroundStyle(.secondary)
            }
        }
    }
}
