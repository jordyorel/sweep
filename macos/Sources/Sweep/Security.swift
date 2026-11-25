// Security section: launch-item audit and on-demand XProtect scans of a folder.
import AppKit
import Observation
import SwiftUI

enum SecurityPage: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case launchItems = "Launch Items"
    case malwareScan = "Malware Scan"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: "shield.lefthalf.filled"
        case .launchItems: "power"
        case .malwareScan: "magnifyingglass"
        }
    }
}

@MainActor @Observable
final class SecurityModel {
    var page: SecurityPage? = .overview

    // Launch items
    var jobs: [LaunchJob] = []
    var auditing = false
    var auditedAt: Date?
    /// Launch items without red flags are grouped and collapsed by default.
    var showTrusted = false
    /// Launch items whose details are expanded.
    var expanded: Set<String> = []

    // Folder scan
    var scanning = false
    var scanTarget: String?
    var progress: UInt64 = 0
    var scan: FolderScan?
    var scannedAt: Date?
    /// Detections moved to the Trash since the scan (put back in the list if the move is undone).
    private var removedDetections: [Detection] = []

    var error: String?
    /// Last move to the Trash from this section, with Undo.
    var outcome: Outcome?
    var undoMessage: String?

    var flaggedJobs: [LaunchJob] { jobs.filter { $0.risk != "info" } }
    var trustedJobs: [LaunchJob] { jobs.filter { $0.risk == "info" } }
    var detections: Int { scan?.summary.detections.count ?? 0 }
    /// Items that need the user's attention across the section.
    var issues: Int { flaggedJobs.count + detections }

    func toggle(_ job: LaunchJob) {
        if expanded.contains(job.id) { expanded.remove(job.id) } else { expanded.insert(job.id) }
    }

    func audit() async {
        auditing = true
        error = nil
        defer { auditing = false }
        do {
            jobs = try await Task.detached { try Core.persistence() }.value
            auditedAt = Date()
            // Dev hook: `--expand` opens every card and the "Looks normal" group (checked by screenshot).
            if ProcessInfo.processInfo.arguments.contains("--expand") {
                showTrusted = true
                expanded = Set(jobs.prefix(2).map(\.id))
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    init() {
        // Dev hooks (checked by screenshot): `--security-page <name>`, `--scan-folder <path>`, `--scan-preset quick|full`.
        let args = ProcessInfo.processInfo.arguments
        if let i = args.firstIndex(of: "--security-page"), i + 1 < args.count {
            page = SecurityPage.allCases.first { $0.rawValue.lowercased().hasPrefix(args[i + 1].lowercased()) }
        }
        if let i = args.firstIndex(of: "--scan-folder"), i + 1 < args.count {
            page = .malwareScan
            let p = args[i + 1]
            Task { await scanFolder(p) }
        }
        if let i = args.firstIndex(of: "--scan-preset"), i + 1 < args.count {
            page = .malwareScan
            let p = args[i + 1]
            Task { await scanPreset(p) }
        }
    }

    /// What the last scan was, for "Scan Again".
    private enum LastScan { case folder(String), preset(String) }
    private var lastScan: LastScan?

    func scanFolder(_ path: String) async {
        lastScan = .folder(path)
        await runScan(label: Format.tilde(path)) { token in try Core.scanFolder(path, token: token) }
    }

    /// `preset`: "quick" or "full".
    func scanPreset(_ preset: String) async {
        lastScan = .preset(preset)
        await runScan(label: preset == "full" ? "your whole Mac" : "the usual malware locations") { token in
            try Core.scanPreset(preset, token: token)
        }
    }

    func scanAgain() async {
        switch lastScan {
        case .folder(let p): await scanFolder(p)
        case .preset(let p): await scanPreset(p)
        case nil: break
        }
    }

    /// Back to the scan choices (the result is dropped; the Overview tile then shows "Not run yet").
    func newScan() {
        scan = nil
        scannedAt = nil
        removedDetections = []
    }

    private func runScan(label: String, _ work: @escaping @Sendable (UInt64) throws -> FolderScan) async {
        scanning = true
        scanTarget = label
        scan = nil
        error = nil
        progress = 0
        removedDetections = []
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
            scan = try await Task.detached { try work(token) }.value
            scannedAt = Date()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func cancelScan() { Core.cancelFolderScan() }

    /// Kind of the last move ("launch_item" / "malware"), for the administrator follow-up.
    private var lastKind = "launch_item"

    func trash(kind: String, paths: [String]) async {
        error = nil
        do {
            let out = try await Task.detached { try Core.trashFindings(kind: kind, paths: paths) }.value
            outcome = out
            lastKind = kind
            undoMessage = nil
            await refreshAfterChange()
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Move what the last action could not (owned by root) behind macOS's administrator prompt.
    func trashWithPassword() async {
        guard let out = outcome, !out.needsPrivileges.isEmpty else { return }
        error = nil
        let kind = lastKind
        let paths = out.needsPrivileges.map(\.path)
        let journal = out.journal
        do {
            let r = try await Task.detached { try Core.trashPrivileged(kind: kind, app: nil, paths: paths, journal: journal) }.value
            outcome = Outcome(journal: r.journal ?? journal, moved: out.moved + r.response.moved, missing: out.missing,
                              needsPrivileges: [], failed: out.failed + r.response.failed)
            await refreshAfterChange()
        } catch {
            let msg = error.localizedDescription
            self.error = msg == "cancelled" ? nil : msg
        }
    }

    func undo() async {
        guard let id = outcome?.journal else { return }
        do {
            let u = try await Task.detached { try Core.undo(id) }.value
            var restored = u.restored.count
            var note = ""
            if !u.needsPrivileges.isEmpty {
                do {
                    let r = try await Task.detached { try Core.undoPrivileged(id) }.value
                    restored += r.restored.count
                    if !r.failed.isEmpty { note = " \(r.failed.count) failed: \(r.failed[0].reason)" }
                } catch {
                    let msg = error.localizedDescription
                    note = msg == "cancelled" ? " System items were left in the Trash (password cancelled)." : " " + msg
                }
            }
            undoMessage = "Restored \(restored) item\(restored == 1 ? "" : "s")."
                + (u.conflicts.isEmpty ? "" : " \(u.conflicts.count) kept in the Trash (something already exists there).")
                + note
            outcome = nil
            await refreshAfterChange()
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// After a move to the Trash or an undo: re-audit launch items (fast), and update the scan result in place
    /// instead of re-running a scan that may take many minutes.
    private func refreshAfterChange() async {
        if !jobs.isEmpty { await audit() }
        guard let s = scan else { return }
        let all = s.summary.detections + removedDetections
        let present = all.filter { FileManager.default.fileExists(atPath: $0.path) }
        var seen = Set<String>()
        let unique = present.filter { seen.insert("\($0.path)|\($0.rule)").inserted }
        removedDetections = all.filter { !FileManager.default.fileExists(atPath: $0.path) }
        let sum = s.summary
        scan = FolderScan(path: s.path, xprotectVersion: s.xprotectVersion,
                          summary: ScanSummary(filesScanned: sum.filesScanned, filesSkipped: sum.filesSkipped,
                                               detections: unique, errors: sum.errors, cancelled: sum.cancelled))
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

// MARK: - Design system for the section

enum Tone {
    case good, notice, warning, danger, neutral

    var color: Color {
        switch self {
        case .good: .green
        case .notice: .blue
        case .warning: .orange
        case .danger: .red
        case .neutral: .secondary
        }
    }

    static func risk(_ r: String) -> Tone {
        switch r {
        case "high": .danger
        case "medium": .warning
        case "low": .notice
        default: .good
        }
    }
}

/// Rounded card used across the section.
struct Card<Content: View>: View {
    var padding: CGFloat = 16
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.primary.opacity(0.08)))
    }
}

/// SF Symbol in a tinted rounded square.
struct IconTile: View {
    let symbol: String
    let tone: Tone
    var size: CGFloat = 34

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.48, weight: .semibold))
            .foregroundStyle(tone.color)
            .frame(width: size, height: size)
            .background(tone.color.opacity(0.16), in: RoundedRectangle(cornerRadius: size * 0.28, style: .continuous))
    }
}

/// Big round status emblem for page headers.
struct StatusEmblem: View {
    let symbol: String
    let tone: Tone
    var size: CGFloat = 76

    var body: some View {
        ZStack {
            Circle().fill(LinearGradient(colors: [tone.color.opacity(0.95), tone.color.opacity(0.65)], startPoint: .top, endPoint: .bottom))
            Circle().strokeBorder(.white.opacity(0.25), lineWidth: 1)
            Image(systemName: symbol).font(.system(size: size * 0.42, weight: .bold)).foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .shadow(color: tone.color.opacity(0.35), radius: 12, y: 4)
    }
}

struct Pill: View {
    let text: String
    let tone: Tone

    var body: some View {
        Text(text)
            .font(.caption2.weight(.bold))
            .tracking(0.4)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(tone.color.opacity(0.16), in: Capsule())
            .foregroundStyle(tone.color)
    }
}

/// Spinning ring for long scans (driven by the clock, so it needs no view state).
struct ScanRing: View {
    var size: CGFloat = 120

    var body: some View {
        TimelineView(.animation) { t in
            let angle = t.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.2) / 1.2 * 360
            ZStack {
                Circle().stroke(Color.accentColor.opacity(0.15), lineWidth: 10)
                Circle().trim(from: 0, to: 0.28)
                    .stroke(Color.accentColor, style: StrokeStyle(lineWidth: 10, lineCap: .round))
                    .rotationEffect(.degrees(angle))
            }
        }
        .frame(width: size, height: size)
    }
}

/// "<prefix>6 min ago", refreshed every 30 s.
struct AgoText: View {
    let prefix: String
    let date: Date

    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { t in Text(prefix + Format.ago(date, now: t.date)) }
    }
}

// MARK: - Sidebar

/// Sidebar content in Security mode.
struct SecuritySidebar: View {
    @Environment(SecurityModel.self) private var sec

    var body: some View {
        List(SecurityPage.allCases, selection: Binding(get: { sec.page }, set: { sec.page = $0 })) { p in
            HStack(spacing: 10) {
                IconTile(symbol: p.icon, tone: tone(p), size: 26)
                Text(p.rawValue)
                Spacer()
                if let n = count(p), n > 0 {
                    Text("\(n)").font(.caption.weight(.bold)).monospacedDigit()
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(Color.orange, in: Capsule())
                        .foregroundStyle(.white)
                }
            }
            .padding(.vertical, 3)
            .tag(p)
        }
        .task { if sec.jobs.isEmpty { await sec.audit() } }
    }

    private func count(_ p: SecurityPage) -> Int? {
        switch p {
        case .overview: sec.issues
        case .launchItems: sec.flaggedJobs.count
        case .malwareScan: sec.detections
        }
    }

    private func tone(_ p: SecurityPage) -> Tone {
        switch p {
        case .overview: sec.issues == 0 ? .good : .warning
        case .launchItems: sec.flaggedJobs.isEmpty ? .notice : .warning
        case .malwareScan: sec.detections == 0 ? .notice : .danger
        }
    }
}

// MARK: - Detail

struct SecurityDetail: View {
    @Environment(SecurityModel.self) private var sec

    var body: some View {
        VStack(spacing: 0) {
            if let e = sec.error {
                Banner(icon: "exclamationmark.triangle", tint: .red, text: e) { Button("Dismiss") { sec.error = nil } }
            }
            if let o = sec.outcome {
                Banner(icon: "trash", tint: .accentColor, text: summary(o)) {
                    if !o.needsPrivileges.isEmpty {
                        Button("Use Administrator Password…") { Task { await sec.trashWithPassword() } }
                            .help("macOS asks for your password, then Sweep checks each item again and moves it to your Trash")
                    }
                    if o.journal != nil { Button("Undo") { Task { await sec.undo() } } }
                    Button("Dismiss") { sec.outcome = nil }
                }
            }
            if let m = sec.undoMessage {
                Banner(icon: "arrow.uturn.backward", tint: .green, text: m) { Button("Dismiss") { sec.undoMessage = nil } }
            }
            switch sec.page ?? .overview {
            case .overview: OverviewView()
            case .launchItems: LaunchItemsView()
            case .malwareScan: MalwareScanView()
            }
        }
    }

    private func summary(_ o: Outcome) -> String {
        var s = "Moved \(o.moved.count) item\(o.moved.count == 1 ? "" : "s") to the Trash."
        if !o.needsPrivileges.isEmpty { s += " \(o.needsPrivileges.count) belong to the system and need your administrator password." }
        if !o.failed.isEmpty { s += " \(o.failed.count) failed: \(o.failed[0].reason)" }
        return s
    }
}

/// Page header: emblem, title, subtitle, trailing actions.
struct PageHeader<Actions: View>: View {
    let symbol: String
    let tone: Tone
    let title: String
    let subtitle: String
    @ViewBuilder let actions: Actions

    var body: some View {
        HStack(spacing: 18) {
            StatusEmblem(symbol: symbol, tone: tone, size: 64)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 22, weight: .bold))
                Text(subtitle).foregroundStyle(.secondary)
            }
            Spacer()
            actions
        }
        .padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 18)
    }
}

// MARK: Overview

struct OverviewView: View {
    @Environment(SecurityModel.self) private var sec
    @Environment(WatchModel.self) private var watch

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                hero
                HStack(alignment: .top, spacing: 14) {
                    tile(symbol: "power", tone: sec.flaggedJobs.isEmpty ? .good : .warning,
                         title: "Launch Items",
                         value: sec.auditing && sec.jobs.isEmpty ? "…" : (sec.flaggedJobs.isEmpty ? "All clear" : "\(sec.flaggedJobs.count) flagged"),
                         caption: "\(sec.jobs.count) programs start on their own", page: .launchItems)
                    tile(symbol: "magnifyingglass", tone: sec.scan == nil ? .neutral : (sec.detections == 0 ? .good : .danger),
                         title: "Malware Scan",
                         value: sec.scan == nil ? "Not run yet" : (sec.detections == 0 ? "Nothing found" : "\(sec.detections) detected"),
                         caption: sec.scan.map { "\($0.summary.filesScanned) files in \(Format.tilde($0.path))" } ?? "Quick scan, full scan, or any folder",
                         page: .malwareScan)
                    watchTile
                }
                .fixedSize(horizontal: false, vertical: true) // tiles share the tallest one's height
                Card {
                    HStack(alignment: .top, spacing: 12) {
                        IconTile(symbol: "info.circle", tone: .notice, size: 28)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("How Sweep checks your Mac").font(.headline)
                            Text("It uses the malware signatures Apple ships with macOS (XProtect), Apple's own signature and notarization checks, and looks at the programs macOS starts automatically, where malware hides to survive a restart. Everything runs on your Mac; nothing is sent anywhere. It is an on-demand check, not real-time protection.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .padding(24)
        }
    }

    private var hero: some View {
        let clean = sec.issues == 0
        return HStack(spacing: 20) {
            StatusEmblem(symbol: clean ? "checkmark.shield.fill" : "exclamationmark.shield.fill", tone: clean ? .good : .warning, size: 88)
            VStack(alignment: .leading, spacing: 6) {
                Text(clean ? "Your Mac looks clean" : "\(sec.issues) item\(sec.issues == 1 ? "" : "s") need\(sec.issues == 1 ? "s" : "") your attention")
                    .font(.system(size: 26, weight: .bold))
                Group {
                    if let t = sec.auditedAt {
                        AgoText(prefix: "Launch items checked ", date: t)
                    } else {
                        Text(sec.auditing ? "Checking launch items…" : "Not checked yet")
                    }
                }
                .foregroundStyle(.secondary)
                HStack(spacing: 8) {
                    Button { Task { await sec.audit() } } label: { Label("Check Again", systemImage: "arrow.clockwise") }
                        .buttonStyle(.borderedProminent).disabled(sec.auditing)
                    if !clean {
                        Button("Review") { sec.page = sec.flaggedJobs.isEmpty ? .malwareScan : .launchItems }
                    }
                    if sec.auditing { ProgressView().controlSize(.small) }
                }
                .padding(.top, 4)
            }
            Spacer()
        }
        .padding(22)
        .background(
            LinearGradient(colors: [(clean ? Color.green : .orange).opacity(0.16), (clean ? Color.green : .orange).opacity(0.04)],
                           startPoint: .topLeading, endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder((clean ? Color.green : .orange).opacity(0.25)))
    }

    private func tile(symbol: String, tone: Tone, title: String, value: String, caption: String, page: SecurityPage) -> some View {
        Button { sec.page = page } label: {
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        IconTile(symbol: symbol, tone: tone)
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                    }
                    Text(title).font(.subheadline).foregroundStyle(.secondary)
                    Text(value).font(.title3.weight(.semibold)).foregroundStyle(tone == .danger || tone == .warning ? tone.color : .primary)
                    Text(caption).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    Spacer(minLength: 0)
                }
                .frame(maxHeight: .infinity, alignment: .topLeading)
            }
            .frame(maxHeight: .infinity)
        }
        .buttonStyle(.plain)
    }

    private var watchTile: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    IconTile(symbol: "eye", tone: watch.installed ? .good : .neutral)
                    Spacer()
                    Toggle("", isOn: Binding(get: { watch.installed }, set: { on in Task { await watch.set(on) } }))
                        .labelsHidden().toggleStyle(.switch).controlSize(.small).disabled(watch.busy)
                }
                Text("Background Watch").font(.subheadline).foregroundStyle(.secondary)
                Text(watch.installed ? "On" : "Off").font(.title3.weight(.semibold))
                Group {
                    if watch.installed, let last = watch.lastRun {
                        AgoText(prefix: "Every \(WatchSidebarRow.label(watch.intervalHours ?? 6).lowercased()) + on change · last check ", date: last)
                    } else {
                        Text(watch.installed ? "Every \(WatchSidebarRow.label(watch.intervalHours ?? 6).lowercased()) + on change" : "Alerts you when a new launch item appears")
                    }
                }
                .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                Spacer(minLength: 0)
            }
            .frame(maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxHeight: .infinity)
    }
}

// MARK: Launch items

struct LaunchItemsView: View {
    @Environment(SecurityModel.self) private var sec

    var body: some View {
        VStack(spacing: 0) {
            PageHeader(symbol: sec.flaggedJobs.isEmpty ? "checkmark.shield.fill" : "power.circle.fill",
                       tone: sec.flaggedJobs.isEmpty ? .good : .warning,
                       title: "Launch Items",
                       subtitle: sec.flaggedJobs.isEmpty
                           ? "Nothing suspicious among the \(sec.jobs.count) programs macOS starts on its own."
                           : "\(sec.flaggedJobs.count) of \(sec.jobs.count) programs that start on their own have red flags.") {
                Button { Task { await sec.audit() } } label: { Label("Check Again", systemImage: "arrow.clockwise") }
                    .disabled(sec.auditing)
            }
            Divider()
            if sec.auditing && sec.jobs.isEmpty {
                VStack(spacing: 14) { ScanRing(size: 64); Text("Checking launch items…").foregroundStyle(.secondary) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        if !sec.flaggedJobs.isEmpty {
                            sectionTitle("Needs attention", count: sec.flaggedJobs.count)
                            ForEach(sec.flaggedJobs) { LaunchJobCard(job: $0) }
                        }
                        if !sec.trustedJobs.isEmpty {
                            Button { sec.showTrusted.toggle() } label: {
                                HStack(spacing: 6) {
                                    Image(systemName: "chevron.right").font(.caption.weight(.bold))
                                        .rotationEffect(.degrees(sec.showTrusted ? 90 : 0))
                                    Text("Looks normal").font(.headline)
                                    Text("\(sec.trustedJobs.count)").foregroundStyle(.secondary)
                                    Spacer()
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .padding(.top, sec.flaggedJobs.isEmpty ? 0 : 12)
                            if sec.showTrusted {
                                ForEach(sec.trustedJobs) { LaunchJobCard(job: $0) }
                            }
                        }
                    }
                    .padding(24)
                }
            }
        }
    }

    private func sectionTitle(_ t: String, count: Int) -> some View {
        HStack(spacing: 6) {
            Text(t).font(.headline)
            Text("\(count)").foregroundStyle(.secondary)
        }
    }
}

struct LaunchJobCard: View {
    @Environment(SecurityModel.self) private var sec
    let job: LaunchJob
    private let confirming = State(initialValue: false) // no @State macro with the Command Line Tools

    private var tone: Tone { Tone.risk(job.risk) }
    private var open: Bool { sec.expanded.contains(job.id) }

    var body: some View {
        Card(padding: 0) {
            VStack(alignment: .leading, spacing: 0) {
                Button { sec.toggle(job) } label: { summary }
                    .buttonStyle(.plain)
                if open {
                    Divider().padding(.horizontal, 14)
                    details
                }
            }
        }
        .overlay(alignment: .leading) {
            if tone != .good {
                UnevenRoundedRectangle(topLeadingRadius: 14, bottomLeadingRadius: 14, style: .continuous)
                    .fill(tone.color).frame(width: 4)
            }
        }
    }

    private var summary: some View {
        HStack(spacing: 12) {
            ProgramIcon(program: job.program)
            VStack(alignment: .leading, spacing: 3) {
                Text(job.label ?? (job.plist as NSString).lastPathComponent).font(.body.weight(.semibold)).lineLimit(1)
                Text("\(job.daemon ? "System daemon, runs as root" : "Agent, runs as you") · \(signer)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if !job.flags.isEmpty && !open && tone != .good {
                    HStack(spacing: 6) {
                        ForEach(Array(job.flags.prefix(2)), id: \.self) { f in
                            Text(f).font(.caption2).lineLimit(1)
                                .padding(.horizontal, 7).padding(.vertical, 2)
                                .background(tone.color.opacity(0.12), in: Capsule())
                                .foregroundStyle(tone.color)
                        }
                        if job.flags.count > 2 { Text("+\(job.flags.count - 2)").font(.caption2).foregroundStyle(.secondary) }
                    }
                    .padding(.top, 2)
                }
            }
            Spacer(minLength: 8)
            if isOwn { Pill(text: "SWEEP", tone: .notice) } else { Pill(text: job.risk == "info" ? "OK" : job.risk.uppercased(), tone: tone) }
            Image(systemName: "chevron.down").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                .rotationEffect(.degrees(open ? 180 : 0))
        }
        .padding(14)
        .contentShape(Rectangle())
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !job.flags.isEmpty || !job.detections.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(job.detections, id: \.rule) { d in
                        Label("Matches XProtect signature \(d.rule)", systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                    }
                    ForEach(job.flags, id: \.self) { f in
                        Label(f, systemImage: tone == .good ? "info.circle" : "exclamationmark.triangle.fill")
                            .foregroundStyle(tone == .good ? Color.secondary : tone.color)
                    }
                }
                .font(.callout)
            }
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                row("Runs", job.program.map(Format.tilde) ?? "unknown")
                if job.arguments.count > 1 { row("Arguments", job.arguments.dropFirst().joined(separator: " ")) }
                row("Defined in", Format.tilde(job.plist))
                row("Signed by", signer)
                row("Starts", [job.runAtLoad ? "at login" : nil, job.keepAlive ? "kept running" : nil].compactMap { $0 }.joined(separator: ", ").ifEmpty("on demand"))
            }
            .font(.callout)
            .textSelection(.enabled)
            HStack {
                Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: job.plist)]) } label: {
                    Label("Show in Finder", systemImage: "folder")
                }
                if let p = job.program, FileManager.default.fileExists(atPath: p) {
                    Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: p)]) } label: {
                        Label("Show Program", systemImage: "terminal")
                    }
                }
                Spacer()
                if isOwn {
                    Text("Turn it off with the Background watch switch.").font(.caption).foregroundStyle(.secondary)
                } else {
                    Button(role: .destructive) { confirming.wrappedValue = true } label: { Label("Move to Trash", systemImage: "trash") }
                        .confirmationDialog("Move \(job.label ?? "this launch item") to the Trash?", isPresented: confirming.projectedValue) {
                            Button("Move to Trash", role: .destructive) { Task { await sec.trash(kind: "launch_item", paths: [job.plist]) } }
                        } message: {
                            Text("It is stopped first and will not start again. You can put it back with Undo. Only its definition is moved: check the program it runs too.")
                        }
                }
            }
            .controlSize(.regular)
        }
        .padding(14)
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary).gridColumnAlignment(.trailing)
            Text(v).lineLimit(2).truncationMode(.middle)
        }
    }

    /// Sweep's own watch agent: shown, but not offered for removal (use the sidebar switch).
    private var isOwn: Bool {
        job.plist.hasSuffix("/LaunchAgents/dev.sweep.watch.plist")
            && job.program == Foundation.Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/sweep").path
    }

    private var signer: String {
        guard let s = job.signature else { return "program not found" }
        if s.apple { return "Apple" }
        if s.adhoc { return "no developer identity" }
        return s.authority.first.map { $0.replacingOccurrences(of: "Developer ID Application: ", with: "") } ?? "not signed"
    }
}

/// Icon of the app that contains the program, or a generic one.
struct ProgramIcon: View {
    let program: String?

    var body: some View {
        if let app = enclosingApp {
            Image(nsImage: NSWorkspace.shared.icon(forFile: app)).resizable().frame(width: 34, height: 34)
        } else {
            IconTile(symbol: "terminal", tone: .neutral)
        }
    }

    private var enclosingApp: String? {
        guard let p = program, let r = p.range(of: ".app/", options: .caseInsensitive) else { return nil }
        let app = String(p[..<r.lowerBound]) + ".app"
        return FileManager.default.fileExists(atPath: app) ? app : nil
    }
}

extension String {
    func ifEmpty(_ s: String) -> String { isEmpty ? s : self }
}

// MARK: Malware scan

struct MalwareScanView: View {
    @Environment(SecurityModel.self) private var sec
    private let confirming = State(initialValue: false)

    var body: some View {
        VStack(spacing: 0) {
            PageHeader(symbol: headerSymbol, tone: headerTone, title: "Malware Scan",
                       subtitle: "Checks files against the malware signatures Apple ships with macOS. Nothing leaves your Mac.") {
                if sec.scan != nil && !sec.scanning {
                    Button { sec.newScan() } label: { Label("New Scan", systemImage: "chevron.left") }
                        .help("Back to Quick Scan, Full Scan and Choose a Folder")
                    Button { Task { await sec.scanAgain() } } label: { Label("Scan Again", systemImage: "arrow.clockwise") }
                }
            }
            Divider()
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var headerTone: Tone { sec.scan == nil || sec.scanning ? .notice : (sec.detections == 0 ? .good : .danger) }
    private var headerSymbol: String {
        sec.scan == nil || sec.scanning ? "magnifyingglass" : (sec.detections == 0 ? "checkmark.shield.fill" : "xmark.shield.fill")
    }

    @ViewBuilder private var content: some View {
        if sec.scanning {
            VStack(spacing: 18) {
                ZStack {
                    ScanRing(size: 140)
                    VStack(spacing: 2) {
                        Text("\(sec.progress)").font(.system(size: 26, weight: .bold)).monospacedDigit()
                        Text("items").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text("Scanning \(sec.scanTarget ?? "")").font(.headline)
                Text("You can keep using your Mac, or stop at any time and see what was found so far.")
                    .font(.callout).foregroundStyle(.secondary)
                Button("Stop") { sec.cancelScan() }.controlSize(.large)
            }
        } else if let s = sec.scan, s.summary.filesScanned == 0, s.summary.detections.isEmpty, let err = s.summary.errors.first {
            VStack(spacing: 12) {
                StatusEmblem(symbol: "questionmark.folder.fill", tone: .warning)
                Text("Nothing could be scanned").font(.title3.weight(.semibold))
                Text(err).foregroundStyle(.secondary).textSelection(.enabled)
                Text("Check that it still exists. For protected folders, give Sweep Full Disk Access.").font(.caption).foregroundStyle(.secondary)
            }
            .padding(24)
        } else if let s = sec.scan {
            result(s)
        } else {
            start
        }
    }

    private var start: some View {
        VStack(spacing: 24) {
            Button { Task { await sec.scanPreset("quick") } } label: {
                ZStack {
                    Circle().fill(LinearGradient(colors: [Color(red: 0.18, green: 0.80, blue: 0.75), Color(red: 0.05, green: 0.45, blue: 0.85)],
                                                 startPoint: .topLeading, endPoint: .bottomTrailing))
                    Circle().strokeBorder(.white.opacity(0.25), lineWidth: 1)
                    VStack(spacing: 6) {
                        Image(systemName: "bolt.shield.fill").font(.system(size: 40, weight: .semibold))
                        Text("Quick Scan").font(.headline)
                        Text("about 2 min").font(.caption).opacity(0.85)
                    }
                    .foregroundStyle(.white)
                }
                .frame(width: 170, height: 170)
                .shadow(color: .blue.opacity(0.35), radius: 18, y: 6)
            }
            .buttonStyle(.plain)
            .help("Downloads, Desktop, apps, Application Support, launch items, shared and temporary folders, hidden files in your home folder")
            HStack(spacing: 14) {
                option(symbol: "internaldrive", title: "Full Scan", detail: "Your home folder, apps and Library folders. Can take a long time.") {
                    Task { await sec.scanPreset("full") }
                }
                option(symbol: "folder", title: "Choose a Folder", detail: "A folder, a disk image or a single file.") {
                    if let p = SecurityModel.chooseFolder() { Task { await sec.scanFolder(p) } }
                }
            }
            .frame(maxWidth: 560)
            .fixedSize(horizontal: false, vertical: true) // both cards take the taller one's height
            if !Core.hasFullDiskAccess() {
                Label("Give Sweep Full Disk Access so scans can read Documents, Desktop, Mail and other protected folders.",
                      systemImage: "lock.shield")
                    .font(.callout).foregroundStyle(.orange)
            }
        }
        .padding(24)
    }

    private func option(symbol: String, title: String, detail: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Card(padding: 14) {
                HStack(alignment: .top, spacing: 12) {
                    IconTile(symbol: symbol, tone: .notice)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title).font(.headline)
                        Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer(minLength: 0)
                }
                .frame(maxHeight: .infinity, alignment: .top)
            }
            .frame(maxHeight: .infinity)
        }
        .buttonStyle(.plain)
    }

    private func result(_ s: FolderScan) -> some View {
        let sum = s.summary
        let clean = sum.detections.isEmpty
        return ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Card {
                    HStack(spacing: 16) {
                        StatusEmblem(symbol: clean ? "checkmark.shield.fill" : "xmark.shield.fill", tone: clean ? .good : .danger, size: 56)
                        VStack(alignment: .leading, spacing: 6) {
                            Text(clean ? "No known malware found" : "\(sum.detections.count) file\(sum.detections.count == 1 ? "" : "s") match known malware")
                                .font(.title3.weight(.bold))
                            Text(Format.tilde(s.path)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                            HStack(spacing: 6) {
                                Pill(text: "\(sum.filesScanned) FILES", tone: .notice)
                                if sum.filesSkipped > 0 { Pill(text: "\(sum.filesSkipped) SKIPPED", tone: .neutral) }
                                if !sum.errors.isEmpty { Pill(text: "\(sum.errors.count) UNREADABLE", tone: .warning) }
                                if sum.cancelled { Pill(text: "STOPPED", tone: .warning) }
                                Pill(text: "XPROTECT \(s.xprotectVersion)", tone: .neutral)
                            }
                            if let t = sec.scannedAt {
                                AgoText(prefix: "Scanned ", date: t).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        if !clean {
                            Button(role: .destructive) { confirming.wrappedValue = true } label: { Label("Move All to Trash", systemImage: "trash") }
                                .controlSize(.large)
                                .confirmationDialog("Move \(Set(sum.detections.map(\.path)).count) files to the Trash?", isPresented: confirming.projectedValue) {
                                    Button("Move to Trash", role: .destructive) {
                                        Task { await sec.trash(kind: "malware", paths: Array(Set(sum.detections.map(\.path)))) }
                                    }
                                } message: { Text("You can put them back with Undo.") }
                        }
                    }
                }
                ForEach(sum.detections, id: \.path) { d in
                    Card(padding: 12) {
                        HStack(spacing: 12) {
                            Image(nsImage: NSWorkspace.shared.icon(forFile: d.path)).resizable().frame(width: 32, height: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text((d.path as NSString).lastPathComponent).font(.body.weight(.semibold))
                                Text(Format.tilde(d.path)).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            Pill(text: d.rule.replacingOccurrences(of: "XProtect_", with: ""), tone: .danger)
                            Button { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: d.path)]) } label: {
                                Image(systemName: "folder")
                            }
                            .help("Show in Finder")
                        }
                    }
                }
                if clean && !sum.errors.isEmpty {
                    Text("Some files could not be read. Giving Sweep Full Disk Access lets it scan everything.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(24)
        }
    }
}
