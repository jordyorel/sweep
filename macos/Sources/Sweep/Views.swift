import AppKit
import SwiftUI
import UniformTypeIdentifiers

@main
struct SweepApp: App {
    // The app struct is created once; a plain constant avoids the @State macro, which the
    // Command Line Tools cannot expand (no SwiftUIMacros plugin without Xcode).
    private let model = AppModel()

    var body: some Scene {
        WindowGroup("Sweep") {
            ContentView()
                .environment(model)
                .frame(minWidth: 820, minHeight: 520)
        }
        .commands {
            CommandGroup(replacing: .undoRedo) {
                Button("Undo Last Removal") { Task { await model.undo() } }
                    .keyboardShortcut("z")
            }
        }
    }
}

struct ContentView: View {
    @Environment(AppModel.self) private var model
    private let dropTargeted = State(initialValue: false) // see SweepApp: no @State macro

    var body: some View {
        NavigationSplitView {
            List(model.filteredApps, id: \.path, selection: Binding(get: { model.selectedApp }, set: { model.selectedApp = $0 })) { app in
                AppRow(path: app.path, name: app.name, subtitle: app.version)
            }
            .searchable(text: Binding(get: { model.search }, set: { model.search = $0 }), placement: .sidebar, prompt: "Search apps")
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
        } detail: {
            VStack(spacing: 0) {
                Banners()
                if let report = model.report {
                    LeftoversView(report: report)
                } else if model.busy {
                    ProgressView("Looking for leftovers…").frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    DropHint(targeted: dropTargeted.wrappedValue)
                }
            }
        }
        .onDrop(of: [.fileURL], isTargeted: dropTargeted.projectedValue) { providers in
            guard let p = providers.first else { return false }
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                guard let url, url.pathExtension.lowercased() == "app" else { return }
                Task { @MainActor in
                    model.selectedApp = nil
                    await model.scan(url.path)
                }
            }
            return true
        }
        .onChange(of: model.selectedApp) { _, path in
            if let path { Task { await model.scan(path) } }
        }
        .task { await model.loadApps() }
        .alert(
            "App is running",
            isPresented: Binding(get: { model.runningConflict != nil }, set: { if !$0 { model.runningConflict = nil } })
        ) {
            Button("Cancel", role: .cancel) {}
            Button("Remove Anyway", role: .destructive) { Task { await model.remove(allowRunning: true) } }
        } message: {
            Text((model.runningConflict ?? "") + "\n\nQuitting it first is safer.")
        }
    }
}

struct AppRow: View {
    let path: String
    let name: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 8) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: path))
                .resizable().frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(name).lineLimit(1)
                if !subtitle.isEmpty {
                    Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

struct DropHint: View {
    let targeted: Bool

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "tray.and.arrow.down")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(targeted ? Color.accentColor : .secondary)
            Text("Drop an app here, or pick one in the list").font(.title3)
            Text("Nothing is deleted: everything goes to the Trash and can be put back.")
                .font(.callout).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(targeted ? Color.accentColor.opacity(0.08) : .clear)
    }
}

struct Banners: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            if !model.hasFullDiskAccess {
                Banner(icon: "lock.shield", tint: .orange,
                       text: "Sweep has no Full Disk Access, so macOS may refuse to move some items.") {
                    Button("Open Settings") {
                        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
                    }
                }
            }
            if let e = model.error {
                Banner(icon: "exclamationmark.triangle", tint: .red, text: e) {
                    Button("Dismiss") { model.error = nil }
                }
            }
            if let out = model.lastOutcome {
                Banner(icon: "trash", tint: .accentColor, text: summary(out)) {
                    if out.journal != nil { Button("Undo") { Task { await model.undo() } } }
                    Button("Dismiss") { model.lastOutcome = nil }
                }
            }
            if let m = model.undoMessage {
                Banner(icon: "arrow.uturn.backward", tint: .green, text: m) {
                    Button("Dismiss") { model.undoMessage = nil }
                }
            }
        }
    }

    private func summary(_ o: Outcome) -> String {
        var s = "Moved \(o.moved.count) item\(o.moved.count == 1 ? "" : "s") to the Trash."
        if !o.needsPrivileges.isEmpty {
            s += " \(o.needsPrivileges.count) need admin rights and were left in place (not supported yet)."
        }
        if !o.failed.isEmpty { s += " \(o.failed.count) failed: \(o.failed[0].reason)" }
        return s
    }
}

struct Banner<Actions: View>: View {
    let icon: String
    let tint: Color
    let text: String
    @ViewBuilder let actions: Actions

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon).foregroundStyle(tint)
            Text(text).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
            actions
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(tint.opacity(0.10))
        .overlay(alignment: .bottom) { Divider() }
    }
}

struct LeftoversView: View {
    @Environment(AppModel.self) private var model
    let report: Report
    private let confirming = State(initialValue: false)

    var body: some View {
        VStack(spacing: 0) {
            header
            if model.check?.verdict.level == "danger" {
                Banner(icon: "xmark.shield.fill", tint: .red,
                       text: "This app looks malicious: \(model.check!.verdict.headline). Moving it and all its leftovers to the Trash is recommended.") { EmptyView() }
            }
            Divider()
            List(report.findings) { f in
                FindingRow(finding: f, locked: report.sipProtected)
            }
            Divider()
            footer
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: report.bundle.path))
                .resizable().frame(width: 48, height: 48)
            VStack(alignment: .leading, spacing: 2) {
                Text(report.bundle.name).font(.title2.weight(.semibold))
                Text([report.bundle.version, report.bundle.rawId ?? "no bundle id"].filter { !$0.isEmpty }.joined(separator: " · "))
                    .foregroundStyle(.secondary)
                if !report.nested.isEmpty {
                    Text("Helpers: " + report.nested.compactMap(\.rawId).joined(separator: ", "))
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer()
            SecurityBadge()
            Button {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: report.bundle.path)])
            } label: { Label("Show in Finder", systemImage: "folder") }
        }
        .padding(14)
    }

    private var footer: some View {
        HStack {
            if report.sipProtected {
                Label("Protected by macOS: cannot be removed", systemImage: "lock.fill").foregroundStyle(.secondary)
            } else {
                Text("\(model.chosenCount) of \(report.findings.count) items · \(Format.size(model.chosenSize))")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Move to Trash", role: .destructive) { confirming.wrappedValue = true }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(report.sipProtected || model.chosenCount == 0 || model.busy)
                .confirmationDialog("Move \(model.chosenCount) items to the Trash?", isPresented: confirming.projectedValue) {
                    Button("Move to Trash", role: .destructive) { Task { await model.remove() } }
                } message: {
                    Text("You can put them back with Undo (⌘Z).")
                }
        }
        .padding(12)
    }
}

struct FindingRow: View {
    @Environment(AppModel.self) private var model
    let finding: Finding
    let locked: Bool

    var body: some View {
        let implied = model.isImplied(finding)
        HStack(alignment: .top, spacing: 10) {
            Toggle("", isOn: Binding(get: { model.isChosen(finding) }, set: { _ in model.toggle(finding) }))
                .labelsHidden()
                .disabled(implied || locked)
                .help(implied ? "Inside a folder that is already being removed" : "")
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(Format.category(finding.category)).font(.caption.weight(.medium))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(.quaternary, in: Capsule())
                    Text(Format.tilde(finding.path)).lineLimit(1).truncationMode(.middle)
                }
                Text(finding.reason + (finding.via.map { " (via \($0))" } ?? ""))
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Text(Format.size(finding.size)).monospacedDigit().foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Show in Finder") {
                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: finding.path)])
            }
            Button("Copy Path") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(finding.path, forType: .string)
            }
        }
    }
}

struct SecurityBadge: View {
    @Environment(AppModel.self) private var model
    private let showing = State(initialValue: false) // no @State macro with the Command Line Tools

    var body: some View {
        Group {
            if model.checking {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Checking security…").foregroundStyle(.secondary)
                }
            } else if let c = model.check {
                Button { showing.wrappedValue = true } label: {
                    Label(c.verdict.headline, systemImage: Self.icon(c.verdict.level))
                        .lineLimit(1)
                        .foregroundStyle(Self.tint(c.verdict.level))
                }
                .buttonStyle(.borderless)
                .frame(maxWidth: 320)
                .popover(isPresented: showing.projectedValue, arrowEdge: .bottom) { SecurityDetails(check: c) }
            } else if let e = model.checkError {
                Label("Check failed", systemImage: "questionmark.diamond").foregroundStyle(.secondary).help(e)
            }
        }
    }

    static func icon(_ level: String) -> String {
        switch level {
        case "ok": "checkmark.shield.fill"
        case "info": "info.circle.fill"
        case "warning": "exclamationmark.shield.fill"
        default: "xmark.shield.fill"
        }
    }

    static func tint(_ level: String) -> Color {
        switch level {
        case "ok": .green
        case "info": .blue
        case "warning": .orange
        default: .red
        }
    }
}

struct SecurityDetails: View {
    let check: AppCheck

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(check.verdict.headline, systemImage: SecurityBadge.icon(check.verdict.level))
                .font(.headline).foregroundStyle(SecurityBadge.tint(check.verdict.level))
            if !check.verdict.reasons.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(check.verdict.reasons, id: \.self) { r in
                        Text("• " + r).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Divider()
            Text("XProtect \(check.xprotectVersion): \(check.scan.filesScanned) files scanned, \(check.scan.detections.count) detections")
                .font(.caption).foregroundStyle(.secondary)
            Text("Signature, Gatekeeper and quarantine are checked with Apple's own tools. This is an on-demand check, not real-time protection.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(width: 380)
        .textSelection(.enabled)
    }
}
