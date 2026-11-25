// Swift side of crates/sweep-ffi: decodes the JSON the Rust core returns.
import CSweep
import Foundation

struct CoreError: LocalizedError, Sendable {
    let message: String
    var errorDescription: String? { message }
}

struct AppBundle: Codable, Hashable, Sendable {
    let path: String
    let alias: String?
    let kind: String
    let name: String
    let displayName: String?
    let executable: String
    let id: String?
    let rawId: String?
    let version: String
}

struct Finding: Codable, Hashable, Sendable, Identifiable {
    let path: String
    let category: String
    let reason: String
    let selected: Bool
    let size: UInt64
    let via: String?
    var id: String { path }
}

struct Report: Codable, Sendable {
    let bundle: AppBundle
    let nested: [AppBundle]
    let sipProtected: Bool
    let findings: [Finding]
}

struct Moved: Codable, Sendable {
    let original: String
    let trashed: String
    let category: String
    /// Moved with the administrator password (absent = false).
    let privileged: Bool?
}

/// Result of an administrator action.
struct PrivilegedResponse: Codable, Sendable {
    let moved: [Moved]
    let restored: [String]
    let missing: [String]
    let failed: [Problem]
}

struct PrivilegedTrash: Codable, Sendable {
    let response: PrivilegedResponse
    let journal: String?
}

struct Problem: Codable, Sendable {
    let path: String
    let reason: String
}

struct Outcome: Codable, Sendable {
    let journal: String?
    let moved: [Moved]
    let missing: [String]
    let needsPrivileges: [Problem]
    let failed: [Problem]
}

struct UndoOutcome: Codable, Sendable {
    let journal: String
    let restored: [String]
    let conflicts: [String]
    let gone: [String]
    let failed: [Problem]
    /// Moved with the administrator password: put back with `undoPrivileged`.
    let needsPrivileges: [Moved]
}

struct Verdict: Codable, Sendable {
    /// ok, info, warning, danger
    let level: String
    let headline: String
    let reasons: [String]
}

struct Detection: Codable, Sendable {
    let path: String
    let rule: String
    let description: String?
}

struct ScanSummary: Codable, Sendable {
    let filesScanned: UInt64
    let filesSkipped: UInt64
    let detections: [Detection]
    let errors: [String]
    let cancelled: Bool
}

struct AppCheck: Codable, Sendable {
    let path: String
    let quarantined: Bool
    let xprotectVersion: String
    let scan: ScanSummary
    let verdict: Verdict
}

struct JobSignature: Codable, Sendable {
    let adhoc: Bool
    let teamId: String?
    let authority: [String]
    let apple: Bool
}

struct LaunchJob: Codable, Sendable, Identifiable {
    let plist: String
    let label: String?
    let program: String?
    let arguments: [String]
    let runAtLoad: Bool
    let keepAlive: Bool
    let daemon: Bool
    let signature: JobSignature?
    let quarantined: Bool
    let flags: [String]
    let detections: [Detection]
    /// info, low, medium, high
    let risk: String
    var id: String { plist }
}

struct FolderScan: Codable, Sendable {
    let path: String
    let xprotectVersion: String
    let summary: ScanSummary
}

struct Journal: Codable, Sendable, Identifiable {
    let id: String
    let appName: String
    let appPath: String
    let createdUnix: UInt64
    let items: [Moved]
}

/// Blocking calls into Rust. Run them off the main thread.
enum Core {
    private struct Envelope<T: Decodable>: Decodable {
        let ok: T?
        let error: String?
    }

    private static func call<T: Decodable>(_ f: () -> UnsafeMutablePointer<CChar>?) throws -> T {
        guard let raw = f() else { throw CoreError(message: "no response from the core") }
        defer { sweep_string_free(raw) }
        let data = Data(bytes: raw, count: strlen(raw))
        let dec = JSONDecoder()
        dec.keyDecodingStrategy = .convertFromSnakeCase
        let env = try dec.decode(Envelope<T>.self, from: data)
        if let e = env.error { throw CoreError(message: e) }
        guard let v = env.ok else { throw CoreError(message: "empty response from the core") }
        return v
    }

    static func listApps() throws -> [AppBundle] { try call { sweep_list_apps() } }

    static func scan(_ app: String) throws -> Report { try call { sweep_scan(app) } }

    static func remove(_ app: String, chosen: [String], allowRunning: Bool) throws -> Outcome {
        let json = String(decoding: try JSONEncoder().encode(chosen), as: UTF8.self)
        return try call { sweep_remove(app, json, allowRunning) }
    }

    /// Starts a new check and cancels any older one still running.
    static func beginCheck() -> UInt64 { sweep_check_begin() }

    static func check(_ app: String, token: UInt64) throws -> AppCheck { try call { sweep_check(app, token) } }

    static func persistence() throws -> [LaunchJob] { try call { sweep_persistence() } }

    static func beginFolderScan() -> UInt64 { sweep_scan_begin() }
    static func cancelFolderScan() { sweep_scan_cancel() }
    static func folderScanProgress() -> UInt64 { sweep_scan_progress() }
    static func scanFolder(_ path: String, token: UInt64) throws -> FolderScan { try call { sweep_scan_folder(path, token) } }
    /// `preset`: "quick" or "full".
    static func scanPreset(_ preset: String, token: UInt64) throws -> FolderScan { try call { sweep_scan_preset(preset, token) } }

    /// `kind`: "launch_item" or "malware". Each path is re-checked by the core before it is moved.
    static func trashFindings(kind: String, paths: [String]) throws -> Outcome {
        let json = String(decoding: try JSONEncoder().encode(paths), as: UTF8.self)
        return try call { sweep_trash_findings(kind, json) }
    }

    static func journals() throws -> [Journal] { try call { sweep_journals() } }

    static func undo(_ id: String? = nil) throws -> UndoOutcome {
        if let id { return try call { sweep_undo(id) } }
        return try call { sweep_undo(nil) }
    }

    /// Shows macOS's administrator prompt and blocks until it is answered: call off the main thread.
    /// `kind`: "leftovers" (with `app`), "launch_item" or "malware".
    static func trashPrivileged(kind: String, app: String?, paths: [String], journal: String?) throws -> PrivilegedTrash {
        let json = String(decoding: try JSONEncoder().encode(paths), as: UTF8.self)
        return try call {
            switch (app, journal) {
            case let (a?, j?): sweep_trash_privileged(kind, a, json, j)
            case let (a?, nil): sweep_trash_privileged(kind, a, json, nil)
            case let (nil, j?): sweep_trash_privileged(kind, nil, json, j)
            case (nil, nil): sweep_trash_privileged(kind, nil, json, nil)
            }
        }
    }

    /// Puts back the items of journal `id` that were moved with the administrator password (prompt again).
    static func undoPrivileged(_ id: String) throws -> PrivilegedResponse { try call { sweep_undo_privileged(id) } }

    static func hasFullDiskAccess() -> Bool { (try? call { sweep_has_full_disk_access() }) ?? true }
}
