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

    static func journals() throws -> [Journal] { try call { sweep_journals() } }

    static func undo(_ id: String? = nil) throws -> UndoOutcome {
        if let id { return try call { sweep_undo(id) } }
        return try call { sweep_undo(nil) }
    }

    static func hasFullDiskAccess() -> Bool { (try? call { sweep_has_full_disk_access() }) ?? true }
}
