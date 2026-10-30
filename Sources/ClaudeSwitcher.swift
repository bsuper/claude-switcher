// Claude Switcher — menubar usage tracker and account switcher for Claude Desktop.
//
// How it works:
//   * Claude Desktop keeps its login in Chromium storage (Cookies, Local Storage, ...)
//     plus a few `oauth:*` keys in config.json. A "profile" is a snapshot of exactly
//     those items; everything else (sessions, settings, workspaces) is left alone.
//   * Switching = quit Claude, snapshot the active profile, restore the target, relaunch.
//   * Usage is read per profile by decrypting its claude.ai `sessionKey` cookie
//     (key from the "Claude Safe Storage" keychain item) and calling
//     claude.ai/api/organizations/{org}/usage.

import AppKit
import CommonCrypto
import Security
import ServiceManagement
import SQLite3
import SwiftUI

// MARK: - Constants

enum Paths {
    static let home = FileManager.default.homeDirectoryForCurrentUser
    static let claudeData = home.appendingPathComponent("Library/Application Support/Claude")
    static let claudeConfig = claudeData.appendingPathComponent("config.json")
    static let usageHistory = claudeData.appendingPathComponent("plan-usage-history.json")
    static let support = home.appendingPathComponent("Library/Application Support/ClaudeSwitcher")
    static let profiles = support.appendingPathComponent("profiles")
    static let backups = support.appendingPathComponent("backups")
    static let state = support.appendingPathComponent("state.json")
}

let claudeBundleID = "com.anthropic.claudefordesktop"
/// Files/dirs inside Claude's data dir that hold the signed-in account.
let authItems = ["Cookies", "Cookies-journal", "Local Storage", "Session Storage", "IndexedDB", "WebStorage"]
func isAuthConfigKey(_ key: String) -> Bool { key.hasPrefix("oauth:") || key == "lastKnownAccountUuid" }

/// Appends one line to switcher.log so a failed switch can be diagnosed after the fact. Never logs secrets.
var switchLogEnabled = true
func switchLog(_ message: String) {
    guard switchLogEnabled else { return }
    let url = Paths.support.appendingPathComponent("switcher.log")
    let line = "\(ISO8601DateFormatter().string(from: Date())) \(message)\n"
    guard let data = line.data(using: .utf8) else { return }
    if let handle = try? FileHandle(forWritingTo: url) {
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: data)
    } else {
        try? data.write(to: url)
    }
}

struct AppError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

// MARK: - Model

struct Usage: Codable, Equatable {
    var fiveHour: Double?
    var fiveHourResets: Date?
    var sevenDay: Double?
    var sevenDayResets: Date?
    var fetchedAt: Date
    var cached = false

    /// Utilization in percent, treating a window whose reset time has passed as empty.
    var fh: Double { (fiveHourResets.map { $0 < Date() } ?? false) ? 0 : (fiveHour ?? 0) }
    var sd: Double { (sevenDayResets.map { $0 < Date() } ?? false) ? 0 : (sevenDay ?? 0) }
}

struct Profile: Codable, Identifiable, Equatable {
    var id = UUID()
    var name: String
    var email: String?
    var orgId: String?
    var usage: Usage?
    var lastError: String?
}

enum SwitchMode: String, Codable, CaseIterable { case off, ask, auto }

struct Settings: Codable, Equatable {
    var mode: SwitchMode = .ask
    var threshold: Double = 90       // 5-hour % that triggers a switch
    var weeklyThreshold: Double = 98 // 7-day % that triggers a switch
    var pollMinutes: Double = 5
    var shareSessions = true         // show every account's Code & Cowork sessions on all accounts
    var shareScheduledTasks = false  // off by default: copying a task restarts it on the active account
    var switchChromeExtension = false // off by default: quits and reopens Chrome on every switch
    var chromeProfileDir: String?

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Settings()
        mode = try c.decodeIfPresent(SwitchMode.self, forKey: .mode) ?? d.mode
        threshold = try c.decodeIfPresent(Double.self, forKey: .threshold) ?? d.threshold
        weeklyThreshold = try c.decodeIfPresent(Double.self, forKey: .weeklyThreshold) ?? d.weeklyThreshold
        pollMinutes = try c.decodeIfPresent(Double.self, forKey: .pollMinutes) ?? d.pollMinutes
        shareSessions = try c.decodeIfPresent(Bool.self, forKey: .shareSessions) ?? d.shareSessions
        shareScheduledTasks = try c.decodeIfPresent(Bool.self, forKey: .shareScheduledTasks) ?? d.shareScheduledTasks
        switchChromeExtension = try c.decodeIfPresent(Bool.self, forKey: .switchChromeExtension) ?? d.switchChromeExtension
        chromeProfileDir = try c.decodeIfPresent(String.self, forKey: .chromeProfileDir)
    }
}

struct AppState: Codable, Equatable {
    var profiles: [Profile] = []
    var activeId: UUID?
    var settings = Settings()
}

// MARK: - Chromium cookie decryption

enum ChromeCrypto {
    private static let lock = NSLock()
    private static var cachedKey: Data?

    static func key() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        if let k = cachedKey { return k }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Claude Safe Storage",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess, let password = out as? Data else {
            throw AppError("Keychain access to “Claude Safe Storage” was denied (\(status)).")
        }
        let salt = Array("saltysalt".utf8)
        var derived = [UInt8](repeating: 0, count: kCCKeySizeAES128)
        let rc = password.withUnsafeBytes { pw in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                 pw.baseAddress!.assumingMemoryBound(to: CChar.self), password.count,
                                 salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1003,
                                 &derived, derived.count)
        }
        guard rc == kCCSuccess else { throw AppError("Key derivation failed") }
        cachedKey = Data(derived)
        return cachedKey!
    }

    /// Decrypts a macOS Chromium "v10" cookie. DB schema >= 24 prefixes the plaintext with SHA256(host).
    static func decrypt(_ blob: Data, hashPrefix: Bool) throws -> String {
        guard blob.count > 3, blob.prefix(3) == Data("v10".utf8) else { throw AppError("Unsupported cookie encryption") }
        let cipher = Data(blob.dropFirst(3))
        let key = try key()
        let iv = [UInt8](repeating: 0x20, count: kCCBlockSizeAES128)
        var out = [UInt8](repeating: 0, count: cipher.count + kCCBlockSizeAES128)
        var moved = 0
        let status = key.withUnsafeBytes { k in
            cipher.withUnsafeBytes { c in
                CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
                        k.baseAddress, key.count, iv, c.baseAddress, cipher.count, &out, out.count, &moved)
            }
        }
        guard status == kCCSuccess else { throw AppError("Cookie decryption failed") }
        var bytes = Array(out.prefix(moved))
        if hashPrefix && bytes.count >= 32 { bytes.removeFirst(32) }
        return String(decoding: bytes, as: UTF8.self)
    }
}

enum CookieReader {
    /// Reads claude.ai cookies from a Chromium Cookies DB (copied first so a live DB is never locked).
    static func read(db: URL, names: Set<String>) throws -> [String: String] {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory.appendingPathComponent("cs-cookies-\(UUID().uuidString)")
        try fm.copyItem(at: db, to: tmp)
        defer { try? fm.removeItem(at: tmp) }

        var handle: OpaquePointer?
        guard sqlite3_open_v2(tmp.path, &handle, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            throw AppError("Could not open cookie store")
        }
        defer { sqlite3_close(handle) }

        var version = 0
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(handle, "SELECT value FROM meta WHERE key='version'", -1, &stmt, nil) == SQLITE_OK,
           sqlite3_step(stmt) == SQLITE_ROW, let text = sqlite3_column_text(stmt, 0) {
            version = Int(String(cString: text)) ?? 0
        }
        sqlite3_finalize(stmt)

        let sql = "SELECT name, value, encrypted_value FROM cookies WHERE host_key IN ('.claude.ai','claude.ai')"
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK else { throw AppError("Unexpected cookie schema") }
        defer { sqlite3_finalize(stmt) }

        var result: [String: String] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            let name = String(cString: sqlite3_column_text(stmt, 0))
            guard names.contains(name) else { continue }
            if let v = sqlite3_column_text(stmt, 1), case let plain = String(cString: v), !plain.isEmpty {
                result[name] = plain
            } else if let blob = sqlite3_column_blob(stmt, 2) {
                let data = Data(bytes: blob, count: Int(sqlite3_column_bytes(stmt, 2)))
                result[name] = try ChromeCrypto.decrypt(data, hashPrefix: version >= 24)
            }
        }
        return result
    }
}

// MARK: - Usage API

func parseISODate(_ s: String) -> Date? {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = f.date(from: s) { return d }
    f.formatOptions = [.withInternetDateTime]
    if let d = f.date(from: s) { return d }
    // Drop fractional seconds of unusual length, e.g. 2026-10-22T15:00:00.123456+00:00
    let trimmed = s.replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression)
    return f.date(from: trimmed)
}

struct FetchResult {
    var usage: Usage
    var orgId: String
    var email: String?
}

enum UsageClient {
    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.timeoutIntervalForRequest = 20
        return URLSession(configuration: c)
    }()

    static func get(_ path: String, sessionKey: String) async throws -> Any {
        var req = URLRequest(url: URL(string: "https://claude.ai" + path)!)
        req.setValue("sessionKey=\(sessionKey)", forHTTPHeaderField: "Cookie")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("web_claude_ai", forHTTPHeaderField: "anthropic-client-platform")
        req.setValue("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
                     forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await session.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        switch status {
        case 200..<300: return try JSONSerialization.jsonObject(with: data)
        case 401: throw AppError("Session expired — switch to this account and sign in again")
        case 403: throw AppError("claude.ai refused the request (HTTP 403)")
        default: throw AppError("claude.ai returned HTTP \(status)")
        }
    }

    static func pickOrg(sessionKey: String) async throws -> String {
        guard let orgs = try await get("/api/organizations", sessionKey: sessionKey) as? [[String: Any]], !orgs.isEmpty else {
            throw AppError("No organizations on this account")
        }
        func has(_ cap: String) -> [String: Any]? { orgs.first { ($0["capabilities"] as? [String])?.contains(cap) ?? false } }
        let org = has("claude_max") ?? has("claude_pro") ?? has("chat") ?? orgs[0]
        guard let uuid = org["uuid"] as? String else { throw AppError("Malformed organizations response") }
        return uuid
    }

    static func login(cookiesDB: URL) throws -> (sessionKey: String, org: String?) {
        guard FileManager.default.fileExists(atPath: cookiesDB.path) else {
            throw AppError("No saved login yet — switch to it once to capture")
        }
        let cookies = try CookieReader.read(db: cookiesDB, names: ["sessionKey", "lastActiveOrg"])
        guard let sk = cookies["sessionKey"], !sk.isEmpty else { throw AppError("Signed out (no session cookie)") }
        return (sk, cookies["lastActiveOrg"])
    }

    static func fetch(cookiesDB: URL, knownOrg: String?, wantEmail: Bool) async throws -> FetchResult {
        let (sk, cookieOrg) = try login(cookiesDB: cookiesDB)
        var org = cookieOrg ?? knownOrg
        var json: [String: Any]
        if let o = org, let j = try? await get("/api/organizations/\(o)/usage", sessionKey: sk) as? [String: Any] {
            json = j
        } else {
            let o = try await pickOrg(sessionKey: sk)
            org = o
            json = try await get("/api/organizations/\(o)/usage", sessionKey: sk) as? [String: Any] ?? [:]
        }

        func window(_ key: String) -> (Double?, Date?) {
            guard let w = json[key] as? [String: Any] else { return (nil, nil) }
            return ((w["utilization"] as? NSNumber)?.doubleValue, (w["resets_at"] as? String).flatMap(parseISODate))
        }
        let (fh, fhr) = window("five_hour")
        let (sd, sdr) = window("seven_day")
        var email: String?
        if wantEmail, let acct = try? await get("/api/account", sessionKey: sk) as? [String: Any] {
            email = acct["email_address"] as? String
        }
        return FetchResult(usage: Usage(fiveHour: fh, fiveHourResets: fhr, sevenDay: sd, sevenDayResets: sdr, fetchedAt: Date()),
                           orgId: org!, email: email)
    }
}

/// Claude Desktop's own usage samples (plan-usage-history.json), used as a fallback per org.
enum UsageHistory {
    static func latestByOrg() -> [String: Usage] {
        guard let data = try? Data(contentsOf: Paths.usageHistory),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let samples = json["samples"] as? [[String: Any]] else { return [:] }
        var out: [String: Usage] = [:]
        for s in samples {
            guard let org = s["org"] as? String, let t = (s["t"] as? NSNumber)?.doubleValue,
                  let u = s["u"] as? [String: Any] else { continue }
            let date = Date(timeIntervalSince1970: t > 1e12 ? t / 1000 : t)
            if let existing = out[org], existing.fetchedAt >= date { continue }
            out[org] = Usage(fiveHour: (u["fh"] as? NSNumber)?.doubleValue, sevenDay: (u["sd"] as? NSNumber)?.doubleValue,
                             fetchedAt: date, cached: true)
        }
        return out
    }
}

// MARK: - Claude Desktop control & snapshots

enum ClaudeDesktop {
    static var running: [NSRunningApplication] { NSRunningApplication.runningApplications(withBundleIdentifier: claudeBundleID) }

    /// Asks Claude to quit and waits. Never force-kills: if Claude refuses (e.g. an unsaved dialog), we abort.
    static func quit() async throws {
        guard !running.isEmpty else { return }
        running.forEach { $0.terminate() }
        for _ in 0..<60 {
            try await Task.sleep(nanoseconds: 500_000_000)
            if running.isEmpty {
                try await Task.sleep(nanoseconds: 1_500_000_000) // let helpers flush to disk
                return
            }
        }
        throw AppError("Claude didn’t quit within 30s. Close it manually and try again.")
    }

    static func launch() {
        let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: claudeBundleID)
            ?? URL(fileURLWithPath: "/Applications/Claude.app")
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }
}

enum Snapshot {
    static let fm = FileManager.default

    static func readConfig() throws -> [String: Any] {
        guard let data = try? Data(contentsOf: Paths.claudeConfig) else { return [:] }
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AppError("Claude config.json is not an object")
        }
        return dict
    }

    static func writeConfig(_ dict: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .withoutEscapingSlashes])
        try data.write(to: Paths.claudeConfig, options: .atomic)
    }

    /// Copies the current login out of Claude's data dir into `dir` (replacing it).
    static func capture(to dir: URL) throws {
        let tmp = dir.deletingLastPathComponent().appendingPathComponent(dir.lastPathComponent + ".partial")
        try? fm.removeItem(at: tmp)
        try fm.createDirectory(at: tmp, withIntermediateDirectories: true)
        for item in authItems {
            let src = Paths.claudeData.appendingPathComponent(item)
            if fm.fileExists(atPath: src.path) { try fm.copyItem(at: src, to: tmp.appendingPathComponent(item)) }
        }
        let auth = try readConfig().filter { isAuthConfigKey($0.key) }
        try JSONSerialization.data(withJSONObject: auth, options: .prettyPrinted)
            .write(to: tmp.appendingPathComponent("auth-config.json"))
        try? fm.removeItem(at: dir)
        try fm.moveItem(at: tmp, to: dir)
    }

    /// Replaces Claude's login with the snapshot in `dir`, or signs out when `dir` is nil / missing.
    static func restore(from dir: URL?) throws {
        for item in authItems { try? fm.removeItem(at: Paths.claudeData.appendingPathComponent(item)) }
        var config = try readConfig().filter { !isAuthConfigKey($0.key) }
        if let dir, fm.fileExists(atPath: dir.path) {
            for item in authItems {
                let src = dir.appendingPathComponent(item)
                if fm.fileExists(atPath: src.path) { try fm.copyItem(at: src, to: Paths.claudeData.appendingPathComponent(item)) }
            }
            if let data = try? Data(contentsOf: dir.appendingPathComponent("auth-config.json")),
               let auth = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                config.merge(auth) { _, new in new }
            }
        }
        try writeConfig(config)
    }

    /// Safety copy of the current login before every switch; keeps the newest 5.
    static func backup() throws -> URL {
        try fm.createDirectory(at: Paths.backups, withIntermediateDirectories: true)
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let dir = Paths.backups.appendingPathComponent(stamp)
        try capture(to: dir)
        let all = (try? fm.contentsOfDirectory(at: Paths.backups, includingPropertiesForKeys: nil)) ?? []
        for old in all.sorted(by: { $0.lastPathComponent > $1.lastPathComponent }).dropFirst(5) { try? fm.removeItem(at: old) }
        return dir
    }
}

// MARK: - Shared Code & Cowork sessions
//
// Claude Desktop files local sessions under <root>/<accountUuid>/<orgUuid>/ and only shows the
// active account's folder. While Claude is closed during a switch, we merge every account's
// sessions into every folder (newest .json wins, APFS clones so nothing is really duplicated).
// A session that disappeared from a folder since the last sync was deleted there; it is moved
// out of the other folders into a trash dir instead of being re-added.

struct SessionSyncResult {
    var copied = 0
    var trashed = 0
    var listItems = 0
    var summary: String {
        copied + trashed + listItems == 0 ? "Sessions already in sync"
            : "Synced sessions: \(copied) copied, \(trashed) removed, \(listItems) lists updated"
    }
}

enum SessionSync {
    static let roots = ["claude-code-sessions", "local-agent-mode-sessions"]
    static let uuidPattern = #"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"#
    static let fm = FileManager.default

    /// `base` is Claude's data dir; `store` holds the manifest, trash and backups.
    static func sync(base: URL = Paths.claudeData, store: URL = Paths.support,
                     ensure extra: [(account: String, org: String)] = [],
                     includeScheduledTasks: Bool = false) throws -> SessionSyncResult {
        let manifestURL = store.appendingPathComponent("session-manifest.json")
        var manifest = (try? JSONDecoder().decode([String: [String]].self, from: Data(contentsOf: manifestURL))) ?? [:]
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        var result = SessionSyncResult()

        for rootName in roots {
            let root = base.appendingPathComponent(rootName)
            guard fm.fileExists(atPath: root.path) else { continue }
            for (account, org) in extra {
                try fm.createDirectory(at: root.appendingPathComponent(account).appendingPathComponent(org),
                                       withIntermediateDirectories: true)
            }
            let folders = accountFolders(root)
            guard folders.count > 1 else { continue }

            // id -> (folder, mtime) for every copy
            var copies: [String: [(folder: URL, mtime: Date)]] = [:]
            var present: [String: Set<String>] = [:]
            for folder in folders {
                let ids = sessionIds(in: folder)
                present[folder.path] = Set(ids.keys)
                for (id, mtime) in ids { copies[id, default: []].append((folder, mtime)) }
            }

            // Deleted = listed for a folder last time but gone now.
            var deleted = Set<String>()
            for folder in folders {
                if let before = manifest[folder.path] { deleted.formUnion(Set(before).subtracting(present[folder.path] ?? [])) }
            }
            if !deleted.isEmpty {
                let trash = store.appendingPathComponent("session-trash").appendingPathComponent(stamp)
                for id in deleted {
                    for c in copies[id] ?? [] {
                        let dest = trash.appendingPathComponent(rootName)
                            .appendingPathComponent(c.folder.deletingLastPathComponent().lastPathComponent)
                            .appendingPathComponent(c.folder.lastPathComponent)
                        try fm.createDirectory(at: dest, withIntermediateDirectories: true)
                        for item in items(for: id, in: c.folder) {
                            try? fm.removeItem(at: dest.appendingPathComponent(item.lastPathComponent))
                            try fm.moveItem(at: item, to: dest.appendingPathComponent(item.lastPathComponent))
                        }
                        result.trashed += 1
                    }
                    copies[id] = nil
                }
            }

            // Newest copy wins; push it to every folder that is missing or older.
            for (id, list) in copies {
                guard let best = list.max(by: { $0.mtime < $1.mtime }) else { continue }
                for folder in folders where folder != best.folder {
                    let mine = list.first { $0.folder == folder }
                    if let mine, mine.mtime.timeIntervalSince(best.mtime) > -1 { continue }
                    for item in items(for: id, in: best.folder) {
                        try clone(item, to: folder.appendingPathComponent(item.lastPathComponent))
                    }
                    result.copied += 1
                }
            }

            for folder in folders { manifest[folder.path] = Array(sessionIds(in: folder).keys).sorted() }

            if rootName == "claude-code-sessions" {
                try rebuildArchiveIndexes(folders)
                result.listItems += try mergeList(file: "backlog/tasks.json", key: "items", folders, &manifest)
                if includeScheduledTasks {
                    result.listItems += try mergeList(file: "scheduled-tasks.json", key: "scheduledTasks", folders, &manifest)
                }
            }
        }
        try fm.createDirectory(at: store, withIntermediateDirectories: true)
        try JSONEncoder().encode(manifest).write(to: manifestURL, options: .atomic)
        return result
    }

    /// Claude's archive index goes stale once sessions are merged, so each folder's is rebuilt from its session files.
    static func rebuildArchiveIndexes(_ folders: [URL]) throws {
        for folder in folders {
            let archived = sessionIds(in: folder).keys.filter { id in
                let file = folder.appendingPathComponent(id + ".json")
                let json = (try? Data(contentsOf: file)).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
                return json?["isArchived"] as? Bool == true
            }.sorted()
            let url = folder.appendingPathComponent("archived-sessions.idx")
            let current = (try? Data(contentsOf: url)).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
            if ((current?["archived"] as? [String]) ?? []).sorted() == archived && (current != nil || archived.isEmpty) { continue }
            let data = try JSONSerialization.data(withJSONObject: ["v": 1, "archived": archived] as [String: Any])
            try data.write(to: url, options: .atomic)
        }
    }

    /// Merges a JSON file holding a list of `{id: ...}` items across folders; returns how many folders were rewritten.
    /// For an id in several folders the copy in the newest file wins; an id gone from a folder since the last
    /// sync was removed there, so it is removed everywhere.
    static func mergeList(file: String, key: String, _ folders: [URL], _ manifest: inout [String: [String]]) throws -> Int {
        struct Source { var folder: URL; var mtime: Date; var top: [String: Any]; var items: [[String: Any]] }
        var sources: [Source] = []
        for folder in folders {
            let url = folder.appendingPathComponent(file)
            guard let data = try? Data(contentsOf: url),
                  let top = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            let mtime = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            sources.append(Source(folder: folder, mtime: mtime, top: top, items: top[key] as? [[String: Any]] ?? []))
        }
        guard !sources.isEmpty else { return 0 }
        sources.sort { $0.mtime > $1.mtime }

        var deleted = Set<String>()
        for s in sources {
            if let before = manifest["\(s.folder.path)#\(file)"] {
                deleted.formUnion(Set(before).subtracting(s.items.compactMap { $0["id"] as? String }))
            }
        }
        var merged: [[String: Any]] = [], seen = Set<String>()
        for s in sources {
            for item in s.items {
                guard let id = item["id"] as? String, !deleted.contains(id), seen.insert(id).inserted else { continue }
                var winner = item
                // Run history only moves forward, whichever file won.
                for field in ["lastRunAt", "lastScheduledFor"] {
                    let times = sources.flatMap { $0.items }.filter { $0["id"] as? String == id }.compactMap { $0[field] as? String }
                    if let latest = times.max() { winner[field] = latest }
                }
                merged.append(winner)
            }
        }

        var rewritten = 0
        let ids = merged.compactMap { $0["id"] as? String }.sorted()
        for folder in folders {
            let existing = sources.first { $0.folder == folder }
            let url = folder.appendingPathComponent(file)
            var top = existing?.top ?? sources[0].top
            top[key] = merged
            let options: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
            let new = try JSONSerialization.data(withJSONObject: top, options: options)
            let old = try existing.map { try JSONSerialization.data(withJSONObject: $0.top, options: options) }
            if new != old {
                try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                try JSONSerialization.data(withJSONObject: top, options: [.prettyPrinted, .withoutEscapingSlashes])
                    .write(to: url, options: .atomic)
                rewritten += 1
            }
            manifest["\(folder.path)#\(file)"] = ids
        }
        return rewritten
    }

    /// <root>/<accountUuid>/<orgUuid> folders (skips non-account dirs like skills-plugin).
    static func accountFolders(_ root: URL) -> [URL] {
        let accounts = (try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        return accounts.filter { $0.lastPathComponent.range(of: uuidPattern, options: .regularExpression) != nil }
            .flatMap { acct in
                ((try? fm.contentsOfDirectory(at: acct, includingPropertiesForKeys: [.isDirectoryKey])) ?? [])
                    .filter { $0.lastPathComponent.range(of: uuidPattern, options: .regularExpression) != nil }
            }
            .sorted { $0.path < $1.path }
    }

    /// local_<id>.json files in a folder, with their modification dates.
    static func sessionIds(in folder: URL) -> [String: Date] {
        let files = (try? fm.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
        var out: [String: Date] = [:]
        for f in files where f.lastPathComponent.hasPrefix("local_") && f.pathExtension == "json" {
            let date = (try? f.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            out[f.deletingPathExtension().lastPathComponent] = date
        }
        return out
    }

    /// The session's .json plus its sibling data folder (Cowork), when present.
    static func items(for id: String, in folder: URL) -> [URL] {
        [folder.appendingPathComponent(id + ".json"), folder.appendingPathComponent(id)]
            .filter { fm.fileExists(atPath: $0.path) }
    }

    /// Replaces `dest` with an APFS clone of `src` (falls back to a copy), keeping timestamps.
    static func clone(_ src: URL, to dest: URL) throws {
        let tmp = dest.deletingLastPathComponent().appendingPathComponent(".cs-\(UUID().uuidString)")
        let flags = copyfile_flags_t(COPYFILE_ALL | COPYFILE_CLONE | COPYFILE_RECURSIVE)
        guard copyfile(src.path, tmp.path, nil, flags) == 0 else {
            try? fm.removeItem(at: tmp)
            throw AppError("Couldn’t copy \(src.lastPathComponent) (errno \(errno))")
        }
        try? fm.removeItem(at: dest)
        try fm.moveItem(at: tmp, to: dest)
    }

    /// Clone-copies both session roots so a sync can be undone; keeps the newest 3.
    static func backup(base: URL = Paths.claudeData, store: URL = Paths.support) throws {
        let dir = store.appendingPathComponent("backups-sessions")
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let dest = dir.appendingPathComponent(stamp)
        try fm.createDirectory(at: dest, withIntermediateDirectories: true)
        for r in roots where fm.fileExists(atPath: base.appendingPathComponent(r).path) {
            try clone(base.appendingPathComponent(r), to: dest.appendingPathComponent(r))
        }
        let all = (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        for old in all.sorted(by: { $0.lastPathComponent > $1.lastPathComponent }).dropFirst(3) { try? fm.removeItem(at: old) }
    }
}

// MARK: - Claude in Chrome login
//
// The extension's tokens are memory-only, so they don't survive a Chrome restart. On startup it signs back in
// silently using the accountUuid and tokenOrg in chrome.storage.local (one LevelDB folder per Chrome profile) and
// Chrome's own claude.ai login, and fails if those two disagree. So both are swapped together while Chrome is
// closed. The cookies stay encrypted throughout: they are moved within one Chrome profile and never decrypted.
// Shortcuts and tasks saved in the extension live in the same folder, so they switch along with it.

enum ChromeExtension {
    static let id = "fcoeoabgfenejglbffodgkkbkcdhcgfn"
    static let bundleID = "com.google.Chrome"
    static let dataDir = Paths.home.appendingPathComponent("Library/Application Support/Google/Chrome")
    static let fm = FileManager.default

    static var running: [NSRunningApplication] { NSRunningApplication.runningApplications(withBundleIdentifier: bundleID) }

    static func storage(_ profile: String, chromeDir: URL) -> URL {
        chromeDir.appendingPathComponent(profile).appendingPathComponent("Local Extension Settings").appendingPathComponent(id)
    }

    /// Chrome profiles with the extension installed, as (folder, display name).
    static func profiles(chromeDir: URL = dataDir) -> [(dir: String, name: String)] {
        guard let data = try? Data(contentsOf: chromeDir.appendingPathComponent("Local State")),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let cache = (json["profile"] as? [String: Any])?["info_cache"] as? [String: [String: Any]] else { return [] }
        return cache.keys.sorted()
            .filter { fm.fileExists(atPath: chromeDir.appendingPathComponent($0).appendingPathComponent("Extensions").appendingPathComponent(id).path) }
            .map { ($0, cache[$0]?["name"] as? String ?? $0) }
    }

    /// Chrome's last used profile if it has the extension, else the first that does.
    static func suggestedProfile(chromeDir: URL = dataDir) -> String? {
        let all = profiles(chromeDir: chromeDir).map(\.dir)
        let local = (try? Data(contentsOf: chromeDir.appendingPathComponent("Local State"))).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
        if let last = (local?["profile"] as? [String: Any])?["last_used"] as? String, all.contains(last) { return last }
        return all.first
    }

    /// Moves Chrome's claude.ai cookies: saves the live rows to `saveTo`, then replaces them with `restoreFrom`'s
    /// (none = signed out of claude.ai). The replace is one transaction, so a failure leaves the cookies as they were.
    /// With `replace` false the live cookies are only copied, never changed.
    static func swapCookies(db path: URL, saveTo: URL?, restoreFrom: URL?, replace: Bool = true) throws {
        guard fm.fileExists(atPath: path.path) else { return }
        var db: OpaquePointer?
        // CREATE is for the ATTACHed snapshot file, which inherits these flags; the live DB is known to exist.
        guard sqlite3_open_v2(path.path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK else { throw AppError("Couldn’t open Chrome’s cookies") }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 5000)
        func run(_ sql: String) throws {
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                throw AppError("Chrome cookie swap failed: \(String(cString: sqlite3_errmsg(db)))")
            }
        }
        func quoted(_ url: URL) -> String { "'" + url.path.replacingOccurrences(of: "'", with: "''") + "'" }
        let hosts = "host_key = 'claude.ai' OR host_key LIKE '%.claude.ai'"
        if let saveTo {
            try fm.createDirectory(at: saveTo.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? fm.removeItem(at: saveTo)
            try run("ATTACH \(quoted(saveTo)) AS saved")
            try run("CREATE TABLE saved.cookies AS SELECT * FROM main.cookies WHERE \(hosts)")
            var check: OpaquePointer?
            var sessions = 0
            if sqlite3_prepare_v2(db, "SELECT count(*) FROM saved.cookies WHERE name = 'sessionKey'", -1, &check, nil) == SQLITE_OK,
               sqlite3_step(check) == SQLITE_ROW { sessions = Int(sqlite3_column_int(check, 0)) }
            sqlite3_finalize(check)
            switchLog("cookies: saved \(saveTo.deletingLastPathComponent().lastPathComponent.prefix(8)) hasSession=\(sessions > 0)")
            try run("DETACH saved")
        }
        guard replace else { return }
        let restore = restoreFrom.flatMap { fm.fileExists(atPath: $0.path) ? $0 : nil }
        if let restore { try run("ATTACH \(quoted(restore)) AS target") }
        try run("BEGIN IMMEDIATE")
        do {
            try run("DELETE FROM main.cookies WHERE \(hosts)")
            if restore != nil { try run("INSERT INTO main.cookies SELECT * FROM target.cookies") }
            try run("COMMIT")
        } catch {
            try? run("ROLLBACK")
            throw error
        }
    }

    /// Asks Chrome to quit, then falls back to SIGTERM, which Chrome also treats as a clean exit and which
    /// restores tabs afterwards. Never force-kills, so if both fail the swap is abandoned.
    static func quit() async throws {
        func waitForExit(seconds: Int) async throws -> Bool {
            for _ in 0..<(seconds * 2) {
                try await Task.sleep(nanoseconds: 500_000_000)
                if running.isEmpty { return true }
            }
            return false
        }
        guard !running.isEmpty else { return switchLog("chrome: not running") }
        let accepted = running.map { $0.terminate() }
        switchLog("chrome: terminate accepted=\(accepted)")
        var exited = try await waitForExit(seconds: 6)
        if !exited {
            let pids = running.map(\.processIdentifier)
            switchLog("chrome: still running after terminate, sending SIGTERM to \(pids)")
            pids.forEach { kill($0, SIGTERM) }
            exited = try await waitForExit(seconds: 12)
        }
        switchLog("chrome: exited=\(exited)")
        guard exited else { throw AppError("Chrome didn’t quit, so the extension stayed on its current account.") }
        try await Task.sleep(nanoseconds: 1_500_000_000) // let Chrome release the LevelDB lock
    }

    static func reopen() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { return }
        let config = NSWorkspace.OpenConfiguration()
        config.arguments = ["--restore-last-session"]
        NSWorkspace.shared.openApplication(at: url, configuration: config)
    }

    /// The Claude account the extension in this profile was last signed in to: the newest `accountUuid` value
    /// in its storage files. Values sit unencrypted in LevelDB, and newer files and later bytes win.
    static func liveAccount(profile: String, chromeDir: URL = dataDir) -> String? {
        let dir = storage(profile, chromeDir: chromeDir)
        let files = ((try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [])
            .filter { ["ldb", "log"].contains($0.pathExtension) }
            // LevelDB numbers files in write order; the .log holds the newest writes.
            .sorted { ($0.pathExtension == "log" ? 1 : 0, $0.lastPathComponent) < ($1.pathExtension == "log" ? 1 : 0, $1.lastPathComponent) }
        let key = Data("accountUuid".utf8)
        let uuid = try! NSRegularExpression(pattern: "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        var latest: String?
        for file in files {
            guard let data = try? Data(contentsOf: file) else { continue }
            var start = data.startIndex
            while let r = data.range(of: key, in: start..<data.endIndex) {
                let window = data[r.upperBound..<min(r.upperBound + 64, data.endIndex)]
                let text = String(decoding: window, as: UTF8.self)
                if let m = uuid.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
                   let range = Range(m.range, in: text) { latest = String(text[range]) }
                start = r.upperBound
            }
        }
        return latest
    }

    /// Saves the live login under the account it actually belongs to and restores `to`'s; an account with nothing
    /// saved comes up signed out. `accounts` maps Claude account UUIDs to switcher account ids, so a login that
    /// drifted out of step with Claude Desktop is never filed under the wrong account. Chrome must be closed.
    static func swap(profile: String, from: String?, to: String, accounts: [String: String]? = nil,
                     chromeDir: URL = dataDir, store: URL = Paths.support) throws {
        let live = storage(profile, chromeDir: chromeDir)
        func saved(_ account: String) -> URL {
            store.appendingPathComponent("chrome-extension").appendingPathComponent(account).appendingPathComponent(profile)
        }
        let hadLogin = fm.fileExists(atPath: live.path)
        let liveUuid = hadLogin ? liveAccount(profile: profile, chromeDir: chromeDir) : nil
        // Without a mapping (test hook) trust `from`; with one, file the login only under its real owner.
        let owner = accounts == nil ? from : liveUuid.flatMap { accounts?[$0] }
        switchLog("extension: live account=\(liveUuid?.prefix(8) ?? "none") owner=\(owner?.prefix(8) ?? "none") from=\(from?.prefix(8) ?? "none") to=\(to.prefix(8))")
        func savedCookies(_ account: String) -> URL { saved(account).appendingPathExtension("cookies.sqlite") }
        let cookies = chromeDir.appendingPathComponent(profile).appendingPathComponent("Cookies")
        if owner == to, hadLogin {
            // Already signed in to the target; just remember it, cookies included.
            try fm.createDirectory(at: saved(to).deletingLastPathComponent(), withIntermediateDirectories: true)
            try SessionSync.clone(live, to: saved(to))
            try swapCookies(db: cookies, saveTo: savedCookies(to), restoreFrom: nil, replace: false)
            return
        }
        let backups = store.appendingPathComponent("backups-chrome")
        let backup = backups.appendingPathComponent(ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-"))
        // Cookies are backed up first and unconditionally: they are about to be replaced, and an unknown owner
        // (below) means there is no account to file them under.
        try fm.createDirectory(at: backup, withIntermediateDirectories: true)
        try swapCookies(db: cookies, saveTo: backup.appendingPathComponent(profile).appendingPathExtension("cookies.sqlite"), restoreFrom: nil, replace: false)
        if hadLogin {
            try SessionSync.clone(live, to: backup.appendingPathComponent(profile))
            let all = (try? fm.contentsOfDirectory(at: backups, includingPropertiesForKeys: nil)) ?? []
            for old in all.sorted(by: { $0.lastPathComponent > $1.lastPathComponent }).dropFirst(3) { try? fm.removeItem(at: old) }
        }
        if let owner, hadLogin {
            try fm.createDirectory(at: saved(owner).deletingLastPathComponent(), withIntermediateDirectories: true)
            try SessionSync.clone(live, to: saved(owner))
        }
        try swapCookies(db: cookies, saveTo: owner.map(savedCookies), restoreFrom: savedCookies(to))
        do {
            if fm.fileExists(atPath: saved(to).path) {
                try fm.createDirectory(at: live.deletingLastPathComponent(), withIntermediateDirectories: true)
                try SessionSync.clone(saved(to), to: live)
            } else if hadLogin {
                try fm.removeItem(at: live)
            }
        } catch {
            if hadLogin { try? SessionSync.clone(backup.appendingPathComponent(profile), to: live) }
            throw error
        }
    }

    static func forget(account: String, store: URL = Paths.support) {
        try? fm.removeItem(at: store.appendingPathComponent("chrome-extension").appendingPathComponent(account))
    }
}

// MARK: - Permissions

/// Touches everything the app needs so macOS asks for all of it during setup, not in the middle of a switch.
/// Each check is a plain read that triggers the system prompt if access hasn't been granted yet.
struct PermissionCheck: Identifiable, Equatable {
    var id: String { name }
    var name: String
    var purpose: String
    var problem: String?
}

enum Permissions {
    static func check() -> [PermissionCheck] {
        func read(_ url: URL) -> String? {
            guard FileManager.default.fileExists(atPath: url.path) else { return nil }
            do {
                _ = try Data(contentsOf: url, options: .mappedIfSafe)
                return nil
            } catch {
                switchLog("permissions: can't read \(url.lastPathComponent): \(error.localizedDescription)")
                return "macOS blocked access. Use Try Again and choose Allow, or turn on Full Disk Access for Claude Switcher."
            }
        }
        var checks = [PermissionCheck(name: "Claude Desktop data", purpose: "To save and restore each account’s login",
                                      problem: read(Paths.claudeData.appendingPathComponent("Cookies")) ?? read(Paths.claudeConfig))]
        var keychain: String?
        do { _ = try ChromeCrypto.key() } catch { keychain = error.localizedDescription }
        checks.append(PermissionCheck(name: "“Claude Safe Storage” in Keychain", purpose: "To check usage on every account. Choose Always Allow.", problem: keychain))
        if FileManager.default.fileExists(atPath: ChromeExtension.dataDir.path) {
            let chrome = ChromeExtension.suggestedProfile().map { ChromeExtension.dataDir.appendingPathComponent($0).appendingPathComponent("Cookies") }
            let blocked = read(ChromeExtension.dataDir.appendingPathComponent("Local State")) ?? chrome.flatMap(read)
            checks.append(PermissionCheck(name: "Chrome data", purpose: "To switch the Claude in Chrome extension",
                                          problem: blocked == nil ? nil : "Needs Full Disk Access. Click Grant Access and drag the app into the list."))
        }
        return checks
    }

    static func openSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") { NSWorkspace.shared.open(url) }
    }

}

// MARK: - Full Disk Access helper
//
// macOS has no API to request Full Disk Access, and an app only shows up in that list once it's added. So this
// opens the list next to a small floating window holding the app's icon to drag in, then watches for the grant
// and closes itself once Chrome's data is readable.

enum AccessHelper {
    private static var panel: NSPanel?
    private static var timer: Timer?

    static var chromeReadable: Bool {
        (try? Data(contentsOf: ChromeExtension.dataDir.appendingPathComponent("Local State"))) != nil
    }

    @MainActor static func show(model: AppModel) {
        Permissions.openSettings()
        if panel == nil {
            let p = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 300, height: 290),
                            styleMask: [.titled, .closable, .utilityWindow, .nonactivatingPanel],
                            backing: .buffered, defer: false)
            p.title = "Give Full Disk Access"
            p.level = .floating
            p.isReleasedWhenClosed = false
            p.hidesOnDeactivate = false
            p.contentView = NSHostingView(rootView: AccessHelperView())
            panel = p
        }
        if let visible = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame, let p = panel {
            p.setFrameTopLeftPoint(NSPoint(x: visible.maxX - p.frame.width - 24, y: visible.maxY - 24))
        }
        panel?.orderFrontRegardless()
        switchLog("permissions: showing Full Disk Access helper")
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { _ in
            guard chromeReadable else { return }
            timer?.invalidate()
            timer = nil
            panel?.close()
            switchLog("permissions: Chrome data readable")
            Task { @MainActor in await model.checkPermissions() }
        }
    }
}

struct AccessHelperView: View {
    var body: some View {
        VStack(spacing: 12) {
            Text("Drag this icon into the Full Disk Access list")
                .font(.system(size: 13, weight: .semibold)).multilineTextAlignment(.center)
            VStack(spacing: 4) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath))
                    .resizable().frame(width: 64, height: 64)
                Text("ClaudeSwitcher").font(.system(size: 11, weight: .medium))
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.claude.opacity(0.6), style: StrokeStyle(lineWidth: 1.5, dash: [5, 4])))
            .onDrag { NSItemProvider(object: Bundle.main.bundleURL as NSURL) }
            .help("Drag into System Settings → Full Disk Access")
            VStack(alignment: .leading, spacing: 4) {
                Text("1. Drop it on the list in System Settings")
                Text("2. Confirm with Touch ID or your password")
                Text("3. Make sure its switch is on")
            }
            .font(.system(size: 11)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
            Text("This window closes by itself once access works.")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
            Button("Show in Finder Instead") { NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL]) }
                .buttonStyle(.link).font(.system(size: 11))
        }
        .padding(16)
        .frame(width: 300)
    }
}

// MARK: - App model

@MainActor
final class AppModel: ObservableObject {
    @Published var state: AppState { didSet { if state != oldValue && !isDemo { save() } } }
    @Published var busy: String?
    @Published var lastRefresh: Date?
    @Published var lastSessionSync: String?
    @Published var permissions: [PermissionCheck] = []
    private var pendingAlert: String?
    private var restartChrome = true
    var isSnapshot = false
    @Published var launchAtLogin = SMAppService.mainApp.status == .enabled

    private var timer: Timer?
    private var refreshing = false
    private var lastAutoPrompt: Date?

    init(autoRefresh: Bool = true) {
        if let data = try? Data(contentsOf: Paths.state), let s = try? JSONDecoder.app.decode(AppState.self, from: data) {
            state = s
        } else {
            state = AppState()
        }
        try? FileManager.default.createDirectory(at: Paths.profiles, withIntermediateDirectories: true)
        guard autoRefresh else { return }
        timer = Timer.scheduledTimer(withTimeInterval: max(1, state.settings.pollMinutes) * 60, repeats: true) { [weak self] _ in
            Task { await self?.refreshAll() }
        }
        reconcileActiveAccount()
        Task {
            await checkPermissions()
            if state.settings.switchChromeExtension, permissions.contains(where: { $0.name == "Chrome data" && $0.problem != nil }) {
                AccessHelper.show(model: self)
            }
            await refreshAll()
        }
    }

    /// Runs off the main thread: each check can block on a system prompt until it's answered.
    func checkPermissions() async {
        permissions = await Task.detached { Permissions.check() }.value
    }

    var active: Profile? { state.profiles.first { $0.id == state.activeId } }

    /// Made-up accounts for README screenshots (`--snapshot out.png --demo`). Never saved.
    func loadDemo() {
        let now = Date()
        func usage(_ fh: Double, _ fhIn: Double, _ sd: Double, _ sdIn: Double) -> Usage {
            Usage(fiveHour: fh, fiveHourResets: now + fhIn * 3600, sevenDay: sd, sevenDayResets: now + sdIn * 3600, fetchedAt: now)
        }
        let personal = Profile(name: "Personal", email: "alex@example.com", usage: usage(42, 2.6, 18, 90))
        let work = Profile(name: "Work", email: "alex@acme.example", usage: usage(93, 0.7, 64, 40))
        let side = Profile(name: "Side Project", email: "alex.builds@example.com", usage: usage(3, 4.9, 27, 130))
        isDemo = true
        state = AppState(profiles: [work, personal, side], activeId: work.id, settings: state.settings)
    }

    /// Empty first-run state for screenshots. Never saved.
    func isDemoOnly() {
        isDemo = true
        state = AppState()
    }

    /// Demo data is never written to disk.
    private var isDemo = false

    var menuTitle: String {
        guard let u = active?.usage else { return "–" }
        return "\(Int(u.fh.rounded()))%"
    }

    func save() {
        try? FileManager.default.createDirectory(at: Paths.support, withIntermediateDirectories: true)
        if let data = try? JSONEncoder.app.encode(state) { try? data.write(to: Paths.state, options: .atomic) }
    }

    func profileDir(_ id: UUID) -> URL { Paths.profiles.appendingPathComponent(id.uuidString) }

    // MARK: Refresh

    func refreshAll() async {
        guard !refreshing else { return }
        if busy == nil { reconcileActiveAccount() }
        refreshing = true
        defer { refreshing = false }
        let history = UsageHistory.latestByOrg()

        for p in state.profiles {
            let db = (p.id == state.activeId ? Paths.claudeData : profileDir(p.id)).appendingPathComponent("Cookies")
            let org = p.orgId, wantEmail = p.email == nil
            let result = await Task.detached { try await UsageClient.fetch(cookiesDB: db, knownOrg: org, wantEmail: wantEmail) }.result
            guard let i = state.profiles.firstIndex(where: { $0.id == p.id }) else { continue }
            switch result {
            case .success(let r):
                state.profiles[i].usage = r.usage
                state.profiles[i].orgId = r.orgId
                if let e = r.email { state.profiles[i].email = e }
                state.profiles[i].lastError = nil
            case .failure(let e):
                state.profiles[i].lastError = e.localizedDescription
                if let org = state.profiles[i].orgId, let cached = history[org],
                   cached.fetchedAt > (state.profiles[i].usage?.fetchedAt ?? .distantPast) {
                    state.profiles[i].usage = cached
                }
            }
        }
        lastRefresh = Date()
        evaluateAutoSwitch()
    }

    // MARK: Auto-switch

    func evaluateAutoSwitch() {
        let s = state.settings
        guard s.mode != .off, busy == nil, let cur = active, let u = cur.usage else { return }
        guard u.fh >= s.threshold || u.sd >= s.weeklyThreshold else { return }
        if let last = lastAutoPrompt, Date().timeIntervalSince(last) < 20 * 60 { return }

        let candidates = state.profiles
            .filter { $0.id != cur.id && $0.lastError == nil }
            .compactMap { p in p.usage.map { (p, $0) } }
            .filter { $0.1.fh < s.threshold - 10 && $0.1.sd < s.weeklyThreshold }
            .sorted { ($0.1.fh, $0.1.sd) < ($1.1.fh, $1.1.sd) }
        guard let (target, tu) = candidates.first else { return }
        lastAutoPrompt = Date()

        let reason = u.fh >= s.threshold ? "\(Int(u.fh))% of its 5-hour limit" : "\(Int(u.sd))% of its weekly limit"
        if s.mode == .ask {
            let ok = confirm("“\(cur.name)” is at \(reason)",
                             "Switch Claude Desktop to “\(target.name)” (5h \(Int(tu.fh))%, 7d \(Int(tu.sd))%)?\n\nClaude will quit and relaunch — running chats and Code sessions are interrupted.",
                             ok: "Switch")
            guard ok else { return }
        }
        Task { await switchTo(target.id) }
    }

    // MARK: Account actions

    func importCurrent(name: String) {
        let p = Profile(name: name)
        state.profiles.append(p)
        state.activeId = p.id
        Task { await refreshAll() }
    }

    func switchTo(_ id: UUID) async {
        guard busy == nil, id != state.activeId, let target = state.profiles.first(where: { $0.id == id }) else { return }
        reconcileActiveAccount()
        // A switch you just made shouldn't be undone by auto-switch, even onto an account near its limit.
        lastAutoPrompt = Date()
        switchLog("switch: to \(id.uuidString.prefix(8))")
        await perform("Switching to \(target.name)…") {
            try await self.swapLogin(to: self.profileDir(id), org: target.orgId, target: id, name: target.name)
            self.state.activeId = id
        }
    }

    func addAccount(name: String) async {
        guard busy == nil else { return }
        await perform("Signing out for new account…") {
            let p = Profile(name: name)
            try await self.swapLogin(to: nil, org: nil, target: p.id, name: name)
            self.state.profiles.append(p)
            self.state.activeId = p.id
        }
    }

    /// Quit Claude, save the active login, restore `dir` (nil = signed out), relaunch.
    private func swapLogin(to dir: URL?, org: String?, target: UUID, name: String) async throws {
        restartChrome = confirmChromeRestart(name: name)
        try await ClaudeDesktop.quit()
        let backup = try Snapshot.backup()
        do {
            if let cur = state.activeId { try Snapshot.capture(to: profileDir(cur)) }
            try Snapshot.restore(from: dir)
        } catch {
            try? Snapshot.restore(from: backup)
            ClaudeDesktop.launch()
            throw error
        }
        if state.settings.shareSessions { await syncSessions(org: org) }
        pendingAlert = await swapChromeExtension(to: target)
        ClaudeDesktop.launch()
    }

    /// Makes the active account match who Claude Desktop is really signed in as, so a login can never be
    /// captured under the wrong account (after a crash, a quit mid-switch, or signing in by hand).
    func reconcileActiveAccount() {
        guard let live = (try? Snapshot.readConfig())?["lastKnownAccountUuid"] as? String else { return }
        for p in state.profiles where p.id != state.activeId {
            let url = profileDir(p.id).appendingPathComponent("auth-config.json")
            let config = (try? Data(contentsOf: url)).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
            if config?["lastKnownAccountUuid"] as? String == live {
                switchLog("reconcile: Claude Desktop is on \(p.id.uuidString.prefix(8)), was marked \(state.activeId?.uuidString.prefix(8) ?? "none")")
                state.activeId = p.id
                return
            }
        }
    }

    /// Asks before anything quits, so Chrome closing is never a surprise. Also pauses an automatic switch until
    /// answered, because closing Chrome unattended could lose work. Returns false to leave Chrome alone.
    private func confirmChromeRestart(name: String) -> Bool {
        guard state.settings.switchChromeExtension, !ChromeExtension.running.isEmpty else { return true }
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Restart Chrome to switch to “\(name)”?"
        a.informativeText = "Chrome has to restart so the Claude extension can load this account. It closes and reopens by itself with your tabs restored. Save anything you’re working on in Chrome first."
        a.addButton(withTitle: "Restart Chrome")
        a.addButton(withTitle: "Keep Chrome Open")
        let ok = a.runModal() == .alertFirstButtonReturn
        switchLog("extension: restart Chrome answered \(ok)")
        return ok
    }

    /// Never blocks a switch: returns what went wrong, if anything, so Claude still ends up on the new account.
    private func swapChromeExtension(to target: UUID) async -> String? {
        guard state.settings.switchChromeExtension else { switchLog("extension: toggle off"); return nil }
        guard restartChrome else { return "Chrome stayed open, so the Claude extension is still on its previous account. Switch again to restart it." }
        guard let profile = state.settings.chromeProfileDir ?? ChromeExtension.suggestedProfile() else {
            let blocked = FileManager.default.fileExists(atPath: ChromeExtension.dataDir.path)
                && (try? Data(contentsOf: ChromeExtension.dataDir.appendingPathComponent("Local State"))) == nil
            switchLog("extension: no profile found, macOS blocking Chrome data=\(blocked)")
            return blocked ? "Claude Switcher needs Full Disk Access to switch the Chrome extension. Open the panel and click Grant Access."
                           : "No Chrome profile with the Claude extension was found."
        }
        busy = "Switching Chrome extension…"
        let wasRunning = !ChromeExtension.running.isEmpty
        switchLog("extension: profile=\(profile) chromeRunning=\(wasRunning)")
        do {
            try await ChromeExtension.quit()
        } catch {
            switchLog("extension: \(error.localizedDescription)")
            return error.localizedDescription
        }
        defer { if wasRunning { ChromeExtension.reopen() } }
        let from = state.activeId?.uuidString
        do {
            try ChromeExtension.swap(profile: profile, from: from, to: target.uuidString, accounts: claudeAccounts())
            switchLog("extension: swapped")
            return nil
        } catch {
            switchLog("extension: swap failed: \(error.localizedDescription)")
            return error.localizedDescription
        }
    }

    /// Claude account UUID → switcher account id, from each account's saved login. Never from Claude Desktop's live
    /// config: mid-switch that already holds the target account, while the outgoing one was just saved.
    private func claudeAccounts() -> [String: String] {
        var map: [String: String] = [:]
        for p in state.profiles {
            let url = profileDir(p.id).appendingPathComponent("auth-config.json")
            let config = (try? Data(contentsOf: url)).flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
            if let uuid = config?["lastKnownAccountUuid"] as? String { map[uuid] = p.id.uuidString }
        }
        return map
    }


    /// Syncs without switching, e.g. to bring sessions to an account that just signed in for the first time.
    func promptSyncNow() {
        guard busy == nil, confirm("Sync Code sessions now?", "Claude Desktop will quit and relaunch — running chats and Code sessions are interrupted.", ok: "Sync") else { return }
        let org = active?.orgId
        Task {
            await perform("Syncing Code & Cowork sessions…") {
                try await ClaudeDesktop.quit()
                await self.syncSessions(org: org)
                ClaudeDesktop.launch()
            }
        }
    }

    /// Merges Code & Cowork sessions across accounts. Never blocks a switch: failures are only reported.
    private func syncSessions(org: String?) async {
        busy = "Syncing Code & Cowork sessions…"
        let account = (try? Snapshot.readConfig())?["lastKnownAccountUuid"] as? String
        let ensure = [account, org].allSatisfy { $0 != nil } ? [(account!, org!)] : []
        let includeTasks = state.settings.shareScheduledTasks
        let result = await Task.detached { () -> Result<SessionSyncResult, Error> in
            Result {
                try SessionSync.backup()
                return try SessionSync.sync(ensure: ensure, includeScheduledTasks: includeTasks)
            }
        }.value
        switch result {
        case .success(let r): lastSessionSync = r.summary
        case .failure(let e): lastSessionSync = "Session sync failed: \(e.localizedDescription)"
        }
    }

    @discardableResult
    private func perform(_ label: String, _ work: @escaping () async throws -> Void) async -> Bool {
        busy = label
        do {
            try await work()
            busy = nil
            // Shown only after the caller's work, so the new active account is already saved.
            if let message = pendingAlert {
                pendingAlert = nil
                alert("Chrome extension not switched", message)
            }
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            await refreshAll()
            return true
        } catch {
            busy = nil
            alert("Couldn’t switch accounts", error.localizedDescription)
            return false
        }
    }

    func remove(_ id: UUID) {
        guard id != state.activeId else { return }
        try? FileManager.default.removeItem(at: profileDir(id))
        ChromeExtension.forget(account: id.uuidString)
        state.profiles.removeAll { $0.id == id }
    }

    func rename(_ id: UUID, to name: String) {
        if let i = state.profiles.firstIndex(where: { $0.id == id }) { state.profiles[i].name = name }
    }

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            alert("Launch at login failed", error.localizedDescription + "\n\nMove the app to ~/Applications or /Applications first.")
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    // MARK: Prompts

    func promptImport() {
        if let name = promptText("Name this account", "Saves the account currently signed in to Claude Desktop.", "Account 1") {
            importCurrent(name: name)
        }
    }

    func promptAdd() {
        if let name = promptText("Add another account",
                                 "Claude Desktop will quit and reopen signed out. Sign in with the new account — it’s saved automatically the next time you switch.",
                                 "Account \(state.profiles.count + 1)") {
            Task { await addAccount(name: name) }
        }
    }

    func promptSwitch(_ id: UUID) {
        guard let p = state.profiles.first(where: { $0.id == id }) else { return }
        if confirm("Switch to “\(p.name)”?", "Claude Desktop will quit and relaunch signed in as \(p.email ?? p.name).", ok: "Switch") {
            Task { await switchTo(id) }
        }
    }

    func promptRename(_ id: UUID) {
        guard let p = state.profiles.first(where: { $0.id == id }) else { return }
        if let name = promptText("Rename account", "", p.name) { rename(id, to: name) }
    }

    func promptRemove(_ id: UUID) {
        guard let p = state.profiles.first(where: { $0.id == id }) else { return }
        if confirm("Remove “\(p.name)”?", "Deletes its saved login from Claude Switcher. The account itself is not affected.", ok: "Remove") {
            remove(id)
        }
    }
}

// MARK: - Dialog helpers

@MainActor func promptText(_ title: String, _ info: String, _ initial: String) -> String? {
    NSApp.activate(ignoringOtherApps: true)
    let a = NSAlert()
    a.messageText = title
    a.informativeText = info
    let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
    field.stringValue = initial
    a.accessoryView = field
    a.addButton(withTitle: "OK")
    a.addButton(withTitle: "Cancel")
    a.window.initialFirstResponder = field
    guard a.runModal() == .alertFirstButtonReturn else { return nil }
    let s = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    return s.isEmpty ? nil : s
}

@MainActor func confirm(_ title: String, _ info: String, ok: String) -> Bool {
    NSApp.activate(ignoringOtherApps: true)
    let a = NSAlert()
    a.messageText = title
    a.informativeText = info
    a.addButton(withTitle: ok)
    a.addButton(withTitle: "Cancel")
    return a.runModal() == .alertFirstButtonReturn
}

@MainActor func alert(_ title: String, _ info: String) {
    NSApp.activate(ignoringOtherApps: true)
    let a = NSAlert()
    a.messageText = title
    a.informativeText = info
    a.alertStyle = .warning
    a.runModal()
}

extension JSONEncoder { static let app: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = .prettyPrinted; return e }() }
extension JSONDecoder { static let app: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }() }

// MARK: - Views

extension Color {
    static let claude = Color(red: 0.851, green: 0.467, blue: 0.341)
    static func level(_ v: Double) -> Color {
        v >= 90 ? Color(red: 0.90, green: 0.32, blue: 0.30) : v >= 70 ? Color(red: 0.95, green: 0.63, blue: 0.23) : .claude
    }
}

func resetText(_ date: Date?) -> String {
    guard let date else { return "" }
    let secs = date.timeIntervalSinceNow
    if secs <= 0 { return "reset" }
    if secs >= 24 * 3600 {
        let f = DateFormatter()
        f.dateFormat = "EEE h a"
        return f.string(from: date)
    }
    let h = Int(secs) / 3600, m = (Int(secs) % 3600) / 60
    return h > 0 ? "in \(h)h \(m)m" : "in \(m)m"
}

/// Template ring for the menubar, filled to the active account's 5-hour usage.
func ringImage(_ pct: Double?) -> NSImage {
    let img = NSImage(size: NSSize(width: 16, height: 16), flipped: false) { rect in
        let lw: CGFloat = 2.2
        let r = rect.insetBy(dx: lw / 2 + 1, dy: lw / 2 + 1)
        let track = NSBezierPath(ovalIn: r)
        track.lineWidth = lw
        NSColor.black.withAlphaComponent(0.3).setStroke()
        track.stroke()
        if let p = pct, p > 0 {
            let arc = NSBezierPath()
            arc.appendArc(withCenter: NSPoint(x: rect.midX, y: rect.midY), radius: r.width / 2,
                          startAngle: 90, endAngle: 90 - 360 * CGFloat(min(p, 100) / 100), clockwise: true)
            arc.lineWidth = lw
            arc.lineCapStyle = .round
            NSColor.black.setStroke()
            arc.stroke()
        }
        return true
    }
    img.isTemplate = true
    return img
}

struct Avatar: View {
    let name: String
    var initials: String {
        let parts = name.split(separator: " ").prefix(2).compactMap(\.first)
        return parts.isEmpty ? "?" : String(parts).uppercased()
    }
    var hue: Double { Double(name.unicodeScalars.reduce(7) { ($0 * 31 + Int($1.value)) % 997 } % 360) / 360 }

    var body: some View {
        Circle()
            .fill(LinearGradient(colors: [Color(hue: hue, saturation: 0.42, brightness: 0.88),
                                          Color(hue: hue, saturation: 0.62, brightness: 0.66)],
                                 startPoint: .topLeading, endPoint: .bottomTrailing))
            .frame(width: 30, height: 30)
            .overlay(Text(initials).font(.system(size: 12, weight: .semibold, design: .rounded)).foregroundStyle(.white))
    }
}

struct Meter: View {
    let title: String
    let value: Double
    let reset: Date?

    var body: some View {
        let color = Color.level(value)
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(title).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                Spacer()
                if reset != nil {
                    Text(resetText(reset)).font(.system(size: 10)).foregroundStyle(.tertiary)
                }
                Text("\(Int(value.rounded()))%")
                    .font(.system(size: 11, weight: .semibold, design: .rounded)).monospacedDigit()
                    .foregroundStyle(value >= 70 ? color : .primary)
                    .frame(minWidth: 30, alignment: .trailing)
            }
            GeometryReader { g in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.primary.opacity(0.08))
                    Capsule()
                        .fill(LinearGradient(colors: [color.opacity(0.7), color], startPoint: .leading, endPoint: .trailing))
                        .frame(width: value > 0 ? max(5, g.size.width * min(value, 100) / 100) : 0)
                }
            }
            .frame(height: 5)
            .animation(.easeOut(duration: 0.4), value: value)
        }
    }
}

struct PillButtonStyle: ButtonStyle {
    var prominent = true
    func makeBody(configuration: Configuration) -> some View { PillLabel(configuration: configuration, prominent: prominent) }

    struct PillLabel: View {
        let configuration: Configuration
        let prominent: Bool
        @Environment(\.isEnabled) private var enabled
        var body: some View {
            configuration.label
                .font(.system(size: 11, weight: .semibold))
                .padding(.horizontal, 11).padding(.vertical, 4)
                .background(Capsule().fill(prominent ? Color.claude : Color.primary.opacity(0.08)))
                .foregroundStyle(prominent ? Color.white : Color.primary)
                .opacity(enabled ? (configuration.isPressed ? 0.75 : 1) : 0.4)
                .contentShape(Capsule())
        }
    }
}

struct IconButton: View {
    let systemName: String
    let help: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(hovering ? .primary : .secondary)
                .frame(width: 24, height: 24)
                .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color.primary.opacity(hovering ? 0.08 : 0)))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(help)
        .onHover { hovering = $0 }
    }
}

struct AccountCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    @State private var hovering = false
    var isActive: Bool { model.state.activeId == profile.id }

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 10) {
                Avatar(name: profile.name)
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(profile.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                        if isActive {
                            Text("ACTIVE")
                                .font(.system(size: 8.5, weight: .bold)).tracking(0.5)
                                .padding(.horizontal, 5).padding(.vertical, 2)
                                .background(Capsule().fill(Color.claude.opacity(0.16)))
                                .foregroundStyle(Color.claude)
                        }
                    }
                    Text(profile.email ?? "Waiting for sign-in…")
                        .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                Spacer(minLength: 4)
                if !isActive {
                    Button("Switch") { model.promptSwitch(profile.id) }
                        .buttonStyle(PillButtonStyle())
                        .disabled(model.busy != nil)
                }
                if model.isSnapshot {
                    // ImageRenderer can't draw AppKit-backed menus.
                    Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary).opacity(0.5)
                } else {
                    Menu {
                        Button("Rename…") { model.promptRename(profile.id) }
                        Button("Show Saved Login in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([model.profileDir(profile.id)])
                        }
                        Divider()
                        Button("Remove…") { model.promptRemove(profile.id) }.disabled(isActive)
                    } label: {
                        Image(systemName: "ellipsis").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)
                    }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                    .opacity(hovering ? 1 : 0.5)
                }
            }

            if let u = profile.usage {
                VStack(spacing: 9) {
                    Meter(title: "5-hour session", value: u.fh, reset: u.fiveHourResets)
                    Meter(title: "Weekly", value: u.sd, reset: u.sevenDayResets)
                }
                if u.cached {
                    Text("Cached · \(u.fetchedAt.formatted(date: .omitted, time: .shortened))")
                        .font(.system(size: 10)).foregroundStyle(.tertiary)
                }
            } else if profile.lastError == nil {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.mini)
                    Text("Loading usage…").font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }

            if let err = profile.lastError {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11)).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.primary.opacity(isActive ? 0.055 : (hovering ? 0.045 : 0.025)))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(isActive ? Color.claude.opacity(0.5) : Color.primary.opacity(0.07), lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .onHover { hovering = $0 }
    }
}

struct SettingRow<Control: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder let control: Control

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 12))
                if let subtitle { Text(subtitle).font(.system(size: 10)).foregroundStyle(.secondary) }
            }
            Spacer(minLength: 8)
            control
        }
    }
}

struct SettingsPanel: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            SettingRow(title: "Auto-switch", subtitle: "When the active account runs low") {
                Picker("", selection: $model.state.settings.mode) {
                    Text("Off").tag(SwitchMode.off)
                    Text("Ask").tag(SwitchMode.ask)
                    Text("Auto").tag(SwitchMode.auto)
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
            }
            SettingRow(title: "Switch at", subtitle: "Share of the 5-hour limit used") {
                HStack(spacing: 4) {
                    Text("\(Int(model.state.settings.threshold))%")
                        .font(.system(size: 12, weight: .semibold, design: .rounded)).monospacedDigit()
                    Stepper("", value: $model.state.settings.threshold, in: 50...100, step: 5).labelsHidden()
                }
            }
            .disabled(model.state.settings.mode == .off)
            SettingRow(title: "Share Code & Cowork sessions", subtitle: "Every account sees the same sidebar") {
                Toggle("", isOn: $model.state.settings.shareSessions).toggleStyle(.switch).controlSize(.mini).labelsHidden()
            }
            SettingRow(title: "Share scheduled tasks", subtitle: "They run on whichever account is active") {
                Toggle("", isOn: $model.state.settings.shareScheduledTasks).toggleStyle(.switch).controlSize(.mini).labelsHidden()
            }
            .disabled(!model.state.settings.shareSessions)
            SettingRow(title: "Switch Chrome extension too", subtitle: "Quits and reopens Chrome on every switch") {
                Toggle("", isOn: Binding(get: { model.state.settings.switchChromeExtension }, set: { on in
                    if on && model.state.settings.chromeProfileDir == nil {
                        model.state.settings.chromeProfileDir = ChromeExtension.suggestedProfile()
                    }
                    model.state.settings.switchChromeExtension = on
                    if on && !AccessHelper.chromeReadable { AccessHelper.show(model: model) }
                })).toggleStyle(.switch).controlSize(.mini).labelsHidden()
            }
            if model.state.settings.switchChromeExtension {
                SettingRow(title: "Chrome profile") {
                    Picker("", selection: Binding(get: { model.state.settings.chromeProfileDir ?? ChromeExtension.suggestedProfile() ?? "" },
                                                  set: { model.state.settings.chromeProfileDir = $0 })) {
                        ForEach(ChromeExtension.profiles(), id: \.dir) { Text($0.name).tag($0.dir) }
                    }
                    .labelsHidden().fixedSize()
                }
            }
            SettingRow(title: "Sync sessions", subtitle: "Without switching accounts") {
                Button("Sync Now") { model.promptSyncNow() }
                    .buttonStyle(PillButtonStyle(prominent: false))
                    .disabled(model.busy != nil || !model.state.settings.shareSessions)
            }
            SettingRow(title: "Launch at login") {
                Toggle("", isOn: Binding(get: { model.launchAtLogin }, set: { model.setLaunchAtLogin($0) }))
                    .toggleStyle(.switch).controlSize(.mini).labelsHidden()
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.025)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.primary.opacity(0.07), lineWidth: 1))
    }
}

/// Shown during setup, and afterwards whenever something isn't granted.
struct PermissionsCard: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text("Permissions").font(.system(size: 12, weight: .semibold))
            ForEach(model.permissions) { check in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: check.problem == nil ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 12)).foregroundStyle(check.problem == nil ? Color.green : Color.orange)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(check.name).font(.system(size: 12))
                        Text(check.problem ?? check.purpose).font(.system(size: 10)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if model.permissions.contains(where: { $0.problem != nil }) {
                HStack(spacing: 6) {
                    if model.permissions.contains(where: { $0.name == "Chrome data" && $0.problem != nil }) {
                        Button("Grant Access") { AccessHelper.show(model: model) }.buttonStyle(PillButtonStyle())
                    }
                    Button("Try Again") { Task { await model.checkPermissions() } }
                        .buttonStyle(PillButtonStyle(prominent: !model.permissions.contains { $0.name == "Chrome data" && $0.problem != nil }))
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.025)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.primary.opacity(0.07), lineWidth: 1))
    }
}

struct EmptyState: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "person.2.circle")
                .font(.system(size: 34, weight: .light)).foregroundStyle(Color.claude)
            Text("Add your first account").font(.system(size: 13, weight: .semibold))
            Text("Save the account currently signed in to Claude Desktop, then add the others.")
                .font(.system(size: 11)).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button("Import Current Login") { model.promptImport() }
                .buttonStyle(PillButtonStyle())
                .padding(.top, 2)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 22).padding(.horizontal, 16)
    }
}

struct MenuContent: View {
    @EnvironmentObject var model: AppModel
    @State private var showSettings = false

    var status: String {
        if let busy = model.busy { return busy }
        if let sync = model.lastSessionSync, model.state.settings.shareSessions { return sync }
        if let t = model.lastRefresh { return "Updated \(t.formatted(date: .omitted, time: .shortened))" }
        return "Loading…"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 9) {
                Image(nsImage: ringImage(model.active?.usage?.fh))
                    .renderingMode(.template).foregroundStyle(Color.claude)
                    .scaleEffect(1.25)
                VStack(alignment: .leading, spacing: 0) {
                    Text("Claude Switcher").font(.system(size: 13, weight: .semibold))
                    Text(status).font(.system(size: 10.5)).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                if model.busy != nil {
                    ProgressView().controlSize(.small)
                } else {
                    IconButton(systemName: "arrow.clockwise", help: "Refresh usage") { Task { await model.refreshAll() } }
                }
            }
            .padding(.horizontal, 2)

            if !model.permissions.isEmpty && (model.state.profiles.isEmpty || model.permissions.contains { $0.problem != nil }) {
                PermissionsCard()
            }

            if model.state.profiles.isEmpty {
                EmptyState()
            } else {
                let cards = VStack(spacing: 8) {
                    ForEach(model.state.profiles) { AccountCard(profile: $0) }
                }
                if model.state.profiles.count > 3 {
                    ScrollView { cards }.frame(maxHeight: 470)
                } else {
                    cards
                }
            }

            if showSettings {
                SettingsPanel()
            }

            Divider().opacity(0.6)

            HStack(spacing: 4) {
                Button { model.promptAdd() } label: {
                    Label("Add Account", systemImage: "plus").font(.system(size: 12, weight: .medium))
                }
                .buttonStyle(PillButtonStyle(prominent: false))
                .disabled(model.busy != nil || model.state.activeId == nil)
                Spacer()
                IconButton(systemName: showSettings ? "gearshape.fill" : "gearshape", help: "Settings") {
                    showSettings.toggle()
                }
                IconButton(systemName: "power", help: "Quit Claude Switcher") { NSApp.terminate(nil) }
            }
        }
        .padding(14)
        .frame(width: 344)
    }
}

struct ClaudeSwitcherApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuContent().environmentObject(model)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Separate view so the menubar label re-renders when usage changes.
struct MenuBarLabel: View {
    @ObservedObject var model: AppModel

    var body: some View {
        HStack(spacing: 4) {
            Image(nsImage: ringImage(model.active?.usage?.fh))
            Text(model.menuTitle).monospacedDigit()
        }
    }
}


// MARK: - Entry point

@main
enum Entry {
    static func main() {
        if CommandLine.arguments.contains("--probe") { probe(); return }
        if CommandLine.arguments.contains("--restart-chrome") {
            // Test hook: quits and reopens Chrome the way a switch does, without touching any login.
            Task.detached {
                do { try await ChromeExtension.quit(); print("chrome quit ok") } catch { print("error: \(error.localizedDescription)") }
                ChromeExtension.reopen()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                exit(0)
            }
            RunLoop.main.run()
            return
        }
        if CommandLine.arguments.contains("--chrome-profiles") {
            print("with extension: \(ChromeExtension.profiles().map(\.dir)); suggested: \(ChromeExtension.suggestedProfile() ?? "none")")
            return
        }
        if let i = CommandLine.arguments.firstIndex(of: "--swap-extension"), i + 5 < CommandLine.arguments.count {
            // Test hook: --swap-extension <chrome-dir> <store-dir> <profile> <from-account> <to-account>
            switchLogEnabled = false
            let a = Array(CommandLine.arguments[(i + 1)...])
            let chrome = URL(fileURLWithPath: a[0])
            do {
                // Optional 6th argument: uuid=account,uuid=account maps Claude accounts, as a real switch does.
                let accounts = a.count > 5 ? Dictionary(uniqueKeysWithValues: a[5].split(separator: ",").map { pair -> (String, String) in
                    let kv = pair.split(separator: "="); return (String(kv[0]), String(kv[1])) }) : nil
                try ChromeExtension.swap(profile: a[2], from: a[3], to: a[4], accounts: accounts, chromeDir: chrome, store: URL(fileURLWithPath: a[1]))
                print("swapped; suggested profile: \(ChromeExtension.suggestedProfile(chromeDir: chrome) ?? "none")")
            } catch { print("error: \(error.localizedDescription)") }
            return
        }
        if let i = CommandLine.arguments.firstIndex(of: "--sync-sessions"), i + 2 < CommandLine.arguments.count {
            // Test hook: --sync-sessions <claude-data-dir> <store-dir>
            let base = URL(fileURLWithPath: CommandLine.arguments[i + 1]), store = URL(fileURLWithPath: CommandLine.arguments[i + 2])
            let tasks = CommandLine.arguments.contains("--scheduled-tasks")
            do { print(try SessionSync.sync(base: base, store: store, includeScheduledTasks: tasks).summary) } catch { print("error: \(error.localizedDescription)") }
            return
        }
        if let i = CommandLine.arguments.firstIndex(of: "--snapshot"), i + 1 < CommandLine.arguments.count {
            snapshot(to: CommandLine.arguments[i + 1]); return
        }
        ClaudeSwitcherApp.main()
    }

    /// `ClaudeSwitcher --snapshot out.png [--dark]`: renders the menu panel from saved state (for design checks).
    static func snapshot(to path: String) {
        _ = NSApplication.shared
        NSApp.appearance = NSAppearance(named: CommandLine.arguments.contains("--dark") ? .darkAqua : .aqua)
        MainActor.assumeIsolated {
            let model = AppModel(autoRefresh: false)
            model.isSnapshot = true
            model.lastRefresh = Date()
            if CommandLine.arguments.contains("--demo") { model.loadDemo() }
            if CommandLine.arguments.contains("--setup-demo") {
                model.isDemoOnly()
                model.permissions = [
                    PermissionCheck(name: "Claude Desktop data", purpose: "To save and restore each account’s login"),
                    PermissionCheck(name: "“Claude Safe Storage” in Keychain", purpose: "To check usage on every account. Choose Always Allow."),
                    PermissionCheck(name: "Chrome data", purpose: "To switch the Claude in Chrome extension",
                                    problem: "macOS blocked access. Allow Claude Switcher under Privacy & Security, then try again."),
                ]
            }
            let view = MenuContent()
                .environmentObject(model)
                .background(Color(nsColor: .windowBackgroundColor))
                .environment(\.colorScheme, CommandLine.arguments.contains("--dark") ? .dark : .light)
            let r = CommandLine.arguments.contains("--helper")
                ? ImageRenderer(content: AnyView(AccessHelperView().background(Color(nsColor: .windowBackgroundColor))))
                : ImageRenderer(content: AnyView(view))
            r.scale = 2
            if let img = r.nsImage, let tiff = img.tiffRepresentation,
               let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:]) {
                try? png.write(to: URL(fileURLWithPath: path))
                print("wrote \(path)")
            }
        }
    }

    /// `ClaudeSwitcher --probe`: prints usage for the login currently in Claude Desktop (no secrets printed).
    static func probe() {
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            do {
                let r = try await UsageClient.fetch(cookiesDB: Paths.claudeData.appendingPathComponent("Cookies"),
                                                    knownOrg: nil, wantEmail: true)
                print("account: \(r.email ?? "?")  org: \(r.orgId)")
                print("5h: \(r.usage.fiveHour.map { String(format: "%.0f%%", $0) } ?? "n/a")  \(resetText(r.usage.fiveHourResets))")
                print("7d: \(r.usage.sevenDay.map { String(format: "%.0f%%", $0) } ?? "n/a")  \(resetText(r.usage.sevenDayResets))")
            } catch {
                print("error: \(error.localizedDescription)")
            }
            done.signal()
        }
        done.wait()
    }
}
