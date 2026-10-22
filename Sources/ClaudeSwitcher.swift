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
    static let handoffs = support.appendingPathComponent("handoffs")
}

let claudeBundleID = "com.anthropic.claudefordesktop"
/// Files/dirs inside Claude's data dir that hold the signed-in account.
let authItems = ["Cookies", "Cookies-journal", "Local Storage", "Session Storage", "IndexedDB", "WebStorage"]
func isAuthConfigKey(_ key: String) -> Bool { key.hasPrefix("oauth:") || key == "lastKnownAccountUuid" }

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
    var carryOverOnSwitch = true     // copy the outgoing account's latest chat after switching
    var shareSessions = true         // show every account's Code & Cowork sessions on all accounts

    init() {}
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = Settings()
        mode = try c.decodeIfPresent(SwitchMode.self, forKey: .mode) ?? d.mode
        threshold = try c.decodeIfPresent(Double.self, forKey: .threshold) ?? d.threshold
        weeklyThreshold = try c.decodeIfPresent(Double.self, forKey: .weeklyThreshold) ?? d.weeklyThreshold
        pollMinutes = try c.decodeIfPresent(Double.self, forKey: .pollMinutes) ?? d.pollMinutes
        carryOverOnSwitch = try c.decodeIfPresent(Bool.self, forKey: .carryOverOnSwitch) ?? d.carryOverOnSwitch
        shareSessions = try c.decodeIfPresent(Bool.self, forKey: .shareSessions) ?? d.shareSessions
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

// MARK: - Chats (claude.ai conversations live server-side, per account)

struct ChatSummary: Codable, Identifiable, Equatable {
    var id: String
    var name: String
    var updatedAt: Date?
}

enum ChatClient {
    static func recent(cookiesDB: URL, org: String, limit: Int = 10) async throws -> [ChatSummary] {
        let (sk, _) = try UsageClient.login(cookiesDB: cookiesDB)
        guard let list = try await UsageClient.get("/api/organizations/\(org)/chat_conversations?limit=\(limit)",
                                                   sessionKey: sk) as? [[String: Any]] else { return [] }
        return list.compactMap { c in
            guard let id = c["uuid"] as? String else { return nil }
            let name = (c["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "Untitled chat"
            return ChatSummary(id: id, name: name, updatedAt: (c["updated_at"] as? String).flatMap(parseISODate))
        }
        .sorted { ($0.updatedAt ?? .distantPast) > ($1.updatedAt ?? .distantPast) }
    }

    /// Full text of one conversation (current branch) as Markdown.
    static func transcript(cookiesDB: URL, org: String, chat: ChatSummary) async throws -> String {
        let (sk, _) = try UsageClient.login(cookiesDB: cookiesDB)
        let path = "/api/organizations/\(org)/chat_conversations/\(chat.id)?tree=False&rendering_mode=messages"
        guard let convo = try await UsageClient.get(path, sessionKey: sk) as? [String: Any],
              let messages = convo["chat_messages"] as? [[String: Any]] else {
            throw AppError("Couldn’t read that conversation")
        }
        var out = "# \(chat.name)\n\n"
        for m in messages {
            var text = (m["content"] as? [[String: Any]])?
                .filter { $0["type"] as? String == "text" }
                .compactMap { $0["text"] as? String }
                .joined(separator: "\n\n") ?? ""
            if text.isEmpty { text = m["text"] as? String ?? "" }
            guard !text.isEmpty else { continue }
            out += (m["sender"] as? String == "human" ? "## User\n\n" : "## Claude\n\n") + text + "\n\n"
        }
        return out
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
    var summary: String { copied + trashed == 0 ? "Sessions already in sync" : "Synced sessions: \(copied) copied, \(trashed) removed" }
}

enum SessionSync {
    static let roots = ["claude-code-sessions", "local-agent-mode-sessions"]
    static let uuidPattern = #"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"#
    static let fm = FileManager.default

    /// `base` is Claude's data dir; `store` holds the manifest, trash and backups.
    static func sync(base: URL = Paths.claudeData, store: URL = Paths.support,
                     ensure extra: [(account: String, org: String)] = []) throws -> SessionSyncResult {
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
        }
        try fm.createDirectory(at: store, withIntermediateDirectories: true)
        try JSONEncoder().encode(manifest).write(to: manifestURL, options: .atomic)
        return result
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

// MARK: - App model

@MainActor
final class AppModel: ObservableObject {
    @Published var state: AppState { didSet { if state != oldValue && !isDemo { save() } } }
    @Published var busy: String?
    @Published var lastRefresh: Date?
    @Published var chats: [UUID: [ChatSummary]] = [:]
    @Published var lastSessionSync: String?
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
        Task { await refreshAll() }
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
        chats[personal.id] = [
            ChatSummary(id: "1", name: "Trip itinerary for Lisbon", updatedAt: now - 3600),
            ChatSummary(id: "2", name: "Refactor auth middleware", updatedAt: now - 5 * 3600),
            ChatSummary(id: "3", name: "Quarterly planning notes", updatedAt: now - 26 * 3600),
        ]
        chats[side.id] = [ChatSummary(id: "4", name: "Landing page copy", updatedAt: now - 2 * 3600)]
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
                if let list = try? await Task.detached(operation: { try await ChatClient.recent(cookiesDB: db, org: r.orgId) }).value {
                    chats[p.id] = list
                }
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
        let outgoing = active
        let latest = outgoing.flatMap { chats[$0.id]?.first }
        let ok = await perform("Switching to \(target.name)…") {
            try await self.swapLogin(to: self.profileDir(id), org: target.orgId)
            self.state.activeId = id
        }
        if ok, state.settings.carryOverOnSwitch, let outgoing, let latest {
            await carryOver(from: outgoing.id, chat: latest, afterSwitch: true)
        }
    }

    /// Copies a chat from any saved account so it can be continued on the active one:
    /// writes a Markdown transcript to handoffs/ and puts a ready-to-paste prompt on the clipboard.
    func carryOver(from profileId: UUID, chat: ChatSummary, afterSwitch: Bool = false) async {
        guard let p = state.profiles.first(where: { $0.id == profileId }), let org = p.orgId else { return }
        let db = (p.id == state.activeId ? Paths.claudeData : profileDir(p.id)).appendingPathComponent("Cookies")
        do {
            let md = try await Task.detached { try await ChatClient.transcript(cookiesDB: db, org: org, chat: chat) }.value
            try FileManager.default.createDirectory(at: Paths.handoffs, withIntermediateDirectories: true)
            let safe = chat.name.replacingOccurrences(of: #"[/:\\]"#, with: "-", options: .regularExpression).prefix(60)
            let file = Paths.handoffs.appendingPathComponent("\(safe) (\(p.name)).md")
            try md.write(to: file, atomically: true, encoding: .utf8)

            let prompt = "I'm continuing a conversation I started on another account. Here is the full transcript so far — pick up where it left off.\n\n<previous_conversation>\n\(md)</previous_conversation>"
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(prompt, forType: .string)

            NSApp.activate(ignoringOtherApps: true)
            let a = NSAlert()
            a.messageText = afterSwitch ? "Switched — “\(chat.name)” is ready to continue" : "“\(chat.name)” copied"
            a.informativeText = "The transcript from \(p.name) is on your clipboard. Start a new chat in Claude and paste (⌘V). It’s also saved as a file you can attach instead."
            a.addButton(withTitle: "Open Claude")
            a.addButton(withTitle: "Show File")
            a.addButton(withTitle: "Done")
            switch a.runModal() {
            case .alertFirstButtonReturn: ClaudeDesktop.launch()
            case .alertSecondButtonReturn: NSWorkspace.shared.activateFileViewerSelecting([file])
            default: break
            }
        } catch {
            alert("Couldn’t copy “\(chat.name)”", error.localizedDescription)
        }
    }

    func addAccount(name: String) async {
        guard busy == nil else { return }
        await perform("Signing out for new account…") {
            try await self.swapLogin(to: nil, org: nil)
            let p = Profile(name: name)
            self.state.profiles.append(p)
            self.state.activeId = p.id
        }
    }

    /// Quit Claude, save the active login, restore `dir` (nil = signed out), relaunch.
    private func swapLogin(to dir: URL?, org: String?) async throws {
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
        ClaudeDesktop.launch()
    }

    /// Merges Code & Cowork sessions across accounts. Never blocks a switch: failures are only reported.
    private func syncSessions(org: String?) async {
        busy = "Syncing Code & Cowork sessions…"
        let account = (try? Snapshot.readConfig())?["lastKnownAccountUuid"] as? String
        let ensure = [account, org].allSatisfy { $0 != nil } ? [(account!, org!)] : []
        let result = await Task.detached { () -> Result<SessionSyncResult, Error> in
            Result {
                try SessionSync.backup()
                return try SessionSync.sync(ensure: ensure)
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

struct ChatRow: View {
    let chat: ChatSummary
    let actionLabel: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: "bubble.left").font(.system(size: 10)).foregroundStyle(.tertiary)
                Text(chat.name).font(.system(size: 11.5)).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 6)
                if hovering {
                    Text(actionLabel).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(Color.claude)
                } else if let d = chat.updatedAt {
                    Text(d.formatted(.relative(presentation: .numeric, unitsStyle: .abbreviated)))
                        .font(.system(size: 10)).foregroundStyle(.tertiary)
                }
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color.primary.opacity(hovering ? 0.07 : 0)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help("Copy this chat’s transcript to continue it on the active account")
    }
}

struct AccountCard: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    @State private var hovering = false
    @State private var showChats = false
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

            if let list = model.chats[profile.id], !list.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Button {
                        showChats.toggle()
                    } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "chevron.right")
                                .font(.system(size: 8.5, weight: .bold))
                                .rotationEffect(.degrees(showChats ? 90 : 0))
                                .animation(.easeInOut(duration: 0.15), value: showChats)
                            Text("Recent chats")
                            Text("\(list.count)").foregroundStyle(.tertiary)
                            Spacer()
                        }
                        .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)

                    if showChats {
                        VStack(spacing: 0) {
                            ForEach(list) { chat in
                                ChatRow(chat: chat, actionLabel: isActive ? "Copy" : "Continue here") {
                                    Task { await model.carryOver(from: profile.id, chat: chat) }
                                }
                            }
                        }
                        .padding(.top, 3)
                    }
                }
                .padding(.top, 1)
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
            SettingRow(title: "Bring latest chat along", subtitle: "Copy it to the clipboard after switching") {
                Toggle("", isOn: $model.state.settings.carryOverOnSwitch).toggleStyle(.switch).controlSize(.mini).labelsHidden()
            }
            SettingRow(title: "Share Code & Cowork sessions", subtitle: "Every account sees the same sidebar") {
                Toggle("", isOn: $model.state.settings.shareSessions).toggleStyle(.switch).controlSize(.mini).labelsHidden()
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
        if let i = CommandLine.arguments.firstIndex(of: "--sync-sessions"), i + 2 < CommandLine.arguments.count {
            // Test hook: --sync-sessions <claude-data-dir> <store-dir>
            let base = URL(fileURLWithPath: CommandLine.arguments[i + 1]), store = URL(fileURLWithPath: CommandLine.arguments[i + 2])
            do { print(try SessionSync.sync(base: base, store: store).summary) } catch { print("error: \(error.localizedDescription)") }
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
            let view = MenuContent()
                .environmentObject(model)
                .background(Color(nsColor: .windowBackgroundColor))
                .environment(\.colorScheme, CommandLine.arguments.contains("--dark") ? .dark : .light)
            let r = ImageRenderer(content: view)
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
                let db = Paths.claudeData.appendingPathComponent("Cookies")
                let chats = try await ChatClient.recent(cookiesDB: db, org: r.orgId, limit: 5)
                print("recent chats: \(chats.count)")
                if let first = chats.first {
                    let md = try await ChatClient.transcript(cookiesDB: db, org: r.orgId, chat: first)
                    print("latest transcript: \(md.components(separatedBy: "\n## ").count - 1) messages, \(md.count) chars")
                }
            } catch {
                print("error: \(error.localizedDescription)")
            }
            done.signal()
        }
        done.wait()
    }
}
