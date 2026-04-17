import Foundation

/// Centralized path-containment / ID-sanitization helpers.
///
/// Every tool that accepts a path or an identifier from the LLM (or from
/// JSON config files on disk) should run it through one of these checks
/// before using it in filesystem operations. This prevents:
///   - Path traversal with `..`
///   - Absolute-path escape from a supposedly confined directory
///   - Symlink traversal out of the intended root
///   - Identifier-as-path smuggling (`"../../etc/passwd"` as a session id)
enum PathSecurity {

    /// Resolve a user-supplied path to an absolute, symlink-resolved,
    /// canonical path. Returns nil if the path cannot be resolved.
    static func canonicalize(_ path: String, relativeTo base: String = "") -> String? {
        let expanded = (path as NSString).expandingTildeInPath
        let absolute: String
        if expanded.hasPrefix("/") {
            absolute = expanded
        } else if !base.isEmpty {
            absolute = (base as NSString).appendingPathComponent(expanded)
        } else {
            absolute = (FileManager.default.currentDirectoryPath as NSString)
                .appendingPathComponent(expanded)
        }
        let url = URL(fileURLWithPath: absolute)
            .standardizedFileURL
            .resolvingSymlinksInPath()
        return url.path
    }

    /// Return true when `child` resolves to a path that lies inside `root`,
    /// after both have been canonicalized and symlinks resolved.
    ///
    /// `root` itself must be a real, resolvable path. When `root` does not
    /// exist yet (for example a project folder that hasn't been created), we
    /// fall back to lexical comparison of the expanded/absolute form — this
    /// is still a defense because the caller is expected to create `root`
    /// before writing into it.
    static func isContained(_ child: String, within root: String) -> Bool {
        guard !root.isEmpty else { return false }
        guard let childCanon = canonicalize(child, relativeTo: root) else {
            return false
        }
        let rootCanon = canonicalize(root) ?? ((root as NSString).expandingTildeInPath)
        let rootWithSlash = rootCanon.hasSuffix("/") ? rootCanon : rootCanon + "/"
        return childCanon == rootCanon || childCanon.hasPrefix(rootWithSlash)
    }

    /// Validate an identifier that will be used as a filename component.
    /// Returns the id unchanged when it is safe; returns nil when it
    /// contains path separators, `..`, NULs, or control characters.
    static func safeIdentifier(_ id: String) -> String? {
        guard !id.isEmpty, id.count <= 128 else { return nil }
        if id == "." || id == ".." { return nil }
        if id.contains("/") || id.contains("\\") { return nil }
        if id.contains("\0") { return nil }
        // Reject any control character, including newline/CR.
        for scalar in id.unicodeScalars where scalar.value < 0x20 {
            return nil
        }
        // Reject leading dot chain (e.g. "..foo", "...bar") that could
        // create hidden files and bypass directory listings. Allow
        // filenames that start with a single dot — those are normal.
        if id.hasPrefix("..") { return nil }
        return id
    }

    /// Return true when `path` names an existing symlink (not a regular
    /// file or directory). We reject symlinks for security-sensitive load
    /// paths (dylibs, hooks, configs) because they let an attacker redirect
    /// the load target after the app validated the name.
    static func isSymlink(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        guard let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]) else {
            return false
        }
        return values.isSymbolicLink == true
    }

    /// Validate that `url` uses one of the allowed schemes (default http/https).
    /// Blocks `file://`, `javascript:`, `x-apple-*:`, `data:`, etc.
    static func hasAllowedScheme(_ url: URL, allow: Set<String> = ["http", "https"]) -> Bool {
        guard let scheme = url.scheme?.lowercased() else { return false }
        return allow.contains(scheme)
    }

    /// Block outbound fetch to loopback, link-local, and cloud-metadata ranges.
    static func isPrivateNetworkHost(_ host: String) -> Bool {
        let lower = host.lowercased()
        if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" {
            return true
        }
        // AWS/GCE/Azure metadata endpoint
        if lower == "169.254.169.254" || lower == "metadata.google.internal" {
            return true
        }
        // RFC1918 IPv4
        if lower.hasPrefix("10.") { return true }
        if lower.hasPrefix("192.168.") { return true }
        if lower.hasPrefix("172.") {
            let parts = lower.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]), (16...31).contains(second) {
                return true
            }
        }
        // 169.254.0.0/16 link-local (covers metadata + APIPA)
        if lower.hasPrefix("169.254.") { return true }
        // 0.0.0.0 / fe80:: / fc00::
        if lower == "0.0.0.0" { return true }
        if lower.hasPrefix("fe80:") || lower.hasPrefix("fc") || lower.hasPrefix("fd") {
            return true
        }
        return false
    }
}
