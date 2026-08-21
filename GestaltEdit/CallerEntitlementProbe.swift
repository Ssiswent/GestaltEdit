import Foundation

/// Read-only caller entitlement probe with temporary sandbox-extension assisted file reads.
///
/// It does not impersonate system processes, connect to availability XPC services, replace
/// method IMPs, call setters, or persistently modify system state. `bad_query` leases are
/// consumed only long enough to read/list a target and are immediately released.
enum CallerEntitlementProbe {
    private static let mhMagic64: UInt32 = 0xfeedfacf
    private static let lcCodeSignature: UInt32 = 0x1d
    private static let superBlobMagic: UInt32 = 0xfade0cc0
    private static let entitlementsMagic: UInt32 = 0xfade7171
    private static let derEntitlementsMagic: UInt32 = 0xfade7172

    private struct TargetSpec {
        let name: String
        let candidates: [String]
    }

    private struct ParsedTarget {
        let name: String
        let path: String
        let size: Int
        let entitlements: [String: Any]?
        let notes: [String]
    }

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("========== Caller Entitlement + BAD_QUERY READ-ONLY Diagnostic ==========")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        lines.append("Process: \(ProcessInfo.processInfo.processName)")
        lines.append("Bundle: \(Bundle.main.bundleIdentifier ?? "<nil>")")
        lines.append("")
        lines.append("SAFETY: read-only. Temporary bad_query sandbox extensions are used only for file/directory reads and are released immediately. No availability XPC connection, method swizzling, IMP replacement, setters, preferences/MobileGestalt writes, reboot or respring.")
        lines.append("BadQueryBridgeAvailable = \(BadQueryBridgeAvailable())")
        lines.append("")
        lines.append("Why this build exists:")
        lines.append("  previous probe could parse SpringBoard but sandbox-hid Camera/visualintelligenced/service binaries")
        lines.append("  this build tries direct reads first, then a temporary read lease for each candidate path")

        appendDiscovery(to: &lines)

        var parsed: [ParsedTarget] = []
        for spec in targetList() {
            let target = parseFirstReadable(spec)
            parsed.append(target)
            appendTarget(target, to: &lines)
        }

        appendDirectServiceSearch(parsed, to: &lines)
        appendPairDiff(lhsName: "Camera", rhsName: "SpringBoard", parsed: parsed, to: &lines)
        appendPairDiff(lhsName: "Camera", rhsName: "visualintelligenced", parsed: parsed, to: &lines)
        appendPairDiff(lhsName: "SpringBoard", rhsName: "visualintelligenced", parsed: parsed, to: &lines)

        lines.append("")
        lines.append("==========================================================================")
        return lines.joined(separator: "\n")
    }

    private static func targetList() -> [TargetSpec] {
        var result: [TargetSpec] = []
        if let own = Bundle.main.executablePath {
            result.append(TargetSpec(name: "GestaltEdit (self)", candidates: [own]))
        }

        result.append(TargetSpec(name: "Camera", candidates: [
            "/Applications/Camera.app/Camera",
            "/System/Applications/Camera.app/Camera",
            "/private/preboot/Cryptexes/OS/Applications/Camera.app/Camera",
            "/private/preboot/Cryptexes/OS/System/Applications/Camera.app/Camera"
        ]))

        result.append(TargetSpec(name: "SpringBoard", candidates: [
            "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
            "/private/preboot/Cryptexes/OS/System/Library/CoreServices/SpringBoard.app/SpringBoard"
        ]))

        result.append(TargetSpec(name: "visualintelligenced", candidates: [
            "/usr/libexec/visualintelligenced",
            "/private/preboot/Cryptexes/OS/usr/libexec/visualintelligenced"
        ]))

        result.append(TargetSpec(name: "ScreenshotServicesService", candidates: [
            "/System/Library/PrivateFrameworks/ScreenshotServices.framework/XPCServices/ScreenshotServicesService.xpc/ScreenshotServicesService",
            "/private/preboot/Cryptexes/OS/System/Library/PrivateFrameworks/ScreenshotServices.framework/XPCServices/ScreenshotServicesService.xpc/ScreenshotServicesService"
        ]))

        result.append(TargetSpec(name: "GenerativeExperiencesService", candidates: [
            "/System/Library/PrivateFrameworks/GenerativeExperiences.framework/XPCServices/GenerativeExperiencesService.xpc/GenerativeExperiencesService",
            "/System/Library/PrivateFrameworks/GenerativeExperiencesRuntime.framework/XPCServices/GenerativeExperiencesService.xpc/GenerativeExperiencesService",
            "/private/preboot/Cryptexes/OS/System/Library/PrivateFrameworks/GenerativeExperiences.framework/XPCServices/GenerativeExperiencesService.xpc/GenerativeExperiencesService"
        ]))

        result.append(TargetSpec(name: "GenerativeExperiencesAvailabilityService", candidates: [
            "/System/Library/PrivateFrameworks/GenerativeExperiences.framework/XPCServices/GenerativeExperiencesAvailabilityService.xpc/GenerativeExperiencesAvailabilityService",
            "/System/Library/PrivateFrameworks/GenerativeExperiencesRuntime.framework/XPCServices/GenerativeExperiencesAvailabilityService.xpc/GenerativeExperiencesAvailabilityService",
            "/private/preboot/Cryptexes/OS/System/Library/PrivateFrameworks/GenerativeExperiences.framework/XPCServices/GenerativeExperiencesAvailabilityService.xpc/GenerativeExperiencesAvailabilityService"
        ]))

        return result
    }

    private static func appendDiscovery(to lines: inout [String]) {
        lines.append("")
        lines.append("--- read-only system path discovery ---")
        let roots = [
            "/Applications",
            "/System/Applications",
            "/usr/libexec",
            "/System/Library/PrivateFrameworks/ScreenshotServices.framework/XPCServices",
            "/System/Library/PrivateFrameworks/GenerativeExperiences.framework",
            "/System/Library/PrivateFrameworks/GenerativeExperiencesRuntime.framework"
        ]
        let needles = ["camera", "visual", "intelligence", "screenshot", "generative", "availability"]

        for root in roots {
            var error: NSString?
            let direct = try? FileManager.default.contentsOfDirectory(atPath: root)
            if let direct {
                let hits = direct.filter { entry in
                    let lower = entry.lowercased()
                    return needles.contains { lower.contains($0) }
                }
                lines.append("root=\(root) mode=direct entries=\(direct.count) matching=\(hits)")
                continue
            }

            if let leased = BadQueryListDirectoryAtPath(root, &error) as? [String] {
                let hits = leased.filter { entry in
                    let lower = entry.lowercased()
                    return needles.contains { lower.contains($0) }
                }
                lines.append("root=\(root) mode=bad_query entries=\(leased.count) matching=\(hits)")
            } else {
                lines.append("root=\(root) mode=unavailable error=\(error as String? ?? "<nil>")")
            }
        }
    }

    private static func parseFirstReadable(_ spec: TargetSpec) -> ParsedTarget {
        var failures: [String] = []
        for path in spec.candidates {
            let attempt = parseTarget(name: spec.name, path: path)
            if attempt.entitlements != nil || attempt.size > 0 {
                var notes = attempt.notes
                if path != spec.candidates.first {
                    notes.insert("resolved using alternate candidate path", at: 0)
                }
                return ParsedTarget(name: attempt.name, path: attempt.path, size: attempt.size, entitlements: attempt.entitlements, notes: notes)
            }
            failures.append("\(path): \(attempt.notes.joined(separator: "; "))")
        }
        return ParsedTarget(name: spec.name, path: spec.candidates.first ?? "<none>", size: 0, entitlements: nil, notes: ["all candidate paths failed"] + failures)
    }

    private static func parseTarget(name: String, path: String) -> ParsedTarget {
        let read = readFile(path)
        guard let data = read.data else {
            return ParsedTarget(name: name, path: path, size: 0, entitlements: nil, notes: [read.note])
        }

        var notes: [String] = [read.note]
        guard data.count >= 32 else {
            notes.append("file too small for mach_header_64")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        let magic = u32le(data, 0)
        guard magic == mhMagic64 else {
            notes.append(String(format: "unsupported Mach-O magic 0x%08x (expected thin arm64 mach_header_64)", magic))
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        let ncmds = Int(u32le(data, 16))
        var cursor = 32
        var codeSigRange: Range<Int>?
        for _ in 0..<ncmds {
            guard cursor + 8 <= data.count else {
                notes.append("load command table truncated")
                break
            }
            let cmd = u32le(data, cursor)
            let cmdSize = Int(u32le(data, cursor + 4))
            guard cmdSize >= 8, cursor + cmdSize <= data.count else {
                notes.append("invalid load command size")
                break
            }
            if cmd == lcCodeSignature, cmdSize >= 16 {
                let dataOff = Int(u32le(data, cursor + 8))
                let dataSize = Int(u32le(data, cursor + 12))
                if dataOff >= 0, dataSize > 0, dataOff + dataSize <= data.count {
                    codeSigRange = dataOff..<(dataOff + dataSize)
                }
            }
            cursor += cmdSize
        }

        guard let codeSigRange else {
            notes.append("LC_CODE_SIGNATURE not found")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        let sig = data.subdata(in: codeSigRange)
        guard sig.count >= 12, u32be(sig, 0) == superBlobMagic else {
            notes.append("code signature is not an EmbeddedSignature SuperBlob")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        let count = Int(u32be(sig, 8))
        guard 12 + count * 8 <= sig.count else {
            notes.append("SuperBlob index table truncated")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        var xmlEntitlements: [String: Any]?
        var sawDER = false
        for i in 0..<count {
            let entry = 12 + i * 8
            let blobOffset = Int(u32be(sig, entry + 4))
            guard blobOffset >= 0, blobOffset + 8 <= sig.count else { continue }
            let blobMagic = u32be(sig, blobOffset)
            let blobLength = Int(u32be(sig, blobOffset + 4))
            guard blobLength >= 8, blobOffset + blobLength <= sig.count else { continue }

            if blobMagic == entitlementsMagic {
                var payload = sig.subdata(in: (blobOffset + 8)..<(blobOffset + blobLength))
                while payload.last == 0 { payload.removeLast() }
                if let plist = try? PropertyListSerialization.propertyList(from: payload, options: [], format: nil),
                   let dict = plist as? [String: Any] {
                    xmlEntitlements = dict
                } else {
                    notes.append("XML entitlement blob found but plist parsing failed")
                }
            } else if blobMagic == derEntitlementsMagic {
                sawDER = true
            }
        }

        if sawDER { notes.append("DER entitlement blob present") }
        if xmlEntitlements == nil { notes.append("XML entitlement dictionary not found") }
        return ParsedTarget(name: name, path: path, size: data.count, entitlements: xmlEntitlements, notes: notes)
    }

    private static func readFile(_ path: String) -> (data: Data?, note: String) {
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe]) {
            return (data, "read mode = direct")
        }

        var error: NSString?
        if let data = BadQueryReadDataAtPath(path, &error) {
            return (data as Data, "read mode = bad_query temporary lease")
        }
        return (nil, "read failed; bad_query error=\(error as String? ?? "<nil>")")
    }

    private static func appendTarget(_ target: ParsedTarget, to lines: inout [String]) {
        lines.append("")
        lines.append("--- \(target.name) ---")
        lines.append("path = \(target.path)")
        lines.append("size = \(target.size)")
        for note in target.notes { lines.append("note = \(note)") }

        guard let ent = target.entitlements else {
            lines.append("entitlements = <unavailable>")
            return
        }

        lines.append("entitlementCount = \(ent.count)")
        let relevant = ent.keys.sorted().filter { isInterestingKey($0) }
        lines.append("interestingKeyCount = \(relevant.count)")
        for key in relevant {
            lines.append("  \(key) = \(summarize(ent[key]!))")
        }

        let hits = findInterestingValueHits(ent)
        lines.append("interestingValueHits = \(hits.count)")
        for hit in hits.prefix(120) { lines.append("  \(hit)") }
    }

    private static func appendDirectServiceSearch(_ parsed: [ParsedTarget], to lines: inout [String]) {
        lines.append("")
        lines.append("--- Direct service / entitlement string search ---")
        let needles = [
            "com.apple.generativeexperiences.availabilityService",
            "com.apple.generativeexperiences",
            "visualintelligence",
            "com.apple.gms",
            "os_eligibility",
            "eligibility",
            "country",
            "region"
        ]
        for target in parsed {
            guard let ent = target.entitlements else { continue }
            let flat = flattenStrings(ent)
            for needle in needles {
                let matches = flat.filter { $0.localizedCaseInsensitiveContains(needle) }
                if !matches.isEmpty {
                    lines.append("\(target.name): needle=\(needle) hits=\(matches.count)")
                    for match in matches.prefix(40) { lines.append("  \(match)") }
                }
            }
        }
    }

    private static func appendPairDiff(lhsName: String, rhsName: String, parsed: [ParsedTarget], to lines: inout [String]) {
        lines.append("")
        lines.append("--- \(lhsName) vs \(rhsName) entitlement differential ---")
        guard let lhs = parsed.first(where: { $0.name == lhsName })?.entitlements,
              let rhs = parsed.first(where: { $0.name == rhsName })?.entitlements else {
            lines.append("diff unavailable because one or both entitlement dictionaries could not be parsed")
            return
        }

        let lhsKeys = Set(lhs.keys)
        let rhsKeys = Set(rhs.keys)
        let lhsOnly = lhsKeys.subtracting(rhsKeys).sorted().filter(isInterestingKey)
        let rhsOnly = rhsKeys.subtracting(lhsKeys).sorted().filter(isInterestingKey)

        lines.append("\(lhsName)-only interesting keys: \(lhsOnly.count)")
        for key in lhsOnly { lines.append("  + \(key) = \(summarize(lhs[key]!))") }
        lines.append("\(rhsName)-only interesting keys: \(rhsOnly.count)")
        for key in rhsOnly { lines.append("  - \(key) = \(summarize(rhs[key]!))") }

        let common = lhsKeys.intersection(rhsKeys).sorted().filter(isInterestingKey)
        var changed: [String] = []
        for key in common where normalizedDescription(lhs[key]!) != normalizedDescription(rhs[key]!) {
            changed.append("  * \(key)\n      \(lhsName)=\(summarize(lhs[key]!))\n      \(rhsName)=\(summarize(rhs[key]!))")
        }
        lines.append("Common interesting keys with different values: \(changed.count)")
        lines.append(contentsOf: changed.prefix(120))
    }

    private static func isInterestingKey(_ key: String) -> Bool {
        let lower = key.lowercased()
        let words = [
            "generative", "visual", "intelligence", "availability", "camera", "siri",
            "eligibility", "greymatter", "region", "country", "mach-lookup",
            "shared-preference", "platform-application", "no-container", "sandbox",
            "application-identifier", "team-identifier", "private.security", "mobileasset"
        ]
        return words.contains { lower.contains($0) }
    }

    private static func isInterestingString(_ value: String) -> Bool {
        let lower = value.lowercased()
        let words = [
            "generative", "visualintelligence", "visual-intelligence", "availabilityservice",
            "com.apple.gms", "eligibility", "greymatter", "camera", "siri", "country", "region"
        ]
        return words.contains { lower.contains($0) }
    }

    private static func summarize(_ value: Any) -> String {
        if let string = value as? String { return string }
        if let number = value as? NSNumber { return number.description }
        if let array = value as? [Any] {
            let strings = array.compactMap { $0 as? String }
            let matches = strings.filter(isInterestingString)
            if !matches.isEmpty { return "[count=\(array.count); matching=\(matches)]" }
            if array.count <= 12 { return String(describing: array) }
            return "<array count=\(array.count)>"
        }
        if let dict = value as? [String: Any] {
            let relevant = dict.keys.sorted().filter { isInterestingKey($0) || isInterestingString($0) }
            if !relevant.isEmpty {
                let parts = relevant.prefix(30).map { "\($0)=\(summarize(dict[$0]!))" }
                return "{\(parts.joined(separator: ", "))}"
            }
            return "<dictionary count=\(dict.count)>"
        }
        return String(describing: value)
    }

    private static func normalizedDescription(_ value: Any) -> String {
        if let dict = value as? [String: Any] {
            return dict.keys.sorted().map { "\($0)=\(normalizedDescription(dict[$0]!))" }.joined(separator: "|")
        }
        if let array = value as? [Any] {
            return array.map(normalizedDescription).sorted().joined(separator: "|")
        }
        return String(describing: value)
    }

    private static func flattenStrings(_ value: Any, path: String = "entitlements") -> [String] {
        if let string = value as? String { return ["\(path)=\(string)"] }
        if let array = value as? [Any] {
            return array.enumerated().flatMap { index, child in
                flattenStrings(child, path: "\(path)[\(index)]")
            }
        }
        if let dict = value as? [String: Any] {
            return dict.keys.sorted().flatMap { key in
                flattenStrings(dict[key]!, path: "\(path).\(key)")
            }
        }
        return []
    }

    private static func findInterestingValueHits(_ ent: [String: Any]) -> [String] {
        flattenStrings(ent).filter(isInterestingString)
    }

    private static func u32le(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else { return 0 }
        return UInt32(data[offset]) |
            (UInt32(data[offset + 1]) << 8) |
            (UInt32(data[offset + 2]) << 16) |
            (UInt32(data[offset + 3]) << 24)
    }

    private static func u32be(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else { return 0 }
        return (UInt32(data[offset]) << 24) |
            (UInt32(data[offset + 1]) << 16) |
            (UInt32(data[offset + 2]) << 8) |
            UInt32(data[offset + 3])
    }
}
