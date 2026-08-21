import Foundation

/// Read-only entitlement/path probe focused on the caller-context difference observed by
/// Camera Visual Intelligence on iOS 27. It never changes availability state or system data.
enum ResolvedEntitlementProbe {
    private static let mhMagic64: UInt32 = 0xfeedfacf
    private static let lcCodeSignature: UInt32 = 0x1d
    private static let superBlobMagic: UInt32 = 0xfade0cc0
    private static let entitlementsMagic: UInt32 = 0xfade7171
    private static let derEntitlementsMagic: UInt32 = 0xfade7172

    private struct DynamicApp {
        let root: String
        let bundle: String
        let executable: String
    }

    private struct TargetSpec {
        let name: String
        let candidates: [String]
        let dynamicApp: DynamicApp?
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
        lines.append("========== iOS 27 VI CALLER PATH + ENTITLEMENT READ-ONLY Diagnostic ==========")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        lines.append("Process: \(ProcessInfo.processInfo.processName)")
        lines.append("Bundle: \(Bundle.main.bundleIdentifier ?? "<nil>")")
        lines.append("")
        lines.append("SAFETY: read-only only. No method swizzling/IMP replacement, no availability-service XPC call, no setters, no preference/MobileGestalt writes, no respring/reboot.")
        lines.append("Temporary bad_query leases are used only to read/list protected paths and are released immediately.")
        lines.append("BadQueryBridgeAvailable = \(BadQueryBridgeAvailable())")

        appendDiscovery(to: &lines)

        let specs = targetList()
        var parsed: [ParsedTarget] = []
        for spec in specs {
            let target = resolveAndParse(spec)
            parsed.append(target)
            appendTarget(target, to: &lines)
        }

        appendPrivilegeMatrix(parsed, to: &lines)
        appendPairDiff("Camera", "SpringBoard", parsed, to: &lines)
        appendPairDiff("Camera", "visualintelligenced", parsed, to: &lines)
        appendPairDiff("Camera", "Tamale", parsed, to: &lines)
        appendPairDiff("Camera", "ScreenshotServicesService", parsed, to: &lines)
        appendPairDiff("ScreenshotServicesService", "visualintelligenced", parsed, to: &lines)

        lines.append("")
        lines.append("============================================================================")
        return lines.joined(separator: "\n")
    }

    private static func targetList() -> [TargetSpec] {
        var specs: [TargetSpec] = []
        if let own = Bundle.main.executablePath {
            specs.append(TargetSpec(name: "GestaltEdit (self)", candidates: [own], dynamicApp: nil))
        }

        let appRoot = "/private/var/containers/Bundle/Application"
        specs.append(TargetSpec(
            name: "Camera",
            candidates: [
                "/private/var/staged_system_apps/Camera.app/Camera",
                "/Applications/Camera.app/Camera",
                "/System/Applications/Camera.app/Camera",
                "/private/preboot/Cryptexes/OS/Applications/Camera.app/Camera",
                "/private/preboot/Cryptexes/OS/System/Applications/Camera.app/Camera"
            ],
            dynamicApp: DynamicApp(root: appRoot, bundle: "Camera.app", executable: "Camera")
        ))

        specs.append(TargetSpec(
            name: "SpringBoard",
            candidates: [
                "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
                "/private/preboot/Cryptexes/OS/System/Library/CoreServices/SpringBoard.app/SpringBoard"
            ],
            dynamicApp: nil
        ))

        specs.append(TargetSpec(
            name: "visualintelligenced",
            candidates: [
                "/System/Library/PrivateFrameworks/VisualIntelligenceServices.framework/visualintelligenced",
                "/private/preboot/Cryptexes/OS/System/Library/PrivateFrameworks/VisualIntelligenceServices.framework/visualintelligenced",
                "/usr/libexec/visualintelligenced"
            ],
            dynamicApp: nil
        ))

        specs.append(TargetSpec(
            name: "ScreenshotServicesService",
            candidates: [
                "/Applications/ScreenshotServicesService.app/ScreenshotServicesService",
                "/private/var/staged_system_apps/ScreenshotServicesService.app/ScreenshotServicesService",
                "/System/Library/PrivateFrameworks/ScreenshotServices.framework/XPCServices/ScreenshotServicesService.xpc/ScreenshotServicesService"
            ],
            dynamicApp: DynamicApp(root: appRoot, bundle: "ScreenshotServicesService.app", executable: "ScreenshotServicesService")
        ))

        specs.append(TargetSpec(
            name: "Tamale",
            candidates: [
                "/Applications/Tamale.app/Tamale",
                "/private/var/staged_system_apps/Tamale.app/Tamale",
                "/System/Applications/Tamale.app/Tamale"
            ],
            dynamicApp: DynamicApp(root: appRoot, bundle: "Tamale.app", executable: "Tamale")
        ))

        specs.append(TargetSpec(
            name: "generativeexperiencesd",
            candidates: [
                "/usr/libexec/generativeexperiencesd",
                "/private/preboot/Cryptexes/OS/usr/libexec/generativeexperiencesd",
                "/System/Library/PrivateFrameworks/GenerativeExperiences.framework/generativeexperiencesd"
            ],
            dynamicApp: nil
        ))

        specs.append(TargetSpec(
            name: "countryd",
            candidates: [
                "/usr/libexec/countryd",
                "/private/preboot/Cryptexes/OS/usr/libexec/countryd"
            ],
            dynamicApp: nil
        ))

        specs.append(TargetSpec(
            name: "eligibilityd",
            candidates: [
                "/usr/libexec/eligibilityd",
                "/private/preboot/Cryptexes/OS/usr/libexec/eligibilityd"
            ],
            dynamicApp: nil
        ))

        return specs
    }

    private static func appendDiscovery(to lines: inout [String]) {
        lines.append("")
        lines.append("--- current-system read-only path discovery ---")
        let roots = [
            "/Applications",
            "/private/var/staged_system_apps",
            "/usr/libexec",
            "/System/Library/PrivateFrameworks/VisualIntelligenceServices.framework",
            "/System/Library/PrivateFrameworks/GenerativeExperiences.framework"
        ]
        let needles = ["camera", "tamale", "visual", "screenshot", "generative", "eligibility", "country"]
        for root in roots {
            var error: NSString?
            if let direct = try? FileManager.default.contentsOfDirectory(atPath: root) {
                let matches = direct.filter { value in
                    let lower = value.lowercased()
                    return needles.contains { lower.contains($0) }
                }
                lines.append("root=\(root) mode=direct entries=\(direct.count) matching=\(matches.sorted())")
            } else if let leased = BadQueryListDirectoryAtPath(root, &error) as? [String] {
                let matches = leased.filter { value in
                    let lower = value.lowercased()
                    return needles.contains { lower.contains($0) }
                }
                lines.append("root=\(root) mode=bad_query entries=\(leased.count) matching=\(matches.sorted())")
            } else {
                lines.append("root=\(root) mode=unavailable error=\(error as String? ?? "<nil>")")
            }
        }
    }

    private static func resolveAndParse(_ spec: TargetSpec) -> ParsedTarget {
        var failures: [String] = []
        for path in spec.candidates {
            let result = parseTarget(spec.name, path)
            if result.size > 0 {
                return result
            }
            failures.append("candidate \(path): \(result.notes.joined(separator: "; "))")
        }

        if let dynamic = spec.dynamicApp {
            var error: NSString?
            if let found = BadQueryFindExecutableInImmediateSubdirectories(
                dynamic.root,
                dynamic.bundle,
                dynamic.executable,
                &error
            ) {
                let result = parseTarget(spec.name, found as String)
                if result.size > 0 {
                    return ParsedTarget(
                        name: result.name,
                        path: result.path,
                        size: result.size,
                        entitlements: result.entitlements,
                        notes: ["resolved from installed Application UUID container"] + result.notes
                    )
                }
                failures.append("dynamic resolved path \(found): \(result.notes.joined(separator: "; "))")
            } else {
                failures.append("dynamic app-container lookup: \(error as String? ?? "<nil>")")
            }
        }

        return ParsedTarget(
            name: spec.name,
            path: spec.candidates.first ?? "<none>",
            size: 0,
            entitlements: nil,
            notes: ["all path candidates failed"] + failures
        )
    }

    private static func readData(_ path: String) -> (Data?, String) {
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe]) {
            return (data, "read mode = direct")
        }
        var error: NSString?
        if let data = BadQueryReadDataAtPath(path, &error) {
            return (data as Data, "read mode = bad_query temporary lease")
        }
        return (nil, "read failed; bad_query error=\(error as String? ?? "<nil>")")
    }

    private static func parseTarget(_ name: String, _ path: String) -> ParsedTarget {
        let read = readData(path)
        guard let data = read.0 else {
            return ParsedTarget(name: name, path: path, size: 0, entitlements: nil, notes: [read.1])
        }

        var notes = [read.1]
        guard data.count >= 32 else {
            notes.append("file too small for mach_header_64")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }
        let magic = u32le(data, 0)
        guard magic == mhMagic64 else {
            notes.append(String(format: "unsupported Mach-O magic 0x%08x", magic))
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        let ncmds = Int(u32le(data, 16))
        var cursor = 32
        var codeSignature: Range<Int>?
        for _ in 0..<ncmds {
            guard cursor + 8 <= data.count else { break }
            let cmd = u32le(data, cursor)
            let cmdSize = Int(u32le(data, cursor + 4))
            guard cmdSize >= 8, cursor + cmdSize <= data.count else { break }
            if cmd == lcCodeSignature, cmdSize >= 16 {
                let offset = Int(u32le(data, cursor + 8))
                let size = Int(u32le(data, cursor + 12))
                if offset >= 0, size > 0, offset + size <= data.count {
                    codeSignature = offset..<(offset + size)
                }
            }
            cursor += cmdSize
        }
        guard let codeSignature else {
            notes.append("LC_CODE_SIGNATURE not found")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        let sig = data.subdata(in: codeSignature)
        guard sig.count >= 12, u32be(sig, 0) == superBlobMagic else {
            notes.append("code signature SuperBlob not found")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        let count = Int(u32be(sig, 8))
        guard 12 + count * 8 <= sig.count else {
            notes.append("SuperBlob index table truncated")
            return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: notes)
        }

        var entitlements: [String: Any]?
        var sawDER = false
        for index in 0..<count {
            let entry = 12 + index * 8
            let blobOffset = Int(u32be(sig, entry + 4))
            guard blobOffset + 8 <= sig.count else { continue }
            let blobMagic = u32be(sig, blobOffset)
            let blobLength = Int(u32be(sig, blobOffset + 4))
            guard blobLength >= 8, blobOffset + blobLength <= sig.count else { continue }

            if blobMagic == entitlementsMagic {
                var payload = sig.subdata(in: (blobOffset + 8)..<(blobOffset + blobLength))
                while payload.last == 0 { payload.removeLast() }
                if let plist = try? PropertyListSerialization.propertyList(from: payload, options: [], format: nil),
                   let dictionary = plist as? [String: Any] {
                    entitlements = dictionary
                }
            } else if blobMagic == derEntitlementsMagic {
                sawDER = true
            }
        }
        if sawDER { notes.append("DER entitlement blob present") }
        if entitlements == nil { notes.append("XML entitlement dictionary unavailable") }
        return ParsedTarget(name: name, path: path, size: data.count, entitlements: entitlements, notes: notes)
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
        let keys = ent.keys.sorted().filter(isInterestingKey)
        lines.append("interestingKeyCount = \(keys.count)")
        for key in keys {
            lines.append("  \(key) = \(summarize(ent[key]!))")
        }
        let hits = flattenStrings(ent).filter { isInterestingString($0) }
        lines.append("interestingValueHits = \(hits.count)")
        for hit in hits.prefix(150) { lines.append("  \(hit)") }
    }

    private static func appendPrivilegeMatrix(_ parsed: [ParsedTarget], to lines: inout [String]) {
        lines.append("")
        lines.append("--- VI / GMS critical caller privilege matrix ---")
        lines.append("Columns: directAvailabilityEntitlement | machLookupAvailability | gmsSharedPref | osEligibilityRead | generativeModelAssets | platformApplication")
        for target in parsed {
            guard let ent = target.entitlements else {
                lines.append("\(target.name): <unavailable>")
                continue
            }
            let flat = flattenStrings(ent).map { $0.lowercased() }
            let direct = boolValue(ent["com.apple.generativeexperiences.availabilityService"])
            let mach = flat.contains { $0.contains("mach-lookup") && $0.contains("com.apple.generativeexperiences.availabilityservice") }
            let prefs = flat.contains { $0.contains("shared-preference") && $0.contains("com.apple.gms.availability") }
            let eligibility = ent.keys.contains { $0.lowercased().contains("os_eligibility") } || flat.contains { $0.contains("/private/var/db/os_eligibility") || $0.contains("storage.os_eligibility") }
            let assets = flat.contains { $0.contains("uaf.fm.generativemodels") }
            let platform = boolValue(ent["platform-application"])
            lines.append("\(target.name): \(direct) | \(mach) | \(prefs) | \(eligibility) | \(assets) | \(platform)")
        }
    }

    private static func appendPairDiff(_ lhsName: String, _ rhsName: String, _ parsed: [ParsedTarget], to lines: inout [String]) {
        lines.append("")
        lines.append("--- \(lhsName) vs \(rhsName) entitlement differential ---")
        guard let lhs = parsed.first(where: { $0.name == lhsName })?.entitlements,
              let rhs = parsed.first(where: { $0.name == rhsName })?.entitlements else {
            lines.append("diff unavailable")
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
        for key in common where normalized(lhs[key]!) != normalized(rhs[key]!) {
            changed.append("  * \(key)\n      \(lhsName)=\(summarize(lhs[key]!))\n      \(rhsName)=\(summarize(rhs[key]!))")
        }
        lines.append("common interesting keys with different values: \(changed.count)")
        lines.append(contentsOf: changed.prefix(100))
    }

    private static func isInterestingKey(_ key: String) -> Bool {
        let lower = key.lowercased()
        let words = [
            "generative", "visual", "intelligence", "availability", "camera", "siri", "gms",
            "eligibility", "greymatter", "region", "country", "mach-lookup", "shared-preference",
            "private.security", "platform-application", "no-container", "application-identifier",
            "team-identifier", "accessible-asset-types"
        ]
        return words.contains { lower.contains($0) }
    }

    private static func isInterestingString(_ value: String) -> Bool {
        let lower = value.lowercased()
        let words = [
            "generative", "visualintelligence", "visual-intelligence", "availabilityservice",
            "com.apple.gms", "os_eligibility", "eligibility", "greymatter", "camera", "siri",
            "country", "region"
        ]
        return words.contains { lower.contains($0) }
    }

    private static func boolValue(_ value: Any?) -> Bool {
        if let number = value as? NSNumber { return number.boolValue }
        if let value = value as? Bool { return value }
        return false
    }

    private static func summarize(_ value: Any) -> String {
        if let value = value as? String { return value }
        if let value = value as? NSNumber { return value.description }
        if let array = value as? [Any] {
            let strings = array.compactMap { $0 as? String }
            let matches = strings.filter(isInterestingString)
            if !matches.isEmpty { return "[count=\(array.count); matching=\(matches)]" }
            if array.count <= 10 { return String(describing: array) }
            return "<array count=\(array.count)>"
        }
        if let dict = value as? [String: Any] {
            let keys = dict.keys.sorted().filter(isInterestingKey)
            if !keys.isEmpty {
                return "{" + keys.prefix(20).map { "\($0)=\(summarize(dict[$0]!))" }.joined(separator: ", ") + "}"
            }
            return "<dictionary count=\(dict.count)>"
        }
        return String(describing: value)
    }

    private static func flattenStrings(_ value: Any, path: String = "entitlements") -> [String] {
        var result: [String] = []
        if let string = value as? String {
            result.append("\(path)=\(string)")
        } else if let array = value as? [Any] {
            for (index, child) in array.enumerated() {
                result.append(contentsOf: flattenStrings(child, path: "\(path)[\(index)]"))
            }
        } else if let dict = value as? [String: Any] {
            for key in dict.keys.sorted() {
                result.append(contentsOf: flattenStrings(dict[key]!, path: "\(path).\(key)"))
            }
        }
        return result
    }

    private static func normalized(_ value: Any) -> String {
        if let dict = value as? [String: Any] {
            return dict.keys.sorted().map { "\($0)=\(normalized(dict[$0]!))" }.joined(separator: "|")
        }
        if let array = value as? [Any] {
            return array.map(normalized).sorted().joined(separator: "|")
        }
        return String(describing: value)
    }

    private static func u32le(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else { return 0 }
        return UInt32(data[offset]) |
            UInt32(data[offset + 1]) << 8 |
            UInt32(data[offset + 2]) << 16 |
            UInt32(data[offset + 3]) << 24
    }

    private static func u32be(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else { return 0 }
        return UInt32(data[offset]) << 24 |
            UInt32(data[offset + 1]) << 16 |
            UInt32(data[offset + 2]) << 8 |
            UInt32(data[offset + 3])
    }
}