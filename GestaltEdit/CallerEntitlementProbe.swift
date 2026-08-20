import Foundation

/// Pure read-only parser for embedded Mach-O entitlements.
/// It does not call privileged XPC services, change process identity, swizzle methods,
/// or modify any system state.
enum CallerEntitlementProbe {
    private static let mhMagic64: UInt32 = 0xfeedfacf
    private static let lcCodeSignature: UInt32 = 0x1d
    private static let superBlobMagic: UInt32 = 0xfade0cc0
    private static let entitlementsMagic: UInt32 = 0xfade7171
    private static let derEntitlementsMagic: UInt32 = 0xfade7172

    private struct ParsedTarget {
        let name: String
        let path: String
        let size: Int
        let entitlements: [String: Any]?
        let notes: [String]
    }

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("========== Caller Entitlement DIFFERENTIAL READ-ONLY Diagnostic ==========")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        lines.append("Process: \(ProcessInfo.processInfo.processName)")
        lines.append("Bundle: \(Bundle.main.bundleIdentifier ?? "<nil>")")
        lines.append("")
        lines.append("SAFETY: pure file reads + Mach-O code-signature parsing only. No method swizzling, no IMP replacement, no XPC connection, no setters, no preferences/MobileGestalt writes.")
        lines.append("")
        lines.append("Previous probe result carried forward:")
        lines.append("  ordinary sandboxed app: GM/VK availability = allowed")
        lines.append("  Camera process logs: same AppleIntelligence use case = unavailable")
        lines.append("  This probe compares embedded caller entitlements without impersonating any process.")

        let targets = targetList()
        var parsed: [ParsedTarget] = []
        for target in targets {
            let result = parseTarget(name: target.name, path: target.path)
            parsed.append(result)
            appendTarget(result, to: &lines)
        }

        appendDirectServiceSearch(parsed, to: &lines)
        appendCameraSpringBoardDiff(parsed, to: &lines)

        lines.append("")
        lines.append("==========================================================================")
        return lines.joined(separator: "\n")
    }

    private static func targetList() -> [(name: String, path: String)] {
        var targets: [(String, String)] = []
        if let own = Bundle.main.executablePath {
            targets.append(("GestaltEdit (self)", own))
        }
        targets.append(("Camera", "/Applications/Camera.app/Camera"))
        targets.append(("SpringBoard", "/System/Library/CoreServices/SpringBoard.app/SpringBoard"))
        targets.append(("visualintelligenced", "/usr/libexec/visualintelligenced"))
        targets.append(("ScreenshotServicesService", "/System/Library/PrivateFrameworks/ScreenshotServices.framework/XPCServices/ScreenshotServicesService.xpc/ScreenshotServicesService"))
        targets.append(("GenerativeExperiencesService", "/System/Library/PrivateFrameworks/GenerativeExperiences.framework/XPCServices/GenerativeExperiencesService.xpc/GenerativeExperiencesService"))
        targets.append(("GenerativeExperiencesAvailabilityService", "/System/Library/PrivateFrameworks/GenerativeExperiences.framework/XPCServices/GenerativeExperiencesAvailabilityService.xpc/GenerativeExperiencesAvailabilityService"))
        return targets
    }

    private static func parseTarget(name: String, path: String) -> ParsedTarget {
        guard FileManager.default.fileExists(atPath: path) else {
            return ParsedTarget(name: name, path: path, size: 0, entitlements: nil, notes: ["FILE NOT FOUND / path unavailable"])
        }

        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
            var notes: [String] = []
            guard data.count >= 32 else {
                return ParsedTarget(name: name, path: path, size: data.count, entitlements: nil, notes: ["file too small for mach_header_64"])
            }

            let magic = u32le(data, 0)
            guard magic == mhMagic64 else {
                notes.append(String(format: "unsupported Mach-O magic 0x%08x (expected thin 64-bit)", magic))
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
        } catch {
            return ParsedTarget(name: name, path: path, size: 0, entitlements: nil, notes: ["READ ERROR: \(error)"])
        }
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
        let keys = ent.keys.sorted()
        let relevant = keys.filter { isInterestingKey($0) }
        lines.append("interestingKeyCount = \(relevant.count)")
        if relevant.isEmpty {
            lines.append("interesting entitlements = <none>")
        } else {
            for key in relevant {
                let value = ent[key]!
                lines.append("  \(key) = \(summarize(value, keyIsInteresting: true))")
            }
        }

        let hits = findInterestingValueHits(ent)
        lines.append("interestingValueHits = \(hits.count)")
        for hit in hits.prefix(80) {
            lines.append("  \(hit)")
        }
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
            "eligibility"
        ]

        for target in parsed {
            guard let ent = target.entitlements else { continue }
            let flat = flattenStrings(ent)
            for needle in needles {
                let matches = flat.filter { $0.lowercased().contains(needle.lowercased()) }
                if !matches.isEmpty {
                    lines.append("\(target.name): needle=\(needle) hits=\(matches.count)")
                    for match in matches.prefix(30) { lines.append("  \(match)") }
                }
            }
        }
    }

    private static func appendCameraSpringBoardDiff(_ parsed: [ParsedTarget], to lines: inout [String]) {
        lines.append("")
        lines.append("--- Camera vs SpringBoard entitlement differential ---")
        guard let camera = parsed.first(where: { $0.name == "Camera" })?.entitlements,
              let spring = parsed.first(where: { $0.name == "SpringBoard" })?.entitlements else {
            lines.append("diff unavailable because one or both entitlement dictionaries could not be parsed")
            return
        }

        let cameraKeys = Set(camera.keys)
        let springKeys = Set(spring.keys)
        let cameraOnly = cameraKeys.subtracting(springKeys).sorted().filter(isInterestingKey)
        let springOnly = springKeys.subtracting(cameraKeys).sorted().filter(isInterestingKey)

        lines.append("Camera-only interesting keys: \(cameraOnly.count)")
        for key in cameraOnly { lines.append("  + \(key) = \(summarize(camera[key]!, keyIsInteresting: true))") }

        lines.append("SpringBoard-only interesting keys: \(springOnly.count)")
        for key in springOnly { lines.append("  - \(key) = \(summarize(spring[key]!, keyIsInteresting: true))") }

        let common = cameraKeys.intersection(springKeys).sorted().filter(isInterestingKey)
        var changed: [String] = []
        for key in common {
            let a = normalizedDescription(camera[key]!)
            let b = normalizedDescription(spring[key]!)
            if a != b {
                changed.append("  * \(key)\n      Camera=\(summarize(camera[key]!, keyIsInteresting: true))\n      SpringBoard=\(summarize(spring[key]!, keyIsInteresting: true))")
            }
        }
        lines.append("Common interesting keys with different values: \(changed.count)")
        lines.append(contentsOf: changed.prefix(80))
    }

    private static func isInterestingKey(_ key: String) -> Bool {
        let lower = key.lowercased()
        let words = [
            "generative", "visual", "intelligence", "availability", "camera", "siri",
            "eligibility", "greymatter", "region", "country", "mach-lookup",
            "shared-preference", "platform-application", "no-container", "sandbox",
            "application-identifier", "team-identifier", "private.security"
        ]
        return words.contains { lower.contains($0) }
    }

    private static func isInterestingString(_ value: String) -> Bool {
        let lower = value.lowercased()
        let words = [
            "generative", "visualintelligence", "visual-intelligence", "availabilityservice",
            "com.apple.gms", "eligibility", "greymatter", "camera", "siri"
        ]
        return words.contains { lower.contains($0) }
    }

    private static func summarize(_ value: Any, keyIsInteresting: Bool) -> String {
        if let string = value as? String { return string }
        if let number = value as? NSNumber { return number.description }
        if let array = value as? [Any] {
            let strings = array.compactMap { $0 as? String }
            let matches = strings.filter(isInterestingString)
            if !matches.isEmpty {
                return "[count=\(array.count); matching=\(matches)]"
            }
            if array.count <= 12 { return String(describing: array) }
            return "<array count=\(array.count)>"
        }
        if let dict = value as? [String: Any] {
            let relevant = dict.keys.sorted().filter { isInterestingKey($0) || isInterestingString($0) }
            if !relevant.isEmpty {
                let parts = relevant.prefix(20).map { "\($0)=\(summarize(dict[$0]!, keyIsInteresting: true))" }
                return "{\(parts.joined(separator: ", "))}"
            }
            return "<dictionary count=\(dict.count)>"
        }
        return keyIsInteresting ? String(describing: value) : "<\(type(of: value))>"
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
        var out: [String] = []
        if let string = value as? String {
            out.append("\(path)=\(string)")
        } else if let array = value as? [Any] {
            for (index, child) in array.enumerated() {
                out.append(contentsOf: flattenStrings(child, path: "\(path)[\(index)]"))
            }
        } else if let dict = value as? [String: Any] {
            for key in dict.keys.sorted() {
                out.append(contentsOf: flattenStrings(dict[key]!, path: "\(path).\(key)"))
            }
        }
        return out
    }

    private static func findInterestingValueHits(_ ent: [String: Any]) -> [String] {
        flattenStrings(ent).filter { isInterestingString($0) }
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
