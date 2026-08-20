import Foundation

/// Read-only diagnostics for the region / eligibility layers relevant to
/// Apple Intelligence and Camera Visual Intelligence.
enum EligibilityCountryDiagnostic {
    private struct Probe {
        let title: String
        let path: String
        let mode: Mode
    }

    private enum Mode {
        case eligibility
        case eligibilityInputs
        case countryd
        case gms
    }

    private static let probes: [Probe] = [
        .init(
            title: "eligibilityd eligibility cache",
            path: "/private/var/db/eligibilityd/eligibility.plist",
            mode: .eligibility
        ),
        .init(
            title: "OS eligibility cache",
            path: "/private/var/db/os_eligibility/eligibility.plist",
            mode: .eligibility
        ),
        .init(
            title: "eligibilityd input cache",
            path: "/private/var/db/eligibilityd/eligibility_inputs.plist",
            mode: .eligibilityInputs
        ),
        .init(
            title: "countryd country cache",
            path: "/private/var/db/com.apple.countryd/countryCodeCache.plist",
            mode: .countryd
        ),
        .init(
            title: "GMS availability preferences",
            path: "/private/var/mobile/Library/Preferences/com.apple.gms.availability.plist",
            mode: .gms
        )
    ]

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("========== Eligibility / Country READ-ONLY Diagnostic ==========")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("OS build: \(GestaltAccess.currentOSBuild())")
        lines.append("Locale identifier: \(Locale.current.identifier)")
        lines.append("Locale region: \(Locale.current.region?.identifier ?? "<nil>")")
        lines.append("Preferred languages: \(Locale.preferredLanguages.joined(separator: ", "))")
        lines.append("Time zone: \(TimeZone.current.identifier)")
        lines.append("")

        lines.append("--- MobileGestalt runtime snapshot ---")
        lines.append(MobileGestaltReadOnlyDiagnostic.generateReport())
        lines.append("")

        for probe in probes {
            lines.append("--- \(probe.title) ---")
            lines.append("Path: \(probe.path)")

            let result = GEReadProtectedFileResult(probe.path)
            if let error = result["error"] as? String {
                lines.append("READ ERROR: \(error)")
                lines.append("")
                continue
            }
            guard let data = result["data"] as? Data else {
                lines.append("READ ERROR: no data returned")
                lines.append("")
                continue
            }

            lines.append("Bytes: \(data.count)")
            do {
                var format = PropertyListSerialization.PropertyListFormat.binary
                let plist = try PropertyListSerialization.propertyList(
                    from: data,
                    options: [],
                    format: &format
                )

                let extracted: [String]
                switch probe.mode {
                case .eligibility:
                    extracted = collectLeaves(
                        from: plist,
                        triggerTokens: [
                            "greymatter",
                            "foundation_models",
                            "foundationmodels",
                            "siri_mode",
                            "sirimode",
                            "strontium",
                            "country_location",
                            "countrylocation",
                            "country_billing",
                            "countrybilling",
                            "device_region_code",
                            "deviceregioncode",
                            "china_cellular",
                            "chinacellular"
                        ]
                    )
                case .eligibilityInputs:
                    extracted = collectLeaves(
                        from: plist,
                        triggerTokens: [
                            "country_location",
                            "countrylocation",
                            "country_billing",
                            "countrybilling",
                            "device_region_code",
                            "deviceregioncode",
                            "china_cellular",
                            "chinacellular",
                            "language",
                            "locale"
                        ]
                    )
                case .countryd:
                    extracted = collectAllLeaves(from: plist)
                case .gms:
                    extracted = collectLeaves(
                        from: plist,
                        triggerTokens: [
                            "unifiedreasons",
                            "usecasereadiness",
                            "accessnotgrantedusecases",
                            "availability",
                            "country",
                            "region",
                            "updatedsinceboot",
                            "secureinitializedusecases"
                        ]
                    )
                }

                if extracted.isEmpty {
                    lines.append("Parsed successfully, but no targeted keys matched.")
                } else {
                    lines.append(contentsOf: extracted)
                }
            } catch {
                lines.append("PLIST PARSE ERROR: \(error.localizedDescription)")
            }
            lines.append("")
        }

        lines.append("===============================================================")
        lines.append("READ-ONLY: no system file or preference was modified by this report.")
        return lines.joined(separator: "\n")
    }

    private static func collectLeaves(
        from value: Any,
        path: String = "$",
        inheritedMatch: Bool = false,
        triggerTokens: [String]
    ) -> [String] {
        if let dictionary = dictionary(from: value) {
            var output: [String] = []
            for key in dictionary.keys.sorted() {
                guard let child = dictionary[key] else { continue }
                let childPath = "\(path).\(key)"
                let keyLower = key.lowercased()
                let matches = inheritedMatch || triggerTokens.contains { keyLower.contains($0) }

                if isContainer(child) {
                    output.append(contentsOf: collectLeaves(
                        from: child,
                        path: childPath,
                        inheritedMatch: matches,
                        triggerTokens: triggerTokens
                    ))
                } else if matches {
                    output.append("\(childPath) = \(describe(child))")
                }
            }
            return output
        }

        if let array = array(from: value) {
            var output: [String] = []
            for (index, child) in array.enumerated() {
                let childPath = "\(path)[\(index)]"
                if isContainer(child) {
                    output.append(contentsOf: collectLeaves(
                        from: child,
                        path: childPath,
                        inheritedMatch: inheritedMatch,
                        triggerTokens: triggerTokens
                    ))
                } else if inheritedMatch {
                    output.append("\(childPath) = \(describe(child))")
                }
            }
            return output
        }

        return inheritedMatch ? ["\(path) = \(describe(value))"] : []
    }

    private static func collectAllLeaves(
        from value: Any,
        path: String = "$"
    ) -> [String] {
        if let dictionary = dictionary(from: value) {
            var output: [String] = []
            for key in dictionary.keys.sorted() {
                guard let child = dictionary[key] else { continue }
                output.append(contentsOf: collectAllLeaves(from: child, path: "\(path).\(key)"))
            }
            return output
        }

        if let array = array(from: value) {
            var output: [String] = []
            for (index, child) in array.enumerated() {
                output.append(contentsOf: collectAllLeaves(from: child, path: "\(path)[\(index)]"))
            }
            return output
        }

        return ["\(path) = \(describe(value))"]
    }

    private static func dictionary(from value: Any) -> [String: Any]? {
        if let dictionary = value as? [String: Any] {
            return dictionary
        }
        if let dictionary = value as? NSDictionary {
            var converted: [String: Any] = [:]
            for (key, child) in dictionary {
                if let key = key as? String {
                    converted[key] = child
                }
            }
            return converted
        }
        return nil
    }

    private static func array(from value: Any) -> [Any]? {
        if let array = value as? [Any] { return array }
        if let array = value as? NSArray { return array.map { $0 } }
        return nil
    }

    private static func isContainer(_ value: Any) -> Bool {
        dictionary(from: value) != nil || array(from: value) != nil
    }

    private static func describe(_ value: Any) -> String {
        if let number = value as? NSNumber,
           CFGetTypeID(number) == CFBooleanGetTypeID() {
            return number.boolValue ? "true [Boolean]" : "false [Boolean]"
        }
        if let date = value as? Date {
            return ISO8601DateFormatter().string(from: date)
        }
        if let data = value as? Data {
            return "<Data \(data.count) bytes>"
        }
        if value is NSNull {
            return "<null>"
        }
        return "\(value) [\(type(of: value))]"
    }
}
