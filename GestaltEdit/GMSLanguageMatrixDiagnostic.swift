import Darwin
import Foundation
import ObjectiveC.runtime

/// Read-only language-option matrix for GenerativeModels availability.
///
/// GreymatterAvailability keys availability by (useCaseIdentifier, languageOption).
/// This probe compares the same Visual Intelligence use cases across nil and
/// valid BCP-47 language tags without touching secure XPC or any setter.
enum GMSLanguageMatrixDiagnostic {
    private typealias GMCurrentFn =
        @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Int64
    private typealias GMBoolUseCaseFn =
        @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Bool

    private struct LanguageCase {
        let label: String
        let value: AnyObject?
    }

    private struct SelectorSpec {
        let name: String
        let label: String
        let kind: Kind

        enum Kind {
            case current
            case boolean
        }
    }

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("========== iOS 27 VI GM LANGUAGE-OPTION MATRIX READ-ONLY Diagnostic ==========")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        lines.append("Process: \(ProcessInfo.processInfo.processName) bundle=\(Bundle.main.bundleIdentifier ?? \"<nil>\")")
        lines.append("Locale.current=\(Locale.current.identifier)")
        lines.append("Locale.preferredLanguages=\(Locale.preferredLanguages.joined(separator: ", "))")
        lines.append("Bundle.preferredLocalizations=\(Bundle.main.preferredLocalizations.joined(separator: ", "))")
        lines.append("SAFETY: read-only GMAvailabilityWrapper class methods only. No secure availability XPC, no setters/preheat, no swizzling/IMP replacement, no preferences/MobileGestalt writes, no respring/reboot.")
        lines.append("")

        let path = "/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels"
        let handle = dlopen(path, RTLD_NOW)
        lines.append("GenerativeModels dlopen=\(handle == nil ? \"FAILED\" : \"OK\")")

        guard let gmClass: AnyClass = NSClassFromString("GMAvailabilityWrapper") else {
            lines.append("GMAvailabilityWrapper=NOT FOUND")
            lines.append("===============================================================================")
            return lines.joined(separator: "\n")
        }
        lines.append("GMAvailabilityWrapper=FOUND")

        let selectors: [SelectorSpec] = [
            .init(name: "currentWithUseCaseIdentifiers:language:", label: "current.rawStatus", kind: .current),
            .init(name: "enabledWithUseCaseIdentifiers:language:", label: "enabled", kind: .boolean),
            .init(name: "isUseCaseDisabledWithUseCaseIdentifiers:language:", label: "useCaseDisabled", kind: .boolean),
            .init(name: "assetIsNotReadyWithUseCaseIdentifiers:language:", label: "assetIsNotReady", kind: .boolean),
            .init(name: "useCasePartnerAllowedInUserLocaleRegionWithUseCaseIdentifiers:language:", label: "partnerAllowedInUserLocaleRegion", kind: .boolean)
        ]

        lines.append("")
        lines.append("--- ABI verification ---")
        var callable: [String: Method] = [:]
        for spec in selectors {
            let selector = NSSelectorFromString(spec.name)
            guard let method = class_getClassMethod(gmClass, selector) else {
                lines.append("+\(spec.name) = <missing>")
                continue
            }
            let types = method_getTypeEncoding(method).map { String(cString: $0) } ?? "<nil>"
            let argc = method_getNumberOfArguments(method)
            let returnOK: Bool
            switch spec.kind {
            case .current:
                returnOK = types.first == "q"
            case .boolean:
                returnOK = types.first == "B" || types.first == "c"
            }
            let ok = argc == 4 && returnOK
            lines.append("+\(spec.name) types=\(types) argc=\(argc) callable=\(ok)")
            if ok { callable[spec.name] = method }
        }

        let languageCases: [LanguageCase] = [
            .init(label: "<nil>", value: nil),
            .init(label: "en", value: "en" as NSString),
            .init(label: "en-US", value: "en-US" as NSString),
            .init(label: "zh", value: "zh" as NSString),
            .init(label: "zh-Hans", value: "zh-Hans" as NSString),
            .init(label: "zh-Hans-US", value: "zh-Hans-US" as NSString),
            .init(label: "zh-Hans-CN", value: "zh-Hans-CN" as NSString),
            .init(label: "zh-CN", value: "zh-CN" as NSString)
        ]

        let useCases = [
            "VisualIntelligence.gvicc",
            "VisualIntelligence.vi_content_classifier",
            "GenerativeAssistant.visualIntelligenceCamera",
            "summarization.visualIntelligenceCamera",
            "com.apple.Settings.AppleIntelligence",
            "com.apple.VisualIntelligenceCamera.ImageSearch",
            "com.apple.VisualIntelligenceCamera.VisualLookup"
        ]

        lines.append("")
        lines.append("--- matrix ---")
        lines.append("Legend: rawStatus/EN/DIS/ASSET/PARTNER = current, enabled, disabled, assetNotReady, partnerAllowed")

        let classObject = gmClass as AnyObject
        for useCase in useCases {
            let identifiers = [useCase] as NSArray
            lines.append("")
            lines.append("useCase=\(useCase)")

            for languageCase in languageCases {
                var values: [String] = []
                for spec in selectors {
                    guard let method = callable[spec.name] else {
                        values.append("\(spec.label)=<skip>")
                        continue
                    }
                    let selector = NSSelectorFromString(spec.name)
                    switch spec.kind {
                    case .current:
                        let fn = unsafeBitCast(method_getImplementation(method), to: GMCurrentFn.self)
                        let raw = fn(classObject, selector, identifiers, languageCase.value)
                        values.append("rawStatus=\(raw)")
                    case .boolean:
                        let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolUseCaseFn.self)
                        let value = fn(classObject, selector, identifiers, languageCase.value)
                        switch spec.label {
                        case "enabled": values.append("EN=\(value)")
                        case "useCaseDisabled": values.append("DIS=\(value)")
                        case "assetIsNotReady": values.append("ASSET=\(value)")
                        case "partnerAllowedInUserLocaleRegion": values.append("PARTNER=\(value)")
                        default: values.append("\(spec.label)=\(value)")
                        }
                    }
                }
                lines.append("  language=\(languageCase.label)  \(values.joined(separator: "  "))")
            }
        }

        lines.append("")
        lines.append("--- interpretation guardrails ---")
        lines.append("1. A language-specific difference for gvicc / visualIntelligenceCamera would show that nil-language availability was masking a concrete languageOption gate.")
        lines.append("2. If all valid language tags match <nil>, languageOption is unlikely to explain Camera-only unavailability and should be deprioritized.")
        lines.append("3. No secure-access selector is called; sandbox/XPC behavior is intentionally excluded from this matrix.")
        lines.append("===============================================================================")
        return lines.joined(separator: "\n")
    }
}
