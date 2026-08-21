import CoreFoundation
import Darwin
import Foundation
import ObjectiveC.runtime

/// Crash-safe, read-only diagnostic for the Camera Visual Intelligence investigation.
///
/// This deliberately avoids method swizzling, IMP replacement, secure availability XPC
/// calls, setters, preference writes, and MobileGestalt writes.
enum SafeGMSDiagnostic {
    private typealias MGCopyAnswerFunction =
        @convention(c) (CFString) -> Unmanaged<CFTypeRef>?

    private typealias GMCurrentFn =
        @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Int64
    private typealias GMBoolFn =
        @convention(c) (AnyObject, Selector) -> Bool
    private typealias GMBoolUseCaseFn =
        @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Bool
    private typealias GMIntFn =
        @convention(c) (AnyObject, Selector) -> Int64

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("========== GMS / VK CRASH-SAFE READ-ONLY Diagnostic ==========")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        lines.append("Process: \(ProcessInfo.processInfo.processName)")
        lines.append("Bundle: \(Bundle.main.bundleIdentifier ?? "<nil>")")
        lines.append("")
        lines.append("SAFETY: no method swizzling, no IMP replacement, no secure-access XPC probe, no setters, no preference writes, no MobileGestalt writes.")

        appendMobileGestalt(to: &lines)
        appendGMS(to: &lines)
        appendVisionKit(to: &lines)
        appendPreferences(to: &lines)

        lines.append("")
        lines.append("===============================================================")
        return lines.joined(separator: "\n")
    }

    private static func appendMobileGestalt(to lines: inout [String]) {
        lines.append("")
        lines.append("--- MobileGestalt runtime snapshot ---")
        for key in [
            "ChinaCellular",
            "green-tea",
            "not-green-tea",
            "RegionCode",
            "RegionInfo",
            "RegulatoryModelNumber",
            "ProductType",
            "HardwareModel",
            "DeviceSupportsGenerativeModelSystems"
        ] {
            lines.append(answerLine(for: key))
        }

        lines.append("")
        lines.append("--- CacheExtra snapshot ---")
        do {
            let access = GestaltAccess.shared()
            try access.connect()
            guard let dictionary = try access.readGestalt() as? [String: Any] else {
                lines.append("CacheExtra = <unable to read MobileGestalt plist>")
                return
            }

            let cacheExtra = GestaltPlist(dict: dictionary).cacheExtra
            let keys: [(String, String)] = [
                ("2xVt/Zm4gAkjGGVTZxO/Qw", "ChinaCellular hash candidate"),
                ("iyfxmLogGVIaH7aEgqwcIA", "green-tea"),
                ("4snMZS8LJkSctKypt2m+xA", "not-green-tea"),
                ("h63QSdBCiT/z0WU6rdQv6Q", "RegionCode"),
                ("zHeENZu+wbg7PUprwNwBWg", "RegionInfo standard hash"),
                ("yK+xavymRGZ3xWc1tb8XDg", "GestaltEdit iOS 27 region override"),
                ("97JDvERpVwO+GHtthIh7hA", "RegulatoryModelNumber"),
                ("A62OafQ85EJAiiqKn4agtg", "DeviceSupportsGenerativeModelSystems")
            ]
            for (key, name) in keys {
                if let value = cacheExtra[key] {
                    lines.append("CacheExtra \(name) [\(key)] = \(value) [\(type(of: value))]")
                } else {
                    lines.append("CacheExtra \(name) [\(key)] = <ABSENT>")
                }
            }
        } catch {
            lines.append("CacheExtra read failed: \(error.localizedDescription)")
        }
    }

    private static func appendGMS(to lines: inout [String]) {
        lines.append("")
        lines.append("--- GenerativeModels baseline ---")

        let path = "/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels"
        let handle = dlopen(path, RTLD_NOW)
        lines.append("GenerativeModels dlopen = \(handle == nil ? "FAILED" : "OK")")
        // Intentionally keep the framework loaded for the lifetime of the process.
        // This avoids any unload/lifetime edge case while Objective-C runtime metadata is in use.

        guard let gmClass: AnyClass = NSClassFromString("GMAvailabilityWrapper") else {
            lines.append("GMAvailabilityWrapper = NOT FOUND")
            return
        }
        lines.append("GMAvailabilityWrapper = FOUND")

        let classObject = gmClass as AnyObject
        let language: AnyObject? = nil

        let eligibleSel = NSSelectorFromString("isDeviceEligible")
        if let method = class_getClassMethod(gmClass, eligibleSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
            lines.append("+isDeviceEligible = \(fn(classObject, eligibleSel))")
        } else {
            lines.append("+isDeviceEligible = <selector unavailable>")
        }

        let everSel = NSSelectorFromString("wasEverAvailable")
        if let method = class_getClassMethod(gmClass, everSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
            lines.append("+wasEverAvailable = \(fn(classObject, everSel))")
        }

        let enhancedSel = NSSelectorFromString("enhancedSiriAvailability")
        if let method = class_getClassMethod(gmClass, enhancedSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMIntFn.self)
            lines.append("+enhancedSiriAvailability raw = \(fn(classObject, enhancedSel))")
        }

        let sensitiveSel = NSSelectorFromString("isSensitiveRegionForEnhancedSiri")
        if let method = class_getClassMethod(gmClass, sensitiveSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
            lines.append("+isSensitiveRegionForEnhancedSiri = \(fn(classObject, sensitiveSel))")
        }

        let useCases = [
            "com.apple.Settings.AppleIntelligence",
            "VisualIntelligence.gvicc",
            "GenerativeAssistant.visualIntelligenceCamera",
            "com.apple.VisualIntelligenceCamera.ImageSearch",
            "com.apple.VisualIntelligenceCamera.VisualLookup",
            "summarization.visualIntelligenceCamera"
        ]

        for useCase in useCases {
            let identifiers = [useCase] as NSArray
            lines.append("")
            lines.append("useCase=\(useCase)")

            let currentSel = NSSelectorFromString("currentWithUseCaseIdentifiers:language:")
            if let method = class_getClassMethod(gmClass, currentSel) {
                let fn = unsafeBitCast(method_getImplementation(method), to: GMCurrentFn.self)
                let raw = fn(classObject, currentSel, identifiers, language)
                lines.append("  current.rawStatus = \(raw)")
            } else {
                lines.append("  current.rawStatus = <selector unavailable>")
            }

            appendBoolUseCase(
                selectorName: "enabledWithUseCaseIdentifiers:language:",
                label: "enabled",
                gmClass: gmClass,
                classObject: classObject,
                identifiers: identifiers,
                language: language,
                to: &lines
            )
            appendBoolUseCase(
                selectorName: "useCasePartnerAllowedInUserLocaleRegionWithUseCaseIdentifiers:language:",
                label: "partnerAllowedInUserLocaleRegion",
                gmClass: gmClass,
                classObject: classObject,
                identifiers: identifiers,
                language: language,
                to: &lines
            )
            appendBoolUseCase(
                selectorName: "isUseCaseDisabledWithUseCaseIdentifiers:language:",
                label: "useCaseDisabled",
                gmClass: gmClass,
                classObject: classObject,
                identifiers: identifiers,
                language: language,
                to: &lines
            )
            appendBoolUseCase(
                selectorName: "assetIsNotReadyWithUseCaseIdentifiers:language:",
                label: "assetIsNotReady",
                gmClass: gmClass,
                classObject: classObject,
                identifiers: identifiers,
                language: language,
                to: &lines
            )
        }

        lines.append("")
        lines.append("NOTE: isUseCaseAccessNotGrantedSecure... is intentionally NOT called in this build because it crosses a privileged availability-service/XPC boundary from a sandboxed diagnostic app.")
    }

    private static func appendBoolUseCase(
        selectorName: String,
        label: String,
        gmClass: AnyClass,
        classObject: AnyObject,
        identifiers: NSArray,
        language: AnyObject?,
        to lines: inout [String]
    ) {
        let selector = NSSelectorFromString(selectorName)
        guard let method = class_getClassMethod(gmClass, selector) else {
            lines.append("  \(label) = <selector unavailable>")
            return
        }
        let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolUseCaseFn.self)
        lines.append("  \(label) = \(fn(classObject, selector, identifiers, language))")
    }

    private static func appendVisionKit(to lines: inout [String]) {
        lines.append("")
        lines.append("--- VisionKitCore baseline ---")
        let path = "/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore"
        let handle = dlopen(path, RTLD_NOW)
        lines.append("VisionKitCore dlopen = \(handle == nil ? "FAILED" : "OK")")
        // Intentionally not dlclose()'d; see GenerativeModels note above.

        guard let vkClass: AnyClass = NSClassFromString("VKCGMAvailability") else {
            lines.append("VKCGMAvailability = NOT FOUND")
            return
        }
        lines.append("VKCGMAvailability = FOUND")
        let classObject = vkClass as AnyObject

        for name in [
            "deviceIsEligibleForVI",
            "supportsVI",
            "enhancedSiriAvailable",
            "enhancedSiriEnabled"
        ] {
            let selector = NSSelectorFromString(name)
            if let method = class_getClassMethod(vkClass, selector) {
                let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
                lines.append("+\(name) = \(fn(classObject, selector))")
            } else {
                lines.append("+\(name) = <selector unavailable>")
            }
        }

        let sharedSel = NSSelectorFromString("sharedListener")
        if let method = class_getClassMethod(vkClass, sharedSel) {
            typealias ObjFn = @convention(c) (AnyObject, Selector) -> AnyObject?
            let fn = unsafeBitCast(method_getImplementation(method), to: ObjFn.self)
            if let listener = fn(classObject, sharedSel) {
                lines.append("+sharedListener = \(listener)")
                for name in ["deviceIsEligibleForVI", "supportsVI", "enhancedSiriAvailable", "enhancedSiriEnabled"] {
                    let selector = NSSelectorFromString(name)
                    if let method = class_getInstanceMethod(vkClass, selector) {
                        let boolFn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
                        lines.append("  listener.\(name) = \(boolFn(listener, selector))")
                    }
                }
            } else {
                lines.append("+sharedListener = <nil>")
            }
        }
    }

    private static func appendPreferences(to lines: inout [String]) {
        lines.append("")
        lines.append("--- com.apple.gms.availability preferences visible to this app ---")
        let domain = "com.apple.gms.availability" as CFString
        let keys = [
            "com.apple.gms.availability.key",
            "com.apple.gms.availability.unifiedReasons",
            "com.apple.gms.availability.useCaseReadiness",
            "com.apple.gms.availability.accessNotGrantedUseCases",
            "com.apple.gms.availability.foundationModelsCompatibilityVersionsInfo",
            "com.apple.gms.availability.secureInitializedUseCases",
            "com.apple.gms.availability.updatedSinceBootUUID",
            "key",
            "unifiedReasons",
            "useCaseReadiness",
            "accessNotGrantedUseCases",
            "secureInitializedUseCases",
            "updatedSinceBootUUID"
        ]

        for key in keys {
            let value = CFPreferencesCopyValue(
                key as CFString,
                domain,
                kCFPreferencesCurrentUser,
                kCFPreferencesAnyHost
            )
            if let value {
                lines.append("CFPreferences[\(key)] = \(String(describing: value)) [\(type(of: value))]")
            } else {
                lines.append("CFPreferences[\(key)] = <nil>")
            }
        }
    }

    private static func copyAnswer(_ key: String) -> AnyObject? {
        let paths = [
            "/usr/lib/libMobileGestalt.dylib",
            "/System/Library/PrivateFrameworks/MobileGestalt.framework/MobileGestalt"
        ]

        for path in paths {
            guard let handle = dlopen(path, RTLD_NOW) else { continue }
            // Deliberately keep MobileGestalt loaded as well; this is a tiny diagnostic process.
            guard let symbol = dlsym(handle, "MGCopyAnswer") else { continue }
            let function = unsafeBitCast(symbol, to: MGCopyAnswerFunction.self)
            guard let unmanaged = function(key as CFString) else { return nil }
            return unmanaged.takeRetainedValue() as AnyObject
        }
        return nil
    }

    private static func answerLine(for key: String) -> String {
        guard let value = copyAnswer(key) else {
            return "MGCopyAnswer(\(key)) = <nil>"
        }

        if let number = value as? NSNumber,
           CFGetTypeID(number) == CFBooleanGetTypeID() {
            return "MGCopyAnswer(\(key)) = \(number.boolValue) [Boolean]"
        }
        return "MGCopyAnswer(\(key)) = \(value) [\(type(of: value))]"
    }
}
