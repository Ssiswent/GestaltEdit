import CoreFoundation
import Darwin
import Foundation
import ObjectiveC.runtime

private enum GMSCallerContextProbe {
    private typealias GMCurrentFn = @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Int64
    private typealias GMBoolFn = @convention(c) (AnyObject, Selector) -> Bool
    private typealias GMBoolUseCaseFn = @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Bool
    private typealias GMSecureFn = @convention(c) (AnyObject, Selector, AnyObject, AnyObject?, UnsafeMutablePointer<AnyObject?>?) -> Bool

    private typealias SecTaskCreateFromSelfFn = @convention(c) (CFAllocator?) -> OpaquePointer?
    private typealias SecTaskCopyValueFn = @convention(c) (OpaquePointer, CFString, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFTypeRef>?
    private typealias SecTaskCopySigningIdentifierFn = @convention(c) (OpaquePointer, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFString>?

    private struct ScenarioResult {
        let name: String
        let observedBundleID: String
        let observedProcessName: String
        let rawStatus: Int64?
        let deviceEligible: Bool?
        let enabled: Bool?
        let partnerAllowed: Bool?
        let secureDenied: Bool?
        let secureError: String?
    }

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("--- GMS Caller Context Differential Probe ---")
        lines.append("READ-ONLY / EPHEMERAL: no system file, MobileGestalt value, preference, or availability return value is modified. Two Objective-C identity getters may be replaced only inside this app process for one query at a time and are restored immediately.")
        lines.append("Process: \(ProcessInfo.processInfo.processName) bundle=\(Bundle.main.bundleIdentifier ?? "<nil>")")
        lines.append("")

        let gmPath = "/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels"
        let gmHandle = dlopen(gmPath, RTLD_NOW)
        defer { if let gmHandle { dlclose(gmHandle) } }
        let gmClass: AnyClass? = NSClassFromString("GMAvailabilityWrapper")
        lines.append("GenerativeModels dlopen: \(gmHandle == nil ? "FAILED" : "OK")")
        lines.append("GMAvailabilityWrapper: \(gmClass == nil ? "NOT FOUND" : "FOUND")")

        lines.append("")
        lines.append("Self code-signing / entitlement snapshot:")
        lines.append(contentsOf: entitlementLines())

        lines.append("")
        lines.append("com.apple.gms.availability preference-domain snapshot:")
        lines.append(contentsOf: preferenceLines())

        guard let gmClass else {
            lines.append("")
            lines.append("GM class unavailable; differential scenarios skipped.")
            return lines.joined(separator: "\n")
        }

        let useCases = ["com.apple.Settings.AppleIntelligence"] as NSArray

        lines.append("")
        lines.append("Caller-identity differential scenarios:")
        lines.append("NOTE: bundle/process-name spoofing here affects only ordinary Objective-C getters in this process. It does NOT spoof code signature, entitlements, audit token, XPC identity, or Apple platform status.")

        let baseline = queryScenario(name: "baseline", gmClass: gmClass, useCases: useCases)
        appendScenario(baseline, to: &lines)

        let bundleOnly = withTemporaryBundleIdentifier("com.apple.camera") {
            queryScenario(name: "fake NSBundle.bundleIdentifier = com.apple.camera", gmClass: gmClass, useCases: useCases)
        }
        appendScenario(bundleOnly, to: &lines)

        let processOnly = withTemporaryProcessName("Camera") {
            queryScenario(name: "fake NSProcessInfo.processName = Camera", gmClass: gmClass, useCases: useCases)
        }
        appendScenario(processOnly, to: &lines)

        let both = withTemporaryBundleIdentifier("com.apple.camera") {
            withTemporaryProcessName("Camera") {
                queryScenario(name: "fake bundleIdentifier + processName", gmClass: gmClass, useCases: useCases)
            }
        }
        appendScenario(both, to: &lines)

        lines.append("")
        lines.append("Interpretation helper:")
        if let baseStatus = baseline.rawStatus {
            let changed = [bundleOnly, processOnly, both].contains {
                $0.rawStatus.map { $0 != baseStatus } ?? false
            }
            lines.append("  ordinary caller-name spoof changed GM rawStatus = \(changed)")
        } else {
            lines.append("  baseline GM rawStatus unavailable")
        }
        lines.append("  If all scenarios stay identical while secure query reports sandbox/XPC denial, the remaining difference is more likely privileged caller identity (entitlement / audit token / secure availability service) than NSBundle/processName.")
        lines.append("Probe complete: any temporary Objective-C IMP replacements were restored before this report returned.")

        return lines.joined(separator: "\n")
    }

    private static func queryScenario(name: String, gmClass: AnyClass, useCases: NSArray) -> ScenarioResult {
        let classObject = gmClass as AnyObject
        let language: AnyObject? = nil

        var rawStatus: Int64?
        let currentSel = NSSelectorFromString("currentWithUseCaseIdentifiers:language:")
        if let method = class_getClassMethod(gmClass, currentSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMCurrentFn.self)
            rawStatus = fn(classObject, currentSel, useCases, language)
        }

        var deviceEligible: Bool?
        let eligibleSel = NSSelectorFromString("isDeviceEligible")
        if let method = class_getClassMethod(gmClass, eligibleSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
            deviceEligible = fn(classObject, eligibleSel)
        }

        var enabled: Bool?
        let enabledSel = NSSelectorFromString("enabledWithUseCaseIdentifiers:language:")
        if let method = class_getClassMethod(gmClass, enabledSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolUseCaseFn.self)
            enabled = fn(classObject, enabledSel, useCases, language)
        }

        var partnerAllowed: Bool?
        let partnerSel = NSSelectorFromString("useCasePartnerAllowedInUserLocaleRegionWithUseCaseIdentifiers:language:")
        if let method = class_getClassMethod(gmClass, partnerSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolUseCaseFn.self)
            partnerAllowed = fn(classObject, partnerSel, useCases, language)
        }

        var secureDenied: Bool?
        var secureErrorText: String?
        let secureSel = NSSelectorFromString("isUseCaseAccessNotGrantedSecureWithUseCaseIdentifiers:language:error:")
        if let method = class_getClassMethod(gmClass, secureSel) {
            let fn = unsafeBitCast(method_getImplementation(method), to: GMSecureFn.self)
            var errorObject: AnyObject?
            secureDenied = withUnsafeMutablePointer(to: &errorObject) { ptr in
                fn(classObject, secureSel, useCases, language, ptr)
            }
            if let errorObject {
                secureErrorText = String(describing: errorObject)
            }
        }

        return ScenarioResult(
            name: name,
            observedBundleID: Bundle.main.bundleIdentifier ?? "<nil>",
            observedProcessName: ProcessInfo.processInfo.processName,
            rawStatus: rawStatus,
            deviceEligible: deviceEligible,
            enabled: enabled,
            partnerAllowed: partnerAllowed,
            secureDenied: secureDenied,
            secureError: secureErrorText
        )
    }

    private static func appendScenario(_ result: ScenarioResult, to lines: inout [String]) {
        lines.append("  [\(result.name)]")
        lines.append("    observed bundleIdentifier = \(result.observedBundleID)")
        lines.append("    observed processName = \(result.observedProcessName)")
        lines.append("    current.rawStatus = \(result.rawStatus.map(String.init) ?? "<unavailable>")")
        lines.append("    isDeviceEligible = \(format(result.deviceEligible))")
        lines.append("    enabled = \(format(result.enabled))")
        lines.append("    partnerAllowedInUserLocaleRegion = \(format(result.partnerAllowed))")
        lines.append("    accessNotGrantedSecure = \(format(result.secureDenied))")
        if let error = result.secureError {
            lines.append("    secure.error = \(error)")
        } else {
            lines.append("    secure.error = <nil>")
        }
    }

    private static func format(_ value: Bool?) -> String {
        guard let value else { return "<unavailable>" }
        return value ? "true" : "false"
    }

    private static func preferenceLines() -> [String] {
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
            "foundationModelsCompatibilityVersionsInfo",
            "secureInitializedUseCases",
            "updatedSinceBootUUID"
        ]

        var lines: [String] = []
        for key in keys {
            let value = CFPreferencesCopyValue(
                key as CFString,
                domain,
                kCFPreferencesCurrentUser,
                kCFPreferencesAnyHost
            )
            if let value {
                lines.append("  CFPreferences[\(key)] = \(String(describing: value)) [\(type(of: value))]")
            } else {
                lines.append("  CFPreferences[\(key)] = <nil>")
            }
        }

        if let suite = UserDefaults(suiteName: "com.apple.gms.availability") {
            let dict = suite.dictionaryRepresentation()
            lines.append("  UserDefaults suite keyCount = \(dict.count)")
            let interesting = dict.keys.sorted().filter {
                let lower = $0.lowercased()
                return lower.contains("availability") || lower.contains("reason") || lower.contains("usecase") || lower.contains("secure") || lower.contains("region")
            }
            if interesting.isEmpty {
                lines.append("  UserDefaults suite interesting keys = <none visible>")
            } else {
                for key in interesting.prefix(50) {
                    lines.append("  UserDefaults[\(key)] = \(String(describing: dict[key]!))")
                }
            }
        } else {
            lines.append("  UserDefaults(suiteName:) = <nil>")
        }
        return lines
    }

    private static func entitlementLines() -> [String] {
        guard let security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW) else {
            return ["  Security.framework dlopen = FAILED"]
        }
        defer { dlclose(security) }

        guard let createSym = dlsym(security, "SecTaskCreateFromSelf"),
              let copySym = dlsym(security, "SecTaskCopyValueForEntitlement") else {
            return ["  SecTask private symbols = unavailable"]
        }

        let create = unsafeBitCast(createSym, to: SecTaskCreateFromSelfFn.self)
        let copy = unsafeBitCast(copySym, to: SecTaskCopyValueFn.self)
        guard let task = create(kCFAllocatorDefault) else {
            return ["  SecTaskCreateFromSelf = <nil>"]
        }

        var lines: [String] = []
        if let signingSym = dlsym(security, "SecTaskCopySigningIdentifier") {
            let signing = unsafeBitCast(signingSym, to: SecTaskCopySigningIdentifierFn.self)
            var signingError: Unmanaged<CFError>?
            if let identifier = signing(task, &signingError)?.takeRetainedValue() {
                lines.append("  signingIdentifier = \(identifier)")
            } else {
                lines.append("  signingIdentifier = <unavailable>")
            }
        }

        let keys = [
            "application-identifier",
            "platform-application",
            "com.apple.generativeexperiences.availabilityService",
            "com.apple.generativeexperiences.generativeexperiencessession",
            "com.apple.private.security.storage.os_eligibility.readonly",
            "com.apple.security.exception.mach-lookup.global-name",
            "com.apple.security.temporary-exception.mach-lookup.global-name",
            "com.apple.security.exception.shared-preference.read-only",
            "com.apple.security.exception.shared-preference.read-write"
        ]

        for key in keys {
            var error: Unmanaged<CFError>?
            if let value = copy(task, key as CFString, &error)?.takeRetainedValue() {
                lines.append("  entitlement[\(key)] = \(String(describing: value))")
            } else if let error {
                lines.append("  entitlement[\(key)] = <nil> error=\(error.takeRetainedValue())")
            } else {
                lines.append("  entitlement[\(key)] = <nil>")
            }
        }
        return lines
    }

    private static func withTemporaryBundleIdentifier<T>(_ value: String, _ body: () -> T) -> T {
        let selector = NSSelectorFromString("bundleIdentifier")
        guard let method = class_getInstanceMethod(Bundle.self, selector) else {
            return body()
        }
        let original = method_getImplementation(method)
        let block: @convention(block) (AnyObject) -> NSString? = { _ in value as NSString }
        let replacement = imp_implementationWithBlock(block)
        method_setImplementation(method, replacement)
        defer {
            method_setImplementation(method, original)
            imp_removeBlock(replacement)
        }
        return body()
    }

    private static func withTemporaryProcessName<T>(_ value: String, _ body: () -> T) -> T {
        let selector = NSSelectorFromString("processName")
        guard let method = class_getInstanceMethod(ProcessInfo.self, selector) else {
            return body()
        }
        let original = method_getImplementation(method)
        let block: @convention(block) (AnyObject) -> NSString = { _ in value as NSString }
        let replacement = imp_implementationWithBlock(block)
        method_setImplementation(method, replacement)
        defer {
            method_setImplementation(method, original)
            imp_removeBlock(replacement)
        }
        return body()
    }
}

enum MobileGestaltReadOnlyDiagnostic {
    private typealias MGCopyAnswerFunction =
        @convention(c) (CFString) -> Unmanaged<CFTypeRef>?

    static func run() {
        print(generateReport())
    }

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("========== GMS Caller Context READ-ONLY Diagnostic ==========")
        lines.append("Generated: \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("OS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
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
                lines.append("")
                lines.append(GMSCallerContextProbe.generateReport())
                lines.append("===============================================================")
                return lines.joined(separator: "\n")
            }

            let plist = GestaltPlist(dict: dictionary)
            let cacheExtra = plist.cacheExtra
            lines.append(cacheExtraLine(cacheExtra, key: "2xVt/Zm4gAkjGGVTZxO/Qw", name: "ChinaCellular hash candidate"))
            lines.append(cacheExtraLine(cacheExtra, key: "iyfxmLogGVIaH7aEgqwcIA", name: "green-tea"))
            lines.append(cacheExtraLine(cacheExtra, key: "4snMZS8LJkSctKypt2m+xA", name: "not-green-tea"))
            lines.append(cacheExtraLine(cacheExtra, key: "h63QSdBCiT/z0WU6rdQv6Q", name: "RegionCode"))
            lines.append(cacheExtraLine(cacheExtra, key: "zHeENZu+wbg7PUprwNwBWg", name: "RegionInfo standard hash"))
            lines.append(cacheExtraLine(cacheExtra, key: "yK+xavymRGZ3xWc1tb8XDg", name: "GestaltEdit iOS 27 region override key"))
            lines.append(cacheExtraLine(cacheExtra, key: "97JDvERpVwO+GHtthIh7hA", name: "RegulatoryModelNumber"))
        } catch {
            lines.append("CacheExtra read failed: \(error.localizedDescription)")
        }

        lines.append("")
        lines.append(GMSCallerContextProbe.generateReport())
        lines.append("")
        lines.append("===============================================================")
        lines.append("READ-ONLY: no persistent system setting was modified by this report.")
        return lines.joined(separator: "\n")
    }

    private static func copyAnswer(_ key: String) -> AnyObject? {
        let paths = [
            "/usr/lib/libMobileGestalt.dylib",
            "/System/Library/PrivateFrameworks/MobileGestalt.framework/MobileGestalt"
        ]

        for path in paths {
            guard let handle = dlopen(path, RTLD_NOW) else { continue }
            defer { dlclose(handle) }
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

    private static func cacheExtraLine(_ cacheExtra: [String: Any], key: String, name: String) -> String {
        if let value = cacheExtra[key] {
            return "CacheExtra \(name) [\(key)] = \(value) [\(type(of: value))]"
        }
        return "CacheExtra \(name) [\(key)] = <ABSENT>"
    }
}
