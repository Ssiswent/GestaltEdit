import Darwin
import Foundation
import ObjectiveC.runtime

/// Targeted diagnostic/experiment for the Camera Visual Intelligence investigation.
///
/// Evidence from device logs shows Camera returning a cached unavailable GMS state while
/// other processes on the same device report the same Apple Intelligence use case as available.
/// VisionKitCore's VKCGMAvailability caches its result and observes
/// com.apple.gms.availability.notification. This probe snapshots the same public-in-process
/// surfaces before/after broadcasting that Darwin notification.
///
/// The broadcast is transient and non-persistent: it does not write preferences, MobileGestalt,
/// files, or availability state. It merely posts the notification name already observed by
/// GenerativeModels/VisionKitCore.
enum GMSCacheRefreshDiagnostic {
    private static let notificationName = "com.apple.gms.availability.notification"

    private typealias GMCurrentFn =
        @convention(c) (AnyObject, Selector, AnyObject, AnyObject?) -> Int64
    private typealias GMBoolFn =
        @convention(c) (AnyObject, Selector) -> Bool
    private typealias ObjFn =
        @convention(c) (AnyObject, Selector) -> AnyObject?

    static func snapshotReport() -> String {
        var lines = header(title: "SNAPSHOT")
        appendSnapshot(label: "current", to: &lines)
        lines.append("")
        lines.append("No notification was posted in this snapshot.")
        lines.append("===============================================================================")
        return lines.joined(separator: "\n")
    }

    static func broadcastAndMeasureReport() -> String {
        var lines = header(title: "BROADCAST + BEFORE/AFTER")
        appendSnapshot(label: "before", to: &lines)

        lines.append("")
        lines.append("--- transient Darwin availability refresh signal ---")
        let status: Int32 = notificationName.withCString { name in
            notify_post(name)
        }
        lines.append("notify_post(\(notificationName)) status=\(status)")
        lines.append("NOTE: this posts a transient notification only; it does not persist or write availability values.")

        // Run off the main thread from the UI so observers have time to process the signal.
        Thread.sleep(forTimeInterval: 0.75)

        lines.append("")
        appendSnapshot(label: "after-750ms", to: &lines)
        lines.append("")
        lines.append("INTERPRETATION:")
        lines.append("1. If this app's values change after the signal, a live cache refresh path is confirmed locally.")
        lines.append("2. Camera can be left alive in the app switcher while this button is pressed; then return to Camera and test VI. A functional change would directly implicate Camera's stale GMS/VK cache.")
        lines.append("3. If Camera remains unavailable, the next priority is caller/process-specific initialization rather than language, requestType, VLU authorization, or PartnerImageSearch.")
        lines.append("===============================================================================")
        return lines.joined(separator: "\n")
    }

    private static func header(title: String) -> [String] {
        [
            "========== iOS 27 VI GMS/VK CACHE REFRESH \(title) Diagnostic ==========",
            "Generated: \(ISO8601DateFormatter().string(from: Date()))",
            "OS: \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "Process: \(ProcessInfo.processInfo.processName) bundle=\(Bundle.main.bundleIdentifier ?? "<nil>")",
            "Locale.current=\(Locale.current.identifier)",
            "SAFETY: snapshots use only previously verified zero/two-argument getters. Broadcast mode only posts the transient Darwin notification com.apple.gms.availability.notification. No secure XPC, setters/preheat, swizzling/IMP replacement, preferences/MobileGestalt/file writes, respring or reboot.",
            ""
        ]
    }

    private static func appendSnapshot(label: String, to lines: inout [String]) {
        lines.append("--- snapshot: \(label) ---")

        let gmPath = "/System/Library/PrivateFrameworks/GenerativeModels.framework/GenerativeModels"
        let vkPath = "/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore"
        let gmHandle = dlopen(gmPath, RTLD_NOW)
        let vkHandle = dlopen(vkPath, RTLD_NOW)
        lines.append("GenerativeModels dlopen=\(gmHandle == nil ? "FAILED" : "OK")")
        lines.append("VisionKitCore dlopen=\(vkHandle == nil ? "FAILED" : "OK")")

        appendGM(to: &lines)
        appendVK(to: &lines)
    }

    private static func appendGM(to lines: inout [String]) {
        guard let gmClass: AnyClass = NSClassFromString("GMAvailabilityWrapper") else {
            lines.append("GMAvailabilityWrapper=NOT FOUND")
            return
        }
        let classObject = gmClass as AnyObject
        lines.append("GMAvailabilityWrapper=FOUND")

        let currentSel = NSSelectorFromString("currentWithUseCaseIdentifiers:language:")
        if let method = class_getClassMethod(gmClass, currentSel) {
            let types = method_getTypeEncoding(method).map { String(cString: $0) } ?? "<nil>"
            let argc = method_getNumberOfArguments(method)
            lines.append("+currentWithUseCaseIdentifiers:language: types=\(types) argc=\(argc)")
            if argc == 4, types.first == "q" {
                let fn = unsafeBitCast(method_getImplementation(method), to: GMCurrentFn.self)
                let empty = NSArray()
                let settings = ["com.apple.Settings.AppleIntelligence"] as NSArray
                let emptyRaw = fn(classObject, currentSel, empty, nil)
                let settingsRaw = fn(classObject, currentSel, settings, nil)
                lines.append("GM current useCases=[] language=nil -> rawStatus=\(emptyRaw)")
                lines.append("GM current useCases=[com.apple.Settings.AppleIntelligence] language=nil -> rawStatus=\(settingsRaw)")
            } else {
                lines.append("GM current skipped: ABI mismatch")
            }
        } else {
            lines.append("+currentWithUseCaseIdentifiers:language:=<missing>")
        }

        appendClassBool(name: "isDeviceEligible", cls: gmClass, object: classObject, prefix: "GM", to: &lines)
        appendClassBool(name: "isOkayToHaveAsset", cls: gmClass, object: classObject, prefix: "GM", to: &lines)
        appendClassBool(name: "wasEverAvailable", cls: gmClass, object: classObject, prefix: "GM", to: &lines)
    }

    private static func appendVK(to lines: inout [String]) {
        guard let vkClass: AnyClass = NSClassFromString("VKCGMAvailability") else {
            lines.append("VKCGMAvailability=NOT FOUND")
            return
        }
        let classObject = vkClass as AnyObject
        lines.append("VKCGMAvailability=FOUND")

        appendClassBool(name: "supportsVI", cls: vkClass, object: classObject, prefix: "VK class", to: &lines)
        appendClassBool(name: "deviceIsEligibleForVI", cls: vkClass, object: classObject, prefix: "VK class", to: &lines)
        appendClassBool(name: "enhancedSiriAvailable", cls: vkClass, object: classObject, prefix: "VK class", to: &lines)
        appendClassBool(name: "enhancedSiriEnabled", cls: vkClass, object: classObject, prefix: "VK class", to: &lines)

        let sharedSel = NSSelectorFromString("sharedListener")
        guard let sharedMethod = class_getClassMethod(vkClass, sharedSel) else {
            lines.append("VK +sharedListener=<missing>")
            return
        }
        let types = method_getTypeEncoding(sharedMethod).map { String(cString: $0) } ?? "<nil>"
        lines.append("VK +sharedListener types=\(types)")
        guard types.first == "@" else {
            lines.append("VK sharedListener skipped: ABI mismatch")
            return
        }

        let fn = unsafeBitCast(method_getImplementation(sharedMethod), to: ObjFn.self)
        guard let listener = fn(classObject, sharedSel) else {
            lines.append("VK sharedListener=<nil>")
            return
        }
        lines.append("VK sharedListener=\(listener)")
        appendInstanceBool(name: "supportsVI", cls: vkClass, object: listener, prefix: "VK listener", to: &lines)
        appendInstanceBool(name: "deviceIsEligibleForVI", cls: vkClass, object: listener, prefix: "VK listener", to: &lines)
        appendInstanceBool(name: "enhancedSiriAvailable", cls: vkClass, object: listener, prefix: "VK listener", to: &lines)
        appendInstanceBool(name: "enhancedSiriEnabled", cls: vkClass, object: listener, prefix: "VK listener", to: &lines)
    }

    private static func appendClassBool(name: String, cls: AnyClass, object: AnyObject, prefix: String, to lines: inout [String]) {
        let sel = NSSelectorFromString(name)
        guard let method = class_getClassMethod(cls, sel) else {
            lines.append("\(prefix) +\(name)=<missing>")
            return
        }
        let types = method_getTypeEncoding(method).map { String(cString: $0) } ?? "<nil>"
        let argc = method_getNumberOfArguments(method)
        guard argc == 2, types.first == "B" || types.first == "c" else {
            lines.append("\(prefix) +\(name) types=\(types) argc=\(argc) <ABI mismatch; not called>")
            return
        }
        let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
        lines.append("\(prefix) +\(name)=\(fn(object, sel)) types=\(types)")
    }

    private static func appendInstanceBool(name: String, cls: AnyClass, object: AnyObject, prefix: String, to lines: inout [String]) {
        let sel = NSSelectorFromString(name)
        guard let method = class_getInstanceMethod(cls, sel) else {
            lines.append("\(prefix).\(name)=<missing>")
            return
        }
        let types = method_getTypeEncoding(method).map { String(cString: $0) } ?? "<nil>"
        let argc = method_getNumberOfArguments(method)
        guard argc == 2, types.first == "B" || types.first == "c" else {
            lines.append("\(prefix).\(name) types=\(types) argc=\(argc) <ABI mismatch; not called>")
            return
        }
        let fn = unsafeBitCast(method_getImplementation(method), to: GMBoolFn.self)
        lines.append("\(prefix).\(name)=\(fn(object, sel)) types=\(types)")
    }
}
