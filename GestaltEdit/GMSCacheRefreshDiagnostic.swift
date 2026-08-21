import CoreFoundation
import Darwin
import Foundation
import ObjectiveC.runtime
import UIKit

/// Targeted diagnostic/experiment for the Camera Visual Intelligence investigation.
///
/// Native device logs show that the direct Camera Control launch can start Camera, compute an
/// unavailable GMS/VisionKit state very early, and only later register the Darwin availability
/// observer. A single notification sent before Camera launches can therefore be missed.
///
/// This version opens a short background execution window and repeatedly broadcasts the same
/// transient com.apple.gms.availability.notification while the user directly long-presses Camera
/// Control. This lets a freshly launched Camera process receive the signal after its observer is
/// registered. No preferences, MobileGestalt, files, or availability values are written.
enum GMSCacheRefreshDiagnostic {
    private static let notificationName = "com.apple.gms.availability.notification"
    private static let refreshWindowSeconds: TimeInterval = 8.0
    private static let refreshIntervalSeconds: TimeInterval = 0.25

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

    static func directCameraControlTestStartingReport() -> String {
        [
            "========== iOS 27 VI DIRECT CAMERA CONTROL CACHE REFRESH ==========",
            "TEST WINDOW: 8 seconds",
            "",
            "NOW:",
            "1. Do NOT open Camera manually.",
            "2. Immediately long-press Camera Control to invoke Visual Intelligence directly.",
            "3. Keep the VI/Camera screen open while the 8-second refresh window runs.",
            "4. Afterward, return to GestaltEdit and Copy the completed report.",
            "",
            "The app is repeatedly posting only the transient Darwin notification:",
            notificationName,
            "",
            "No preferences, MobileGestalt, files, GMS values, respring, or reboot are performed.",
            "==================================================================="
        ].joined(separator: "\n")
    }

    /// Starts an 8-second refresh window intended specifically for the real user flow:
    /// GestaltEdit -> long-press Camera Control -> Camera launches directly into the VI path.
    /// A UIKit background task keeps this app alive briefly after Camera takes foreground.
    static func startDirectCameraControlRefreshWindow(completion: @escaping (String) -> Void) {
        var lines = header(title: "DIRECT CAMERA CONTROL 8s WINDOW")
        appendSnapshot(label: "before-window", to: &lines)
        lines.append("")
        lines.append("--- direct Camera Control refresh window ---")
        lines.append("windowSeconds=\(String(format: "%.2f", refreshWindowSeconds))")
        lines.append("intervalSeconds=\(String(format: "%.2f", refreshIntervalSeconds))")
        lines.append("expectedPosts≈\(Int(refreshWindowSeconds / refreshIntervalSeconds))")
        lines.append("Instruction: do NOT open Camera first; long-press Camera Control directly while this window is active.")

        let app = UIApplication.shared
        var backgroundTask: UIBackgroundTaskIdentifier = .invalid
        var finished = false
        var postCount = 0
        let startedAt = Date()

        func endBackgroundTaskIfNeeded() {
            if backgroundTask != .invalid {
                app.endBackgroundTask(backgroundTask)
                backgroundTask = .invalid
            }
        }

        func finish(reason: String) {
            guard !finished else { return }
            finished = true

            let elapsed = Date().timeIntervalSince(startedAt)
            lines.append("finishReason=\(reason)")
            lines.append("elapsedSeconds=\(String(format: "%.3f", elapsed))")
            lines.append("postCount=\(postCount)")
            lines.append("")
            appendSnapshot(label: "after-window", to: &lines)
            lines.append("")
            lines.append("INTERPRETATION:")
            lines.append("1. If direct long-press VI works during/after this window, Camera's early stale GMS/VK cache becomes the leading cause.")
            lines.append("2. If Camera still falls back to Photo/VI unavailable, the next priority is Camera-specific caller/process initialization or a privileged availability input, not languageOption.")
            lines.append("3. Repeated posts are used because native logs show Camera can compute AIAvailability before it registers the GMS Darwin observer during launch.")
            lines.append("===============================================================================")

            endBackgroundTaskIfNeeded()
            completion(lines.joined(separator: "\n"))
        }

        backgroundTask = app.beginBackgroundTask(withName: "VI-GMS-Refresh-Window") {
            finish(reason: "background-task-expired")
        }

        func tick() {
            guard !finished else { return }

            let elapsed = Date().timeIntervalSince(startedAt)
            if elapsed >= refreshWindowSeconds {
                finish(reason: "completed-8s-window")
                return
            }

            postAvailabilityNotification()
            postCount += 1

            DispatchQueue.main.asyncAfter(deadline: .now() + refreshIntervalSeconds) {
                tick()
            }
        }

        // Post immediately, then continue every 250 ms. If Camera launches after the first post,
        // later posts can still arrive after its observer registration completes.
        tick()
    }

    private static func postAvailabilityNotification() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let name = CFNotificationName(rawValue: notificationName as CFString)
        CFNotificationCenterPostNotification(center, name, nil, nil, true)
    }

    private static func header(title: String) -> [String] {
        [
            "========== iOS 27 VI GMS/VK CACHE REFRESH \(title) Diagnostic ==========",
            "Generated: \(ISO8601DateFormatter().string(from: Date()))",
            "OS: \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "Process: \(ProcessInfo.processInfo.processName) bundle=\(Bundle.main.bundleIdentifier ?? "<nil>")",
            "Locale.current=\(Locale.current.identifier)",
            "SAFETY: snapshots use only previously verified zero/two-argument getters. Refresh mode only posts the transient Darwin notification com.apple.gms.availability.notification and briefly requests normal UIKit background execution so posting can continue when Camera takes foreground. No secure XPC, setters/preheat, swizzling/IMP replacement, preferences/MobileGestalt/file writes, respring or reboot.",
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
