import CoreFoundation
import Darwin
import Foundation

enum MobileGestaltReadOnlyDiagnostic {
    private typealias MGCopyAnswerFunction =
        @convention(c) (CFString) -> Unmanaged<CFTypeRef>?

    static func run() {
        print("")
        print("========== MobileGestalt READ-ONLY Diagnostic ==========")

        dumpAnswer("ChinaCellular")
        dumpAnswer("RegionCode")
        dumpAnswer("RegionInfo")
        dumpAnswer("RegulatoryModelNumber")
        dumpAnswer("ProductType")
        dumpAnswer("HardwareModel")

        print("")
        print("--- CacheExtra ---")

        do {
            let access = GestaltAccess.shared()
            try access.connect()
            guard let dictionary = try access.readGestalt() as? [String: Any] else {
                print("CacheExtra = <unable to read MobileGestalt plist>")
                print("=========================================================")
                print("")
                return
            }

            let plist = GestaltPlist(dict: dictionary)
            let cacheExtra = plist.cacheExtra

            dumpCacheExtra(
                cacheExtra,
                key: "2xVt/Zm4gAkjGGVTZxO/Qw",
                name: "ChinaCellular"
            )
            dumpCacheExtra(
                cacheExtra,
                key: "h63QSdBCiT/z0WU6rdQv6Q",
                name: "RegionCode"
            )
            dumpCacheExtra(
                cacheExtra,
                key: "yK+xavymRGZ3xWc1tb8XDg",
                name: "RegionInfo"
            )
            dumpCacheExtra(
                cacheExtra,
                key: "97JDvERpVwO+GHtthIh7hA",
                name: "RegulatoryModelNumber"
            )
        } catch {
            print("CacheExtra read failed: \(error.localizedDescription)")
        }

        print("=========================================================")
        print("")
    }

    private static func copyAnswer(_ key: String) -> AnyObject? {
        let paths = [
            "/usr/lib/libMobileGestalt.dylib",
            "/System/Library/PrivateFrameworks/MobileGestalt.framework/MobileGestalt"
        ]

        for path in paths {
            guard let handle = dlopen(path, RTLD_NOW) else {
                continue
            }
            defer { dlclose(handle) }

            guard let symbol = dlsym(handle, "MGCopyAnswer") else {
                continue
            }

            let function = unsafeBitCast(
                symbol,
                to: MGCopyAnswerFunction.self
            )

            guard let unmanaged = function(key as CFString) else {
                return nil
            }

            return unmanaged.takeRetainedValue() as AnyObject
        }

        return nil
    }

    private static func dumpAnswer(_ key: String) {
        guard let value = copyAnswer(key) else {
            print("MGCopyAnswer(\(key)) = <nil>")
            return
        }

        if let number = value as? NSNumber,
           CFGetTypeID(number) == CFBooleanGetTypeID() {
            print("MGCopyAnswer(\(key)) = \(number.boolValue) [Boolean]")
            return
        }

        print("MGCopyAnswer(\(key)) = \(value) [\(type(of: value))]")
    }

    private static func dumpCacheExtra(
        _ cacheExtra: [String: Any],
        key: String,
        name: String
    ) {
        if let value = cacheExtra[key] {
            print("CacheExtra \(name) [\(key)] = \(value) [\(type(of: value))]")
        } else {
            print("CacheExtra \(name) [\(key)] = <ABSENT>")
        }
    }
}
