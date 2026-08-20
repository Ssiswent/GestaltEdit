import CoreFoundation
import Darwin
import Foundation

enum MobileGestaltReadOnlyDiagnostic {
    private typealias MGCopyAnswerFunction =
        @convention(c) (CFString) -> Unmanaged<CFTypeRef>?

    static func run() {
        print(generateReport())
    }

    static func generateReport() -> String {
        var lines: [String] = []
        lines.append("========== MobileGestalt READ-ONLY Diagnostic ==========")
        lines.append("")

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
        lines.append("--- CacheExtra ---")

        do {
            let access = GestaltAccess.shared()
            try access.connect()
            guard let dictionary = try access.readGestalt() as? [String: Any] else {
                lines.append("CacheExtra = <unable to read MobileGestalt plist>")
                lines.append("=========================================================")
                return lines.joined(separator: "\n")
            }

            let plist = GestaltPlist(dict: dictionary)
            let cacheExtra = plist.cacheExtra

            lines.append(cacheExtraLine(
                cacheExtra,
                key: "2xVt/Zm4gAkjGGVTZxO/Qw",
                name: "ChinaCellular hash candidate"
            ))
            lines.append(cacheExtraLine(
                cacheExtra,
                key: "iyfxmLogGVIaH7aEgqwcIA",
                name: "green-tea (Chinese-market device flag)"
            ))
            lines.append(cacheExtraLine(
                cacheExtra,
                key: "4snMZS8LJkSctKypt2m+xA",
                name: "not-green-tea (non-Chinese-market device flag)"
            ))
            lines.append(cacheExtraLine(
                cacheExtra,
                key: "h63QSdBCiT/z0WU6rdQv6Q",
                name: "RegionCode"
            ))
            lines.append(cacheExtraLine(
                cacheExtra,
                key: "zHeENZu+wbg7PUprwNwBWg",
                name: "RegionInfo (standard hash)"
            ))
            lines.append(cacheExtraLine(
                cacheExtra,
                key: "yK+xavymRGZ3xWc1tb8XDg",
                name: "GestaltEdit iOS 27 region override key"
            ))
            lines.append(cacheExtraLine(
                cacheExtra,
                key: "97JDvERpVwO+GHtthIh7hA",
                name: "RegulatoryModelNumber"
            ))
            lines.append(cacheExtraLine(
                cacheExtra,
                key: "A62OafQ85EJAiiqKn4agtg",
                name: "DeviceSupportsGenerativeModelSystems"
            ))
        } catch {
            lines.append("CacheExtra read failed: \(error.localizedDescription)")
        }

        lines.append("=========================================================")
        return lines.joined(separator: "\n")
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

    private static func cacheExtraLine(
        _ cacheExtra: [String: Any],
        key: String,
        name: String
    ) -> String {
        if let value = cacheExtra[key] {
            return "CacheExtra \(name) [\(key)] = \(value) [\(type(of: value))]"
        }
        return "CacheExtra \(name) [\(key)] = <ABSENT>"
    }
}
