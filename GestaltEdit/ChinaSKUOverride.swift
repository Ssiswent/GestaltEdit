import CoreFoundation
import Foundation

enum ChinaSKUOverride {
    static let greenTeaKey = "iyfxmLogGVIaH7aEgqwcIA"
    static let notGreenTeaKey = "4snMZS8LJkSctKypt2m+xA"

    struct Result {
        let message: String
    }

    enum OverrideError: LocalizedError {
        case invalidPlist
        case cacheExtraMissing
        case preexistingOverrideValues
        case verificationFailed

        var errorDescription: String? {
            switch self {
            case .invalidPlist:
                return "The MobileGestalt plist is not a valid dictionary."
            case .cacheExtraMissing:
                return "MobileGestalt is missing CacheExtra. No changes were made."
            case .preexistingOverrideValues:
                return "One or both China SKU override keys already exist in CacheExtra. For safety, this experimental tool will not overwrite pre-existing values."
            case .verificationFailed:
                return "The values read back after writing did not match the intended override."
            }
        }
    }

    static func apply() throws -> Result {
        let access = GestaltAccess.shared()
        try access.connect()

        let originalData = try access.readGestaltData()
        let backup = try GestaltBackupStore.create(from: originalData)

        guard var dictionary = try access.readGestalt() as? [String: Any] else {
            throw OverrideError.invalidPlist
        }
        guard var cacheExtra = dictionary["CacheExtra"] as? [String: Any] else {
            throw OverrideError.cacheExtraMissing
        }

        guard cacheExtra[greenTeaKey] == nil,
              cacheExtra[notGreenTeaKey] == nil else {
            throw OverrideError.preexistingOverrideValues
        }

        cacheExtra[greenTeaKey] = NSNumber(value: false)
        cacheExtra[notGreenTeaKey] = NSNumber(value: true)
        dictionary["CacheExtra"] = cacheExtra

        try access.saveGestalt(dictionary)

        guard let verification = try access.readGestalt() as? [String: Any],
              let verifiedCacheExtra = verification["CacheExtra"] as? [String: Any],
              booleanValue(verifiedCacheExtra[greenTeaKey]) == false,
              booleanValue(verifiedCacheExtra[notGreenTeaKey]) == true else {
            throw OverrideError.verificationFailed
        }

        return Result(
            message: "Override written and verified in CacheExtra. Backup: \(backup.name). No reboot or respring was performed. For the runtime MGCopyAnswer test, restart the iPhone, then reopen this app and tap Refresh."
        )
    }

    static func revert() throws -> Result {
        let access = GestaltAccess.shared()
        try access.connect()

        let originalData = try access.readGestaltData()
        let backup = try GestaltBackupStore.create(from: originalData)

        guard var dictionary = try access.readGestalt() as? [String: Any] else {
            throw OverrideError.invalidPlist
        }
        guard var cacheExtra = dictionary["CacheExtra"] as? [String: Any] else {
            throw OverrideError.cacheExtraMissing
        }

        cacheExtra.removeValue(forKey: greenTeaKey)
        cacheExtra.removeValue(forKey: notGreenTeaKey)
        dictionary["CacheExtra"] = cacheExtra

        try access.saveGestalt(dictionary)

        guard let verification = try access.readGestalt() as? [String: Any],
              let verifiedCacheExtra = verification["CacheExtra"] as? [String: Any],
              verifiedCacheExtra[greenTeaKey] == nil,
              verifiedCacheExtra[notGreenTeaKey] == nil else {
            throw OverrideError.verificationFailed
        }

        return Result(
            message: "China SKU override keys were removed and the result was verified. Backup of the pre-revert state: \(backup.name). Restart the iPhone to restore runtime-derived MobileGestalt answers."
        )
    }

    static func cacheExtraStateDescription() -> String {
        do {
            let access = GestaltAccess.shared()
            try access.connect()
            guard let dictionary = try access.readGestalt() as? [String: Any],
                  let cacheExtra = dictionary["CacheExtra"] as? [String: Any] else {
                return "CacheExtra state unavailable"
            }

            let green = describeBoolean(cacheExtra[greenTeaKey])
            let notGreen = describeBoolean(cacheExtra[notGreenTeaKey])
            return "green-tea override: \(green)\nnot-green-tea override: \(notGreen)"
        } catch {
            return "CacheExtra state error: \(error.localizedDescription)"
        }
    }

    private static func booleanValue(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID() else {
            return nil
        }
        return number.boolValue
    }

    private static func describeBoolean(_ value: Any?) -> String {
        guard let value = booleanValue(value) else { return "<ABSENT>" }
        return value ? "true" : "false"
    }
}
