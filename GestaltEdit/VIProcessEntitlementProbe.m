#import "VIProcessEntitlementProbe.h"
#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <errno.h>
#import <sys/types.h>

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_name(int pid, void *buffer, uint32_t buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

#define VI_CS_OPS_STATUS 0
#define VI_CS_OPS_ENTITLEMENTS_BLOB 7
#define VI_CS_OPS_IDENTITY 11
#define VI_CS_OPS_TEAMID 14
#define VI_CS_OPS_DER_ENTITLEMENTS_BLOB 16

#define VI_CS_PLATFORM_BINARY 0x04000000u
#define VI_CSMAGIC_EMBEDDED_ENTITLEMENTS 0xfade7171u
#define VI_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS 0xfade7172u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t length;
} VICSBlobHeader;

static NSString *VIErrnoString(int err) {
    if (err == 0) return @"0";
    const char *s = strerror(err);
    return [NSString stringWithFormat:@"%d (%s)", err, s ?: "unknown"];
}

static NSString *VIStringFromCStringBuffer(const void *buf, size_t len) {
    if (!buf || len == 0) return @"<nil>";
    const char *c = (const char *)buf;
    size_t n = strnlen(c, len);
    if (n == 0) return @"<empty>";
    NSString *s = [[NSString alloc] initWithBytes:c length:n encoding:NSUTF8StringEncoding];
    return s ?: @"<non-utf8>";
}

static NSDictionary *VIEntitlementsForPID(pid_t pid, NSMutableArray<NSString *> *notes) {
    VICSBlobHeader header = {0};
    errno = 0;
    int rc = csops(pid, VI_CS_OPS_ENTITLEMENTS_BLOB, &header, sizeof(header));
    int firstErr = errno;
    uint32_t len = ntohl(header.length);
    uint32_t magic = ntohl(header.magic);

    [notes addObject:[NSString stringWithFormat:@"csops(xml) header rc=%d errno=%@ magic=0x%08x len=%u", rc, VIErrnoString(firstErr), magic, len]];

    if (len >= sizeof(VICSBlobHeader) && len <= (1024u * 1024u)) {
        NSMutableData *data = [NSMutableData dataWithLength:len];
        errno = 0;
        int rc2 = csops(pid, VI_CS_OPS_ENTITLEMENTS_BLOB, data.mutableBytes, data.length);
        int err2 = errno;
        [notes addObject:[NSString stringWithFormat:@"csops(xml) full rc=%d errno=%@", rc2, VIErrnoString(err2)]];
        if (rc2 == 0) {
            const uint8_t *bytes = data.bytes;
            if (data.length >= sizeof(VICSBlobHeader)) {
                uint32_t m = ntohl(*(const uint32_t *)(bytes + 0));
                uint32_t l = ntohl(*(const uint32_t *)(bytes + 4));
                if (l >= sizeof(VICSBlobHeader) && l <= data.length) {
                    NSData *payload = [NSData dataWithBytes:(bytes + sizeof(VICSBlobHeader)) length:(l - sizeof(VICSBlobHeader))];
                    NSError *plistError = nil;
                    id plist = [NSPropertyListSerialization propertyListWithData:payload options:NSPropertyListImmutable format:NULL error:&plistError];
                    if ([plist isKindOfClass:NSDictionary.class]) {
                        [notes addObject:[NSString stringWithFormat:@"xml entitlement plist parsed magic=0x%08x", m]];
                        return (NSDictionary *)plist;
                    }
                    [notes addObject:[NSString stringWithFormat:@"xml plist parse failed magic=0x%08x error=%@", m, plistError.localizedDescription ?: @"<nil>"]];
                }
            }
        }
    }

    VICSBlobHeader derHeader = {0};
    errno = 0;
    int drc = csops(pid, VI_CS_OPS_DER_ENTITLEMENTS_BLOB, &derHeader, sizeof(derHeader));
    int derr = errno;
    uint32_t dlen = ntohl(derHeader.length);
    uint32_t dmagic = ntohl(derHeader.magic);
    [notes addObject:[NSString stringWithFormat:@"csops(der) header rc=%d errno=%@ magic=0x%08x len=%u", drc, VIErrnoString(derr), dmagic, dlen]];
    return nil;
}

static NSString *VIIdentityForPID(pid_t pid, unsigned int op, NSString *label) {
    uint8_t buf[256] = {0};
    errno = 0;
    int rc = csops(pid, op, buf, sizeof(buf));
    int err = errno;
    if (rc == 0) return [NSString stringWithFormat:@"%@=%@", label, VIStringFromCStringBuffer(buf, sizeof(buf))];
    return [NSString stringWithFormat:@"%@=<unavailable rc=%d errno=%@>", label, rc, VIErrnoString(err)];
}

static BOOL VIBool(id value) {
    if ([value isKindOfClass:NSNumber.class]) return [(NSNumber *)value boolValue];
    return NO;
}

static BOOL VIArrayContains(NSDictionary *ent, NSString *key, NSString *needle) {
    id value = ent[key];
    if ([value isKindOfClass:NSString.class]) return [(NSString *)value isEqualToString:needle];
    if (![value isKindOfClass:NSArray.class]) return NO;
    for (id item in (NSArray *)value) {
        if ([item isKindOfClass:NSString.class] && [(NSString *)item isEqualToString:needle]) return YES;
    }
    return NO;
}

static BOOL VIAssetAccess(NSDictionary *ent) {
    return VIArrayContains(ent, @"com.apple.private.assets.accessible-asset-types", @"com.apple.MobileAsset.UAF.FM.GenerativeModels");
}

static BOOL VIGMSPref(NSDictionary *ent) {
    return VIArrayContains(ent, @"com.apple.security.exception.shared-preference.read-only", @"com.apple.gms.availability") ||
           VIArrayContains(ent, @"com.apple.security.exception.shared-preference.read-write", @"com.apple.gms.availability") ||
           VIArrayContains(ent, @"com.apple.security.temporary-exception.shared-preference.read-only", @"com.apple.gms.availability") ||
           VIArrayContains(ent, @"com.apple.security.temporary-exception.shared-preference.read-write", @"com.apple.gms.availability");
}

static BOOL VIAvailabilityMach(NSDictionary *ent) {
    NSString *name = @"com.apple.generativeexperiences.availabilityService";
    return VIArrayContains(ent, @"com.apple.security.exception.mach-lookup.global-name", name) ||
           VIArrayContains(ent, @"com.apple.security.temporary-exception.mach-lookup.global-name", name);
}

static BOOL VIVisualPreferenceRW(NSDictionary *ent) {
    return VIArrayContains(ent, @"com.apple.security.exception.shared-preference.read-write", @"com.apple.visualintelligence") ||
           VIArrayContains(ent, @"com.apple.security.temporary-exception.shared-preference.read-write", @"com.apple.visualintelligence");
}

static BOOL VIOSeligibilityRead(NSDictionary *ent) {
    if (VIBool(ent[@"com.apple.private.security.storage.os_eligibility.readonly"])) return YES;
    id paths = ent[@"com.apple.security.exception.files.absolute-path.read-only"];
    if ([paths isKindOfClass:NSArray.class]) {
        for (id item in (NSArray *)paths) {
            if ([item isKindOfClass:NSString.class] && [(NSString *)item containsString:@"os_eligibility"]) return YES;
        }
    }
    return NO;
}

static BOOL VIInterestingKey(NSString *key) {
    NSString *s = key.lowercaseString;
    NSArray<NSString *> *needles = @[@"gms", @"generative", @"visual", @"intelligence", @"eligibility", @"country", @"region", @"location", @"mobileasset", @"asset", @"shared-preference", @"mach-lookup", @"platform-application", @"application-identifier", @"mobilegestalt", @"camera", @"siri"];
    for (NSString *needle in needles) if ([s containsString:needle]) return YES;
    return NO;
}

static NSString *VICompactValue(id value) {
    if (!value || value == NSNull.null) return @"<nil>";
    if ([value isKindOfClass:NSString.class] || [value isKindOfClass:NSNumber.class]) return [value description];
    if ([value isKindOfClass:NSArray.class]) {
        NSArray *a = value;
        NSMutableArray<NSString *> *matches = [NSMutableArray array];
        for (id item in a) {
            NSString *d = [item description];
            NSString *l = d.lowercaseString;
            if ([l containsString:@"gms"] || [l containsString:@"generative"] || [l containsString:@"visual"] || [l containsString:@"intelligence"] || [l containsString:@"eligibility"] || [l containsString:@"camera"] || [l containsString:@"country"] || [l containsString:@"region"] || [l containsString:@"siri"]) {
                [matches addObject:d];
                if (matches.count >= 16) break;
            }
        }
        if (matches.count) return [NSString stringWithFormat:@"[count=%lu; matching=%@]", (unsigned long)a.count, matches];
        return [NSString stringWithFormat:@"[count=%lu]", (unsigned long)a.count];
    }
    if ([value isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"<dictionary count=%lu>", (unsigned long)[(NSDictionary *)value count]];
    return [value description];
}

static NSDictionary<NSString *, NSDictionary *> *VIFindTargetProcesses(NSMutableString *out) {
    int count = proc_listallpids(NULL, 0);
    if (count <= 0) count = 2048;
    int capacity = MAX(count + 256, 2048);
    NSMutableData *pidData = [NSMutableData dataWithLength:(NSUInteger)capacity * sizeof(pid_t)];
    errno = 0;
    int found = proc_listallpids(pidData.mutableBytes, (int)pidData.length);
    int err = errno;
    [out appendFormat:@"proc_listallpids capacity=%d result=%d errno=%@\n", capacity, found, VIErrnoString(err)];

    NSArray<NSString *> *targets = @[@"Camera", @"Tamale", @"ScreenshotServicesService", @"visualintelligenced", @"generativeexperiencesd", @"SpringBoard", @"countryd", @"eligibilityd", @"GestaltEdit"];
    NSMutableDictionary<NSString *, NSDictionary *> *result = [NSMutableDictionary dictionary];
    if (found <= 0) return result;

    pid_t *pids = pidData.mutableBytes;
    int pidCount = MIN(found, capacity);
    for (int i = 0; i < pidCount; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;
        char nameBuf[256] = {0};
        char pathBuf[4096] = {0};
        int nameLen = proc_name(pid, nameBuf, sizeof(nameBuf));
        int pathLen = proc_pidpath(pid, pathBuf, sizeof(pathBuf));
        NSString *name = nameLen > 0 ? [NSString stringWithUTF8String:nameBuf] : @"";
        NSString *path = pathLen > 0 ? [NSString stringWithUTF8String:pathBuf] : @"";
        NSString *base = path.lastPathComponent ?: @"";
        for (NSString *target in targets) {
            if ([name caseInsensitiveCompare:target] == NSOrderedSame || [base caseInsensitiveCompare:target] == NSOrderedSame) {
                if (!result[target]) result[target] = @{@"pid": @(pid), @"name": name ?: @"", @"path": path ?: @""};
            }
        }
    }
    return result;
}

static NSString *VIMatrixLine(NSDictionary *ent) {
    if (!ent) return @"<unavailable>";
    BOOL direct = VIBool(ent[@"com.apple.generativeexperiences.availabilityService"]);
    BOOL mach = VIAvailabilityMach(ent);
    BOOL gms = VIGMSPref(ent);
    BOOL ose = VIOSeligibilityRead(ent);
    BOOL assets = VIAssetAccess(ent);
    BOOL platform = VIBool(ent[@"platform-application"]);
    BOOL viRW = VIVisualPreferenceRW(ent);
    BOOL storage = VIBool(ent[@"com.apple.private.security.storage.MobileAssetGenerativeModels"]);
    return [NSString stringWithFormat:@"%@ | %@ | %@ | %@ | %@ | %@ | %@ | %@",
            direct?@"true":@"false", mach?@"true":@"false", gms?@"true":@"false", ose?@"true":@"false",
            assets?@"true":@"false", platform?@"true":@"false", viRW?@"true":@"false", storage?@"true":@"false"];
}

static void VIDiff(NSMutableString *out, NSString *lhsName, NSDictionary *lhs, NSString *rhsName, NSDictionary *rhs) {
    [out appendFormat:@"\n--- %@ vs %@ entitlement differential ---\n", lhsName, rhsName];
    if (!lhs || !rhs) { [out appendString:@"diff unavailable\n"]; return; }
    NSSet *lhsKeys = [NSSet setWithArray:lhs.allKeys];
    NSSet *rhsKeys = [NSSet setWithArray:rhs.allKeys];
    NSMutableSet *lhsOnlySet = [lhsKeys mutableCopy]; [lhsOnlySet minusSet:rhsKeys];
    NSMutableSet *rhsOnlySet = [rhsKeys mutableCopy]; [rhsOnlySet minusSet:lhsKeys];
    NSArray *lhsOnly = [[lhsOnlySet allObjects] sortedArrayUsingSelector:@selector(compare:)];
    NSArray *rhsOnly = [[rhsOnlySet allObjects] sortedArrayUsingSelector:@selector(compare:)];
    NSUInteger emitted = 0;
    for (NSString *k in lhsOnly) {
        if (!VIInterestingKey(k)) continue;
        [out appendFormat:@"%@ only: %@ = %@\n", lhsName, k, VICompactValue(lhs[k])];
        if (++emitted >= 50) break;
    }
    emitted = 0;
    for (NSString *k in rhsOnly) {
        if (!VIInterestingKey(k)) continue;
        [out appendFormat:@"%@ only: %@ = %@\n", rhsName, k, VICompactValue(rhs[k])];
        if (++emitted >= 50) break;
    }
}

NSString *VIProcessEntitlementGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    NSISO8601DateFormatter *formatter = [NSISO8601DateFormatter new];
    [out appendString:@"========== iOS 27 VI LIVE PROCESS CSOPS ENTITLEMENT READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [formatter stringFromDate:[NSDate date]]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: read-only proc_listallpids/proc_name/proc_pidpath and csops code-signing queries only. No task_for_pid, no process memory access, no XPC, no setters, no swizzling, no preference/MobileGestalt/file writes, no bad_query, no respring/reboot.\n"];
    [out appendString:@"NOTE: Camera/Tamale/ScreenshotServicesService must still exist as a running/suspended process to be discoverable.\n\n"];

    NSDictionary<NSString *, NSDictionary *> *processes = VIFindTargetProcesses(out);
    NSArray<NSString *> *order = @[@"GestaltEdit", @"Camera", @"Tamale", @"ScreenshotServicesService", @"visualintelligenced", @"generativeexperiencesd", @"SpringBoard", @"countryd", @"eligibilityd"];
    NSMutableDictionary<NSString *, NSDictionary *> *entByName = [NSMutableDictionary dictionary];

    for (NSString *target in order) {
        [out appendFormat:@"\n--- %@ ---\n", target];
        NSDictionary *p = processes[target];
        if (!p) {
            [out appendString:@"process = <not found>\n"];
            continue;
        }
        pid_t pid = [p[@"pid"] intValue];
        [out appendFormat:@"pid = %d\nname = %@\npath = %@\n", pid, p[@"name"], p[@"path"]];

        uint32_t status = 0;
        errno = 0;
        int src = csops(pid, VI_CS_OPS_STATUS, &status, sizeof(status));
        int serr = errno;
        [out appendFormat:@"csStatus rc=%d errno=%@ flags=0x%08x platformBinary=%@\n", src, VIErrnoString(serr), status, (status & VI_CS_PLATFORM_BINARY)?@"true":@"false"];
        [out appendFormat:@"%@\n", VIIdentityForPID(pid, VI_CS_OPS_IDENTITY, @"signingIdentity")];
        [out appendFormat:@"%@\n", VIIdentityForPID(pid, VI_CS_OPS_TEAMID, @"teamID")];

        NSMutableArray<NSString *> *notes = [NSMutableArray array];
        NSDictionary *ent = VIEntitlementsForPID(pid, notes);
        for (NSString *note in notes) [out appendFormat:@"note = %@\n", note];
        if (!ent) {
            [out appendString:@"entitlements = <unavailable>\n"];
            continue;
        }
        entByName[target] = ent;
        [out appendFormat:@"entitlementCount = %lu\n", (unsigned long)ent.count];
        NSArray<NSString *> *keys = [ent.allKeys sortedArrayUsingSelector:@selector(compare:)];
        NSUInteger interesting = 0;
        for (NSString *k in keys) if (VIInterestingKey(k)) interesting++;
        [out appendFormat:@"interestingKeyCount = %lu\n", (unsigned long)interesting];
        NSUInteger emitted = 0;
        for (NSString *k in keys) {
            if (!VIInterestingKey(k)) continue;
            [out appendFormat:@"  %@ = %@\n", k, VICompactValue(ent[k])];
            if (++emitted >= 90) { [out appendString:@"  ... truncated ...\n"]; break; }
        }
    }

    [out appendString:@"\n--- VI / GMS live-process privilege matrix ---\n"];
    [out appendString:@"Columns: directAvailabilityEntitlement | machLookupAvailability | gmsSharedPref | osEligibilityRead | generativeModelAssets | platformApplication | visualIntelligencePrefRW | MobileAssetGenerativeModelsStorage\n"];
    for (NSString *target in order) [out appendFormat:@"%@: %@\n", target, VIMatrixLine(entByName[target])];

    VIDiff(out, @"Camera", entByName[@"Camera"], @"visualintelligenced", entByName[@"visualintelligenced"]);
    VIDiff(out, @"Camera", entByName[@"Camera"], @"SpringBoard", entByName[@"SpringBoard"]);
    VIDiff(out, @"Camera", entByName[@"Camera"], @"Tamale", entByName[@"Tamale"]);
    VIDiff(out, @"Tamale", entByName[@"Tamale"], @"visualintelligenced", entByName[@"visualintelligenced"]);
    VIDiff(out, @"ScreenshotServicesService", entByName[@"ScreenshotServicesService"], @"visualintelligenced", entByName[@"visualintelligenced"]);

    [out appendString:@"\nINTERPRETATION TARGETS:\n"];
    [out appendString:@"1. If Camera's XML entitlements are readable, compare its gms shared-preference, availabilityService, GenerativeModels asset and visualintelligence preference privileges with visualintelligenced/SpringBoard.\n"];
    [out appendString:@"2. If Camera is found but csops entitlement read is denied while self/system daemons succeed, that denial itself is a caller-access boundary; do not interpret it as Camera lacking entitlements.\n"];
    [out appendString:@"3. If Camera is not found, launch Camera once, return to GestaltEdit without force-quitting Camera, and rerun. For Tamale, invoke Visual Intelligence once, return, then rerun.\n"];
    [out appendString:@"================================================================================\n"];
    return out;
}
