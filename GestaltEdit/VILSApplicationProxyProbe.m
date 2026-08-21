#import "VILSApplicationProxyProbe.h"
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

static BOOL GETypeIsObjectGetter(Method m) {
    if (!m) return NO;
    const char *t = method_getTypeEncoding(m);
    return t && strcmp(t, "@16@0:8") == 0;
}

static id GECallObjectGetter(id obj, NSString *name, NSMutableString *out) {
    SEL sel = NSSelectorFromString(name);
    Method m = class_getInstanceMethod(object_getClass(obj) == obj ? obj : [obj class], sel);
    if (!m || !GETypeIsObjectGetter(m)) {
        [out appendFormat:@"  %@ = <missing-or-ABI-mismatch>\n", name];
        return nil;
    }
    @try {
        id (*fn)(id, SEL) = (void *)method_getImplementation(m);
        id v = fn(obj, sel);
        [out appendFormat:@"  %@ = %@\n", name, v ?: @"<nil>"];
        return v;
    } @catch (NSException *e) {
        [out appendFormat:@"  %@ = <exception %@: %@>\n", name, e.name, e.reason ?: @""];
        return nil;
    }
}

static id GECallProxyForIdentifier(Class cls, NSString *bundleID, NSMutableString *out) {
    SEL sel = NSSelectorFromString(@"applicationProxyForIdentifier:");
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        [out appendString:@"applicationProxyForIdentifier: = <missing>\n"];
        return nil;
    }
    const char *t = method_getTypeEncoding(m);
    [out appendFormat:@"applicationProxyForIdentifier: types=%s\n", t ?: "<nil>"];
    @try {
        id (*fn)(id, SEL, id) = (void *)method_getImplementation(m);
        return fn((id)cls, sel, bundleID);
    } @catch (NSException *e) {
        [out appendFormat:@"proxy exception %@: %@\n", e.name, e.reason ?: @""];
        return nil;
    }
}

static BOOL GEInterestingKey(NSString *key) {
    NSString *s = key.lowercaseString;
    NSArray *needles = @[@"generative", @"gms", @"visualintelligence", @"visual-intelligence", @"siri",
                         @"os_eligibility", @"eligibility", @"shared-preference", @"mach-lookup", @"mobileasset",
                         @"asset", @"platform-application", @"security.storage", @"country", @"region", @"camera"];
    for (NSString *n in needles) if ([s containsString:n]) return YES;
    return NO;
}

static NSString *GESummaryValue(id v) {
    if (!v) return @"<nil>";
    if ([v isKindOfClass:NSArray.class]) {
        NSArray *a = v; NSMutableArray *hits = [NSMutableArray array];
        for (id x in a) if ([x isKindOfClass:NSString.class] && GEInterestingKey(x)) [hits addObject:x];
        return [NSString stringWithFormat:@"[count=%lu; matching=%@]", (unsigned long)a.count, hits];
    }
    if ([v isKindOfClass:NSDictionary.class]) return [NSString stringWithFormat:@"<dictionary count=%lu>", (unsigned long)[v count]];
    return [v description];
}

static NSDictionary *GEEntitlementsFromProxy(id proxy, NSMutableString *out) {
    SEL sel = NSSelectorFromString(@"entitlements");
    Method m = class_getInstanceMethod([proxy class], sel);
    if (!m) {
        [out appendString:@"  entitlements getter = <missing>\n"];
        return nil;
    }
    const char *t = method_getTypeEncoding(m);
    [out appendFormat:@"  entitlements types=%s\n", t ?: "<nil>"];
    if (!GETypeIsObjectGetter(m)) {
        [out appendString:@"  entitlements = <ABI mismatch; not invoked>\n"];
        return nil;
    }
    @try {
        id (*fn)(id, SEL) = (void *)method_getImplementation(m);
        id v = fn(proxy, sel);
        if (![v isKindOfClass:NSDictionary.class]) {
            [out appendFormat:@"  entitlements = %@\n", v ?: @"<nil>"];
            return nil;
        }
        NSDictionary *d = v;
        [out appendFormat:@"  entitlementCount=%lu\n", (unsigned long)d.count];
        NSArray *keys = [[d allKeys] sortedArrayUsingSelector:@selector(compare:)];
        NSUInteger interesting = 0;
        for (NSString *k in keys) {
            if (![k isKindOfClass:NSString.class] || !GEInterestingKey(k)) continue;
            interesting++;
            [out appendFormat:@"    %@ = %@\n", k, GESummaryValue(d[k])];
        }
        [out appendFormat:@"  interestingEntitlementCount=%lu\n", (unsigned long)interesting];
        return d;
    } @catch (NSException *e) {
        [out appendFormat:@"  entitlements = <exception %@: %@>\n", e.name, e.reason ?: @""];
        return nil;
    }
}

static BOOL GEArrayContains(NSDictionary *d, NSString *key, NSString *needle) {
    id v = d[key];
    if ([v isKindOfClass:NSString.class]) return [v isEqualToString:needle];
    if ([v isKindOfClass:NSArray.class]) return [v containsObject:needle];
    return NO;
}

static NSString *GETri(NSDictionary *d, NSString *key) {
    if (!d) return @"?";
    id v = d[key];
    if ([v respondsToSelector:@selector(boolValue)]) return [v boolValue] ? @"1" : @"0";
    return v ? @"present" : @"0";
}

static void GEAppendMatrixLine(NSMutableString *out, NSString *name, NSDictionary *d) {
    if (!d) { [out appendFormat:@"%@: <unavailable>\n", name]; return; }
    BOOL mach = GEArrayContains(d, @"com.apple.security.exception.mach-lookup.global-name", @"com.apple.generativeexperiences.availabilityService");
    BOOL pref = GEArrayContains(d, @"com.apple.security.exception.shared-preference.read-only", @"com.apple.gms.availability") ||
                GEArrayContains(d, @"com.apple.security.exception.shared-preference.read-write", @"com.apple.gms.availability");
    BOOL vipref = GEArrayContains(d, @"com.apple.security.exception.shared-preference.read-write", @"com.apple.visualintelligence") ||
                  GEArrayContains(d, @"com.apple.security.exception.shared-preference.read-only", @"com.apple.visualintelligence");
    BOOL assets = GEArrayContains(d, @"com.apple.private.assets.accessible-asset-types", @"com.apple.MobileAsset.UAF.FM.GenerativeModels");
    [out appendFormat:@"%@: availabilityEnt=%@ | mach=%d | gmsPref=%d | osElig=%@ | GMAssets=%d | platform=%@ | viPref=%d | MAStorage=%@\n",
     name,
     GETri(d, @"com.apple.generativeexperiences.availabilityService"), mach, pref,
     GETri(d, @"com.apple.private.security.storage.os_eligibility.readonly"), assets,
     GETri(d, @"platform-application"), vipref,
     GETri(d, @"com.apple.private.security.storage.MobileAssetGenerativeModels")];
}

NSString *VILSApplicationProxyGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    NSISO8601DateFormatter *f = [NSISO8601DateFormatter new];
    [out appendString:@"========== iOS 27 VI LAUNCHSERVICES APP-PROXY ENTITLEMENT READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [f stringFromDate:NSDate.date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: read-only LaunchServices application-proxy lookup and zero-argument object getters only. No process enumeration, csops, filesystem escape, XPC, setters, swizzling, preferences/MobileGestalt writes, respring or reboot. The entitlements getter is invoked only if present with the exact @16@0:8 ABI.\n\n"];

    void *a = dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_LAZY|RTLD_LOCAL);
    void *b = dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY|RTLD_LOCAL);
    [out appendFormat:@"CoreServices dlopen=%@ MobileCoreServices dlopen=%@\n", a ? @"OK" : @"NO", b ? @"OK" : @"NO"];
    Class cls = NSClassFromString(@"LSApplicationProxy");
    [out appendFormat:@"LSApplicationProxy=%@\n\n", cls ? @"FOUND" : @"MISSING"];
    if (!cls) return out;

    NSArray<NSDictionary *> *targets = @[
        @{@"name":@"Camera", @"ids":@[@"com.apple.camera"]},
        @{@"name":@"Tamale/VisualIntelligenceCamera", @"ids":@[@"com.apple.VisualIntelligenceCamera", @"com.apple.tamale", @"com.apple.Tamale"]},
        @{@"name":@"ScreenshotServicesService", @"ids":@[@"com.apple.ScreenshotServicesService", @"com.apple.screenshotservices"]},
        @{@"name":@"SpringBoard", @"ids":@[@"com.apple.springboard"]},
        @{@"name":@"Photos", @"ids":@[@"com.apple.mobileslideshow"]},
        @{@"name":@"GestaltEdit", @"ids":@[NSBundle.mainBundle.bundleIdentifier ?: @"me.ssus.gestaltedit"]}
    ];
    NSMutableDictionary<NSString *, NSDictionary *> *matrix = [NSMutableDictionary dictionary];

    for (NSDictionary *target in targets) {
        NSString *name = target[@"name"];
        [out appendFormat:@"--- %@ ---\n", name];
        id proxy = nil; NSString *resolvedID = nil;
        for (NSString *bid in target[@"ids"]) {
            [out appendFormat:@"bundleID candidate=%@\n", bid];
            id p = GECallProxyForIdentifier(cls, bid, out);
            [out appendFormat:@"proxy=%@\n", p ?: @"<nil>"];
            if (p) { proxy = p; resolvedID = bid; break; }
        }
        if (!proxy) { [out appendString:@"result=<no proxy>\n\n"]; continue; }
        [out appendFormat:@"resolvedBundleID=%@ class=%@\n", resolvedID, NSStringFromClass([proxy class])];
        GECallObjectGetter(proxy, @"applicationIdentifier", out);
        GECallObjectGetter(proxy, @"applicationType", out);
        GECallObjectGetter(proxy, @"bundleURL", out);
        GECallObjectGetter(proxy, @"resourcesDirectoryURL", out);
        GECallObjectGetter(proxy, @"teamID", out);
        GECallObjectGetter(proxy, @"signerIdentity", out);
        GECallObjectGetter(proxy, @"groupContainers", out);
        NSDictionary *ents = GEEntitlementsFromProxy(proxy, out);
        if (ents) matrix[name] = ents;
        [out appendString:@"\n"];
    }

    [out appendString:@"--- VI / GMS LaunchServices entitlement matrix ---\n"];
    [out appendString:@"Columns: availabilityEnt | availabilityService mach lookup | gms shared pref | osEligibilityRead | GenerativeModels asset | platformApplication | visualintelligence pref | MobileAssetGenerativeModels storage\n"];
    for (NSDictionary *target in targets) GEAppendMatrixLine(out, target[@"name"], matrix[target[@"name"]]);

    [out appendString:@"\nINTERPRETATION:\n1. A readable Camera entitlement dictionary gives an exact same-build comparison without opening Camera's protected executable or enumerating processes.\n2. A valid Camera proxy with entitlements=nil/missing means LaunchServices intentionally withholds that field from this caller; do not interpret it as Camera having no entitlements.\n3. bundleURL/applicationType/teamID/signerIdentity still tell us whether LaunchServices resolved the real system Camera registration.\n===============================================================================\n"];
    return out;
}
