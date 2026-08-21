#import "CallerIdentityBridge.h"

#import <dlfcn.h>
#import <objc/message.h>
#import <objc/runtime.h>

static id ObjMsg0(id obj, SEL sel) {
    if (!obj || ![obj respondsToSelector:sel]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(obj, sel);
}

static id ObjMsg1(id obj, SEL sel, id arg) {
    if (!obj || ![obj respondsToSelector:sel]) return nil;
    return ((id (*)(id, SEL, id))objc_msgSend)(obj, sel, arg);
}

static NSString *SafeDesc(id obj) {
    if (!obj) return @"<nil>";
    @try { return [obj description] ?: @"<nil-description>"; }
    @catch (__unused NSException *e) { return @"<description threw>"; }
}

static BOOL InterestingKey(NSString *key) {
    NSString *s = key.lowercaseString;
    NSArray<NSString *> *words = @[@"generative", @"visual", @"intelligence", @"availability", @"camera", @"siri", @"eligibility", @"greymatter", @"region", @"country", @"mach-lookup", @"shared-preference", @"platform-application", @"private.security", @"assets"];
    for (NSString *w in words) if ([s containsString:w]) return YES;
    return NO;
}

static void AppendInterestingEntitlements(NSMutableString *out, NSDictionary *ent) {
    if (![ent isKindOfClass:NSDictionary.class]) {
        [out appendString:@"  entitlements = <unavailable>\n"];
        return;
    }
    [out appendFormat:@"  entitlementCount = %lu\n", (unsigned long)ent.count];
    NSArray *keys = [[ent allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSUInteger hits = 0;
    for (id k in keys) {
        if (![k isKindOfClass:NSString.class] || !InterestingKey(k)) continue;
        hits++;
        [out appendFormat:@"    %@ = %@\n", k, SafeDesc(ent[k])];
    }
    [out appendFormat:@"  interestingKeyCount = %lu\n", (unsigned long)hits];
}

typedef int32_t OSStatus;
typedef const struct __SecCode *SecStaticCodeRef;
typedef OSStatus (*SecStaticCodeCreateWithPathFn)(CFURLRef, uint32_t, SecStaticCodeRef *);
typedef OSStatus (*SecStaticCodeCreateWithPathAndAttributesFn)(CFURLRef, uint32_t, CFDictionaryRef, SecStaticCodeRef *);
typedef OSStatus (*SecCodeCopySigningInformationFn)(SecStaticCodeRef, uint32_t, CFDictionaryRef *);

static NSDictionary *SigningEntitlementsForURL(NSURL *url, NSMutableString *out) {
    if (!url) return nil;
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_LOCAL);
    if (!sec) {
        [out appendString:@"  Security dlopen = FAIL\n"];
        return nil;
    }
    SecStaticCodeCreateWithPathFn create = (SecStaticCodeCreateWithPathFn)dlsym(sec, "SecStaticCodeCreateWithPath");
    SecStaticCodeCreateWithPathAndAttributesFn createAttrs = (SecStaticCodeCreateWithPathAndAttributesFn)dlsym(sec, "SecStaticCodeCreateWithPathAndAttributes");
    SecCodeCopySigningInformationFn copyInfo = (SecCodeCopySigningInformationFn)dlsym(sec, "SecCodeCopySigningInformation");
    CFStringRef *entKeyPtr = (CFStringRef *)dlsym(sec, "kSecCodeInfoEntitlementsDict");
    if ((!create && !createAttrs) || !copyInfo || !entKeyPtr || !*entKeyPtr) {
        [out appendFormat:@"  Security symbols: create=%@ createAttrs=%@ copyInfo=%@ entKey=%@\n",
         create ? @"YES" : @"NO", createAttrs ? @"YES" : @"NO", copyInfo ? @"YES" : @"NO", (entKeyPtr && *entKeyPtr) ? @"YES" : @"NO"];
        return nil;
    }

    SecStaticCodeRef code = NULL;
    OSStatus rc = create ? create((__bridge CFURLRef)url, 0, &code) : createAttrs((__bridge CFURLRef)url, 0, NULL, &code);
    [out appendFormat:@"  SecStaticCodeCreate rc=%d url=%@\n", (int)rc, url.path ?: url.absoluteString];
    if (rc != 0 || !code) return nil;

    CFDictionaryRef info = NULL;
    rc = copyInfo(code, (1u << 1), &info); // kSecCSSigningInformation
    [out appendFormat:@"  SecCodeCopySigningInformation rc=%d\n", (int)rc];
    NSDictionary *result = nil;
    if (rc == 0 && info) {
        NSDictionary *dict = (__bridge NSDictionary *)info;
        id ent = dict[(__bridge NSString *)*entKeyPtr];
        if ([ent isKindOfClass:NSDictionary.class]) result = [ent copy];
        CFRelease(info);
    }
    CFRelease(code);
    return result;
}

static NSArray *WorkspaceApplications(NSMutableString *out) {
    dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_NOW | RTLD_LOCAL);
    dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_NOW | RTLD_LOCAL);
    Class wsClass = NSClassFromString(@"LSApplicationWorkspace");
    [out appendFormat:@"LSApplicationWorkspace class = %@\n", wsClass ? @"FOUND" : @"MISSING"];
    if (!wsClass) return @[];
    id ws = ObjMsg0(wsClass, NSSelectorFromString(@"defaultWorkspace"));
    if (!ws) return @[];
    NSArray *apps = ObjMsg0(ws, NSSelectorFromString(@"allApplications"));
    if (![apps isKindOfClass:NSArray.class]) apps = ObjMsg0(ws, NSSelectorFromString(@"allInstalledApplications"));
    if (![apps isKindOfClass:NSArray.class]) return @[];
    [out appendFormat:@"LaunchServices application count = %lu\n", (unsigned long)apps.count];
    return apps;
}

static NSString *StringProperty(id obj, NSString *name) {
    id v = ObjMsg0(obj, NSSelectorFromString(name));
    if ([v isKindOfClass:NSString.class]) return v;
    if ([v isKindOfClass:NSURL.class]) return [v path] ?: [v absoluteString];
    return v ? SafeDesc(v) : nil;
}

static BOOL IsInterestingProxy(id proxy) {
    NSString *bid = StringProperty(proxy, @"applicationIdentifier") ?: @"";
    NSString *name = StringProperty(proxy, @"localizedName") ?: @"";
    NSString *path = StringProperty(proxy, @"bundleURL") ?: @"";
    NSString *all = [[NSString stringWithFormat:@"%@ %@ %@", bid, name, path] lowercaseString];
    NSArray *needles = @[@"camera", @"tamale", @"screenshot", @"visualintelligence", @"visual intelligence"];
    for (NSString *n in needles) if ([all containsString:n]) return YES;
    return NO;
}

static void AppendProxy(NSMutableString *out, id proxy, NSString *label) {
    [out appendFormat:@"\n--- %@ ---\n", label];
    NSArray<NSString *> *props = @[@"applicationIdentifier", @"localizedName", @"applicationType", @"bundleURL", @"bundleExecutable", @"canonicalExecutablePath", @"bundleContainerURL", @"dataContainerURL", @"teamID"];
    for (NSString *p in props) [out appendFormat:@"%@ = %@\n", p, StringProperty(proxy, p) ?: @"<nil>"];

    if ([proxy respondsToSelector:NSSelectorFromString(@"entitlements")]) {
        id ent = ObjMsg0(proxy, NSSelectorFromString(@"entitlements"));
        [out appendString:@"LSApplicationProxy.entitlements selector present\n"];
        AppendInterestingEntitlements(out, [ent isKindOfClass:NSDictionary.class] ? ent : nil);
    } else {
        [out appendString:@"LSApplicationProxy.entitlements selector = absent\n"];
    }

    NSURL *bundleURL = ObjMsg0(proxy, NSSelectorFromString(@"bundleURL"));
    if ([bundleURL isKindOfClass:NSURL.class]) {
        NSDictionary *ent = SigningEntitlementsForURL(bundleURL, out);
        [out appendString:@"CodeSigning entitlements from bundleURL:\n"];
        AppendInterestingEntitlements(out, ent);
    }
}

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI LaunchServices + CodeSigning READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: read-only metadata/signature inspection. No GenerativeExperiences availability XPC call, no setters, no method swizzling/IMP replacement, no preference/MobileGestalt writes, no respring/reboot. LaunchServices may use its normal internal read-only IPC.\n\n"];

    NSArray *apps = WorkspaceApplications(out);
    NSMutableArray *interesting = [NSMutableArray array];
    for (id proxy in apps) if (IsInterestingProxy(proxy)) [interesting addObject:proxy];
    [out appendFormat:@"Interesting LaunchServices proxies = %lu\n", (unsigned long)interesting.count];
    NSUInteger idx = 0;
    for (id proxy in interesting) {
        NSString *bid = StringProperty(proxy, @"applicationIdentifier") ?: @"<unknown>";
        AppendProxy(out, proxy, [NSString stringWithFormat:@"LS match %lu: %@", (unsigned long)++idx, bid]);
    }

    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    NSArray *explicitIDs = @[@"com.apple.camera", @"com.apple.Camera", @"com.apple.ScreenshotServicesService", @"com.apple.screenshotservices", @"com.apple.Tamale", @"com.apple.tamale"];
    if (proxyClass) {
        [out appendString:@"\n--- explicit LSApplicationProxy bundle-id lookups ---\n"];
        for (NSString *bid in explicitIDs) {
            id proxy = ObjMsg1(proxyClass, NSSelectorFromString(@"applicationProxyForIdentifier:"), bid);
            [out appendFormat:@"%@ -> %@\n", bid, proxy ? SafeDesc(proxy) : @"<nil>"];
            if (proxy) AppendProxy(out, proxy, [NSString stringWithFormat:@"explicit %@", bid]);
        }
    }

    [out appendString:@"\n--- direct readable system code-signing controls ---\n"];
    NSArray<NSString *> *paths = @[@"/System/Library/CoreServices/SpringBoard.app", @"/System/Library/PrivateFrameworks/VisualIntelligenceServices.framework/visualintelligenced"];
    for (NSString *path in paths) {
        [out appendFormat:@"\npath=%@\n", path];
        NSDictionary *ent = SigningEntitlementsForURL([NSURL fileURLWithPath:path], out);
        AppendInterestingEntitlements(out, ent);
    }

    [out appendString:@"\n===============================================================================\n"];
    return out;
}
