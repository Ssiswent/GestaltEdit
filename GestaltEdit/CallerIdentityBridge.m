#import "CallerIdentityBridge.h"

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#pragma mark - Swift reflection metadata structs

typedef struct __attribute__((packed)) {
    int32_t mangledTypeName;
    int32_t superclass;
    uint16_t kind;
    uint16_t fieldRecordSize;
    uint32_t numFields;
} GEFieldDescriptor;

typedef struct __attribute__((packed)) {
    uint32_t flags;
    int32_t mangledTypeName;
    int32_t fieldName;
} GEFieldRecord;

typedef struct {
    const struct mach_header_64 *header;
    intptr_t slide;
    uintptr_t minAddress;
    uintptr_t maxAddress;
    uint32_t imageIndex;
} GELoadedImage;

typedef char *(*GESwiftDemangleFn)(const char *, size_t, char *, size_t *, uint32_t);

static BOOL GEFindLoadedImage(NSString *needle, GELoadedImage *outInfo) {
    if (!outInfo) return NO;
    memset(outInfo, 0, sizeof(*outInfo));
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *path = [NSString stringWithUTF8String:name];
        if (![path containsString:needle]) continue;
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)h;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        uintptr_t minAddr = UINTPTR_MAX;
        uintptr_t maxAddr = 0;
        const uint8_t *cmdPtr = (const uint8_t *)(h64 + 1);
        for (uint32_t c = 0; c < h64->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)cmdPtr;
            if (lc->cmdsize < sizeof(struct load_command)) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (seg->vmsize > 0) {
                    uintptr_t start = (uintptr_t)(seg->vmaddr + slide);
                    uintptr_t end = start + (uintptr_t)seg->vmsize;
                    if (start < minAddr) minAddr = start;
                    if (end > maxAddr) maxAddr = end;
                }
            }
            cmdPtr += lc->cmdsize;
        }
        if (minAddr == UINTPTR_MAX || maxAddr <= minAddr) {
            minAddr = (uintptr_t)h64;
            maxAddr = minAddr + 0x2000000;
        }
        outInfo->header = h64;
        outInfo->slide = slide;
        outInfo->minAddress = minAddr;
        outInfo->maxAddress = maxAddr;
        outInfo->imageIndex = i;
        return YES;
    }
    return NO;
}

static const uint8_t *GEResolveRelative32(const int32_t *field, GELoadedImage image) {
    if (!field || *field == 0) return NULL;
    intptr_t base = (intptr_t)field;
    intptr_t target = base + (intptr_t)(*field);
    if ((uintptr_t)target < image.minAddress || (uintptr_t)target >= image.maxAddress) return NULL;
    return (const uint8_t *)target;
}

static NSString *GESafeCString(const uint8_t *ptr, GELoadedImage image, NSUInteger maxLen) {
    if (!ptr) return nil;
    uintptr_t p = (uintptr_t)ptr;
    if (p < image.minAddress || p >= image.maxAddress) return nil;
    NSUInteger available = (NSUInteger)MIN((uintptr_t)maxLen, image.maxAddress - p);
    const void *nul = memchr(ptr, 0, available);
    if (!nul) return nil;
    NSUInteger len = (NSUInteger)((const uint8_t *)nul - ptr);
    if (len == 0) return @"";
    NSData *data = [NSData dataWithBytes:ptr length:len];
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return s;
}

static NSString *GEHexPreview(const uint8_t *ptr, GELoadedImage image, NSUInteger maxLen) {
    if (!ptr) return @"<nil>";
    uintptr_t p = (uintptr_t)ptr;
    if (p < image.minAddress || p >= image.maxAddress) return @"<out-of-image>";
    NSUInteger available = (NSUInteger)MIN((uintptr_t)maxLen, image.maxAddress - p);
    NSMutableString *s = [NSMutableString string];
    for (NSUInteger i = 0; i < available; i++) {
        uint8_t b = ptr[i];
        if (b == 0) break;
        if (b >= 0x20 && b <= 0x7e) {
            [s appendFormat:@"%c", b];
        } else {
            [s appendFormat:@"\\x%02x", b];
        }
    }
    return s.length ? s : @"<empty>";
}

static NSString *GEDemanglePlain(NSString *mangled) {
    if (!mangled.length) return nil;
    void *swift = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW | RTLD_LOCAL);
    GESwiftDemangleFn fn = swift ? (GESwiftDemangleFn)dlsym(swift, "swift_demangle") : NULL;
    if (!fn) return nil;

    NSArray<NSString *> *candidates;
    if ([mangled hasPrefix:@"$s"] || [mangled hasPrefix:@"_$s"]) {
        candidates = @[mangled];
    } else {
        candidates = @[[NSString stringWithFormat:@"$s%@", mangled], mangled];
    }
    for (NSString *candidate in candidates) {
        NSData *d = [candidate dataUsingEncoding:NSUTF8StringEncoding];
        if (!d.length) continue;
        char *result = fn((const char *)d.bytes, d.length, NULL, NULL, 0);
        if (result) {
            NSString *out = [NSString stringWithUTF8String:result];
            free(result);
            if (out.length) return out;
        }
    }
    return nil;
}

static NSString *GEFieldKindName(uint16_t kind) {
    switch (kind) {
        case 0: return @"struct";
        case 1: return @"class";
        case 2: return @"enum";
        case 3: return @"multiPayloadEnum";
        case 4: return @"protocol";
        case 5: return @"classProtocol";
        case 6: return @"objcProtocol";
        case 7: return @"objcClass";
        default: return [NSString stringWithFormat:@"kind(%u)", kind];
    }
}

static BOOL GEKeywordHit(NSString *s) {
    if (!s.length) return NO;
    NSString *l = s.lowercaseString;
    NSArray<NSString *> *needles = @[
        @"requesttype", @"request type", @"environmentbundleidentifier",
        @"hasadditionalchinapolicy", @"ischinaregion", @"chinapolicy",
        @"availabilitykey", @"partneravailability", @"availability",
        @"usecaseidentifier", @"languageoption", @"visualintelligencecamera",
        @"gvicccontentclassifier", @"currentipcountrycodeallowance",
        @"camera", @"screenshot", @"context", @"userdefaults", @"unspecified",
        @"greymatter", @"montara", @"askacme"
    ];
    for (NSString *needle in needles) if ([l containsString:needle]) return YES;
    return NO;
}

static void GEAppendSwiftFieldMetadata(NSMutableString *out, NSString *imageNeedle) {
    [out appendFormat:@"\n--- %@ Swift __swift5_fieldmd descriptors ---\n", imageNeedle];
    GELoadedImage image;
    if (!GEFindLoadedImage(imageNeedle, &image)) {
        [out appendString:@"loaded image not found\n"];
        return;
    }

    unsigned long size = 0;
    const uint8_t *section = getsectiondata(image.header, "__TEXT", "__swift5_fieldmd", &size);
    if (!section || size < sizeof(GEFieldDescriptor)) {
        [out appendFormat:@"section unavailable size=%lu\n", size];
        return;
    }
    const uint8_t *end = section + size;
    const uint8_t *cursor = section;
    NSUInteger descriptorIndex = 0;
    NSUInteger validDescriptors = 0;
    NSUInteger emitted = 0;

    while (cursor + sizeof(GEFieldDescriptor) <= end && descriptorIndex < 10000) {
        const GEFieldDescriptor *fd = (const GEFieldDescriptor *)cursor;
        uint16_t recordSize = fd->fieldRecordSize;
        uint32_t numFields = fd->numFields;
        if (recordSize < sizeof(GEFieldRecord) || recordSize > 128 || numFields > 2048) {
            cursor += 4;
            descriptorIndex++;
            continue;
        }
        uint64_t total = sizeof(GEFieldDescriptor) + (uint64_t)recordSize * (uint64_t)numFields;
        if (total == 0 || cursor + total > end) {
            cursor += 4;
            descriptorIndex++;
            continue;
        }
        validDescriptors++;

        const uint8_t *typePtr = GEResolveRelative32(&fd->mangledTypeName, image);
        NSString *plainType = GESafeCString(typePtr, image, 512);
        NSString *demangled = plainType ? GEDemanglePlain(plainType) : nil;
        NSString *typePreview = plainType ?: GEHexPreview(typePtr, image, 96);

        NSMutableArray<NSDictionary *> *fields = [NSMutableArray array];
        BOOL descriptorHit = GEKeywordHit(plainType) || GEKeywordHit(demangled);
        const uint8_t *records = cursor + sizeof(GEFieldDescriptor);
        for (uint32_t i = 0; i < numFields; i++) {
            const GEFieldRecord *fr = (const GEFieldRecord *)(records + (uint64_t)i * recordSize);
            const uint8_t *namePtr = GEResolveRelative32(&fr->fieldName, image);
            NSString *name = GESafeCString(namePtr, image, 256) ?: @"<unreadable>";
            const uint8_t *ftPtr = GEResolveRelative32(&fr->mangledTypeName, image);
            NSString *fieldType = GESafeCString(ftPtr, image, 256);
            NSString *fieldTypeDemangled = fieldType ? GEDemanglePlain(fieldType) : nil;
            if (GEKeywordHit(name) || GEKeywordHit(fieldType) || GEKeywordHit(fieldTypeDemangled)) descriptorHit = YES;
            [fields addObject:@{
                @"name": name,
                @"flags": @(fr->flags),
                @"type": fieldType ?: GEHexPreview(ftPtr, image, 48),
                @"demangled": fieldTypeDemangled ?: @""
            }];
        }

        if (descriptorHit && emitted < 120) {
            [out appendFormat:@"\n[%lu] offset=0x%lx kind=%@ recordSize=%u numFields=%u\n",
             (unsigned long)descriptorIndex,
             (unsigned long)(cursor - section),
             GEFieldKindName(fd->kind), recordSize, numFields];
            [out appendFormat:@"  mangledType=%@\n", typePreview ?: @"<nil>"];
            if (demangled.length) [out appendFormat:@"  demangledType=%@\n", demangled];
            for (NSUInteger i = 0; i < fields.count; i++) {
                NSDictionary *f = fields[i];
                NSString *name = f[@"name"];
                NSString *mark = GEKeywordHit(name) ? @"*" : @" ";
                [out appendFormat:@"%@ field[%lu] name=%@ flags=0x%x type=%@",
                 mark, (unsigned long)i, name, [f[@"flags"] unsignedIntValue], f[@"type"]];
                NSString *fdm = f[@"demangled"];
                if (fdm.length) [out appendFormat:@" demangled=%@", fdm];
                [out appendString:@"\n"];
            }
            emitted++;
        }
        cursor += total;
        descriptorIndex++;
    }

    [out appendFormat:@"\nfieldmdSize=%lu scannedDescriptorSlots=%lu validDescriptors=%lu emittedRelevant=%lu\n",
     size, (unsigned long)descriptorIndex, (unsigned long)validDescriptors, (unsigned long)emitted];
    [out appendString:@"NOTE: for enum descriptors, field order is the Swift case order. This build does NOT invoke enum-taking availability APIs; it only recovers the actual enum/type metadata first.\n"];
}

static NSString *GEClassMethodTypes(Class cls, NSString *name) {
    Method m = cls ? class_getClassMethod(cls, NSSelectorFromString(name)) : NULL;
    if (!m) return @"<missing>";
    const char *t = method_getTypeEncoding(m);
    return t ? [NSString stringWithUTF8String:t] : @"<nil>";
}

static void GEAppendKnownBaselines(NSMutableString *out) {
    Class vic = NSClassFromString(@"VICVisualIntelligenceAnalyzer");
    Class vkc = NSClassFromString(@"VKCImageAnalyzer");
    Class config = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");
    Class internal = NSClassFromString(@"VIInternalSettings");

    [out appendString:@"\n--- Objective-C bridge baseline (no enum probing) ---\n"];
    [out appendFormat:@"VIC +isRichAnalysisAvailableForRequestType:bundleID: types=%@\n",
     GEClassMethodTypes(vic, @"isRichAnalysisAvailableForRequestType:bundleID:")];
    [out appendFormat:@"VKC +viEntryType types=%@\n", GEClassMethodTypes(vkc, @"viEntryType")];
    [out appendFormat:@"VKC +viBundleIdentifier types=%@\n", GEClassMethodTypes(vkc, @"viBundleIdentifier")];

    if (vkc) {
        Method m = class_getClassMethod(vkc, NSSelectorFromString(@"viEntryType"));
        const char *t = m ? method_getTypeEncoding(m) : NULL;
        if (t && strcmp(t, "Q16@0:8") == 0) {
            unsigned long long v = ((unsigned long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viEntryType"));
            [out appendFormat:@"VKC.viEntryType(raw)=%llu\n", v];
        }
        m = class_getClassMethod(vkc, NSSelectorFromString(@"viBundleIdentifier"));
        t = m ? method_getTypeEncoding(m) : NULL;
        if (t && strcmp(t, "@16@0:8") == 0) {
            id v = ((id (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viBundleIdentifier"));
            [out appendFormat:@"VKC.viBundleIdentifier=%@\n", v ?: @"<nil>"];
        }
    }

    if (config) {
        id obj = ((id (*)(id, SEL))objc_msgSend)((id)config, @selector(alloc));
        obj = ((id (*)(id, SEL))objc_msgSend)(obj, @selector(init));
        Method m = class_getInstanceMethod(config, NSSelectorFromString(@"requestType"));
        const char *t = m ? method_getTypeEncoding(m) : NULL;
        if (obj && t && strcmp(t, "q16@0:8") == 0) {
            long long v = ((long long (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"requestType"));
            [out appendFormat:@"freshConfig.requestType(raw)=%lld\n", v];
        }
    }

    [out appendString:@"\n--- VIInternalSettings read-only key lookup ---\n"];
    [out appendFormat:@"VIInternalSettings=%@\n", internal ? @"FOUND" : @"MISSING"];
    SEL defaultsKeySel = NSSelectorFromString(@"defaultsKeyForKey:");
    SEL settingsValueSel = NSSelectorFromString(@"settingsValueForKey:");
    Method dm = internal ? class_getClassMethod(internal, defaultsKeySel) : NULL;
    Method sm = internal ? class_getClassMethod(internal, settingsValueSel) : NULL;
    [out appendFormat:@"+defaultsKeyForKey: types=%@\n", GEClassMethodTypes(internal, @"defaultsKeyForKey:")];
    [out appendFormat:@"+settingsValueForKey: types=%@\n", GEClassMethodTypes(internal, @"settingsValueForKey:")];
    NSArray<NSString *> *keys = @[@"hasAdditionalChinaPolicy", @"isChinaRegion", @"currentIPCountryCodeAllowance", @"chinaPolicy"];
    if (dm && sm) {
        const char *dt = method_getTypeEncoding(dm);
        const char *st = method_getTypeEncoding(sm);
        if (dt && st && strcmp(dt, "@24@0:8@16") == 0 && strcmp(st, "@24@0:8@16") == 0) {
            for (NSString *key in keys) {
                id dk = ((id (*)(id, SEL, id))objc_msgSend)(internal, defaultsKeySel, key);
                id sv = ((id (*)(id, SEL, id))objc_msgSend)(internal, settingsValueSel, key);
                [out appendFormat:@"key=%@ defaultsKey=%@ settingsValue=%@\n", key, dk ?: @"<nil>", sv ?: @"<nil>"];
            }
        } else {
            [out appendString:@"key lookups skipped due ABI mismatch\n"];
        }
    }
}

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI SWIFT-FIELDMETADATA READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName,
     NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: metadata parsing + ABI-verified read-only getters only. No call to isRichAnalysisAvailableForRequestType:bundleID:, no arbitrary Swift enum values, no setters/preheat/XPC/swizzling/IMP replacement, no preference or MobileGestalt writes, no respring/reboot.\n\n"];

    void *vic = dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore", RTLD_NOW | RTLD_LOCAL);
    void *vk = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vic ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen=%@\n", vk ? @"OK" : @"FAIL"];

    [out appendString:@"\n--- interpretation of previous result ---\n"];
    [out appendString:@"requestType=0 returned false for every tested bundle identifier, including GestaltEdit and com.apple.camera, while all tested GM use cases were available. Therefore requestType=0 rich-analysis is NOT evidence of a Camera-bundle-specific denial. This probe first recovers the real Swift enum/type layout instead of guessing more raw values.\n"];

    GEAppendKnownBaselines(out);
    GEAppendSwiftFieldMetadata(out, @"VisualIntelligenceCore.framework/VisualIntelligenceCore");
    GEAppendSwiftFieldMetadata(out, @"VisionKitCore.framework/VisionKitCore");

    [out appendString:@"\n--- targets to inspect in this report ---\n"];
    [out appendString:@"Look for descriptors containing requestType, camera/screenshot/context/userDefaults/unspecified, GreymatterAvailability, visualIntelligenceCamera, gviccContentClassifier, availability/partnerAvailability/hasAdditionalChinaPolicy, and currentIPCountryCodeAllowance. If the request enum cases are recovered, the next build can probe ONLY those validated cases without another Swift enum trap.\n"];
    [out appendString:@"================================================================================\n"];
    return out;
}
