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
} GELoadedImage;

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
        outInfo->header = (const struct mach_header_64 *)h;
        outInfo->slide = _dyld_get_image_vmaddr_slide(i);
        return YES;
    }
    return NO;
}

static BOOL GEAddressMapped(GELoadedImage image, const void *ptr, size_t len) {
    if (!image.header || !ptr) return NO;
    uintptr_t p = (uintptr_t)ptr;
    if (len > UINTPTR_MAX - p) return NO;
    uintptr_t end = p + len;
    const uint8_t *cmdPtr = (const uint8_t *)(image.header + 1);
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmdsize < sizeof(struct load_command)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t s = (uintptr_t)(seg->vmaddr + image.slide);
            uintptr_t e = s + (uintptr_t)seg->vmsize;
            if (p >= s && end <= e) return YES;
        }
        cmdPtr += lc->cmdsize;
    }
    return NO;
}

static size_t GEReadableBytesInSegment(GELoadedImage image, const void *ptr, size_t cap) {
    if (!image.header || !ptr) return 0;
    uintptr_t p = (uintptr_t)ptr;
    const uint8_t *cmdPtr = (const uint8_t *)(image.header + 1);
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmdPtr;
        if (lc->cmdsize < sizeof(struct load_command)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            uintptr_t s = (uintptr_t)(seg->vmaddr + image.slide);
            uintptr_t e = s + (uintptr_t)seg->vmsize;
            if (p >= s && p < e) {
                size_t avail = (size_t)(e - p);
                return MIN(avail, cap);
            }
        }
        cmdPtr += lc->cmdsize;
    }
    return 0;
}

static const uint8_t *GEResolveRelative32(const int32_t *field, GELoadedImage image) {
    if (!field || !GEAddressMapped(image, field, sizeof(*field))) return NULL;
    int32_t rel = 0;
    memcpy(&rel, field, sizeof(rel));
    if (rel == 0) return NULL;
    const uint8_t *target = (const uint8_t *)field + rel;
    return GEAddressMapped(image, target, 1) ? target : NULL;
}

static NSString *GESafeCString(const uint8_t *ptr, GELoadedImage image, NSUInteger maxLen) {
    if (!ptr) return nil;
    size_t readable = GEReadableBytesInSegment(image, ptr, maxLen);
    if (!readable) return nil;
    const void *nul = memchr(ptr, 0, readable);
    if (!nul) return nil;
    NSUInteger len = (NSUInteger)((const uint8_t *)nul - ptr);
    if (!len) return @"";
    NSData *data = [NSData dataWithBytes:ptr length:len];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static NSString *GEHexPreview(const uint8_t *ptr, GELoadedImage image, NSUInteger maxLen) {
    if (!ptr) return @"<nil>";
    size_t readable = GEReadableBytesInSegment(image, ptr, maxLen);
    if (!readable) return @"<unmapped>";
    NSMutableString *s = [NSMutableString string];
    for (NSUInteger i = 0; i < readable; i++) {
        uint8_t b = ptr[i];
        if (b == 0) break;
        if (b >= 0x20 && b <= 0x7e) [s appendFormat:@"%c", b];
        else [s appendFormat:@"\\x%02x", b];
    }
    return s.length ? s : @"<empty>";
}

static NSString *GEContextKindName(uint32_t kind) {
    switch (kind) {
        case 0: return @"module";
        case 1: return @"extension";
        case 2: return @"anonymous";
        case 3: return @"protocol";
        case 4: return @"opaqueType";
        case 16: return @"class";
        case 17: return @"struct";
        case 18: return @"enum";
        default: return [NSString stringWithFormat:@"kind(%u)", kind];
    }
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

static NSString *GEContextLocalName(const uint8_t *ctx, GELoadedImage image) {
    if (!GEAddressMapped(image, ctx, 12)) return nil;
    uint32_t flags = 0;
    memcpy(&flags, ctx, sizeof(flags));
    uint32_t kind = flags & 0x1f;
    if (!(kind == 0 || kind == 3 || kind == 16 || kind == 17 || kind == 18)) return nil;
    const int32_t *nameField = (const int32_t *)(ctx + 8);
    const uint8_t *namePtr = GEResolveRelative32(nameField, image);
    return GESafeCString(namePtr, image, 256);
}

static const uint8_t *GEContextParent(const uint8_t *ctx, GELoadedImage image) {
    if (!GEAddressMapped(image, ctx, 8)) return NULL;
    return GEResolveRelative32((const int32_t *)(ctx + 4), image);
}

static NSString *GEContextFullName(const uint8_t *ctx, GELoadedImage image) {
    if (!ctx) return nil;
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    const uint8_t *cur = ctx;
    for (NSUInteger depth = 0; depth < 10 && cur; depth++) {
        if (!GEAddressMapped(image, cur, 12)) break;
        uint32_t flags = 0;
        memcpy(&flags, cur, sizeof(flags));
        uint32_t kind = flags & 0x1f;
        NSString *name = GEContextLocalName(cur, image);
        if (name.length) [parts insertObject:name atIndex:0];
        if (kind == 0) break;
        cur = GEContextParent(cur, image);
    }
    return parts.count ? [parts componentsJoinedByString:@"."] : nil;
}

static const GEFieldDescriptor *GEFieldDescriptorForContext(const uint8_t *ctx, GELoadedImage image) {
    if (!GEAddressMapped(image, ctx, 20)) return NULL;
    uint32_t flags = 0;
    memcpy(&flags, ctx, sizeof(flags));
    uint32_t kind = flags & 0x1f;
    if (!(kind == 16 || kind == 17 || kind == 18)) return NULL;
    const uint8_t *fieldPtr = GEResolveRelative32((const int32_t *)(ctx + 16), image);
    if (!fieldPtr || !GEAddressMapped(image, fieldPtr, sizeof(GEFieldDescriptor))) return NULL;
    return (const GEFieldDescriptor *)fieldPtr;
}

static BOOL GEValidFieldDescriptor(const GEFieldDescriptor *fd, GELoadedImage image) {
    if (!fd || !GEAddressMapped(image, fd, sizeof(*fd))) return NO;
    uint16_t recordSize = fd->fieldRecordSize;
    uint32_t numFields = fd->numFields;
    if (recordSize < sizeof(GEFieldRecord) || recordSize > 128 || numFields > 2048) return NO;
    uint64_t total = sizeof(GEFieldDescriptor) + (uint64_t)recordSize * (uint64_t)numFields;
    return total <= SIZE_MAX && GEAddressMapped(image, fd, (size_t)total);
}

static void GEAppendContextDescriptor(NSMutableString *out, const uint8_t *ctx, GELoadedImage image, NSString *prefix) {
    if (!ctx || !GEAddressMapped(image, ctx, 12)) {
        [out appendFormat:@"%@context=<unresolved>\n", prefix];
        return;
    }
    uint32_t flags = 0;
    memcpy(&flags, ctx, sizeof(flags));
    uint32_t kind = flags & 0x1f;
    NSString *full = GEContextFullName(ctx, image) ?: @"<unnamed>";
    [out appendFormat:@"%@context=%@ kind=%@ flags=0x%x\n", prefix, full, GEContextKindName(kind), flags];

    if (kind == 18 && GEAddressMapped(image, ctx + 20, 8)) {
        uint32_t payloadPacked = 0, emptyCases = 0;
        memcpy(&payloadPacked, ctx + 20, 4);
        memcpy(&emptyCases, ctx + 24, 4);
        uint32_t payloadCases = payloadPacked & 0x00ffffff;
        [out appendFormat:@"%@enumPayloadCases=%u enumEmptyCases=%u totalCases=%u\n",
         prefix, payloadCases, emptyCases, payloadCases + emptyCases];
    }

    const GEFieldDescriptor *fd = GEFieldDescriptorForContext(ctx, image);
    if (!GEValidFieldDescriptor(fd, image)) return;
    [out appendFormat:@"%@fieldDescriptor kind=%@ numFields=%u\n", prefix, GEFieldKindName(fd->kind), fd->numFields];
    const uint8_t *records = (const uint8_t *)fd + sizeof(GEFieldDescriptor);
    for (uint32_t i = 0; i < fd->numFields && i < 64; i++) {
        const GEFieldRecord *fr = (const GEFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
        const uint8_t *namePtr = GEResolveRelative32(&fr->fieldName, image);
        NSString *name = GESafeCString(namePtr, image, 256) ?: @"<unreadable>";
        [out appendFormat:@"%@  case/field[%u]=%@ flags=0x%x\n", prefix, i, name, fr->flags];
    }
}

static void GEAppendSymbolicRefs(NSMutableString *out, const uint8_t *mangled, GELoadedImage image, NSString *prefix) {
    if (!mangled) return;
    size_t readable = GEReadableBytesInSegment(image, mangled, 256);
    if (!readable) return;
    const uint8_t *nul = memchr(mangled, 0, readable);
    size_t len = nul ? (size_t)((const uint8_t *)nul - mangled) : readable;
    NSUInteger refs = 0;
    for (size_t i = 0; i + 5 <= len; i++) {
        if (mangled[i] != 0x01) continue;
        int32_t rel = 0;
        memcpy(&rel, mangled + i + 1, 4);
        const uint8_t *base = mangled + i + 1;
        const uint8_t *target = base + rel;
        [out appendFormat:@"%@symbolicRef[%lu] kind=0x01 rel=%d\n", prefix, (unsigned long)refs, rel];
        if (GEAddressMapped(image, target, 12)) {
            GEAppendContextDescriptor(out, target, image, [prefix stringByAppendingString:@"  "]);
        } else {
            [out appendFormat:@"%@  target=<outside mapped image>\n", prefix];
        }
        refs++;
        i += 4;
    }
    if (!refs) [out appendFormat:@"%@symbolicRefs=<none resolved>\n", prefix];
}

static BOOL GENameInteresting(NSString *name) {
    if (!name.length) return NO;
    static NSArray<NSString *> *targets;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        targets = @[
            @"requestType", @"environmentBundleIdentifier", @"useCaseIdentifier",
            @"availability", @"partnerAvailability", @"hasAdditionalChinaPolicy",
            @"availabilityEntries", @"availabilityKey", @"languageOption",
            @"currentIPCountryCodeAllowance", @"visualIntelligenceCamera",
            @"gviccContentClassifier", @"camera", @"screenshot", @"context",
            @"unspecified", @"unaware", @"opened", @"used"
        ];
    });
    return [targets containsObject:name];
}

static void GEAppendResolvedFieldMetadata(NSMutableString *out, NSString *imageNeedle) {
    [out appendFormat:@"\n--- %@ resolved Swift symbolic field metadata ---\n", imageNeedle];
    GELoadedImage image;
    if (!GEFindLoadedImage(imageNeedle, &image)) {
        [out appendString:@"loaded image not found\n"];
        return;
    }
    unsigned long size = 0;
    const uint8_t *section = getsectiondata(image.header, "__TEXT", "__swift5_fieldmd", &size);
    if (!section || size < sizeof(GEFieldDescriptor)) {
        [out appendFormat:@"fieldmd unavailable size=%lu\n", size];
        return;
    }
    const uint8_t *end = section + size;
    const uint8_t *cursor = section;
    NSUInteger index = 0, emitted = 0;
    while (cursor + sizeof(GEFieldDescriptor) <= end && index < 10000) {
        const GEFieldDescriptor *fd = (const GEFieldDescriptor *)cursor;
        if (!GEValidFieldDescriptor(fd, image)) {
            cursor += 4;
            index++;
            continue;
        }
        uint64_t total = sizeof(GEFieldDescriptor) + (uint64_t)fd->fieldRecordSize * fd->numFields;
        const uint8_t *records = cursor + sizeof(GEFieldDescriptor);
        BOOL hit = NO;
        NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];
        for (uint32_t i = 0; i < fd->numFields; i++) {
            const GEFieldRecord *fr = (const GEFieldRecord *)(records + (uint64_t)i * fd->fieldRecordSize);
            NSString *name = GESafeCString(GEResolveRelative32(&fr->fieldName, image), image, 256) ?: @"<unreadable>";
            if (GENameInteresting(name)) hit = YES;
            [rows addObject:@{@"name": name, @"ptr": [NSValue valueWithPointer:GEResolveRelative32(&fr->mangledTypeName, image)], @"flags": @(fr->flags)}];
        }
        if (hit && emitted < 80) {
            [out appendFormat:@"\n[%lu] offset=0x%lx fieldKind=%@ numFields=%u\n",
             (unsigned long)index, (unsigned long)(cursor - section), GEFieldKindName(fd->kind), fd->numFields];
            const uint8_t *ownerMangled = GEResolveRelative32(&fd->mangledTypeName, image);
            [out appendFormat:@"ownerMangled=%@\n", GEHexPreview(ownerMangled, image, 96)];
            GEAppendSymbolicRefs(out, ownerMangled, image, @"  owner.");
            for (NSUInteger i = 0; i < rows.count; i++) {
                NSDictionary *row = rows[i];
                NSString *name = row[@"name"];
                if (!GENameInteresting(name)) continue;
                const uint8_t *typePtr = [row[@"ptr"] pointerValue];
                [out appendFormat:@"  field[%lu] name=%@ flags=0x%x typeMangled=%@\n",
                 (unsigned long)i, name, [row[@"flags"] unsignedIntValue], GEHexPreview(typePtr, image, 96)];
                GEAppendSymbolicRefs(out, typePtr, image, @"    type.");
            }
            emitted++;
        }
        cursor += total;
        index++;
    }
    [out appendFormat:@"\nfieldmdSize=%lu descriptorsScanned=%lu relevantDescriptors=%lu\n",
     size, (unsigned long)index, (unsigned long)emitted];
}

static NSString *GEClassMethodTypes(Class cls, NSString *name) {
    Method m = cls ? class_getClassMethod(cls, NSSelectorFromString(name)) : NULL;
    if (!m) return @"<missing>";
    const char *t = method_getTypeEncoding(m);
    return t ? [NSString stringWithUTF8String:t] : @"<nil>";
}

static void GEAppendBaseline(NSMutableString *out) {
    Class vkc = NSClassFromString(@"VKCImageAnalyzer");
    Class config = NSClassFromString(@"VICVisualIntelligenceAnalysisRequestConfig");
    Class vic = NSClassFromString(@"VICVisualIntelligenceAnalyzer");
    [out appendString:@"\n--- bridge baseline; NO rich-analysis enum call ---\n"];
    [out appendFormat:@"VIC +isRichAnalysisAvailableForRequestType:bundleID: types=%@\n",
     GEClassMethodTypes(vic, @"isRichAnalysisAvailableForRequestType:bundleID:")];
    [out appendFormat:@"VKC +viEntryType types=%@\n", GEClassMethodTypes(vkc, @"viEntryType")];
    if (vkc && [GEClassMethodTypes(vkc, @"viEntryType") isEqualToString:@"Q16@0:8"]) {
        unsigned long long raw = ((unsigned long long (*)(id, SEL))objc_msgSend)(vkc, NSSelectorFromString(@"viEntryType"));
        [out appendFormat:@"VKC.viEntryType(raw)=%llu\n", raw];
    }
    if (config) {
        id obj = ((id (*)(id, SEL))objc_msgSend)((id)config, @selector(alloc));
        obj = ((id (*)(id, SEL))objc_msgSend)(obj, @selector(init));
        Method m = class_getInstanceMethod(config, NSSelectorFromString(@"requestType"));
        const char *t = m ? method_getTypeEncoding(m) : NULL;
        if (obj && t && strcmp(t, "q16@0:8") == 0) {
            long long raw = ((long long (*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"requestType"));
            [out appendFormat:@"freshConfig.requestType(raw)=%lld\n", raw];
        }
    }
}

NSString *CallerIdentityGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    [out appendString:@"========== iOS 27 VI SWIFT-SYMBOLIC-REF RESOLVER READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [NSDate date]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: Swift reflection metadata parsing plus already-ABI-verified scalar getters only. No call to +isRichAnalysisAvailableForRequestType:bundleID:, no arbitrary enum raw values, no setters/preheat/XPC/swizzling/IMP replacement, no preference or MobileGestalt writes, no respring/reboot.\n\n"];
    [out appendString:@"PURPOSE: the previous fieldmd probe exposed the exact GreymatterAvailability layout — including visualIntelligenceCamera, gviccContentClassifier, availability, partnerAvailability and hasAdditionalChinaPolicy — but several type names were still encoded as Swift symbolic references. This build resolves those references back to their concrete context descriptors and enum case lists without executing the enum-taking availability API.\n"];

    void *vicHandle = dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore", RTLD_NOW | RTLD_LOCAL);
    void *vkHandle = dlopen("/System/Library/PrivateFrameworks/VisionKitCore.framework/VisionKitCore", RTLD_NOW | RTLD_LOCAL);
    [out appendFormat:@"VisualIntelligenceCore dlopen=%@\n", vicHandle ? @"OK" : @"FAIL"];
    [out appendFormat:@"VisionKitCore dlopen=%@\n", vkHandle ? @"OK" : @"FAIL"];

    GEAppendBaseline(out);
    GEAppendResolvedFieldMetadata(out, @"VisualIntelligenceCore.framework/VisualIntelligenceCore");
    GEAppendResolvedFieldMetadata(out, @"VisionKitCore.framework/VisionKitCore");

    [out appendString:@"\n--- what to look for ---\n"];
    [out appendString:@"1. requestType field -> concrete enum context name + its validated case list.\n"];
    [out appendString:@"2. GreymatterAvailability availabilityEntries key/value types -> concrete UseCaseIdentifier/entry-result type names.\n"];
    [out appendString:@"3. the struct containing availability + partnerAvailability + hasAdditionalChinaPolicy -> its exact type name.\n"];
    [out appendString:@"4. enums containing currentIPCountryCodeAllowance and camera/screenshot context -> exact owner type names.\n"];
    [out appendString:@"No inferred raw-value probing is performed in this build.\n"];
    [out appendString:@"================================================================================\n"];
    return out;
}
