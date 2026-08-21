#import "VICameraSiriPreflightXrefSafeProbe.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const struct mach_header_64 *header;
    intptr_t slide;
    const char *path;
    uintptr_t imageBase;
    uintptr_t textVMAddr;
    uintptr_t textAddr;
    size_t textSize;
    uintptr_t cstringAddr;
    size_t cstringSize;
    uintptr_t reflstrAddr;
    size_t reflstrSize;
    uintptr_t linkeditBase;
    uint32_t functionStartsDataOff;
    uint32_t functionStartsDataSize;
} VISafeImageInfo;

typedef struct {
    uintptr_t *items;
    size_t count;
} VISafeFunctionStarts;

static int64_t VISafeSignExtend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static BOOL VISafeContains(const char *value, const char *needle) {
    if (!value || !needle) return NO;
    NSString *v = [[NSString stringWithUTF8String:value] lowercaseString];
    NSString *n = [[NSString stringWithUTF8String:needle] lowercaseString];
    return [v containsString:n];
}

static BOOL VISafeInteresting(const char *value) {
    if (!value) return NO;
    static const char *keywords[] = {
        "preflight", "siri", "appleintelligence", "apple intelligence",
        "capab", "eligib", "availability", "greymatter", "intelligencecamera"
    };
    for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if (VISafeContains(value, keywords[i])) return YES;
    }
    return NO;
}

static BOOL VISafeLoadImage(VISafeImageInfo *outInfo) {
    memset(outInfo, 0, sizeof(*outInfo));
    dlopen("/System/Library/PrivateFrameworks/VisualIntelligenceCore.framework/VisualIntelligenceCore", RTLD_LAZY | RTLD_LOCAL);

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "VisualIntelligenceCore.framework/VisualIntelligenceCore")) continue;
        const struct mach_header *baseHeader = _dyld_get_image_header(i);
        if (!baseHeader || baseHeader->magic != MH_MAGIC_64) continue;

        const struct mach_header_64 *header = (const struct mach_header_64 *)baseHeader;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct load_command *lc = (const struct load_command *)((const uint8_t *)header + sizeof(*header));
        uint64_t textVMAddr = 0, linkeditVMAddr = 0, linkeditFileOff = 0;
        uintptr_t textAddr = 0, cstringAddr = 0, reflstrAddr = 0;
        size_t textSize = 0, cstringSize = 0, reflstrSize = 0;
        uint32_t fsOff = 0, fsSize = 0;

        for (uint32_t c = 0; c < header->ncmds; c++) {
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (strncmp(seg->segname, "__TEXT", 16) == 0) textVMAddr = seg->vmaddr;
                if (strncmp(seg->segname, "__LINKEDIT", 16) == 0) {
                    linkeditVMAddr = seg->vmaddr;
                    linkeditFileOff = seg->fileoff;
                }
                const struct section_64 *sec = (const struct section_64 *)(seg + 1);
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strncmp(sec[s].segname, "__TEXT", 16) != 0) continue;
                    uintptr_t runtime = (uintptr_t)(slide + sec[s].addr);
                    if (strncmp(sec[s].sectname, "__text", 16) == 0) {
                        textAddr = runtime;
                        textSize = (size_t)sec[s].size;
                    } else if (strncmp(sec[s].sectname, "__cstring", 16) == 0) {
                        cstringAddr = runtime;
                        cstringSize = (size_t)sec[s].size;
                    } else if (strncmp(sec[s].sectname, "__swift5_reflstr", 16) == 0) {
                        reflstrAddr = runtime;
                        reflstrSize = (size_t)sec[s].size;
                    }
                }
            } else if (lc->cmd == LC_FUNCTION_STARTS) {
                const struct linkedit_data_command *cmd = (const struct linkedit_data_command *)lc;
                fsOff = cmd->dataoff;
                fsSize = cmd->datasize;
            }
            lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
        }

        outInfo->header = header;
        outInfo->slide = slide;
        outInfo->path = name;
        outInfo->imageBase = (uintptr_t)header;
        outInfo->textVMAddr = (uintptr_t)textVMAddr;
        outInfo->textAddr = textAddr;
        outInfo->textSize = textSize;
        outInfo->cstringAddr = cstringAddr;
        outInfo->cstringSize = cstringSize;
        outInfo->reflstrAddr = reflstrAddr;
        outInfo->reflstrSize = reflstrSize;
        outInfo->linkeditBase = linkeditVMAddr ? (uintptr_t)(slide + linkeditVMAddr - linkeditFileOff) : 0;
        outInfo->functionStartsDataOff = fsOff;
        outInfo->functionStartsDataSize = fsSize;
        return textAddr && cstringAddr;
    }
    return NO;
}

static VISafeFunctionStarts VISafeParseFunctionStarts(const VISafeImageInfo *info) {
    VISafeFunctionStarts result = {0};
    if (!info->linkeditBase || !info->functionStartsDataOff || !info->functionStartsDataSize || !info->textVMAddr) return result;

    const uint8_t *p = (const uint8_t *)(info->linkeditBase + info->functionStartsDataOff);
    const uint8_t *end = p + info->functionStartsDataSize;
    size_t capacity = info->functionStartsDataSize + 1;
    uintptr_t *items = calloc(capacity, sizeof(uintptr_t));
    if (!items) return result;

    uint64_t cumulative = 0;
    size_t count = 0;
    while (p < end) {
        uint64_t delta = 0;
        unsigned shift = 0;
        BOOL done = NO;
        while (p < end && shift < 64) {
            uint8_t b = *p++;
            delta |= ((uint64_t)(b & 0x7f)) << shift;
            if (!(b & 0x80)) { done = YES; break; }
            shift += 7;
        }
        if (!done || delta == 0) break;
        cumulative += delta;
        if (count < capacity) items[count++] = (uintptr_t)(info->slide + info->textVMAddr + cumulative);
    }
    result.items = items;
    result.count = count;
    return result;
}

static uintptr_t VISafeNearestFunction(VISafeFunctionStarts starts, uintptr_t address) {
    if (!starts.items || starts.count == 0) return 0;
    size_t lo = 0, hi = starts.count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (starts.items[mid] <= address) lo = mid + 1;
        else hi = mid;
    }
    return lo ? starts.items[lo - 1] : 0;
}

static uintptr_t VISafeFindCString(const VISafeImageInfo *info, const char *needle) {
    if (!needle || !info->cstringAddr || !info->cstringSize) return 0;
    size_t n = strlen(needle);
    if (n + 1 > info->cstringSize) return 0;
    const uint8_t *base = (const uint8_t *)info->cstringAddr;
    for (size_t i = 0; i + n + 1 <= info->cstringSize; i++) {
        if (base[i] != (uint8_t)needle[0]) continue;
        if (memcmp(base + i, needle, n) == 0 && base[i + n] == 0) return info->cstringAddr + i;
    }
    return 0;
}

static NSArray<NSNumber *> *VISafeFindDirectXrefs(const VISafeImageInfo *info, uintptr_t stringAddress) {
    NSMutableArray<NSNumber *> *hits = [NSMutableArray array];
    if (!stringAddress || !info->textAddr || info->textSize < 4) return hits;

    const uint32_t *code = (const uint32_t *)info->textAddr;
    size_t count = info->textSize / 4;
    for (size_t i = 0; i < count; i++) {
        uint32_t insn = code[i];
        uintptr_t pc = info->textAddr + i * 4;

        if ((insn & 0x9F000000u) == 0x10000000u) { // ADR
            uint64_t immlo = (insn >> 29) & 3;
            uint64_t immhi = (insn >> 5) & 0x7ffff;
            int64_t imm = VISafeSignExtend((immhi << 2) | immlo, 21);
            if ((uintptr_t)((int64_t)pc + imm) == stringAddress) [hits addObject:@(pc)];
        }

        if ((insn & 0x9F000000u) == 0x90000000u) { // ADRP
            uint64_t immlo = (insn >> 29) & 3;
            uint64_t immhi = (insn >> 5) & 0x7ffff;
            int64_t pages = VISafeSignExtend((immhi << 2) | immlo, 21);
            uintptr_t page = (pc & ~(uintptr_t)0xfff) + (intptr_t)(pages << 12);
            uint32_t baseReg = insn & 0x1f;

            // Only inspect instruction words already inside __text. No pointer-slot dereferences.
            for (size_t j = 1; j <= 5 && i + j < count; j++) {
                uint32_t next = code[i + j];
                if ((next & 0xFF000000u) != 0x91000000u) continue; // ADD Xd,Xn,#imm
                uint32_t rn = (next >> 5) & 0x1f;
                if (rn != baseReg) continue;
                uint64_t imm12 = (next >> 10) & 0xfff;
                uint64_t shift = ((next >> 22) & 1) ? 12 : 0;
                uintptr_t target = page + (uintptr_t)(imm12 << shift);
                if (target == stringAddress) {
                    [hits addObject:@(pc)];
                    break;
                }
            }
        }
    }
    return hits;
}

static void VISafeAppendSymbol(NSMutableString *out, uintptr_t address) {
    Dl_info di = {0};
    if (address && dladdr((void *)address, &di) && di.dli_sname) {
        uintptr_t sym = (uintptr_t)di.dli_saddr;
        [out appendFormat:@" symbol=%s+0x%llx", di.dli_sname, (unsigned long long)(address - sym)];
    } else {
        [out appendString:@" symbol=<stripped/unresolved>"];
    }
}

static void VISafeAppendInstructionWindow(NSMutableString *out, const VISafeImageInfo *info, uintptr_t xref) {
    if (xref < info->textAddr || xref >= info->textAddr + info->textSize) return;
    uintptr_t first = xref >= info->textAddr + 16 ? xref - 16 : info->textAddr;
    uintptr_t end = MIN(xref + 24, info->textAddr + info->textSize);
    [out appendString:@"    instructions:"];
    for (uintptr_t p = first; p + 4 <= end; p += 4) {
        uint32_t insn = *(const uint32_t *)p;
        [out appendFormat:@" %@0x%llx:%08x", p == xref ? @"*" : @"", (unsigned long long)(p - info->imageBase), insn];
    }
    [out appendString:@"\n"];
}

static void VISafeAppendRelevantSelectors(NSMutableString *out) {
    [out appendString:@"\n--- VisualIntelligenceCore related Objective-C selectors (metadata only) ---\n"];
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) { [out appendString:@"objc_getClassList returned none\n"]; return; }
    Class *classes = (__unsafe_unretained Class *)calloc((size_t)total, sizeof(Class));
    total = objc_getClassList(classes, total);
    NSUInteger emitted = 0;
    for (int i = 0; i < total && emitted < 220; i++) {
        Class cls = classes[i];
        const char *image = class_getImageName(cls);
        if (!image || !strstr(image, "VisualIntelligenceCore.framework")) continue;
        const char *className = class_getName(cls);
        Class targets[2] = {cls, object_getClass(cls)};
        const char *prefix[2] = {"-", "+"};
        for (int k = 0; k < 2 && emitted < 220; k++) {
            unsigned int count = 0;
            Method *methods = class_copyMethodList(targets[k], &count);
            for (unsigned int m = 0; m < count && emitted < 220; m++) {
                const char *sel = sel_getName(method_getName(methods[m]));
                if (!(VISafeInteresting(sel) || (VISafeInteresting(className) && (VISafeContains(sel, "is") || VISafeContains(sel, "support") || VISafeContains(sel, "enable") || VISafeContains(sel, "avail"))))) continue;
                [out appendFormat:@"%s %s %s types=%s\n", prefix[k], className ?: "<nil>", sel ?: "<nil>", method_getTypeEncoding(methods[m]) ?: "<nil>"];
                emitted++;
            }
            free(methods);
        }
    }
    free(classes);
    [out appendFormat:@"selectorHits=%lu\n", (unsigned long)emitted];
}

static void VISafeAppendReflectionStrings(NSMutableString *out, const VISafeImageInfo *info) {
    [out appendString:@"\n--- selected __swift5_reflstr strings ---\n"];
    if (!info->reflstrAddr || !info->reflstrSize) { [out appendString:@"section unavailable\n"]; return; }
    const char *p = (const char *)info->reflstrAddr;
    const char *end = p + info->reflstrSize;
    NSUInteger emitted = 0;
    while (p < end && emitted < 220) {
        size_t remain = (size_t)(end - p);
        size_t len = strnlen(p, remain);
        if (len == remain) break;
        if (len && VISafeInteresting(p)) {
            [out appendFormat:@"+0x%llx: %s\n", (unsigned long long)((uintptr_t)p - info->reflstrAddr), p];
            emitted++;
        }
        p += len + 1;
    }
    [out appendFormat:@"reflectionHits=%lu\n", (unsigned long)emitted];
}

NSString *VICameraSiriPreflightXrefSafeGenerateReport(void) {
    NSMutableString *out = [NSMutableString string];
    NSISO8601DateFormatter *fmt = [NSISO8601DateFormatter new];
    [out appendString:@"========== iOS 27 VI CAMERA SIRI-AI PREFLIGHT DIRECT-XREF CRASH-SAFE READ-ONLY Diagnostic ==========\n"];
    [out appendFormat:@"Generated: %@\n", [fmt stringFromDate:[NSDate date]]];
    [out appendFormat:@"OS: %@\n", NSProcessInfo.processInfo.operatingSystemVersionString];
    [out appendFormat:@"Process: %@ bundle=%@\n", NSProcessInfo.processInfo.processName, NSBundle.mainBundle.bundleIdentifier ?: @"<nil>"];
    [out appendString:@"SAFETY: reads only mapped VisualIntelligenceCore Mach-O header/sections, __text instruction words, __cstring/__swift5_reflstr bytes, LC_FUNCTION_STARTS, and Objective-C runtime metadata. Direct xref detection supports ADR and ADRP+ADD only; it deliberately does NOT dereference GOT/LDR pointer slots. No availability/private VI API invocation, no enum calls, XPC, process inspection, swizzling, preferences/MobileGestalt/file writes, respring or reboot.\n\n"];

    VISafeImageInfo info;
    if (!VISafeLoadImage(&info)) {
        [out appendString:@"VisualIntelligenceCore image/sections unresolved.\n"];
        return out;
    }
    [out appendFormat:@"image=%s\n", info.path ?: "<nil>"];
    [out appendFormat:@"imageBase=0x%llx slide=0x%llx textOffset=0x%llx textSize=0x%llx cstringOffset=0x%llx cstringSize=0x%llx\n",
     (unsigned long long)info.imageBase,
     (unsigned long long)info.slide,
     (unsigned long long)(info.textAddr - info.imageBase),
     (unsigned long long)info.textSize,
     (unsigned long long)(info.cstringAddr - info.imageBase),
     (unsigned long long)info.cstringSize];

    VISafeFunctionStarts starts = VISafeParseFunctionStarts(&info);
    [out appendFormat:@"LC_FUNCTION_STARTS count=%llu\n\n", (unsigned long long)starts.count];

    const char *targets[] = {
        "Preflight: device not capable of Apple Intelligence for '%s'",
        "The Siri mode in Camera requires Siri AI",
        "Turn on Siri AI?",
        "settings-navigation://com.apple.Settings.Siri",
        "GreymatterAvailability preheated availability for %s to availability: %s, partnerAvailability: %s, chinaPolicy: %{BOOL}d"
    };

    NSMutableDictionary<NSNumber *, NSMutableArray<NSString *> *> *clusters = [NSMutableDictionary dictionary];
    for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++) {
        const char *needle = targets[t];
        [out appendFormat:@"--- target[%llu] ---\n%s\n", (unsigned long long)t, needle];
        uintptr_t strAddr = VISafeFindCString(&info, needle);
        if (!strAddr) {
            [out appendString:@"cstring=<not found>\n\n"];
            continue;
        }
        [out appendFormat:@"cstringOffset=0x%llx runtime=0x%llx\n", (unsigned long long)(strAddr - info.imageBase), (unsigned long long)strAddr];
        NSArray<NSNumber *> *xrefs = VISafeFindDirectXrefs(&info, strAddr);
        [out appendFormat:@"directArm64Xrefs=%lu\n", (unsigned long)xrefs.count];
        for (NSNumber *number in xrefs) {
            uintptr_t xref = (uintptr_t)number.unsignedLongLongValue;
            uintptr_t fn = VISafeNearestFunction(starts, xref);
            [out appendFormat:@"  xrefOffset=0x%llx", (unsigned long long)(xref - info.imageBase)];
            if (fn) {
                [out appendFormat:@" functionStartOffset=0x%llx functionDelta=0x%llx", (unsigned long long)(fn - info.imageBase), (unsigned long long)(xref - fn)];
                VISafeAppendSymbol(out, fn);
                NSNumber *key = @(fn);
                NSMutableArray<NSString *> *arr = clusters[key];
                if (!arr) { arr = [NSMutableArray array]; clusters[key] = arr; }
                NSString *value = [NSString stringWithUTF8String:needle];
                if (![arr containsObject:value]) [arr addObject:value];
            } else {
                [out appendString:@" functionStart=<unresolved>"];
            }
            [out appendString:@"\n"];
            VISafeAppendInstructionWindow(out, &info, xref);
        }
        [out appendString:@"\n"];
    }

    [out appendString:@"--- xref function clustering ---\n"];
    NSArray<NSNumber *> *keys = [[clusters allKeys] sortedArrayUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) { return [a compare:b]; }];
    if (!keys.count) [out appendString:@"no direct ADR/ADRP+ADD references resolved\n"];
    for (NSNumber *key in keys) {
        uintptr_t fn = (uintptr_t)key.unsignedLongLongValue;
        [out appendFormat:@"functionStartOffset=0x%llx targets=%@", (unsigned long long)(fn - info.imageBase), [clusters[key] componentsJoinedByString:@" | "]];
        VISafeAppendSymbol(out, fn);
        [out appendString:@"\n"];
    }

    VISafeAppendRelevantSelectors(out);
    VISafeAppendReflectionStrings(out, &info);

    [out appendString:@"\nINTERPRETATION TARGETS:\n"];
    [out appendString:@"1. The exact 24A5390f-added Camera Siri-AI strings can be tied to concrete function-start offsets without invoking the preflight.\n"];
    [out appendString:@"2. If several targets cluster in one function, that is the strongest candidate owner for the new Camera-specific Apple-Intelligence preflight.\n"];
    [out appendString:@"3. If direct xrefs are zero, do not infer absence; the compiler may use an indirect constant/GOT reference that this crash-safe build intentionally does not dereference.\n"];
    [out appendString:@"================================================================================\n"];

    free(starts.items);
    return out;
}
