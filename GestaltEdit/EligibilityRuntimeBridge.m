#import "EligibilityRuntimeBridge.h"

#import <dlfcn.h>
#import <stdint.h>
#import <stdlib.h>

// Keep this bridge self-contained: use opaque XPC pointers and dynamically
// resolve all private/system symbols instead of linking private headers.
typedef void *GEXPCObject;
typedef int (*GEGetXPCFn)(GEXPCObject *outObject);
typedef int (*GEGetDomainAnswerFn)(uint64_t domain,
                                   uint64_t *answer,
                                   uint64_t *source,
                                   GEXPCObject *status,
                                   GEXPCObject *context);
typedef char *(*GEXPCDescriptionFn)(GEXPCObject object);

static NSString *GEAnswerName(uint64_t answer)
{
    switch (answer) {
        case 0: return @"INVALID";
        case 1: return @"NOT_YET_AVAILABLE";
        case 2: return @"NOT_ELIGIBLE";
        case 3: return @"MAYBE";
        case 4: return @"ELIGIBLE";
        default: return [NSString stringWithFormat:@"UNKNOWN(%llu)", answer];
    }
}

static NSString *GESourceName(uint64_t source)
{
    switch (source) {
        case 0: return @"INVALID";
        case 1: return @"COMPUTED";
        case 2: return @"FORCED";
        default: return [NSString stringWithFormat:@"UNKNOWN(%llu)", source];
    }
}

static NSString *GEDescribeXPC(GEXPCObject object, GEXPCDescriptionFn copyDescription)
{
    if (!object) return @"<nil>";
    if (!copyDescription) {
        return [NSString stringWithFormat:@"<xpc %p; xpc_copy_description unavailable>", object];
    }

    char *description = copyDescription(object);
    if (!description) return @"<description unavailable>";
    NSString *string = [NSString stringWithUTF8String:description] ?: @"<invalid UTF-8 description>";
    free(description);
    return string;
}

static void GEAppendXPCProbe(NSMutableString *report,
                             NSString *name,
                             GEGetXPCFn function,
                             GEXPCDescriptionFn copyDescription)
{
    if (!function) {
        [report appendFormat:@"%@ = <symbol unavailable>\n", name];
        return;
    }

    GEXPCObject object = NULL;
    int result = function(&object);
    [report appendFormat:@"%@ rc=%d\n", name, result];
    if (object) {
        [report appendFormat:@"%@ value=%@\n", name, GEDescribeXPC(object, copyDescription)];
    } else {
        [report appendFormat:@"%@ value=<nil>\n", name];
    }
}

NSString *GEEligibilityRuntimeReport(void)
{
    NSMutableString *report = [NSMutableString string];
    [report appendString:@"--- libsystem_eligibility runtime API ---\n"];
    [report appendString:@"READ-ONLY: only get_state_dump / get_all_domain_answers / get_internal_state / get_domain_answer are called.\n"];

    const char *paths[] = {
        "/usr/lib/system/libsystem_eligibility.dylib",
        "/usr/lib/libsystem_eligibility.dylib"
    };

    void *handle = NULL;
    const char *loadedPath = NULL;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        handle = dlopen(paths[i], RTLD_NOW | RTLD_LOCAL);
        if (handle) {
            loadedPath = paths[i];
            break;
        }
    }

    if (!handle) {
        const char *error = dlerror();
        [report appendFormat:@"dlopen failed: %s\n", error ?: "unknown error"];
        return report;
    }

    [report appendFormat:@"Loaded: %s\n", loadedPath ?: "<unknown>"];

    GEGetXPCFn getStateDump = (GEGetXPCFn)dlsym(handle, "os_eligibility_get_state_dump");
    GEGetXPCFn getAllAnswers = (GEGetXPCFn)dlsym(handle, "os_eligibility_get_all_domain_answers");
    GEGetXPCFn getInternalState = (GEGetXPCFn)dlsym(handle, "os_eligibility_get_internal_state");
    GEGetDomainAnswerFn getDomainAnswer =
        (GEGetDomainAnswerFn)dlsym(handle, "os_eligibility_get_domain_answer");

    void *xpcHandle = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW | RTLD_LOCAL);
    GEXPCDescriptionFn copyDescription = NULL;
    if (xpcHandle) {
        copyDescription = (GEXPCDescriptionFn)dlsym(xpcHandle, "xpc_copy_description");
    }
    if (!copyDescription) {
        copyDescription = (GEXPCDescriptionFn)dlsym(RTLD_DEFAULT, "xpc_copy_description");
    }

    GEAppendXPCProbe(report, @"os_eligibility_get_state_dump", getStateDump, copyDescription);
    GEAppendXPCProbe(report, @"os_eligibility_get_all_domain_answers", getAllAnswers, copyDescription);
    GEAppendXPCProbe(report, @"os_eligibility_get_internal_state", getInternalState, copyDescription);

    [report appendString:@"\n--- selected domain answers ---\n"];
    if (!getDomainAnswer) {
        [report appendString:@"os_eligibility_get_domain_answer = <symbol unavailable>\n"];
    } else {
        struct {
            uint64_t domain;
            const char *name;
        } domains[] = {
            { 39,  "STRONTIUM" },
            { 122, "GREYMATTER" },
            { 130, "FOUNDATION_MODELS" },
            { 155, "SIRI_MODE" }
        };

        for (size_t i = 0; i < sizeof(domains) / sizeof(domains[0]); i++) {
            uint64_t answer = 0;
            uint64_t source = 0;
            GEXPCObject status = NULL;
            GEXPCObject context = NULL;
            int rc = getDomainAnswer(domains[i].domain, &answer, &source, &status, &context);

            [report appendFormat:@"%s(%llu): rc=%d answer=%@ source=%@\n",
             domains[i].name,
             domains[i].domain,
             rc,
             GEAnswerName(answer),
             GESourceName(source)];
            [report appendFormat:@"  status=%@\n", GEDescribeXPC(status, copyDescription)];
            [report appendFormat:@"  context=%@\n", GEDescribeXPC(context, copyDescription)];
        }
    }

    if (xpcHandle) dlclose(xpcHandle);
    dlclose(handle);
    return report;
}
