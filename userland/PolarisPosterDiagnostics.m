#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <dlfcn.h>
#include <mach/mach.h>

@interface EXExtensionPointCatalog : NSObject
- (NSDictionary *)extensionPointByIdentifierPlatform;
- (id)extensionPointForIdentifier:(NSString *)identifier platform:(unsigned)platform;
@end

@interface LSApplicationExtensionRecord : NSObject
+ (NSEnumerator *)enumeratorWithOptions:(NSUInteger)options;
- (id)extensionPointRecord;
- (NSString *)bundleIdentifier;
@end

@interface NSObject (PolarisExtensionPointIdentity)
- (NSString *)identifier;
@end

@interface _EXQuery : NSObject
- (id)initWithExtensionPointIdentifier:(NSString *)identifier;
@end

@interface _EXQueryController : NSObject
+ (void)executeQuery:(id)query completionHandler:(void (^)(NSArray *))handler;
@end

void PolarisPosterDiagnostics(void (*logger)(NSString *));

void PolarisPosterDiagnostics(void (*logger)(NSString *))
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_queue_t results = dispatch_queue_create("polaris.poster.diagnostic.results", NULL);
        __block BOOL finished = NO;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            @autoreleasepool {
                logger(@"Poster diagnostics started; read-only catalog and registration queries");
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), results, ^{
                    if (!finished) logger(@"Poster diagnostics: no query completion within 15 seconds");
                });
                @try {
                    void *extension = dlopen(
                        "/System/Library/Frameworks/ExtensionFoundation.framework/ExtensionFoundation",
                        RTLD_NOW | RTLD_LOCAL);
                    void *services = dlopen(
                        "/System/Library/Frameworks/CoreServices.framework/CoreServices",
                        RTLD_NOW | RTLD_LOCAL);
                    logger([NSString stringWithFormat:@"Frameworks loaded: ExtensionFoundation=%d CoreServices=%d",
                        extension != NULL, services != NULL]);

                    void *iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",
                        RTLD_NOW | RTLD_LOCAL);
                    CFMutableDictionaryRef (*matching)(const char *) =
                        iokit ? dlsym(iokit, "IOServiceMatching") : NULL;
                    mach_port_t (*service)(mach_port_t, CFDictionaryRef) =
                        iokit ? dlsym(iokit, "IOServiceGetMatchingService") : NULL;
                    int (*release)(mach_port_t) =
                        iokit ? dlsym(iokit, "IOObjectRelease") : NULL;
                    if (matching && service && release) {
                        CFMutableDictionaryRef match = matching("AppleMobileFileIntegrity");
                        if (match) {
                            mach_port_t port = service(MACH_PORT_NULL, match);
                            logger([NSString stringWithFormat:@"AppleMobileFileIntegrity service present=%d",
                                port != MACH_PORT_NULL]);
                            if (port != MACH_PORT_NULL) release(port);
                        }
                    }

                    NSString *point = @"com.apple.posterkit.provider";
                    Class catalogClass = NSClassFromString(@"EXExtensionPointCatalog");
                    if ([catalogClass instancesRespondToSelector:@selector(extensionPointByIdentifierPlatform)] &&
                        [catalogClass instancesRespondToSelector:@selector(extensionPointForIdentifier:platform:)]) {
                        EXExtensionPointCatalog *catalog = [[catalogClass alloc] init];
                        logger([NSString stringWithFormat:@"Extension catalog entries=%lu poster platform2=%d",
                            (unsigned long)catalog.extensionPointByIdentifierPlatform.count,
                            [catalog extensionPointForIdentifier:point platform:2] != nil]);
                    } else {
                        logger(@"Extension catalog API unavailable");
                    }

                    Class recordClass = NSClassFromString(@"LSApplicationExtensionRecord");
                    if ([recordClass respondsToSelector:@selector(enumeratorWithOptions:)]) {
                        NSUInteger total = 0, posters = 0;
                        for (LSApplicationExtensionRecord *record in [recordClass enumeratorWithOptions:0]) {
                            if (++total > 2048) break;
                            if ([[record.extensionPointRecord identifier] isEqualToString:point]) {
                                if (++posters <= 32) {
                                    logger([NSString stringWithFormat:@"Registered poster provider: %@",
                                        record.bundleIdentifier]);
                                }
                            }
                        }
                        logger([NSString stringWithFormat:@"LaunchServices extension records=%lu poster providers=%lu",
                            (unsigned long)total, (unsigned long)posters]);
                    }

                    void *content = dlopen(
                        "/System/Library/PrivateFrameworks/InstalledContentLibrary.framework/InstalledContentLibrary",
                        RTLD_NOW | RTLD_LOCAL);
                    id (*copyEntry)(NSString *, unsigned, NSError **) =
                        content ? dlsym(content, "MICopyExtensionCacheEntryWithPlatform") : NULL;
                    if (copyEntry) {
                        NSError *error = nil;
                        id entry = copyEntry(point, 2, &error);
                        logger([NSString stringWithFormat:@"Poster extension cache entry=%d error=%@",
                            entry != nil, error]);
                    }

                    Class queryClass = NSClassFromString(@"_EXQuery");
                    Class controller = NSClassFromString(@"_EXQueryController");
                    if ([queryClass instancesRespondToSelector:@selector(initWithExtensionPointIdentifier:)] &&
                        [controller respondsToSelector:@selector(executeQuery:completionHandler:)]) {
                        id query = [[queryClass alloc] initWithExtensionPointIdentifier:point];
                        if (query) {
                            [controller executeQuery:query completionHandler:^(NSArray *providers) {
                                dispatch_async(results, ^{
                                    finished = YES;
                                    logger([NSString stringWithFormat:@"Extension query returned %lu poster providers",
                                        (unsigned long)providers.count]);
                                });
                            }];
                        }
                    } else {
                        logger(@"Extension query API unavailable");
                    }
                } @catch (NSException *exception) {
                    logger([NSString stringWithFormat:@"Poster diagnostics exception: %@ %@",
                        exception.name, exception.reason]);
                }
            }
        });
    });
}
