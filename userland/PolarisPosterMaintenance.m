#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

@interface LSApplicationWorkspace : NSObject
+ (id)defaultWorkspace;
- (BOOL)registerPlugin:(NSURL *)url;
@end

@interface LSApplicationExtensionRecord : NSObject
+ (NSEnumerator *)enumeratorWithOptions:(NSUInteger)options;
- (NSString *)bundleIdentifier;
@end

static int logFD = -1;
static NSString *const providerID = @"com.apple.GradientPoster.GradientPosterExtension";
static NSString *const providerPath =
    @"/System/Library/PrivateFrameworks/GradientPoster.framework/PlugIns/GradientPosterExtension.appex";

static void Log(NSString *message)
{
    NSData *data = [[message stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (logFD >= 0 && data.length <= 8192) {
        (void)write(logFD, data.bytes, data.length);
        (void)fsync(logFD);
    }
}

static NSInteger RegisteredCount(void)
{
    Class records = NSClassFromString(@"LSApplicationExtensionRecord");
    if (![records respondsToSelector:@selector(enumeratorWithOptions:)]) return -1;
    NSUInteger inspected = 0;
    NSInteger found = 0;
    for (LSApplicationExtensionRecord *record in [records enumeratorWithOptions:0]) {
        if (++inspected > 2048) return -1;
        if ([record.bundleIdentifier isEqualToString:providerID]) found++;
    }
    return found;
}

int main(int argc, char **argv)
{
    BOOL repair = argc == 2 && strcmp(argv[1], "--register-gradient-once") == 0;
    if (argc != 1 && !repair) return 64;
    if (geteuid() != 0) return 77;
    logFD = open("/private/var/log/polaris-poster-maintenance.log",
        O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    struct stat st;
    if (logFD < 0 || fstat(logFD, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || st.st_nlink != 1) return 74;
    @autoreleasepool {
        Log(repair ? @"Scoped gradient registration requested" : @"Inspection only");
        int marker = -1;
        if (repair) {
            marker = open("/private/var/db/polaris-gradient-registration-v1.once",
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            if (marker < 0) {
                int error = errno;
                Log([NSString stringWithFormat:@"No registration: one-shot marker unavailable errno=%d", error]);
                return error == EEXIST ? 0 : 74;
            }
            const char attempted[] = "gradient-registration-v1 attempted\n";
            if (write(marker, attempted, sizeof(attempted) - 1) != sizeof(attempted) - 1 ||
                fsync(marker)) {
                close(marker);
                Log(@"No registration: durable attempt record failed");
                return 74;
            }
            close(marker);
        }
        if (setgroups(0, NULL) || setgid(501) || setuid(501) ||
            getuid() != 501 || geteuid() != 501 || getgid() != 501) {
            Log(@"No registration: failed to enter mobile user context");
            return 77;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                Log(@"Maintenance deadline expired; no automatic retry");
                _exit(124);
            });
        @try {
            if (!dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_NOW)) {
                Log(@"CoreServices unavailable");
                return 69;
            }
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                [providerPath stringByAppendingPathComponent:@"Info.plist"]];
            if (![info[@"CFBundleIdentifier"] isEqualToString:providerID] ||
                ![info[@"CFBundleExecutable"] isEqualToString:@"GradientPosterExtension"] ||
                ![info[@"NSExtension"][@"NSExtensionPointIdentifier"] isEqualToString:@"com.apple.posterkit.provider"]) {
                Log(@"No registration: existing provider identity mismatch");
                return 65;
            }
            NSInteger count = RegisteredCount();
            Log([NSString stringWithFormat:@"Mobile database: gradient records before=%ld", (long)count]);
            if (count < 0) return 69;
            if (!repair || count > 0) return 0;
            Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
            if (![workspaceClass respondsToSelector:@selector(defaultWorkspace)] ||
                ![workspaceClass instancesRespondToSelector:@selector(registerPlugin:)]) {
                Log(@"No registration: workspace API unavailable");
                return 69;
            }
            LSApplicationWorkspace *workspace = [workspaceClass defaultWorkspace];
            if (!workspace) return 69;
            BOOL accepted = [workspace registerPlugin:[NSURL fileURLWithPath:providerPath isDirectory:YES]];
            Log([NSString stringWithFormat:@"registerPlugin returned=%d; no trust or database-rebuild override", accepted]);
            for (unsigned attempt = 0; attempt < 10; ++attempt) {
                count = RegisteredCount();
                if (count != 0 || !accepted) break;
                usleep(200000);
            }
            Log([NSString stringWithFormat:@"Mobile database: gradient records after=%ld", (long)count]);
            return count > 0 ? 0 : 1;
        } @catch (NSException *exception) {
            Log([NSString stringWithFormat:@"Maintenance exception: %@ %@", exception.name, exception.reason]);
            return 70;
        }
    }
}
