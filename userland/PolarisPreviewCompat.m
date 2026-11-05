/* Scoped iOS16 preview fallback for a port without a Metal device.
 * Only PBFHomeScreenPreviewImageBuilder's snapshot method is replaced.
 * This does not advertise Metal/GPU support or suppress wallpaper errors.
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <Metal/Metal.h>
#import <objc/runtime.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

static IMP originalPreview;
static unsigned int loggedPreviews;

static void PreviewLog(NSString *message)
{
    @autoreleasepool {
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:
            @"Library/Caches/PolarisPreviewCompat.log"];
        NSData *data = [[message stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
        NSFileHandle *file = [NSFileHandle fileHandleForWritingAtPath:path];
        if (file) {
            [file seekToEndOfFile];
            [file writeData:data];
            [file closeFile];
        } else {
            [data writeToFile:path atomically:YES];
        }
    }
}

static UIImage *CPUHomeScreenPreview(id object, SEL selector, UIView *view)
{
    if (MTLCreateSystemDefaultDevice() != nil && originalPreview != NULL) {
        return ((UIImage *(*)(id, SEL, UIView *))originalPreview)(object, selector, view);
    }
    if (![view respondsToSelector:@selector(layer)]) {
        PreviewLog(@"CPU preview failed: argument has no layer");
        return nil;
    }
    CALayer *layer = view.layer;
    CGRect bounds = layer.bounds;
    CGFloat scale = layer.contentsScale;
    if (!isfinite(scale) || scale <= 0) scale = 1;
    double width = ceil(bounds.size.width * scale);
    double height = ceil(bounds.size.height * scale);
    if (!isfinite(width) || !isfinite(height) || width < 1 || height < 1 ||
        width > 8192 || height > 8192 || width * height > 33554432) {
        PreviewLog(@"CPU preview failed: invalid bitmap geometry");
        return nil;
    }
    UIImage *result = nil;
    BOOL began = NO;
    @try {
        /* iOS16's bitmap context avoids the unavailable Metal texture,
         * command queue and CARenderer rendererWithMTLTexture path. */
        UIGraphicsBeginImageContextWithOptions(bounds.size, NO, scale);
        began = YES;
        CGContextRef context = UIGraphicsGetCurrentContext();
        if (context != NULL) {
            CGContextTranslateCTM(context, -bounds.origin.x, -bounds.origin.y);
            [layer renderInContext:context];
            result = UIGraphicsGetImageFromCurrentImageContext();
        }
        if (loggedPreviews++ < 16) {
            PreviewLog([NSString stringWithFormat:@"CPU preview %@ %.0fx%.0f",
                result != nil ? @"created" : @"failed", width, height]);
        }
    } @catch (NSException *exception) {
        PreviewLog([NSString stringWithFormat:@"CPU preview exception: %@ %@",
            exception.name, exception.reason]);
    } @finally {
        if (began) UIGraphicsEndImageContext();
    }
    return result;
}

__attribute__((constructor)) static void InstallPreviewFallback(void)
{
    const char *program = getprogname();
    if (program == NULL || strcmp(program, "PosterBoard") != 0) return;
    @autoreleasepool {
        Class builder = objc_getClass("PBFHomeScreenPreviewImageBuilder");
        Method method = builder ? class_getInstanceMethod(builder, sel_registerName("_imageForView:")) : NULL;
        if (method == NULL) {
            PreviewLog(@"Fallback NOT installed: expected iOS16 method missing");
            return;
        }
        originalPreview = method_getImplementation(method);
        method_setImplementation(method, (IMP)CPUHomeScreenPreview);
        PreviewLog(@"Scoped PBFHomeScreenPreviewImageBuilder CPU fallback installed");
    }
}
