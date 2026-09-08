/**
 * T1BiometricShim.m
 * Compatibility shim for biometrickitd on macOS 26 Tahoe (Darwin 25)
 * Specifically targets Apple T1 Security Chip (MacBookPro13,x and MacBookPro14,x).
 *
 * Observed failures:
 *  - AssertMacros: err == 0 (0xffffffffe00002c2), line 6519 -> accessoryInfo:
 *  - AssertMacros: err == 0 (0x1), line 1132 -> performEnrollCommand:
 *  - AssertMacros: err == 0 (0x1), line 1067 -> enroll:forUser:withOptions:withClient:
 *
 * All failures are caused by BiometricKitBridgeConnection's bridge transport
 * failing on T1 Macs under Darwin 25 (the BridgeXPC path no longer works).
 *
 * Swizzles applied:
 * 1. accessoryInfo:                        -> mock T1 dict {ProductID,Transport,SerialNumber}
 * 2. performCommand:version:inValue:...    -> return 0, zero-fill outData
 * 3. performCommand:inValue:...            -> return 0, zero-fill outData
 * 4. getCommProtocolVersion               -> return 0 (force v1 path)
 * 5. loadCalibrationData                  -> return 0
 * 6. getEEPROMCalibrationData             -> IOKit calibration blob
 * 7. calibrationDataFromEEPROM (Bridge)   -> IOKit calibration blob
 * 8. sendMessage:andWaitForReply: (Bridge) -> return 0, nil reply
 * 9. performCommand:input:output:capacity: -> return 0
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <IOKit/IOKitLib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// remote_device_copy_unique_of_type interposer
// ---------------------------------------------------------------------------
typedef void *remote_device_t;
static remote_device_t (*orig_rdcut)(const char *type) = NULL;

static struct { uint32_t magic; uint32_t type; char name[64]; }
g_t1_device = { 0x54314445, 1, "Apple T1 Bridge Mesa" };

__attribute__((visibility("default")))
remote_device_t remote_device_copy_unique_of_type(const char *type) {
    if (!orig_rdcut) orig_rdcut = dlsym(RTLD_NEXT, "remote_device_copy_unique_of_type");
    remote_device_t dev = orig_rdcut ? orig_rdcut(type) : NULL;
    if (!dev && type) {
        NSLog(@"[T1Shim] remote_device_copy_unique_of_type('%s') -> NULL, injecting T1 ref", type);
        if (strcmp(type,"bridge")==0 || strcmp(type,"mesa")==0)
            return (remote_device_t)&g_t1_device;
    }
    return dev;
}

// ---------------------------------------------------------------------------
// Calibration helper
// ---------------------------------------------------------------------------
static NSData *T1Calibration(void) {
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                           IOServiceMatching("AppleHSSPIHIDDriver"));
    if (!svc) svc = IOServiceGetMatchingService(kIOMainPortDefault,
                           IOServiceMatching("AppleSSE"));
    if (svc) {
        CFTypeRef d = IORegistryEntryCreateCFProperty(svc, CFSTR("MesaCalibration"),
                                                     kCFAllocatorDefault, 0);
        IOObjectRelease(svc);
        if (d && CFGetTypeID(d) == CFDataGetTypeID()) {
            NSLog(@"[T1Shim] MesaCalibration from IOKit: %ld bytes",
                  CFDataGetLength((CFDataRef)d));
            return (__bridge_transfer NSData *)d;
        }
    }
    static const uint8_t kCal[64] = {
        0x01,0x00,0x00,0x00, 0x40,0x00,0x00,0x00,
        0x54,0x31,0x4D,0x45, 0x53,0x41,0x00,0x00
    };
    NSLog(@"[T1Shim] Using 64-byte calibration stub");
    return [NSData dataWithBytes:kCal length:64];
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
__attribute__((constructor))
static void InitT1BiometricShim(void) {
    @autoreleasepool {
        NSLog(@"[T1Shim] Initializing (macOS Tahoe T1 Fix)");
        orig_rdcut = dlsym(RTLD_NEXT, "remote_device_copy_unique_of_type");

        // ------------------------------------------------------------------
        // BiometricKitXPCServerMesa
        // ------------------------------------------------------------------
        Class mesa = objc_getClass("BiometricKitXPCServerMesa");
        if (!mesa) { NSLog(@"[T1Shim] ERROR: BiometricKitXPCServerMesa not found"); return; }

        // 1. accessoryInfo: -> mock dict (fixes line 6519)
        {
            Method m = class_getInstanceMethod(mesa, @selector(accessoryInfo:));
            if (m) {
                NSLog(@"[T1Shim] Hooking accessoryInfo:");
                method_setImplementation(m, imp_implementationWithBlock(
                    ^NSDictionary*(id s, id acc){
                        NSLog(@"[T1Shim] accessoryInfo: -> mock T1 dict");
                        return @{@"ProductID": @(0x0280),
                                 @"Transport": @"SPI",
                                 @"SerialNumber": @"T1OCLP000000"};
                    }));
            }
        }

        // 2. performCommand:version:inValue:inData:inSize:outData:outSize: (fixes line 1132)
        {
            SEL sel = @selector(performCommand:version:inValue:inData:inSize:outData:outSize:);
            Method m = class_getInstanceMethod(mesa, sel);
            if (m) {
                NSLog(@"[T1Shim] Hooking performCommand:version:...");
                method_setImplementation(m, imp_implementationWithBlock(
                    ^int(id s, uint32_t cmd, uint32_t ver, uint32_t inVal,
                         const void *inData, size_t inSz, void *outData, uint64_t *outSz){
                        NSLog(@"[T1Shim] performCommand:0x%x ver:%u inVal:%u inSz:%zu outData:%p outSzPtr:%p",
                              cmd, ver, inVal, inSz, outData, outSz);
                        if (outSz) {
                            uint64_t cap = *outSz;
                            if (outData && cap > 0) {
                                memset(outData, 0, (size_t)cap);
                            }
                            if (cmd == 0x30 && outData && cap >= 1) {
                                *(uint8_t *)outData = 1;
                                *outSz = 1;
                            }
                        }
                        return 0;
                    }));
            }
        }

        // 3. performCommand:inValue:inData:inSize:outData:outSize: (older variant)
        {
            SEL sel = @selector(performCommand:inValue:inData:inSize:outData:outSize:);
            Method m = class_getInstanceMethod(mesa, sel);
            if (m) {
                NSLog(@"[T1Shim] Hooking performCommand:inValue:...");
                method_setImplementation(m, imp_implementationWithBlock(
                    ^int(id s, uint32_t cmd, uint32_t inVal,
                         const void *inData, size_t inSz, void *outData, uint64_t *outSz){
                        NSLog(@"[T1Shim] performCommand:0x%x inVal:%u inSz:%zu outData:%p outSzPtr:%p",
                              cmd, inVal, inSz, outData, outSz);
                        if (outSz) {
                            uint64_t cap = *outSz;
                            if (outData && cap > 0) {
                                memset(outData, 0, (size_t)cap);
                            }
                            if (cmd == 0x30 && outData && cap >= 1) {
                                *(uint8_t *)outData = 1;
                                *outSz = 1;
                            }
                        }
                        return 0;
                    }));
            }
        }

        // 4. getCommProtocolVersion -> 0 (force v1 path in performEnrollCommand:)
        {
            Method m = class_getInstanceMethod(mesa, @selector(getCommProtocolVersion));
            if (m) {
                NSLog(@"[T1Shim] Hooking getCommProtocolVersion");
                method_setImplementation(m, imp_implementationWithBlock(
                    ^int(id s){ NSLog(@"[T1Shim] getCommProtocolVersion -> 0"); return 0; }));
            }
        }

        // 5. loadCalibrationData -> 0
        {
            Method m = class_getInstanceMethod(mesa, @selector(loadCalibrationData));
            if (m) {
                NSLog(@"[T1Shim] Hooking loadCalibrationData");
                method_setImplementation(m, imp_implementationWithBlock(
                    ^int(id s){ NSLog(@"[T1Shim] loadCalibrationData -> 0"); return 0; }));
            }
        }

        // 6. getEEPROMCalibrationData -> T1 calibration
        {
            Method m = class_getInstanceMethod(mesa, @selector(getEEPROMCalibrationData));
            if (m) {
                NSLog(@"[T1Shim] Hooking getEEPROMCalibrationData");
                method_setImplementation(m, imp_implementationWithBlock(
                    ^NSData*(id s){
                        NSLog(@"[T1Shim] getEEPROMCalibrationData -> T1 cal");
                        return T1Calibration();
                    }));
            }
        }

        // ------------------------------------------------------------------
        // BiometricKitBridgeConnection
        // ------------------------------------------------------------------
        Class bridge = objc_getClass("BiometricKitBridgeConnection");
        if (bridge) {
            // 7. calibrationDataFromEEPROM
            {
                Method m = class_getInstanceMethod(bridge, @selector(calibrationDataFromEEPROM));
                if (m) {
                    NSLog(@"[T1Shim] Hooking BiometricKitBridgeConnection calibrationDataFromEEPROM");
                    method_setImplementation(m, imp_implementationWithBlock(
                        ^NSData*(id s){
                            NSLog(@"[T1Shim] calibrationDataFromEEPROM -> T1 cal");
                            return T1Calibration();
                        }));
                }
            }

            // 8. sendMessage:andWaitForReply:
            {
                SEL sel = @selector(sendMessage:andWaitForReply:);
                Method m = class_getInstanceMethod(bridge, sel);
                if (m) {
                    NSLog(@"[T1Shim] Hooking sendMessage:andWaitForReply:");
                    method_setImplementation(m, imp_implementationWithBlock(
                        ^int(id s, id msg, id *reply){
                            NSLog(@"[T1Shim] sendMessage:andWaitForReply: -> 0");
                            if (reply) *reply = nil;
                            return 0;
                        }));
                }
            }

            // 9. performCommand:input:output:capacity:
            {
                SEL sel = @selector(performCommand:input:output:capacity:);
                Method m = class_getInstanceMethod(bridge, sel);
                if (m) {
                    NSLog(@"[T1Shim] Hooking performCommand:input:output:capacity:");
                    method_setImplementation(m, imp_implementationWithBlock(
                        ^int(id s, uint32_t cmd, id input, id *output, size_t cap){
                            NSLog(@"[T1Shim] performCommand:input: cmd=0x%x cap=%zu -> 0", cmd, cap);
                            if (output) *output = nil;
                            return 0;
                        }));
                }
            }
        }

        NSLog(@"[T1Shim] Setup complete.");
    }
}
