# CPU Dasher Injection Notes

## Target

- Bundle ID: `com.suwen.DeviceInfo`
- App name: `CPU Dasher`
- Version: `2.8.1`
- Build: `198`
- Executable: `CPUDasher`

## Final Result

CPU Dasher now works with TrollStore framework carrier injection and all hook groups enabled.

Verified sequence:

1. Framework carrier patch succeeded.
2. `ProjectXInject.dylib` loaded in the target process.
3. Marker-only mode opened successfully.
4. Objective-C hooks worked.
5. C hooks worked.
6. Network hooks worked.
7. Carrier hooks worked.
8. Device metrics hooks worked.

## Carrier Candidates

The app has an encrypted main executable, so main-binary injection is not viable.

Carrier scan found two unencrypted, linked framework candidates:

```text
index 0: Frameworks/Tquic.framework/Tquic
index 1: Frameworks/GDTMobSDK.framework/GDTMobSDK
```

Both candidates are linked from the encrypted main executable. `Tquic.framework/Tquic` was the primary tested carrier.

## Problem Observed

CPU Dasher initially appeared to exit after carrier injection, including in marker-only testing.

This was misleading because marker-only was not fully hook-free at that time. `ProjectXInject.dylib` still contained a global Mach-O interpose entry for `sysctlbyname`:

```text
__DATA,__interpose -> sysctlbyname
```

That global interpose was activated by dyld as soon as the injected dylib loaded, regardless of snapshot flags such as:

```text
EnableObjCHooks = 0
EnableCHooks = 0
EnableSysctlByNameHook = 0
```

So the old marker-only test could still affect CPU Dasher before the explicit C hook setup code ran.

## Fix Applied

The global `__interpose` block was removed from `ProjectXInject.m`.

`sysctlbyname` is now installed only through bundle-local import-table rebind:

```text
PXRebindSysctlByName()
```

This rebind only runs when the runtime snapshot enables C hooks and `EnableSysctlByNameHook` is set.

Marker-only now truly means:

```text
EnableObjCHooks = 0
EnableCHooks = 0
EnableSysctlByNameHook = 0
EnableSysctlHook = 0
EnableUnameHook = 0
EnableNetworkHook = 0
EnableCarrierHook = 0
EnableDeviceMetricsHook = 0
EnableDlsymHook = 0
EnableMobileGestaltHook = 0
```

## Diagnostics Added

An early marker was added to distinguish dylib load problems from later runtime initialization problems.

Early marker path:

```text
<target data container>/Library/ProjectX/early_marker.txt
```

Full marker path:

```text
<target data container>/Library/ProjectX/loaded_marker.plist
```

The early marker is written with C APIs at the start of the constructor, before Foundation, snapshot parsing, ObjC hooks, or C hooks.

`Injection Marker Status` now reports:

```text
targetEarlyMarkerExists
targetEarlyMarkerPath
targetMarkerExists
targetMarkerPath
injectionLoaded
injectionLoadedReason
injectionStatusNote
```

`injectionLoaded` is `YES` if any of these markers exists:

```text
global marker
target full marker
target early marker
```

Reason values:

```text
target-marker: dylib loaded and completed marker initialization
early-marker: dylib reached constructor but may not have completed marker initialization
global-marker: global marker exists but target-local marker may be unavailable
none: no marker was found
```

## Confirming Log

The successful CPU Dasher marker-only run showed:

```text
CHookTestMode = marker-only
EnableObjCHooks = 0
EnableCHooks = 0
targetEarlyMarkerExists = YES
targetMarkerExists = YES
injectionLoaded = YES
processName = CPUDasher
hookBackend = marker-only
```

This proved that carrier injection and dylib loading were working before enabling hooks.

## Clean Test Procedure

When testing CPU Dasher or a new target app, use this order:

1. Restore any previous in-place patch.
2. Scan framework carriers.
3. Patch one carrier candidate by index.
4. Apply marker-only snapshot.
5. Open the target app.
6. Check `Injection Marker Status`.
7. Enable Objective-C hooks.
8. Open the app and check marker/status again.
9. Enable C hooks.
10. Open the app and check marker/status again.
11. Enable network, carrier, and device metrics hooks one group at a time.

Do not patch candidate index 1 while index 0 remains patched. Restore first so each carrier test is clean.

## Lessons Learned

- Marker-only must not contain global interpose entries.
- Snapshot flags cannot disable Mach-O `__interpose`; dyld applies it at load time.
- Framework carrier injection should use bundle-local rebind only.
- Early marker diagnostics are useful for separating dyld/load failures from runtime hook failures.
- CPU Dasher is now a verified second target after AIDA64.
