# Framework Carrier Injection Notes

## Result

Carrier injection for the App Store AIDA64 target is now root-side verified.

CPU Dasher (`com.suwen.DeviceInfo`) was also verified after removing global `sysctlbyname` interpose and switching to bundle-local rebind. See `CPU_DASHER_NOTES.md` for the full issue record and test sequence.

For apps where carrier scan finds no patchable file, see `NO_CARRIER_FALLBACK_NOTES.md`. The scanner now reports fallback categories such as dependency-chain, Swift runtime, weak missing loads, extension-only, and rejected candidates.

Verified from `diagnostic (9).log`:

- `targetDylibExists = YES`
- `signBundledDylib.status = ldid-signed`
- `signTargetDylib.status = ldid-signed`
- `installedCarrierHasLoadCommand = YES`
- `rootInstalledCarrierContainsLoadPathAfterToolCopy.ok = YES`
- `rootTargetDylibInfoAfterChown.ok = YES`
- Carrier owner restored to `uid=33 gid=33`
- Inject dylib owner restored to `uid=33 gid=33`

Selected carrier:

```text
/private/var/containers/Bundle/Application/322D1548-4B8B-459C-8B22-41161790C931/AIDA64_c3.app/Frameworks/FirebaseCore.framework/FirebaseCore
```

Injected load path:

```text
@executable_path/Frameworks/ProjectXInject.dylib
```

## Problems Hit

1. App Store main executable is encrypted.

   AIDA64 main executable has `cryptid = 1`. TrollStore/CoreTrust rejects patched encrypted main binaries, so direct main executable injection is not viable.

2. DYLD launch path was killed.

   The experimental `DYLD_INSERT_LIBRARIES` route spawned the target but it died with `SIGKILL 9`, and no marker was written.

3. Initial installed-bundle writes were ineffective.

   Helper operations like `cpfile`, `installfile`, and `overwritefile` returned success, but root-side `fileinfo` and `contains` still showed the original installed carrier or missing dylib.

4. Device had no system `cp`.

   `toolcpfile` originally failed with `cp not found` because `/bin/cp` and `/usr/bin/cp` were unavailable.

5. Bundled `cp-15` missed `libiosexec.1.dylib`.

   `cp-15` failed to launch until `libiosexec.1.dylib` and related support dylibs were bundled into `ProjectXTroll.app/Tools`.

6. Bundled `cp` was too new for the device.

   `cp` failed with missing `_mkfifoat` from `libSystem.B.dylib`, so the helper now prefers `cp-15` over `cp`.

7. `cp-15` was denied by AppBundles policy.

   Even with root persona, `cp-15` could not create/remove files in another installed app bundle until helper entitlements included AppBundles/container/storage permissions.

8. Helper entitlements were too minimal.

   Because bundled tools are spawned by `weaponx_root_helper`, they inherit helper entitlements, not only the main app entitlements.

## Fixes Applied

1. Switched App Store encrypted app strategy to framework carrier injection.

   The patcher scans `Frameworks/`, picks an unencrypted Mach-O linked from the encrypted main executable, and inserts `LC_LOAD_DYLIB` there instead of touching the encrypted main executable.

2. Added bundled tools under `trollstore/tools/`.

   Required tools include `cp`, `cp-15`, `mv`, `mv-15`, `rm`, `ldid`, `ct_bypass`, `insert_dylib`, `install_name_tool`, and dylib dependencies such as `libiosexec.1.dylib`.

3. Updated build staging.

   The TrollStore app build and GitHub Action copy optional tools and `.dylib` dependencies into `ProjectXTroll.app/Tools` and sign them.

4. Updated tool lookup.

   `weaponx_root_helper` now searches `ProjectXTroll.app/Tools` before system paths.

5. Preferred `cp-15` over `cp`.

   This avoids `_mkfifoat` incompatibility on the tested iOS 16.x device.

6. Spawned bundled tools with root persona.

   Tool subprocesses are spawned with persona override uid/gid `0` and `DISABLE_TWEAKS=1`.

7. Expanded helper entitlements.

   Added storage/container/AppBundles entitlements to `trollstore/helper/entitlements.plist`, matching the permissions needed by child tools that mutate installed app bundles.

8. Added root-side verification.

   Diagnostics now prefer root-side `fileinfo` and `contains` checks, since app-side bundle view can be stale.

## Next Step

Launch AIDA64 and verify runtime injection by checking:

```text
Diag -> Injection Marker Status
```

Expected marker paths:

```text
<AIDA64 data container>/Library/ProjectX/loaded_marker.plist
/var/mobile/Library/ProjectXTroll/InjectionLogs/com.finalwire.aida64.loaded.plist
```

If marker exists, expand `ProjectXInject.dylib` beyond the initial Objective-C hooks.

## If Target Exits On Launch

After the first verified carrier patch, AIDA64 exited immediately on launch. The patch itself was root-side verified, so the next suspects are dyld/AMFI/CoreTrust validation or code running inside the dylib constructor.

Mitigations added:

- `ct_bypass` helper op applies `ct_bypass -r -i <binary> -t <teamID>` to patched carrier and injected dylib after signing/copying.
- `ProjectXInject` now writes its loaded marker before installing hooks.
- Objective-C hooks are disabled by default unless the runtime snapshot contains `EnableObjCHooks = YES`.
- Default runtime mode is marker-only, which separates load/signing failures from hook implementation crashes.

Validation sequence:

1. Patch carrier again with the new build.
2. Launch AIDA64.
3. Open `Diag -> Injection Marker Status`.
4. If `markerExists = YES`, runtime loading works; enable hooks gradually.
5. If AIDA64 still exits before marker appears, collect a crash log and inspect dyld/AMFI/CoreTrust messages.
