# No Carrier Fallback Notes

## Problem

Some App Store targets have an encrypted main executable and no obvious unencrypted framework carrier to patch.

Example target under investigation:

```text
com.benchu.ARMCPUZ
```

If the main executable is encrypted, direct main-binary injection is not viable. If no linked unencrypted bundled Mach-O exists, framework carrier injection is blocked unless another load path can be used.

## Scanner Output Added

`scanFrameworkCarriersBundleID:` now reports additional categories to explain why a target is or is not patchable:

```text
linkedFrameworkCandidates
dependencyChainCandidates
swiftRuntimeCandidates
fallbackCandidates
weakMissingLoadCandidates
extensionOnlyCandidates
rejectedCandidates
```

It also reports:

```text
selectionReason
recommendedPatchAction
recommendationReason
selectedCarrierCategory
standardLinkedEligibleCount
dependencyEligibleCount
swiftRuntimeCandidateCount
fallbackEligibleCount
rejectedCandidateCount
```

## Candidate Categories

### linked-from-main

Best case. The main executable directly loads an unencrypted app-bundled Mach-O in `Frameworks/`.

Recommended action:

```text
Patch Framework Carrier
```

### dependency-chain

Second-best case. A framework loaded by the main executable loads another app-bundled Mach-O.

Recommended action:

```text
Patch Dependency Carrier
```

This is less certain than `linked-from-main`, but usually still viable if the parent framework always loads.

### swift-runtime-linked

The only linked candidate may be a bundled Swift runtime dylib such as:

```text
libswift_Concurrency.dylib
libswift*.dylib
```

Recommended action:

```text
Patch Swift Runtime Carrier (diagnostic)
```

This is diagnostic-only and should be manually selected by index. It is not preferred automatically over app-owned framework/dylib candidates.

### fallback-unlinked

The file is an unencrypted bundled Mach-O, but the scanner cannot prove it is loaded by the main app.

Recommended action:

```text
Patch Framework Carrier can try fallback, but target may not load it
```

### weak-missing-load

The main executable has a weak non-system load command whose resolved file is missing.

This may support a future synthetic carrier approach where the missing weak framework/dylib is created inside the app bundle.

Current status:

```text
Reported only. Synthetic carrier creation is not implemented yet.
```

### extension-only

The Mach-O exists under an extension path, usually:

```text
PlugIns/*.appex/Frameworks/*
```

This does not inject into the main app unless the extension process itself is launched, so it is reported but not used as a carrier for the main executable.

### rejected

The file was found but rejected because it is encrypted, unreadable, ignored by name, or otherwise unsuitable.

## Practical Interpretation

If scan output says:

```text
mainExecutableEncrypted = YES
standardLinkedEligibleCount = 0
dependencyEligibleCount = 0
swiftRuntimeCandidateCount = 0
fallbackEligibleCount = 0
weakMissingLoadCandidates = ()
```

Then in-place framework carrier injection is blocked for that target.

Remaining options are:

1. Repack/decrypt route.
2. Future synthetic weak-load carrier if `weakMissingLoadCandidates` exists.
3. Experimental DYLD launch diagnostics.
4. Mark the app unsupported for TrollStore in-place carrier mode.

## Test Flow For `com.benchu.ARMCPUZ`

1. Select target app: `com.benchu.ARMCPUZ`.
2. Run `Scan Framework Carriers`.
3. Read `recommendedPatchAction` and `recommendationReason`.
4. If `dependencyChainCandidates` has entries, try patch by the candidate index listed in `candidates`.
5. If only `swiftRuntimeCandidates` exists, test manually by index in marker-only mode first.
6. If only `extensionOnlyCandidates` exists, do not patch for main app injection.
7. If no candidates exist and main is encrypted, treat the app as blocked for in-place carrier mode.
