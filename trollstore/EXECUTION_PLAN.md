# X-vl → TrollStore — Execution Plan (G5 → G6)

> Kế hoạch thực thi hoàn chỉnh cho phần còn lại của việc chuyển đổi ProjectXTweak
> từ rootful sang TrollStore. Phản ánh **trạng thái code thực tế đã verified**,
> không theo `HANDOFF.md` (vốn đã lệch so với code).
>
> Tiếp nối: `MIGRATION_PLAN.md`, `NEXT_PLAN.md`, `HANDOFF.md`.

---

## 0. Quyết định đã khóa

| Mục | Lựa chọn |
|---|---|
| Nguồn `TSUtil` | Copy `TSUtil.{h,m}` từ TrollStore repo (user tự thêm nội dung) |
| Mục tiêu build | Tách target TrollStore riêng — **Makefile riêng** tại `trollstore/app/Makefile` |
| Archive (G4.2) | TrollStore dùng `PXArchive` in-process; rootful vẫn dùng tar |
| Entitlements | Target TrollStore dùng `trollstore/app/entitlements.plist`; helper dùng `trollstore/helper/entitlements.plist`; CI re-sign + verify trước khi zip `.tipa` |
| G2 phân lô | 3 PR (PR-R1 → PR-R2 → PR-R3) |
| UI | Không đụng cho tới G6.3 |
| Dọn jailbreak | Để G6 |
| Makefile gốc | **Không sửa** — target mới cô lập hoàn toàn |

**Cập nhật triển khai hiện tại:** G5 đã được triển khai phần code + target
TrollStore riêng. `TSUtil` đã được strip tối giản chỉ còn `spawnRoot`, không
còn phụ thuộc `CoreServices.h`, `libroot`, Security, MobileContainerManager,
UIKit hay CoreTelephony.

---

## 1. Trạng thái khởi điểm (verified từ code)

| Thành phần | Trạng thái |
|---|---|
| `trollstore/PXFileOps.{h,m}` | Hoàn chỉnh, implementation thật (591 dòng, đủ API G1.5) |
| `trollstore/PXRootHelper.{h,m}` | Hoàn chỉnh, gate iOS 17.6, surface NSError thật |
| `trollstore/PXEntitlements.{h,m}` | Hoàn chỉnh, parser Mach-O thin+fat 32/64-bit |
| `trollstore/helper/main.m` | Hoàn chỉnh, 5 op (rm/chown/chmod/chflags/mv) + allowlist mở rộng |
| `trollstore/helper/{entitlements.plist,Makefile}` | Hoàn chỉnh |
| `trollstore/PXShellRouter.{h,m}` | `.m` đã tạo bước đầu: parser + handler core PR-R1/PR-R2 một phần |
| `trollstore/TSUtil.{h,m}` | Tối giản, chỉ expose/implement C-function `spawnRoot(...)` |
| Wiring vào codebase chính | `AppEntitlementsReader.m` đã wire `PXEntitlements`; target TS riêng đã compile-list primitives |
| `runCommandWithPrivileges:` (AppDataCleaner.m:2957) | TrollStore target dùng `PXShellRouter`; rootful target giữ `/bin/sh` qua `#ifndef PROJECTX_TROLLSTORE` |
| `AppEntitlementsReader.m` | Đã bỏ `ldid -e`, dùng `[PXEntitlements entitlementsForBinaryAtPath:error:]` |
| `trollstore/` trong build | Có target riêng `trollstore/app/Makefile` |

**Rủi ro chung lớn nhất:** wiring build cho `trollstore/` chưa từng được kiểm chứng.
G5 được chọn làm phép thử rủi-ro-thấp cho chính việc này.

---

## 2. `TSUtil` tối giản cho ProjectX

`TSUtil` từ TrollStore repo đã được strip xuống đúng nhu cầu hiện tại: chỉ cần
spawn root. `PXRootHelper.m` gọi C-function:

```objc
int spawnRoot(NSString *path, NSArray *args, NSString **stdOut, NSString **stdErr);
```

Các phần TrollStore không dùng đã bị loại bỏ: app-management, entitlement dump,
persistence helper, exploit detection, `CoreServices.h`, `libroot`, Security,
MobileContainerManager, UIKit, CoreTelephony.

---

## 3. Tiền đề chung — Dựng target TrollStore riêng

- `trollstore/app/Makefile`: `APPLICATION_NAME = ProjectXTroll`,
  compile sources gồm app `.m` cần thiết + `trollstore/*.m`, `-I./trollstore`
  + `-I` tới `common`, KHÔNG gồm `WeaponXDaemon`/`tweak.mk`/LaunchDaemon.
- `TSRootBinaries` khai báo helper trong `trollstore/app/Info.plist`.
- Helper build từ `trollstore/helper/Makefile` (đã có), copy vào app bundle root.
- Tham chiếu file `.m` từ thư mục gốc bằng đường dẫn tương đối (tránh nhân bản code).

---

## 4. G5 — Wire `PXEntitlements` (ĐÃ TRIỂN KHAI)

**Mục tiêu:** gỡ phụ thuộc `ldid -e`, đọc entitlements in-process; kiểm chứng
đường wiring build cho `trollstore/` ở quy mô 1 file.

### 4.1 Code — `AppEntitlementsReader.m` (done)
1. Đã thêm `#import "PXEntitlements.h"`.
2. Đã thay thân `fullEntitlementsForBundleID:error:`:

   ```objc
   NSError *entErr = nil;
   NSDictionary *ents = [PXEntitlements entitlementsForBinaryAtPath:binaryPath error:&entErr];
   if (!ents) { if (error) *error = entErr; return nil; }
   return ents;
   ```
3. Đã xóa path resolution `ldid`, nhánh chạy `ldid`, parse thủ công.
4. Đã xóa local `PXShellQuote` và import `CommandRunner.h` khỏi file này.

### 4.2 Build (done)
- Đã tạo `trollstore/app/Makefile` target riêng.
- Đã thêm `PXEntitlements.m`, `PXFileOps.m`, `PXRootHelper.m`, `TSUtil.m` vào target mới.
- Đã tạo `trollstore/app/Info.plist` với `TSRootBinaries = [weaponx_root_helper]`.
- **Không** đụng Makefile gốc.

### 4.3 Verify
- [x] `AppEntitlementsReader.m` sạch `ldid`/`CommandRunner`/`PXShellQuote`.
- [x] Caller downstream (`applicationGroupsForBundleID:`, `keychainAccessGroupsForBundleID:`)
  nhận `NSDictionary` đúng như cũ.
- [x] GitHub Action `.github/workflows/trollstore-build.yml` đã thêm để build riêng
  target `trollstore/app`.
- [ ] Compile pass arm64 + arm64e (chưa chạy/chưa pass trong phiên này).

---

## 5. G2 — Router `PXShellRouter` (ĐANG TRIỂN KHAI)

### 5.1 Tiền-khảo sát (read-only)
- Phân loại >100 call-site `runCommandWithPrivileges:` theo pattern.
- Đếm `2>/dev/null || true`, pipe `|`, `&&`, `;`, glob `*`, `find -exec`.
- Đọc `runCommandAndGetOutput:` (caller ~397).

### 5.2 Viết `trollstore/PXShellRouter.m`
Pipeline: tách composite (`;`/`&&`/`||`/`|`) → strip `2>/dev/null || true`
(`bestEffort=YES`, log+errno, KHÔNG silent) → argv splitter tôn trọng quote →
match `argv[0]` → handler chọn in-process (`PXFileOps`) / root (`PXRootHelper`)
theo scope → `bestEffort=NO` fail-fast surface NSError.

**Scope rule:** sandbox/Containers/tmp → in-process; `/var/root`, SpringBoard,
system Prefs → `PXRootHelper`; fallback in-process trước, `EPERM`/`EACCES` →
retry root; 4 điểm G3 → `forceRoot=YES`.

### 5.3 Ba PR
- **PR-R1** (~70%): tokenizer + argv splitter + composite parser +
  `rm`/`mkdir`/`chmod`/`chflags`/`find`; wire thân `runCommandWithPrivileges:timeoutSec:` (2957) → router.
  **Đã tạo bước đầu** trong `trollstore/PXShellRouter.m` và đã wire cho target
  `PROJECTX_TROLLSTORE`. Rootful target vẫn giữ code `/bin/sh` để tránh breaking
  Makefile gốc.
- **PR-R2** (~25%): `mv`/`cp`/`touch`/`chown`/`launchctl`/`security`.
  **Đã có bước đầu**: `mv`/`cp`/`touch`/`chown`/`launchctl`/`security`/`sync` cơ bản.
- **PR-R3** (~5%): `plutil`/`grep`/`sqlite3`/`sync` + composite parser hoàn chỉnh.
  **Đã có bước đầu**: `plutil -convert`, `grep -v ... >`, `sqlite3 DB SQL`, `sync`.

### 5.4 Build
- Đã thêm `PXShellRouter.m` + `PXFileOps.m` + `PXRootHelper.m` + `TSUtil.m`
  vào target mới.
- `-lsqlite3` cho handler sqlite3.

### 5.5 Verify mỗi PR
- Compile pass.
- Unit test qua hook `tokenizeArgv:`/`parseCompositeCommand:`.
- Smoke: clean vendor mobile-scoped, log không còn `/bin/sh`.

---

## 6. G3 — 4 điểm uid-0 (auto sau router)

Verify từng điểm route qua `PXRootHelper`, mark `forceRoot=YES`:
1. `/var/root/Library/Preferences/%@.plist` (1311, 2437, 3654) — allowlist đã có.
2. `/var/mobile/Library/SpringBoard/PushStore/%@*` (4510) — đã có.
3. `/var/mobile/Library/UsageLog/%@*` (4513) — đã có.
4. `chown -R mobile:mobile /var/mobile/Library/Mail` (1169) — op + allowlist đã có.

Test "iOS 17.6+ → `PXRootHelperErrorUnavailable`". Phụ thuộc `TSUtil` thật.

---

## 7. G4 — Backup + Restore

- **G4.1** khảo sát `AppDataBackupManager.m` (read-only): grep
  `runCommand*`/`NSTask`/`posix_spawn`/`/bin/sh`/`tar`/`gzip`; xác định cấu trúc
  bundle + restore có chown/permission.
- **G4.2** archive in-process cho TrollStore: đã thêm `trollstore/PXArchive.{h,m}`
  và wire `_tarCreate`/`_tarExtract` trong `AppDataBackupManager.m` dưới
  `PROJECTX_TROLLSTORE`. Rootful/jailbreak path vẫn dùng tar cũ. File vẫn giữ
  tên `*.tar.gz` để không phải đổi manifest/UI, nhưng backup mới từ TrollStore
  dùng format nội bộ `PXAR` thay vì tar/gzip.
- **G4.3** restore: extract uid 501 → staging; system-scoped → `PXRootHelper chown`;
  `mv` cuối (mobile in-process `rename(2)`, system → `PXRootHelper mv`, op đã có).

Phụ thuộc `TSUtil` thật.

---

## 8. G6 — Dọn dẹp + verification cuối

- **G6.1** xóa tàn dư (sau router stable 100%): `runCommandWithPrivileges:` cũ,
  `runCommandAndGetOutput:` (gate `#ifdef DEBUG` nếu còn), path resolution
  `ldid`/`/var/jb`, `keychain_backup.sh`. Vì đã tách target riêng, **không cần gỡ**
  daemon/tweak khỏi target gốc — chỉ đảm bảo target TrollStore không gồm chúng.
- **G6.2** audit grep đạt 0 (trừ comment/test): `/bin/sh`, `NSTask`,
  `posix_spawn` (trừ PXProcessKiller/PXRootHelper), `system(`, `popen(`.
- **G6.3** UI surface lỗi: chèn banner `PXRootHelperErrorUnavailable` tại VC
  gọi clean/backup — khảo sát VC trước. Đây là chỗ UI được đụng.
- **Diagnostics hiện tại**: đã thêm `PXDiagnostics` ghi log tại
  `/var/mobile/Library/ProjectXTroll/diagnostic.log`, menu tạm `Diag` trong
  `ToolViewController`, self-test environment/root-helper/router, instrumentation
  cho `PXShellRouter`, `PXRootHelper`, entitlement snapshot/check, backup start/tar
  failure và warning rõ rằng runtime hooks của `ProjectXTweak` không hoạt động
  trong TrollStore-only app.
- **G6.4** smoke test 8 scenario × 2 device.
- **G6.5** đồng bộ tài liệu: cập nhật `HANDOFF.md` (đang lệch) + `MIGRATION_PLAN.md`
  + thêm `ROUTER_REFERENCE.md`.

---

## 9. Thứ tự & phụ thuộc

```
G5 (wire PXEntitlements + dựng target mới)  ── làm ngay, không chặn
        │
   [user thêm TSUtil.{h,m} thật] ◄── chặn mọi việc root
        │
G2 PR-R1 → PR-R2 → PR-R3
        ├─► G3 (auto sau router)
        └─► G4 (libarchive + restore)
                │
G6 (cleanup + UI + verify + doc) ◄── chốt sau cùng
```

**Critical path:** G5 → [TSUtil] → G2 → G3/G4 → G6.
**Off-critical:** G5 chạy được ngay, không chờ `TSUtil`.

---

## 10. Việc trước khi execute G2

1. Chạy build target mới để bắt lỗi compile/link từ wiring G5.
2. Nếu build pass, bắt đầu G2 PR-R1 (`PXShellRouter.m` + wire `runCommandWithPrivileges:`).

---

## 11. Definition of Done

- [ ] G5: code/plist/target đã triển khai; còn cần build pass arm64 + arm64e.
- [ ] G2: router đã wire cho TrollStore target; còn cần hoàn thiện PR-R2/R3 + build/smoke test.
- [ ] G3: 4 điểm uid-0 route qua helper, test iOS 17.6+ fail-fast rõ.
- [ ] G4: backup/restore qua libarchive + helper chown/mv.
- [ ] G6.2: audit grep đạt 0 match (trừ comment/test) cho 5 truy vấn.
- [ ] G6.3: UI surface `PXRootHelperErrorUnavailable`.
- [ ] G6.4: smoke test 8 scenario × 2 device khớp bảng.
- [ ] G6.5: tài liệu đồng bộ với code.
- [ ] Helper code-signed `entitlements.plist`, khai báo `TSRootBinaries`.
- [ ] Build pass arm64 + arm64e.
- [ ] Không còn dependency runtime vào `/bin/sh`, `/usr/bin/ldid`, `/var/jb/...`.
