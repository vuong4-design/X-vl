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
| Tar (G4.2) | `libarchive` |
| G2 phân lô | 3 PR (PR-R1 → PR-R2 → PR-R3) |
| UI | Không đụng cho tới G6.3 |
| Dọn jailbreak | Để G6 |
| Makefile gốc | **Không sửa** — target mới cô lập hoàn toàn |

---

## 1. Trạng thái khởi điểm (verified từ code)

| Thành phần | Trạng thái |
|---|---|
| `trollstore/PXFileOps.{h,m}` | Hoàn chỉnh, implementation thật (591 dòng, đủ API G1.5) |
| `trollstore/PXRootHelper.{h,m}` | Hoàn chỉnh, gate iOS 17.6, surface NSError thật |
| `trollstore/PXEntitlements.{h,m}` | Hoàn chỉnh, parser Mach-O thin+fat 32/64-bit |
| `trollstore/helper/main.m` | Hoàn chỉnh, 5 op (rm/chown/chmod/chflags/mv) + allowlist mở rộng |
| `trollstore/helper/{entitlements.plist,Makefile}` | Hoàn chỉnh |
| `trollstore/PXShellRouter.h` | **Chỉ interface, thiếu `.m`** |
| `trollstore/TSUtil.h` | **Stub** — chờ user thay bản thật |
| Wiring vào codebase chính | **Zero** — không file `trollstore/` nào được compile/link |
| `runCommandWithPrivileges:` (AppDataCleaner.m:2957) | Vẫn `posix_spawn /bin/sh` |
| `AppEntitlementsReader.m:42` | Vẫn `ldid -e` shell |
| `trollstore/` trong build | Ngoài build hoàn toàn |

**Rủi ro chung lớn nhất:** wiring build cho `trollstore/` chưa từng được kiểm chứng.
G5 được chọn làm phép thử rủi-ro-thấp cho chính việc này.

---

## 2. Đường dẫn cần thêm `TSUtil`

| File | Vị trí | Ghi chú |
|---|---|---|
| `TSUtil.h` | `trollstore/TSUtil.h` | Đã tồn tại dạng stub — thay nội dung bằng bản thật, giữ nguyên đường dẫn |
| `TSUtil.m` | `trollstore/TSUtil.m` | File mới cần thêm |

`PXRootHelper.m` gọi:

```objc
+ (int)spawnRoot:(NSString *)path
            args:(NSArray<NSString *> *)args
          stdOut:(NSString * _Nullable * _Nullable)stdOut
          stdErr:(NSString * _Nullable * _Nullable)stdErr;
```

Bản thật phải khớp signature này. Nếu repo dùng dạng C-function, cần điều chỉnh
`PXRootHelper.m` cho khớp lúc execute.

---

## 3. Tiền đề chung — Dựng target TrollStore riêng

- Tạo `trollstore/app/Makefile`: `APPLICATION_NAME` riêng (vd `ProjectXTroll`),
  compile sources gồm app `.m` cần thiết + `trollstore/*.m`, `-I./trollstore`
  + `-I` tới `common`, KHÔNG gồm `WeaponXDaemon`/`tweak.mk`/LaunchDaemon.
- `TSRootBinaries` khai báo helper trong `Info.plist` của target này.
- Helper build từ `trollstore/helper/Makefile` (đã có), copy vào app bundle root.
- Tham chiếu file `.m` từ thư mục gốc bằng đường dẫn tương đối (tránh nhân bản code).

---

## 4. G5 — Wire `PXEntitlements` (phép thử wiring, rủi ro thấp)

**Mục tiêu:** gỡ phụ thuộc `ldid -e`, đọc entitlements in-process; kiểm chứng
đường wiring build cho `trollstore/` ở quy mô 1 file.

### 4.1 Code — `AppEntitlementsReader.m`
1. Thêm `#import "PXEntitlements.h"`.
2. Thay thân `fullEntitlementsForBundleID:error:` (dòng 25-79):

   ```objc
   NSError *entErr = nil;
   NSDictionary *ents = [PXEntitlements entitlementsForBinaryAtPath:binaryPath error:&entErr];
   if (!ents) { if (error) *error = entErr; return nil; }
   return ents;
   ```
3. Xóa path resolution `ldid` (25-31) + nhánh chạy `ldid` (33-52) + parse thủ công (54-77).
4. Grep trong file: xóa `PXShellQuote` (12-16) và import `CommandRunner.h` (4)
   **nếu** không còn caller khác.

### 4.2 Build
- Thêm `PXEntitlements.m` + `-I./trollstore` vào `trollstore/app/Makefile` (target mới).
- **Không** đụng Makefile gốc.

### 4.3 Verify
- Compile pass arm64 + arm64e.
- `AppEntitlementsReader.m` sạch `ldid`.
- Caller downstream (`applicationGroupsForBundleID:`, `keychainAccessGroupsForBundleID:`)
  nhận `NSDictionary` đúng như cũ.

---

## 5. G2 — Router `PXShellRouter` (cần `TSUtil` thật trước)

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
- **PR-R2** (~25%): `mv`/`cp`/`touch`/`chown`/`launchctl`/`security`.
- **PR-R3** (~5%): `plutil`/`grep`/`sqlite3`/`sync` + composite parser hoàn chỉnh.

### 5.4 Build
- Thêm `PXShellRouter.m` + `PXFileOps.m` + `PXRootHelper.m` + `TSUtil.m`
  vào target mới (sau khi `TSUtil` thật có mặt).
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
- **G4.2** tar in-process bằng **`libarchive`**: API mới `PXFileOps`
  `createTarArchiveAtPath:fromDirectory:` + `extractTarArchiveAtPath:toDirectory:preservePermissions:`.
  Link `-larchive`; verify `otool -L` libarchive có trên target trước khi khóa.
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

## 10. Việc của user trước khi execute G2

1. Đặt `TSUtil.h` (thay stub) + `TSUtil.m` (mới) vào `trollstore/` — đường dẫn ở §2.
   Xác nhận signature `spawnRoot:args:stdOut:stdErr:` khớp `PXRootHelper.m`;
   nếu lệch, báo để chỉnh khi execute.

---

## 11. Definition of Done

- [ ] G5: build pass, `AppEntitlementsReader.m` sạch `ldid`, target mới compile `trollstore/`.
- [ ] G2: 3 PR merge, router thay `runCommandWithPrivileges:`, log không còn `/bin/sh`.
- [ ] G3: 4 điểm uid-0 route qua helper, test iOS 17.6+ fail-fast rõ.
- [ ] G4: backup/restore qua libarchive + helper chown/mv.
- [ ] G6.2: audit grep đạt 0 match (trừ comment/test) cho 5 truy vấn.
- [ ] G6.3: UI surface `PXRootHelperErrorUnavailable`.
- [ ] G6.4: smoke test 8 scenario × 2 device khớp bảng.
- [ ] G6.5: tài liệu đồng bộ với code.
- [ ] Helper code-signed `entitlements.plist`, khai báo `TSRootBinaries`.
- [ ] Build pass arm64 + arm64e.
- [ ] Không còn dependency runtime vào `/bin/sh`, `/usr/bin/ldid`, `/var/jb/...`.
