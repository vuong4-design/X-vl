# X-vl → TrollStore — Next Phase Plan

> Tiếp nối `trollstore/HANDOFF.md`. Plan này bám sát 3 quyết định đã chốt:
> 1. **Backup + Restore đầy đủ** (cần G3 + G4.2).
> 2. **Giữ nguyên semantics anti-forensic per-vendor** (router phải translate mọi pattern shell).
> 3. **Fail-fast khi spawnRoot không khả dụng** (iOS 17.6+ → NSError rõ ràng, không silent skip).

---

## 0. Trạng thái hiện tại (xác minh từ code)

| Thành phần | Trạng thái | Tồn đọng |
|---|---|---|
| `trollstore/PXFileOps.{h,m}` | API cơ bản OK | `chmodPath:` đi theo symlink; `removeContentsOfDirectory:` chỉ filter top-level; thiếu `touch`, `chown`, glob expansion |
| `trollstore/PXRootHelper.{h,m}` | OK, gate iOS 17.6 | Hardcode tên helper `weaponx_root_helper` (khớp Makefile) |
| `trollstore/PXEntitlements.{h,m}` | Parser hoàn chỉnh | Chưa wire vào `AppEntitlementsReader.m:42` |
| `trollstore/helper/main.m` | Hỗ trợ `rm` + `chown` | Allowlist hẹp; thiếu op `chmod`, `chflags`, `mv` |
| `trollstore/helper/Makefile` | Theos OK | `TOOL_NAME = weaponx_root_helper` đồng bộ |
| Router `runCommandWithPrivileges:` (`AppDataCleaner.m:2843`, `:2957`) | Vẫn shell qua `/bin/sh` | >100 call site phụ thuộc |
| `AppDataBackupManager.m` | Chưa khảo sát | Phụ thuộc tar + chown system-scoped |

**Pattern shell phát hiện ngoài MIGRATION_PLAN §2:** `launchctl kill/stop`, `security delete-generic-password`, `touch`, `plutil -convert`, `grep -v ... > file`, `sqlite3`, `find -depth -empty -delete`, `sync`.

---

## 1. Giai đoạn 1.5 — Đóng lỗ hổng hạ tầng (BẮT BUỘC trước G2)

### 1.1 `PXFileOps` — bổ sung & sửa
- **Fix symlink traversal** trong `chmodPath:recursive:` và `clearImmutableFlagAtPath:recursive:`: dùng `fchmodat(..., AT_SYMLINK_NOFOLLOW)` qua `openat` walker, hoặc skip entry có `NSFileTypeSymbolicLink` khi enumerate.
- **API mới** (header + impl):
  - `+ (BOOL)touchPath:(NSString *)path error:(NSError **)error;`
  - `+ (BOOL)chownPath:(NSString *)path uid:(uid_t)uid gid:(gid_t)gid recursive:(BOOL)recursive error:(NSError **)error;` — trả `EPERM` để router fallback `PXRootHelper`.
  - `+ (BOOL)removeMatchingGlob:(NSString *)pattern inDirectory:(NSString *)dir error:(NSError **)error;` — handle `rm -rf 'BASE/PREFIX*'`.
  - `+ (BOOL)removePathsMatchingPredicate:(NSPredicate *)pred underRoot:(NSString *)root error:(NSError **)error;` — gói `find ... -exec rm`.
  - `+ (BOOL)removeEmptyDirectoriesUnder:(NSString *)root error:(NSError **)error;` — gói `find -depth -type d -empty -delete`.
  - `+ (void)syncFilesystem;` — wrap `sync(2)`.
- Mở rộng `removeContentsOfDirectory:keepNames:` để filter **đệ quy** (hiện chỉ top-level).

### 1.2 `PXRootHelper` + `trollstore/helper/main.m`
- **Mở rộng allowlist** `kAllowedPrefixes`:
  - `/var/mobile/Library/SpringBoard/PushStore/`
  - `/var/mobile/Library/SpringBoard/IconState.plist` (file đơn)
  - `/var/mobile/Library/WebKit/`
  - `/var/mobile/Library/Accounts/`
  - `/var/mobile/Library/UsageLog/`
  - `/var/mobile/Library/Caches/`, `Preferences/`, `Cookies/`
  - `/var/mobile/Containers/Shared/AppGroup/`
- **Op mới trong helper**:
  - `chmod <mode> <path>` (recursive flag)
  - `chflags <flags> <path>` (recursive flag)
  - `mv <src> <dst>` (rename(2)) — cần cho G4 restore vào `/var/root/`
- Verify `PXRootHelper.m` dispatch các op mới với arg validation.

### 1.3 Mini test bench (optional, khuyến cáo)
- XCTest target nhỏ chạy trên fixture trong `tmp/`:
  - `chmodPath:` không đổi mode của symlink target.
  - `removeContentsOfDirectory:keepNames:` filter đệ quy đúng.
  - `removeMatchingGlob:` không escape ra ngoài `inDirectory:`.
- Chạy tay 1 lần trước khi router gọi tới; không cần CI.

---

## 2. Giai đoạn 2 — Router `runCommandWithPrivileges:`

Đây là đòn bẩy lớn nhất: viết đúng router → >100 call site tự động được port.

### 2.1 Pipeline xử lý

```
shell string
   │
   ├─ 1. Tokenize composite: tách `;`, `&&`, `||`, `|`
   ├─ 2. Strip trailing `2>/dev/null || true` → bestEffort = YES
   ├─ 3. argv splitter tôn trọng quote `'...'` và `"..."`
   ├─ 4. Match argv[0] với handler table
   ├─ 5. Handler chọn in-process (PXFileOps) hoặc root (PXRootHelper) theo scope
   └─ 6. bestEffort=YES → log NSError qua PXLog, tiếp tục
       bestEffort=NO  → fail-fast, surface NSError lên caller
```

Vị trí: thay thân `AppDataCleaner.m:2957`. Wrapper `:2843` giữ nguyên signature.

### 2.2 Bảng handler — pattern → primitive

| Pattern shell | Primitive | Call site mẫu |
|---|---|---|
| `rm -rf 'PATH'` | `PXFileOps.removePath:` hoặc `PXRootHelper rm` | 1998, 4519 |
| `rm -rf 'PATH'/*` | `PXFileOps.removeContentsOfDirectory:keepNames:@[]` | 1121, 1289, 1333 |
| `rm -rf 'BASE/PREFIX*'` | `PXFileOps.removeMatchingGlob:inDirectory:` | 1297–1312, 2435–2438, 3654–3693, 4510–4513 |
| `mkdir -p 'A' 'B' …` | Loop `createDirectoryAtPath:withIntermediateDirectories:YES` | 4800 |
| `chmod -R MODE PATH` | `PXFileOps.chmodPath:recursive:YES` | 1415, 1542, 4474, 4777 |
| `chflags -R FLAGS PATH` | `PXFileOps.clearImmutableFlagAtPath:recursive:YES` | 1414, 1545, 2676 |
| `find PATH -mindepth 1 -maxdepth 1 -not -name X -exec rm -rf {} +` | `removeContentsOfDirectory:keepNames:` (multi-keep) | 4794 |
| `find PATH -type f -exec rm` | `removePathsMatchingPredicate:` | 4494, 4500 |
| `find PATH -depth -type d -empty -delete` | `removeEmptyDirectoriesUnder:` | 4797 |
| `mv A B` | `PXFileOps.movePath:toPath:` | (TBD trong AppDataBackupManager) |
| `cp A B` | `PXFileOps.copyPath:toPath:` | 2500, 2531, 4817 |
| `touch A B` | Loop `PXFileOps.touchPath:` | 4808 |
| `chown -R UID:GID PATH` | `PXFileOps.chownPath:…` → fallback `PXRootHelper chown` | 1169 |
| `launchctl kill\|stop LABEL` | `PXProcessKiller` (đã có) | 356–357 |
| `security delete-{generic,internet}-password -l X` | `SecItemDelete` + `kSecAttrLabel` | 2242–2243, 4507 |
| `plutil -convert xml1\|binary1 PATH` | `NSPropertyListSerialization` round-trip | 4821, 4827 |
| `grep -v PATTERN A > B` | `NSString` filter line-by-line | 4824 (IconState rewrite) |
| `sqlite3 DB "SQL"` | `sqlite3_open_v2` + `sqlite3_exec` (link `libsqlite3.tbd`) | 4736–4747 |
| `sync` | `PXFileOps.syncFilesystem` | 3327 |

### 2.3 Quy tắc chọn in-process vs root

```
path ∈ {sandbox, /var/mobile/Containers/, /tmp, /var/tmp}        → in-process
path ∈ {/var/root/, /var/mobile/Library/SpringBoard/,
        /var/mobile/Library/Preferences/com.apple.*, …}          → PXRootHelper
fallback: in-process trước; EPERM/EACCES → retry PXRootHelper
ngoại lệ: 4 path G3 → bypass thử in-process, đi thẳng PXRootHelper
```

### 2.4 Cảnh báo dịch ngữ nghĩa
- `2>/dev/null || true` **KHÔNG** dịch thành "try? ignore". Dịch thành "best-effort + log warning kèm errno". Đây là khác biệt với HANDOFF cảnh báo 2.
- `A; B; C` → tuần tự, lỗi A không chặn B.
- `A && B` → có chặn.
- `rm -rf 'PATH'/*` → glob shell, KHÔNG literal. Phải dùng `removeContentsOfDirectory:`.
- `runCommandAndGetOutput:` (`AppDataCleaner.m:3289`, gọi tại `:397`): cần đọc 380–410 để xác nhận output có path-critical không. Tạm thời có thể giữ `NSTask` nếu chỉ debug; nếu critical → thay bằng API tương ứng.

### 2.5 Phân lô PR
- **PR-R1** (handler high-volume, ~70% call site): `rm`, `mkdir`, `chmod`, `chflags`, `find`.
- **PR-R2** (~25%): `mv`, `cp`, `touch`, `chown`, `launchctl`, `security`.
- **PR-R3** (5% + edge): `plutil`, `grep`, `sqlite3`, `sync` + composite parser hoàn chỉnh.

---

## 3. Giai đoạn 3 — 4 điểm uid-0 chính

Sau khi router ổn định, 4 điểm này tự động được route qua `PXRootHelper`. Cần verify từng điểm:

1. **`/var/root/Library/Preferences/%@.plist`** — `AppDataCleaner.m:1311, 2437, 3654–3655` — `PXRootHelper rm`, allowlist `/var/root/Library/Preferences/` (đã có).
2. **`/var/mobile/Library/SpringBoard/PushStore/%@*`** — line 4510 — cần allowlist mới (G1.5.2).
3. **`/var/mobile/Library/UsageLog/%@*`** — line 4513 — cần allowlist mới (G1.5.2).
4. **`chown -R mobile:mobile /var/mobile/Library/Mail`** — line 1169 — op `chown` đã có; allowlist `/var/mobile/Library/` đã cover.

**Việc cần làm:**
- Audit từng điểm: thử in-process trên iOS test target — nếu mobile-owned path ghi được không EPERM thì skip round-trip helper.
- Test "iOS 17.6+ → `PXRootHelperErrorUnavailable` → UI hiển thị message rõ".
- Trong router, mark 4 path này `forceRoot=YES` để tránh round-trip thử in-process.

---

## 4. Giai đoạn 4 — Backup + Restore

### 4.1 Khảo sát `AppDataBackupManager.m` (chưa đọc)
Cần grep:
- `runCommand*`, `NSTask`, `posix_spawn`, `/bin/sh`, `tar`, `gzip`.
- Cấu trúc bundle: `.tar`? `.tar.gz`? plain dir?
- Restore path: có chown lại? Có set permission/flag?

### 4.2 Bundle tar/untar in-process
- Dùng `libarchive` (có sẵn trên iOS) hoặc viết tar reader tối thiểu (POSIX ustar 512-byte header).
- API mới `PXFileOps`:
  - `+ createTarArchiveAtPath:fromDirectory:error:`
  - `+ extractTarArchiveAtPath:toDirectory:preservePermissions:error:`

### 4.3 Restore workflow
1. Extract tar in-process (uid 501) vào staging dir.
2. Với entry system-scoped → `PXRootHelper chown` về uid/gid lưu trong tar header.
3. `mv` từ staging về vị trí cuối:
   - mobile-scoped → in-process `rename(2)`.
   - system-scoped → `PXRootHelper mv` (op mới ở G1.5.2).

**Quyết định cần xác nhận**: thêm op `mv` vào helper (đề xuất YES — đơn giản, `rename(2)` in-process trong helper).

---

## 5. Giai đoạn 5 — Wire `PXEntitlements`

Nhỏ, độc lập, có thể làm song song bất kỳ giai đoạn nào sau G1.5.

- Tại `AppEntitlementsReader.m:42` (lệnh `ldid -e <binary>`): thay bằng `[PXEntitlements entitlementsForBinaryAtPath:binaryPath error:&err]`.
- Verify shape output (dict plist) khớp downstream consumer — nếu reader hiện trả raw `NSData` của plist, phải convert lại để giữ contract.
- Xóa hoàn toàn nhánh `runCommandAndGetOutput:@"ldid -e ..."` + path resolution `/usr/bin/ldid` / `/var/jb/usr/bin/ldid`.
- Lợi: không phụ thuộc binary ngoài, chạy mọi iOS version (kể cả 17.6+).

---

## 6. Giai đoạn 6 — Dọn dẹp & verification cuối

### 6.1 Xóa tàn dư
- Hàm `runCommandWithPrivileges:` cũ — chỉ xóa sau khi router stable 100% (tất cả 3 PR-R merge + smoke test).
- `runCommandAndGetOutput:` — nếu caller duy nhất tại `:397` đã có thay thế in-process thì xóa; nếu còn dùng cho debug-only, đổi tên `runCommandAndGetOutput_debugOnly:` và gate `#ifdef DEBUG`.
- Path resolution helpers cho `/usr/bin/ldid`, `/var/jb/...` — không còn cần.

### 6.2 Audit grep cuối
Phải đạt 0 match cho mỗi truy vấn dưới (trừ comment và file test):

```
grep -rn "/bin/sh"        X-vl/ trollstore/
grep -rn "NSTask"         X-vl/ trollstore/
grep -rn "posix_spawn"    X-vl/ trollstore/  # ngoại trừ PXProcessKiller, PXRootHelper
grep -rn "system("        X-vl/ trollstore/
grep -rn "popen("         X-vl/ trollstore/
```

### 6.3 Smoke test trên 2 device target

| Scenario | iOS ≤ 17.5 (helper available) | iOS ≥ 17.6 (helper unavailable) |
|---|---|---|
| Clean Uber (mobile-scoped) | PASS | PASS (in-process) |
| Clean Helix (system-scoped Preferences) | PASS | FAIL rõ ràng với `PXRootHelperErrorUnavailable` — UI hiện banner |
| Backup full | PASS | PASS (đọc mobile-scoped) |
| Backup vendor có file system-scoped | PASS | PARTIAL + cảnh báo, không silent |
| Restore vào mobile-scoped | PASS | PASS |
| Restore vào `/var/root/...` | PASS | FAIL rõ ràng |
| `AppEntitlementsReader` đọc entitlements | PASS | PASS (PXEntitlements không cần root) |

### 6.4 Tài liệu
- Cập nhật `trollstore/HANDOFF.md` → đánh dấu G1.5/G2/G3/G4/G5 hoàn thành.
- Thêm `trollstore/ROUTER_REFERENCE.md` — bảng pattern→primitive (copy từ §2.2) làm reference cho dev tương lai khi thêm pattern shell mới.
- Cập nhật `trollstore/MIGRATION_PLAN.md` §2 với 8 pattern bổ sung phát hiện trong khảo sát.

---

## 7. Dependency graph & critical path

```
G1.5 (PXFileOps fix + helper allowlist + helper op mới)
   │
   ├──> G2 (router) ──┬──> G3 (4 điểm uid-0, tự động sau router)
   │                  │
   │                  └──> G4 (backup+restore, cần op mv trong helper từ G1.5)
   │
   └──> G5 (PXEntitlements wire — song song, không chặn ai)

                           G6 (cleanup + verification) ← chốt sau khi G2/G3/G4 xong
```

**Critical path**: G1.5 → G2 (PR-R1 → PR-R2 → PR-R3) → G3 verify → G4 → G6.
**Off-critical**: G5 có thể merge bất cứ lúc nào sau G1.5.

---

## 8. Ước lượng khối lượng

| Giai đoạn | Phạm vi | Mức độ |
|---|---|---|
| G1.5 | 5 API mới + 2 fix symlink + 3 op helper + 7 allowlist | Trung bình |
| G2 PR-R1 | Tokenizer + argv splitter + 5 handler core | Lớn |
| G2 PR-R2 | 6 handler bổ sung | Trung bình |
| G2 PR-R3 | 4 handler edge + composite parser hoàn chỉnh | Trung bình |
| G3 | Audit 4 điểm + force-root flag + UI error surface | Nhỏ |
| G4 | Khảo sát + tar in-process + restore workflow | Lớn |
| G5 | 1 call site swap | Rất nhỏ |
| G6 | Grep audit + 2 device smoke + 3 doc update | Nhỏ |

---

## 9. Câu hỏi cần xác nhận trước khi bắt đầu execution

1. **G1.5.2 — op `mv` trong helper**: đồng ý thêm `mv <src> <dst>` (rename(2)) vào helper để G4 restore vào `/var/root/` chạy được? Hay muốn extract-in-place qua helper với op `extract_tar`?
2. **G2.5 — phân lô PR**: chia 3 PR như đề xuất, hay gộp thành 1 PR lớn để review một lần?
3. **G4.2 — tar implementation**: dùng `libarchive` (link `-larchive`, nặng hơn nhưng đầy đủ POSIX/ustar/pax) hay viết tar reader tối thiểu (~300 LOC, chỉ ustar header, không pax extension)?
4. **G4.1 — khảo sát `AppDataBackupManager.m`**: muốn tôi delegate explore agent đọc trước file này để bổ sung chi tiết G4, hay tiến hành G1.5/G2 trước rồi quay lại G4 sau?
5. **G6.1 — `runCommandAndGetOutput:`**: cần đọc `AppDataCleaner.m:380–410` để xác nhận caller có path-critical hay không. Đồng ý tôi khảo sát điểm này trong G1.5 (cùng lúc audit allowlist) không?

---

## 10. Rủi ro & mitigation

| Rủi ro | Tác động | Mitigation |
|---|---|---|
| Composite parser bỏ sót edge case (nested quote, escape) | Một số call site silent fail | Mini test bench G1.5.3 mở rộng cho parser; log mọi command không match handler |
| Helper allowlist quá hẹp → call site G3 EPERM | Restore/clean fail trên iOS ≤ 17.5 | Audit allowlist trước khi merge G1.5; log path bị reject |
| Helper allowlist quá rộng → tăng surface attack | Compromised caller có thể xóa path nhạy cảm | Giữ nguyên nguyên tắc "ít nhất có thể"; mỗi prefix mới phải có justification trong commit message |
| `libarchive` không có trên iOS target → link fail | G4 không build | Verify `otool -L` trên 1 binary system trước khi chọn; fallback tar reader tối thiểu nếu cần |
| `2>/dev/null \|\| true` dịch sai thành silent skip | Mất visibility lỗi anti-forensic | Code review checklist: mọi bestEffort=YES phải có `PXLog` warning kèm errno |
| Symlink fix làm thay đổi behavior chmod hiện tại | Một số path target không còn được chmod | Audit grep `chmodPath:` trước khi merge; verify không có call site cố ý đi theo symlink |
| iOS 17.6+ fail-fast làm UX tệ hơn silent skip | User báo regression | Surface error rõ với gợi ý "downgrade or skip vendor X"; document trong README |

---

## 11. Định nghĩa "xong" (Definition of Done)

Plan này coi là hoàn tất khi:
- [ ] G6.2 audit grep đạt 0 match cho 5 truy vấn (trừ comment/test).
- [ ] G6.3 smoke test 8 scenario × 2 device đều có kết quả khớp bảng.
- [ ] `HANDOFF.md`, `MIGRATION_PLAN.md`, `ROUTER_REFERENCE.md` đồng bộ với code.
- [ ] Helper binary code-signed với `entitlements.plist` qua `ldid -S`, copy vào app bundle root, khai báo trong `TSRootBinaries` của Info.plist.
- [ ] Build pass `arm64` + `arm64e`, target `iphone:clang:16.5:14.0`.
- [ ] Không còn dependency runtime vào `/bin/sh`, `/usr/bin/ldid`, `/var/jb/...`.
