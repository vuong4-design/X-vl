# Handoff — TrollStore migration & code cleanup

Tài liệu chuyển giao trạng thái công việc giữa chừng cho agent kế tiếp.

---

## 1. Bối cảnh dự án

Repo gốc (`X-vl` / WeaponX / ProjectX) là một **bộ tweak jailbreak rootful/rootless/roothide** gồm:
- App `ProjectX.app` (UI)
- Tweak MobileSubstrate `ProjectXTweak.dylib` tiêm vào UIKit apps
- Tweak `WeaponXKeychainBridge.dylib`
- Root daemon `WeaponXDaemon` (LaunchDaemon)
- CLI helper `backup_helper`, `ProjectXCLI`

Mục tiêu ban đầu: **chuyển sang TrollStore** (ký entitlements tùy ý, không jailbreak).

Xem `trollstore/MIGRATION_PLAN.md` để có phân tích đầy đủ + đánh giá khả thi.

---

## 2. Quyết định đã chốt

- **Chiến lược Lai (Hybrid)**: in-process trước, `spawnRoot` chỉ cho thao tác thật sự cần uid 0.
- **Bundle `tar`** (thay vì libarchive in-process) — ghép với chown uid-0 ở Giai đoạn 3.
- **Parse `LC_CODE_SIGNATURE` in-process** thay `ldid -e`.
- **Router tại primitive**: viết lại `runCommandWithPrivileges:timeoutSec:` thành router định tuyến sang `PXFileOps`/`PXRootHelper` (chưa thực hiện — xem mục 5).
- **Bỏ port các tính năng anti-forensic per-vendor** (đặc biệt `clearAppIssuesForIOS15:` và các hardcoded path Uber/Lyft/Helix/Zimride/DoorDash/Grubhub).

---

## 3. Đã hoàn thành

### 3.1. Bộ khung Giai đoạn 1 trong `trollstore/`

| File | Trạng thái | Mô tả |
|---|---|---|
| `MIGRATION_PLAN.md` | Done | Kế hoạch chi tiết Giai đoạn 1–5 |
| `TSUtil.h` | Done | Stub khai báo `spawnRoot:args:stdOut:stdErr:` (link với TrollStore source thật lúc build) |
| `PXRootHelper.{h,m}` | Done | Wrapper `spawnRoot` + phát hiện iOS ≤ 17.6 + báo lỗi thật |
| `PXFileOps.{h,m}` | Done | File ops in-process: rm, mkdir, mv, cp, chmod, chflags (NSError thật, không nuốt lỗi) |
| `PXEntitlements.{h,m}` | Done | Parser Mach-O `LC_CODE_SIGNATURE` → `CSMAGIC_EMBEDDED_ENTITLEMENTS` (thin + fat, 32/64-bit, swap) |
| `helper/main.m` | Done | Root helper bundled: rm + chown recursive với allowlist path |
| `helper/entitlements.plist` | Done | `com.apple.private.persona-mgmt`, `platform-application`, `no-sandbox` |
| `helper/Makefile` | Done | Theos tool.mk + ldid -S entitlements |

### 3.2. Dọn dẹp code-quality trong `AppDataCleaner.m`

- **Xóa 3 hàm chết** (không có call site nào trong codebase):
  - `cleanAppSpecificFilesInSharedContainer:` — 5718-trở đi
  - `deepCleanSystemSharedContainer:` — chứa hardcoded UUID + per-vendor logic (Maps/Lyft group/Uber group)
  - `cleanDatabaseFile:` — SQL injection: interpolation `bundleID`/`appName`/`companyName` trực tiếp vào `sqlite3 "DELETE FROM ... LIKE '%@%'"`
  - Tổng cộng xóa **316 dòng** (file từ 6402 → 6086 dòng)
- **Xóa 4 dòng commented-out hỏng** (lines 6000–6003 cũ — string literal sai cú pháp)

### 3.3. Audit đã thực hiện (chưa sửa)

- Toàn bộ `AppDataCleaner.m` (6086 dòng sau xóa)
- `AppEntitlementsReader.m`, `AppDataBackupManager.m`, `CommandRunner.m`, `common/PXProcessKiller.m`, `common/PXRoot.m`, `WeaponXKeychainBridge/Tweak.m`, `WeaponXMountDaemon/WeaponXDaemon.m`, các `ProjectXTweak/*.x`
- Báo cáo phân loại A/B/C/D quyền + danh sách file:line các call site shell

### 5.1. Router tại primitive (KHỞI ĐỘNG nhưng chưa code)
- Viết lại `runCommandWithPrivileges:timeoutSec:` (AppDataCleaner.m hiện tại quanh ~2950) thành router:
  - Parse các mẫu shell đã biết (rm/mkdir/mv/cp/chmod/chflags/find-rm)
  - Định tuyến sang `PXFileOps`
  - 4 điểm uid-0 (mục 4.3) → `PXRootHelper`
  - Fallback `/bin/sh` báo lỗi RÕ khi thiếu (không `2>/dev/null || true`)
- Lý do dừng: trước khi viết router, phát hiện code chứa anti-forensic per-vendor (mục 4) — quyết định không port toàn bộ. Router vẫn có ích cho phần backup/clean container hợp lệ nhưng cần thu hẹp scope trước.

### 5.2. `runCommandAndGetOutput:` (AppDataCleaner.m:3289 trước khi xóa, đã dịch)
- Cần xử lý tương tự: nếu `/bin/sh` thiếu → trả nil + log lỗi rõ

### 5.3. `PXKillallByName` → `kill(2)` in-process
- File: `common/PXProcessKiller.m:95-143`
- `PXProcessIsRunning` (145-198) đã enumerate qua `sysctl KERN_PROC_ALL`
- Resolve PID từ cùng bảng `kinfo_proc` + `kill(2)` trực tiếp → xóa phụ thuộc `killall` binary

### 5.4. Bundle tar binary
- Nhúng `gtar` hoặc `bsdtar` tĩnh vào app bundle
- `posix_spawn` trực tiếp (bỏ `/bin/sh`)
- Tùy chọn cho `_tarCreate:`/`_tarExtract:` ở `AppDataBackupManager.m:1079-1092`

### 5.5. Thay `ldid -e` bằng `PXEntitlements` (đã có sẵn)
- File: `AppEntitlementsReader.m:26-79`
- Thay invocation `ldid -e <binary>` bằng `[PXEntitlements entitlementsForBinaryAtPath:error:]`
- Lợi: không phụ thuộc ldid, chạy mọi iOS version (kể cả 17.6+)

### 5.6. PXRoot.m TrollStore-aware
- File: `common/PXRoot.m`
- Hiện degrade về rootful `""` → path hệ thống bị chặn
- Thêm nhánh detect TrollStore: resolve về container app (`NSHomeDirectory()`)

### 5.7. Hardening `PXFileOps`
- `chmodPath:recursive:` dùng `chmod(2)` đi theo symlink → đổi `fchmodat(AT_SYMLINK_NOFOLLOW)` cho cây có symlink
- `removeContentsOfDirectory:keepNames:` chỉ filter top-level → xem có cần đệ quy không tùy use case
- Thêm unit test

---

## 6. Lưu ý cho agent kế tiếp

1. **`AppDataBackupManager.m` chưa được đọc/sửa kỹ** — vùng này là backup chính, có thể giữ phần lớn nếu user xác nhận chỉ làm backup
2. **In-app keychain bridge đã TrollStore-native** (cả 2 phía `AppDataBackupManager.m` + `WeaponXKeychainBridge/Tweak.m`) — không cần đụng
3. **Toàn bộ `ProjectXTweak/*.x` (~25 hook file)** — không port được dưới TrollStore thuần (không có Substrate). Không cố vượt.
4. **`WeaponXMountDaemon` + Guardian** — không cài LaunchDaemon được. Bỏ hoàn toàn hoặc thay bằng `BGTaskScheduler` trong app.
5. **User đã chốt iOS scope: chiến lược Lai** — chấp nhận `spawnRoot` chỉ chạy ≤ iOS 17.6, fallback báo lỗi rõ trên 17.6+

---

## 7. Cấu trúc `trollstore/` hiện tại

```
trollstore/
├── MIGRATION_PLAN.md      # Kế hoạch G1-G5
├── HANDOFF.md             # File này
├── TSUtil.h               # Stub spawnRoot
├── PXRootHelper.{h,m}     # Wrapper spawnRoot + iOS check
├── PXFileOps.{h,m}        # File ops in-process, NSError thật
├── PXEntitlements.{h,m}   # Parser LC_CODE_SIGNATURE
└── helper/
    ├── main.m             # Root helper bundled (rm + chown + allowlist)
    ├── entitlements.plist # persona-mgmt + platform-application + no-sandbox
    └── Makefile           # Theos tool.mk + ldid -S
```

---

## 8. Tóm tắt vị trí dừng

- **Giai đoạn 1 (hạ tầng)**: Hoàn tất.
- **Giai đoạn 2 (migrate file-ops)**: Dừng trước khi viết router. Lý do: phát hiện code anti-forensic per-vendor, cần user xác nhận scope.
- **Giai đoạn 3 (4 điểm uid-0)**: Chưa khởi động.
- **Giai đoạn 4 (binary ngoài)**: Chưa khởi động (PXEntitlements đã viết nhưng chưa wire vào AppEntitlementsReader).
- **Giai đoạn 5 (dọn dẹp tàn dư jailbreak)**: Chưa khởi động.
