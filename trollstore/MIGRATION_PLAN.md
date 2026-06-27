# Kế hoạch chuyển đổi X-vl (WeaponX) sang TrollStore

> Chiến lược: **Lai (Hybrid)** — in-process trước, `spawnRoot` chỉ khi thật sự cần uid 0.
> Quyết định đã chốt: **bundle `tar`** (ghép với chown uid-0 ở Giai đoạn 3) và **parse `LC_CODE_SIGNATURE` in-process** cho việc đọc entitlements (thay `ldid -e`).

---

## Nguyên tắc kiến trúc

Một quy tắc xuyên suốt: **in-process trước, `spawnRoot` chỉ khi thật sự cần uid 0**. Mọi thao tác trên path `mobile`-owned (`/var/mobile/...`, container app khác cùng uid, `/tmp`) viết lại bằng `NSFileManager`/POSIX. Chỉ 4 điểm thật sự cần root đi qua helper bundled. Mọi fallback phải **báo lỗi thật**, không nuốt lỗi im lặng (`2>/dev/null || true`).

## Phạm vi

**Trong phạm vi:** module backup / clean / keychain dữ liệu (app self-contained chạy uid 501 + no-sandbox).

**Ngoài phạm vi (không port được):**
- Toàn bộ `ProjectXTweak/*.x` (~25 hook file tiêm vào app khác — không có substrate dưới TrollStore).
- `WeaponXMountDaemon` + Guardian (không cài LaunchDaemon thật).

Đây là rào cản kiến trúc tuyệt đối; kế hoạch này không cố vượt.

---

## Giai đoạn 1 — Hạ tầng nền tảng

### 1.1. Lớp `PXFileOps` (thay shell file-ops)

Category/lớp tiện ích in-process thay mọi thao tác file đang shell qua `/bin/sh`:

| Thao tác shell hiện tại | Thay bằng |
|---|---|
| `rm -rf` | `removeItemAtPath:` + enumerate cho wildcard |
| `mkdir -p` | `createDirectoryAtPath:withIntermediateDirectories:` |
| `mv` | `moveItemAtPath:` |
| `cp` | `copyItemAtPath:` |
| `chmod` | `chmod(2)` / `setAttributes:` |
| `chflags -R nouchg` | `chflags(2)` đệ quy |
| `find ... -exec rm` | `findPathsUnderRoot:` (đã native) + remove |

Mỗi hàm trả `NSError` thật. Đây là điểm sửa **mối nguy thất bại âm thầm**.

### 1.2. Lớp `PXRootHelper` (spawnRoot wrapper)

Bọc `TSUtil spawnRoot:` với:
- Phát hiện khả dụng (iOS ≤ 17.0 và `spawnRoot` thành công).
- Trả mã lỗi rõ ràng khi thất bại (17.6+).
- API: `runAsRoot:(NSArray *)argv error:(NSError **)` trả exit code + stdout/stderr.

### 1.3. Helper bundled + `TSRootBinaries`

- Theos helper project riêng, entitlements: `com.apple.private.persona-mgmt`, `platform-application`, `com.apple.private.security.no-sandbox`.
- Ký `ldid -Sentitlements.plist`.
- Khai báo `TSRootBinaries` trong `Info.plist` app chính.
- Helper đa năng nhận argv (`rm`, `chown`) phục vụ 4 điểm uid-0.

---

## Giai đoạn 2 — Migrate file-ops (đa số, no-sandbox)

Thay tất cả call site sang `PXFileOps`. Cụ thể `AppDataCleaner.m`:

- **Container scrub:** 1085, 1088, 1092, 1121, 1130–1142, 1289, 1333 → enumerate + remove + create.
- **Mail reset:** 1166 (`mv`), 1168 (`mkdir`), 1171–1174 (rm prefs mobile).
- **Prefs/caches:** 1297–1312, 2435–2438 (mobile + `/private/var/mobile`).
- **Flags/perms:** 1414–1419, 1510–1556, 1913–1998, 2676–2686.
- **Container metadata:** 2500, 2531 (`cp`).
- **`find` còn sót:** 1092, 1130, 1140, 2613 → `findPathsUnderRoot:`.

`runCommandAndGetOutput:` (397) và nhánh không-filesystem (`launchctl` 356/357, `security delete-generic-password` 2242/2243) → gộp vào keychain bridge hoặc native.

---

## Giai đoạn 3 — 4 điểm uid-0 qua spawnRoot

Chỉ những điểm này đi qua `PXRootHelper`; mỗi điểm **thử in-process trước, fallback spawnRoot, lỗi rõ nếu cả hai fail**:

| File:line | Thao tác | Chiến lược |
|---|---|---|
| `AppDataCleaner.m:1311` | `rm /var/root/...plist` | spawnRoot (root-owned) |
| `AppDataCleaner.m:2437` | `rm /var/root/...*` | spawnRoot (root-owned) |
| `AppDataBackupManager.m:2107` | `chown` global Safari | spawnRoot (system-scoped) |
| `AppDataBackupManager.m:2154` | `chown` system lib item | spawnRoot (system-scoped) |

**Conditional** (`1169`, `2027`, `2064`, `2212`, `2272`, `2305`): thử `chown(2)` in-process trước; chỉ rơi xuống spawnRoot nếu `EPERM`.

---

## Giai đoạn 4 — Binary ngoài

### 4.1. Đọc entitlements — parse `LC_CODE_SIGNATURE` in-process (ĐÃ CHỐT)

Thay `ldid -e` (`AppEntitlementsReader.m:42`) bằng parser Mach-O in-process:
- Đọc `LC_CODE_SIGNATURE` → `CSMAGIC_EMBEDDED_ENTITLEMENTS`.
- Không cần root, không phụ thuộc iOS version, chạy cả 17.6+.

### 4.2. `tar` create/extract — bundle tar (ĐÃ CHỐT)

- Bundle `gtar`/`bsdtar` tĩnh, `posix_spawn` trực tiếp (bỏ `/bin/sh`).
- Create chạy uid 501. Extract `--numeric-owner` ghép với chown uid-0 ở Giai đoạn 3.

### 4.3. Process kill (`PXProcessKiller.m:95–143`)

`PXKillallByName` → resolve PID từ `sysctl KERN_PROC_ALL` (đã có ở `PXProcessIsRunning` 145–198) + `kill(2)` trực tiếp. Xóa phụ thuộc `killall`. Không cần uid 0.

### 4.4. Respring (`BottomButtons.m`)

`sbreload`/`ldrestart` → ưu tiên `FBSSystemService` (đã có 433–444). Bundle binary chỉ làm fallback cuối.

---

## Giai đoạn 5 — Dọn dẹp tàn dư jailbreak

- Bỏ resolution `keychain_backup.sh` (`543–545, 1362–1364, 2354–2356`) — in-app bridge đã thay thế.
- Thêm nhánh TrollStore-aware vào `common/PXRoot.m`: thay vì degrade về rootful `""`, resolve về container app (`NSHomeDirectory()`).
- Rút gọn `ent.plist` xuống tập TrollStore thực ký được.
- Bỏ logic re-sign động (`AppDataCleaner.m:707–847`) — helper ký sẵn lúc build.

---

## Đã sẵn sàng (không cần đụng)

- Lớp SQLite C-API (`AppDataCleaner.m:43–257`).
- `findPathsUnderRoot:` (`2848–2955`).
- `PXProcessIsRunning` / `PXWaitForProcessesToExit` (sysctl).
- **Toàn bộ keychain bridge** cả hai phía — đã TrollStore-native.
- `/tmp` staging trong backup manager.

---

## Hai cảnh báo giữ nguyên hiệu lực

1. **Keychain bridge chỉ hoạt động khi app đích nhúng responder.** Với app bên thứ ba bất kỳ không có responder → timeout (30s nếu app mở, 6s nếu không).
2. **Pattern thất bại âm thầm là mối nguy lớn nhất.** Toàn bộ điểm migrate phải trả `NSError` thật để phân biệt "không làm gì" với "thành công".

---

## Thứ tự thực thi

1. **Giai đoạn 1** (hạ tầng `PXFileOps` + `PXRootHelper` + helper bundled).
2. **Giai đoạn 2** (migrate file-ops no-sandbox) — phần lớn breakage, không phụ thuộc root.
3. **Giai đoạn 4.1** (parse entitlements in-process) — gỡ phụ thuộc `ldid`, chạy mọi iOS version.
4. **Giai đoạn 3** (4 điểm uid-0) — sau khi `PXRootHelper` đã kiểm chứng.
5. **Giai đoạn 4.2–4.4 + Giai đoạn 5** (binary ngoài còn lại + dọn dẹp).

Lý do: Giai đoạn 2 và 4.1 gỡ phần lớn breakage **không** phụ thuộc `spawnRoot`, giữ giá trị kể cả trên iOS 17.6+ nơi `spawnRoot` chết. Giai đoạn 3 đặt sau cùng vì mong manh nhất theo phiên bản iOS.
