# SỔ TAY VẬN HÀNH & TRIỂN KHAI PRODUCTION (`RUNBOOK.md`)

**Dự án:** `DA-ResourceLimiter` (`v1.0.4.1`)  
**Repository:** https://github.com/shostwp-byte/da-resourcelimiter  

---

## 1. YÊU CẦU TIÊN QUYẾT TRÊN MÁY CHỦ DIRECTADMIN

1. **Hệ điều hành:** Debian 12, AlmaLinux 8/9, Rocky Linux 8/9, hoặc Ubuntu 22.04/24.04 LTS (`amd64` / `arm64`).
2. **Linux Cgroups v2 (Unified Hierarchy):**
   * Kiểm tra nhanh:
     ```bash
     ls -l /sys/fs/cgroup/cgroup.controllers
     ```
   * Nếu chưa có file này (máy chủ đang chạy Cgroups v1 cũ), bật Cgroups v2 như sau rồi reboot vào khung giờ bảo trì:
     * **AlmaLinux / Rocky 8 & 9:**
       ```bash
       grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=1"
       reboot
       ```
     * **Ubuntu 22.04 / 24.04:** Thêm `systemd.unified_cgroup_hierarchy=1` vào `GRUB_CMDLINE_LINUX` trong `/etc/default/grub`, chạy `update-grub && reboot`.
3. **Database Engine:** Khuyến nghị **MariaDB 10.6 hoặc 10.11 LTS** (tối thiểu MariaDB 10.5 để có cột `MEMORY_USED` trong `information_schema.PROCESSLIST`).

---

## 2. CÀI ĐẶT XÁC THỰC THEO TAG TRÊN MÁY CHỦ MỚI

### Trường hợp A: Repository ở chế độ Public (Ghim Tag + Kiểm tra SHA-256)
Chạy lệnh sau dưới quyền `root`:
```bash
VER="v1.0.4.1"
ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
TMP_DIR="$(mktemp -d /tmp/da-limiter.XXXXXX)" && chmod 0700 "$TMP_DIR"
curl -fsSL "https://github.com/shostwp-byte/da-resourcelimiter/releases/download/${VER}/checksums.txt" -o "${TMP_DIR}/checksums.txt"
curl -fsSL "https://github.com/shostwp-byte/da-resourcelimiter/releases/download/${VER}/da-resource-limiter-linux-${ARCH}.tar.gz" -o "${TMP_DIR}/da-resource-limiter-linux-${ARCH}.tar.gz"
(cd "$TMP_DIR" && grep " da-resource-limiter-linux-${ARCH}\.tar\.gz$" checksums.txt | sha256sum -c -)
tar -xzf "${TMP_DIR}/da-resource-limiter-linux-${ARCH}.tar.gz" -C "$TMP_DIR"
"${TMP_DIR}/da-resource-limiter/scripts/install.sh"
rm -rf "$TMP_DIR"
```

### Trường hợp B: Repository ở chế độ Private (Bảo vệ `GITHUB_TOKEN` qua `curl -K -` stdin)
1. Trên GitHub, vào **Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Chọn Repository access: **Only select repositories** → `shostwp-byte/da-resourcelimiter`.
3. Mục **Repository permissions** → cấp duy nhất quyền **Contents: Read-only**.
4. Truyền header xác thực qua `stdin` (`curl -K -`) để **không bao giờ lộ Token** trong `ps aux` hay `/proc/<pid>/cmdline`:
   ```bash
   export GITHUB_TOKEN="github_pat_XXXXXXXXXXXXXXXXXXXX"
   export TARGET_VERSION="v1.0.4.1"
   TMP_INST="$(mktemp /tmp/da-install.XXXXXX.sh)" && chmod 0700 "$TMP_INST"
   printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN" | \
     curl -fsSL -K - "https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/${TARGET_VERSION}/scripts/install.sh" -o "$TMP_INST"
   "$TMP_INST"
   rm -f "$TMP_INST"
   ```

### Lưu ý nâng cao về dải UID & PHP-FPM Worker Classification
* Mặc định daemon quản lý các tài khoản Hosting có `1000 <= UID <= 65533` (hỗ trợ cả các máy chủ di chuyển từ CloudLinux/LVE có UID `>= 60000`, đồng thời chặn cứng `nobody=65534` và tài khoản `admin`). Nếu máy chủ dùng dải UID đặc thù, có thể khai báo `Environment="DA_LIMITER_MIN_UID=..."` / `Environment="DA_LIMITER_MAX_UID=..."` trong override của systemd.
* Bộ phân loại `Classifier` đối chiếu cả tên tiến trình, `UID` thực và thời điểm khởi tạo tiến trình (`starttime` trong `/proc/<pid>/stat`) ngay trước khi ghi vào `cgroup.procs`. Khi dịch vụ `php-fpmXX` thực hiện `reload`/`restart`, các worker mới sinh ra sẽ được đưa trở lại `user-<UID>.slice/da-php.scope` trong chu kỳ quét kế tiếp (`<= 1s`).

### Kiểm tra tối ưu `/etc/my.cnf` (Tầng 1 MariaDB)
```bash
da-resourced audit-mycnf
```
Nếu có thông số `MISSING`, bổ sung đoạn cấu hình gợi ý vào nhóm `[mysqld]` trong `/etc/my.cnf` và khởi động lại `mariadb` vào khung giờ thấp điểm.

---

## 3. QUY TRÌNH KÝ SỐ ED25519 & CẬP NHẬT TỪ GITHUB RELEASES

### 3.1. Cấu hình Khoá ký số Release (`RELEASE_SIGNING_PRIVATE_KEY`)
Từ phiên bản `v1.0.4.1`, daemon nhúng sẵn khoá công khai Ed25519 trong `internal/version/version.go` (`DefaultReleasePublicKeyHex`) và bắt buộc xác thực tệp chữ ký rời `checksums.txt.sig` trước khi cho phép cập nhật tự động:
1. Vào GitHub Repository → **Settings → Secrets and variables → Actions → New repository secret**:
   * **Name:** `RELEASE_SIGNING_PRIVATE_KEY`
   * **Secret:** Chuỗi hex khoá bí mật Ed25519 tương ứng với `DefaultReleasePublicKeyHex`.
2. Bật **Tag protection rules** cho mẫu `v*` trên GitHub để chỉ Maintainer mới được đẩy tag phát hành.
3. Khi phát hành bản mới (cập nhật đồng bộ số phiên bản tại `plugin/plugin.conf` và `internal/version/version.go` trên nhánh `main`):
   ```bash
   git tag -a v1.0.5 -m "DA-ResourceLimiter v1.0.5"
   git push origin main --tags
   ```
   Workflow `.github/workflows/release.yml` sẽ tự động kiểm tra commit thuộc nhánh `main`, chạy `gofmt`, `staticcheck`, `go test -race`, `shellcheck`, biên dịch đa kiến trúc, ký số `checksums.txt.sig` bằng Ed25519 và xuất bản Release.

### 3.2. Cập nhật trên máy chủ DirectAdmin
Để ngăn chặn leo thang đặc quyền từ các tài khoản quản trị phụ trong `admin.list`, các hành động cập nhật/khôi phục hệ thống và đổi cấu hình Updater chỉ cho phép thực thi bởi `root` hoặc `diradmin`:
```bash
# Kiểm tra bản mới:
da-resourced check-update

# Cập nhật hoặc thay đổi GitHub Token an toàn qua stdin:
printf '%s' 'github_pat_XXXX' | da-resourced config-updater --token-stdin --channel stable

# Tải về, xác thực chữ ký Ed25519 + SHA-256, tạo Snapshot và cập nhật nguyên tử:
da-resourced update

# Hoặc khôi phục bản sao lưu gần nhất bất cứ lúc nào:
da-resourced rollback
```

---

## 4. THAM CHIẾU LỆNH VẬN HÀNH CLI (`da-resourced`)

| Lệnh CLI | Chức năng kỹ thuật |
| :--- | :--- |
| `da-resourced ping` | Kiểm tra nhanh sức khoẻ Daemon và thời gian Uptime qua Unix Socket. |
| `da-resourced stats` | Xem bảng CPU %, Physical RAM, số tiến trình, MySQL RAM/Conns và Penalty của toàn bộ User. |
| `da-resourced stats <user> --json` | Xuất thông số chi tiết dạng JSON của riêng 1 tài khoản Hosting. |
| `da-resourced apply <user>` | Đồng bộ lại tức thời Cgroup Slice, thông số PHP và giới hạn MariaDB cho `<user>`. |
| `da-resourced apply-all` | Đồng bộ gộp lô toàn bộ tài khoản Hosting và dọn các `50-da-limits.conf` mồ côi. |
| `da-resourced apply-package <pkg>` | Đồng bộ lại mọi User thuộc gói `<pkg>` (bỏ qua các VIP user bật `CUSTOM_OVERRIDE=yes`). |
| `da-resourced unblock <user>` | Gỡ trạng thái phạt MySQL Penalty Box ngay lập tức cho `<user>`. |
| `da-resourced audit-mycnf` | Kiểm tra cấu hình `/etc/my.cnf` theo khuyến nghị Lớp 1. |
| `da-resourced check-update` | Kiểm tra phiên bản mới nhất trên GitHub Releases. |
| `da-resourced config-updater` | Cập nhật `/etc/da-resourced/updater.conf` (`0600`) dưới quyền `root`. |
| `da-resourced update` | Tải về, xác thực Ed25519 + SHA-256 và cập nhật nguyên tử kèm Auto-Rollback. |
| `da-resourced rollback` | Khôi phục ngay bản Snapshot Backup gần nhất. |
| `da-resourced verify <file> [sig]` | Kiểm tra chữ ký số Ed25519 của `checksums.txt`. |

---

## 5. KIỂM THỬ NGHIỆM THU & XỬ LÝ SỰ CỐ (TROUBLESHOOTING)

### 5.1. Chạy bộ kiểm tra nghiệm thu tự động trên máy chủ
```bash
/usr/local/directadmin/plugins/da_resource_limiter/scripts/qa_verify.sh preflight
/usr/local/directadmin/plugins/da_resource_limiter/scripts/qa_verify.sh benchmark 15
/usr/local/directadmin/plugins/da_resource_limiter/scripts/qa_verify.sh verify-user <ten_user_test>
```

### 5.2. Các tình huống thường gặp
1. **Giao diện Admin báo `DAEMON OFFLINE`:**
   * Kiểm tra dịch vụ: `systemctl status da-resourced` và `journalctl -u da-resourced -n 50 --no-pager`.
   * Đảm bảo socket `/var/run/da-resourced.sock` đang tồn tại và tài khoản quản trị đăng nhập nằm trong `/usr/local/directadmin/data/admin/admin.list`.
2. **Khách hàng phản ánh lỗi kết nối MySQL (`User ... has exceeded the 'max_user_connections' resource`):**
   * Mở **Tab 1 / Tab 3** kiểm tra nhãn **Penalty Throttled** và **Tab 4 (Violation Logs)** lọc theo Username để lấy câu lệnh SQL gây nghẽn.
   * Gỡ phạt ngay sau khi tối ưu: bấm **Unblock Penalty** hoặc chạy `da-resourced unblock <username>`.
3. **Gỡ cài đặt hoàn toàn khỏi máy chủ:**
   ```bash
   /usr/local/directadmin/plugins/da_resource_limiter/scripts/uninstall.sh
   /usr/local/directadmin/plugins/da_resource_limiter/scripts/uninstall.sh --purge-data
   ```
