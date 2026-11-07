<div align="center">
  <img src="./plugin/images/admin_icon.svg" alt="DA Resource Limiter" width="72" height="72" />
  <h1>DA-ResourceLimiter</h1>
  <p><strong>Hệ thống Cô lập và Giới hạn Tài nguyên Đa tầng cho DirectAdmin (Không cần CloudLinux)</strong></p>
  <p>
    <a href="https://github.com/shostwp-byte/da-resourcelimiter/actions/workflows/ci.yml"><img src="https://github.com/shostwp-byte/da-resourcelimiter/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
    <a href="https://github.com/shostwp-byte/da-resourcelimiter/releases/latest"><img src="https://img.shields.io/github/v/release/shostwp-byte/da-resourcelimiter?label=release" alt="Latest Release" /></a>
    <img src="https://img.shields.io/badge/Go-1.22%2B%20Static%20Binary-00ADD8" alt="Go 1.22+" />
    <img src="https://img.shields.io/badge/Linux-Cgroups%20v2-FCC624" alt="Cgroups v2" />
  </p>
</div>

---

**DA-ResourceLimiter** là giải pháp quản trị tài nguyên gốc (Native Linux Daemon + DirectAdmin Evolution Plugin) viết bằng **Golang thuần (`CGO_ENABLED=0`, không phụ thuộc thư viện ngoài)**, kết hợp **Linux Cgroups v2**, **PHP-FPM / OpenLiteSpeed LSPHP PID Classifier**, **MariaDB 3-Tier Governor** và **GitHub Releases Self-Updater xác thực chữ ký số Ed25519 + SHA-256**.

## Yêu cầu Hệ thống

- **Hệ điều hành:** Debian 12, Ubuntu 22.04 / 24.04, AlmaLinux 8 / 9, Rocky Linux 8 / 9 (`x86_64` / `amd64` & `arm64`) đã bật **Cgroups v2 Unified Hierarchy** (`/sys/fs/cgroup/cgroup.controllers`).
- **Control Panel:** DirectAdmin (tương thích đầy đủ **Evolution Skin** widescreen ở cả chế độ *Icons Grid* & *Sidebar*, hỗ trợ đa tài khoản Admin trong `admin.list`).
- **Cơ sở dữ liệu:** MariaDB 10.5+ (hỗ trợ cột `MEMORY_USED` trong `information_schema.PROCESSLIST`).

---

## Cài đặt Xác thực theo Tag Phát hành (`v1.0.4.2`)

Chạy dưới quyền `root` trên máy chủ DirectAdmin. Để đảm bảo an toàn chuỗi cung ứng (tránh thực thi trực tiếp script chưa kiểm chứng từ nhánh `main` và không làm lộ `GITHUB_TOKEN` trong `/proc/<pid>/cmdline`), hãy tải gói phát hành đã ghim tag, xác thực chữ ký số **Ed25519** (`checksums.txt.sig`) + `SHA-256` trước khi giải nén và cài đặt:

```bash
# 1. Cài đặt từ Public GitHub Release (ghim tag v1.0.4.2 & xác thực Ed25519 + SHA-256 trước khi giải nén):
VER="v1.0.4.2"
ARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
TMP_DIR="$(mktemp -d /tmp/da-limiter.XXXXXX)" && chmod 0700 "$TMP_DIR"
curl -fsSL "https://github.com/shostwp-byte/da-resourcelimiter/releases/download/${VER}/checksums.txt" -o "${TMP_DIR}/checksums.txt"
curl -fsSL "https://github.com/shostwp-byte/da-resourcelimiter/releases/download/${VER}/checksums.txt.sig" -o "${TMP_DIR}/checksums.txt.sig"
curl -fsSL "https://github.com/shostwp-byte/da-resourcelimiter/releases/download/${VER}/da-resource-limiter-linux-${ARCH}.tar.gz" -o "${TMP_DIR}/da-resource-limiter-linux-${ARCH}.tar.gz"
(cd "$TMP_DIR" && grep " da-resource-limiter-linux-${ARCH}\.tar\.gz$" checksums.txt | sha256sum -c -)
tar -xzf "${TMP_DIR}/da-resource-limiter-linux-${ARCH}.tar.gz" -C "$TMP_DIR"
"${TMP_DIR}/da-resource-limiter/bin/da-resourced" verify "${TMP_DIR}/checksums.txt" "${TMP_DIR}/checksums.txt.sig"
"${TMP_DIR}/da-resource-limiter/scripts/install.sh"
rm -rf "$TMP_DIR"
```

```bash
# 2. Cài đặt từ Private GitHub Repository (truyền GITHUB_TOKEN qua stdin `curl -K -`, tự xác thực Ed25519 trước khi giải nén):
export GITHUB_TOKEN="github_pat_XXXXXXXXXXXXXXXXXXXX"
export TARGET_VERSION="v1.0.4.2"
TMP_INST="$(mktemp /tmp/da-install.XXXXXX.sh)" && chmod 0700 "$TMP_INST"
printf 'header = "Authorization: Bearer %s"\n' "$GITHUB_TOKEN" | \
  curl -fsSL -K - "https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/${TARGET_VERSION}/scripts/install.sh" -o "$TMP_INST"
"$TMP_INST"
rm -f "$TMP_INST"
```

Sau khi cài đặt hoàn tất:
- **Giao diện Quản trị (Admin Level):** `/CMD_PLUGINS_ADMIN/da_resource_limiter` — gồm 5 Tab:
  1. *Realtime Monitor* (theo dõi trực tiếp CPU, RAM vật lý, tiến trình, MySQL RAM/Conns và gỡ phạt nhanh).
  2. *Package Limits* (cấu hình mặc định `default.conf` và giới hạn theo từng gói Hosting Package).
  3. *User Overrides* (cấp giới hạn riêng cho tài khoản VIP/Custom, được bảo vệ không bị ghi đè khi đồng bộ Package).
  4. *Violation & OOM Logs* (nhật ký Kernel OOM Kill, truy vấn SQL ngốn RAM/chậm bị ngắt và lịch sử Penalty Box).
  5. *System & GitHub Update* (kiểm tra phiên bản mới, hiển thị trạng thái ghim repo & chữ ký số Ed25519).
- **Giao diện Khách hàng (User Level):** `/CMD_PLUGINS/da_resource_limiter` — hiển thị trực quan mức sử dụng CPU / RAM / Processes / MySQL thực tế và Top 5 truy vấn SQL bị ngắt để khách hàng chủ động tối ưu mã nguồn.

---

## Kiến trúc Bảo vệ Đa tầng

1. **Cô lập Cứng CPU, RAM & Chống Fork Bomb (Linux Cgroups v2):**
   - Quản lý nguyên tử `/etc/systemd/system/user-<UID>.slice.d/50-da-limits.conf` (`CPUQuota`, `CPUWeight`, `MemoryHigh`, `MemoryMax`, `MemorySwapMax=0M`, `IOWeight`, `TasksMax`) và tự động dọn dẹp drop-in mồ côi khi tài khoản Hosting bị xoá.
   - Đọc sự kiện chạm ngưỡng bóp mềm và tràn bộ nhớ trực tiếp từ `memory.events` (`high`, `oom_kill`) ở goroutine độc lập.
2. **Đưa PHP-FPM & OpenLiteSpeed LSPHP vào Cgroup của User (`da-php.scope`):**
   - Quét và di chuyển tức thời các worker `php-fpm` / `lsphp` sang `/sys/fs/cgroup/user.slice/user-<UID>.slice/da-php.scope` có mutex đồng bộ và kiểm tra chống tái sử dụng PID (`starttime` trong `/proc/<pid>/stat`).
   - Chặn cứng việc gom nhầm tài khoản hệ thống (`root`, `diradmin`, `admin`, `nobody=65534`; dải mặc định `1000 <= UID <= 65533`, cấu hình được qua `DA_LIMITER_MIN_UID` / `DA_LIMITER_MAX_UID`).
   - Đồng bộ biến `DA_PHP_MAX_CHILDREN` và `DA_PHP_MEM_LIMIT` vào `user.conf` với khoá file `flock` và bảo toàn quyền sở hữu `diradmin:diradmin` (`0600`).
3. **MariaDB 3-Tier Governor & Penalty Box:**
   - **Lớp 1:** Kiểm toán bộ đệm per-thread `/etc/my.cnf` (`da-resourced audit-mycnf`).
   - **Lớp 2:** Đồng bộ gộp lô chia trang (`Chunked Batch ALTER USER --force`) `MAX_USER_CONNECTIONS` và `MAX_STATEMENT_TIME` an toàn qua `--defaults-extra-file` (`0600`).
   - **Lớp 3:** Watchdog độc lập `1.5s` đọc `MEMORY_USED` trên `information_schema.PROCESSLIST` (tính các kết nối đang thực thi truy vấn `Command IN ('Query', 'Execute')`), ánh xạ chủ sở hữu theo *Longest-Prefix Match*, tự động `KILL QUERY` vượt ngưỡng và đưa tài khoản vi phạm lặp lại vào **Penalty Box**.
4. **Dual Unix Socket, `SO_PEERCRED` Pre-Decode & Chống CSRF:**
   - **Admin Socket (`/var/run/da-resourced.sock`):** Kiểm tra `SO_PEERCRED` ngay trước khi giải mã JSON, giới hạn kết nối đồng thời, kết hợp kiểm tra `Origin`/`Referer`/`Sec-Fetch-Site` (hỗ trợ proxy qua `DA_LIMITER_ALLOWED_HOSTS` / `/etc/da-resourced/web.conf`) và mã HMAC `csrf_token` theo UID thực (`/proc/self/status`) trên `admin/api.php`.
   - **User Socket (`/var/run/da-resourced-user.sock`):** Giới hạn kết nối đồng thời + tần suất theo từng UID, đọc ngược file JSONL theo khối 32 KB dừng sớm tại mốc 24h và khoá chặt mỗi tài khoản chỉ đọc được dữ liệu của chính UID đang gọi.
5. **Cập nhật Nguyên tử Ký số Ed25519 từ GitHub Releases:**
   - Ghim cứng repository cập nhật chính thức (nếu dùng mirror riêng cần khai báo `ALLOW_CUSTOM_REPO=yes` trong `/etc/da-resourced/updater.conf` và vẫn bắt buộc khớp khoá ký số), xác thực chữ ký **Ed25519** (`checksums.txt.sig`) + **SHA-256** + đối chiếu phiên bản `manifest.json`/`plugin.conf` chống phát lại gói cũ, khoá chặt quyền thực thi cập nhật cho `root` CLI (`UID 0`), tạo Snapshot Backup tại `/var/backups/da-resource-limiter/`, bảo toàn `plugin/data/` và tự động **Rollback** (cả khi lỗi giữa chừng hoặc lỗi healthcheck).

---

## Lệnh Vận hành CLI (`da-resourced`) & Cập nhật / Gỡ bỏ

| Lệnh CLI | Mô tả |
| :--- | :--- |
| `da-resourced ping` | Kiểm tra trạng thái hoạt động, phiên bản và Uptime của Daemon qua Unix Socket. |
| `da-resourced stats` | Bảng theo dõi nhanh CPU %, RAM, Processes, MySQL RAM/Conns và Penalty của toàn bộ User. |
| `da-resourced stats <user> --json` | Xuất thông số thời gian thực chi tiết dạng JSON cho 1 tài khoản Hosting. |
| `da-resourced apply <user>` | Áp dụng tức thời Cgroup Slice, PHP tokens và giới hạn MariaDB cho `<user>`. |
| `da-resourced apply-all` | Đồng bộ gộp lô giới hạn cho toàn bộ tài khoản Hosting và dọn slice mồ côi. |
| `da-resourced apply-package <pkg>` | Đồng bộ mọi User thuộc gói `<pkg>` (tự động giữ nguyên các VIP user bật `CUSTOM_OVERRIDE=yes`). |
| `da-resourced unblock <user>` | Gỡ trạng thái phạt MySQL Penalty Box ngay lập tức cho `<user>`. |
| `da-resourced audit-mycnf` | Kiểm tra thông số bộ nhớ `/etc/my.cnf` theo khuyến nghị Lớp 1. |
| `da-resourced check-update` | Kiểm tra phiên bản mới nhất trên GitHub Releases. |
| `da-resourced config-updater` | Cấu hình kênh phát hành / `GITHUB_TOKEN` (`--token-stdin`) dưới quyền `root`. |
| `da-resourced update` | Tải gói phát hành mới, xác thực chữ ký Ed25519 + SHA-256 và cập nhật nguyên tử kèm Auto-Rollback. |
| `da-resourced rollback` | Khôi phục ngay lập tức về bản Snapshot Backup gần nhất. |
| `da-resourced verify <file> [sig]` | Xác thực chữ ký số Ed25519 rời (`checksums.txt.sig`) bằng khoá công khai nhúng sẵn. |

### Gỡ cài đặt an toàn

```bash
# Gỡ Daemon, Cgroup Slices, giới hạn MySQL & Hooks (tự động sao lưu cấu hình data/ vào /var/backups/da-resource-limiter/):
/usr/local/directadmin/plugins/da_resource_limiter/scripts/uninstall.sh

# Gỡ sạch hoàn toàn bao gồm cả lịch sử log và cấu hình:
/usr/local/directadmin/plugins/da_resource_limiter/scripts/uninstall.sh --purge-data
```

---

## Cấu trúc Thư mục Dự án

```text
DA-ResourceLimiter/
├── cmd/da-resourced/       # Entrypoint CLI, Ed25519 Sign/Verify & Systemd Multi-Goroutine Daemon
├── internal/
│   ├── cgroup/             # Quản lý Systemd user-<UID>.slice, da-php.scope & dọn slice mồ côi
│   ├── config/             # Lưu trữ phân cấp default/package/user, validate Penalty & ghim Repo
│   ├── dausers/            # Đồng bộ tài khoản DirectAdmin (1000..65533) & Longest-Prefix DB mapping
│   ├── engine/             # Điều phối trung tâm, Batch Sync nền & phân quyền root/diradmin/admin
│   ├── fpm/                # Quét /proc di chuyển PHP-FPM/lsphp (Mutex + PID starttime) & flock user.conf
│   ├── ipc/                # Dual Unix Domain Socket (Semaphore + Per-UID Rate Limit + Pre-Decode Auth)
│   ├── logger/             # Nhật ký vi phạm JSONL xoay vòng & đọc ngược cuối file 32 KB
│   ├── mysqlgov/           # MariaDB 3-Tier Governor (5s Timeout, Batch ALTER, Ownership Guard)
│   ├── updater/            # GitHub Releases Updater (Ed25519 + SHA-256, Concurrency Lock, Tar-Slip Safe)
│   └── version/            # Phiên bản, Repository ghim mặc định & Ed25519 Public Key nhúng sẵn
├── plugin/                 # Giao diện DirectAdmin Plugin (admin/, user/, hooks/, images/, templates/)
├── scripts/                # install.sh, update.sh, uninstall.sh, qa_verify.sh & da_hooks/
├── systemd/                # Cấu hình dịch vụ da-resourced.service đã bật Systemd Hardening
└── docs/RUNBOOK.md         # Sổ tay triển khai, ký số phát hành, nghiệm thu & vận hành chi tiết
```

---

## Tài liệu Dự án

- [Sổ Tay Vận Hành & Triển Khai (`docs/RUNBOOK.md`)](./docs/RUNBOOK.md)
- [Kế Hoạch Phát Triển Từng Giai Đoạn & Cơ Chế GitHub Update (v1.1)](./plan/Kế%20Hoạch%20Phát%20Triển%20Từng%20Giai%20Đoạn%20&%20Cơ%20Chế%20GitHub%20Update.md)
- [Đặc Tả Kỹ Thuật gốc (v1.0)](./plan/Đặc%20Tả%20Kỹ%20Thuật%20&%20Kế%20Hoạch%20Phát%20Triển%20Plugin%20Giới%20Hạn%20Tài%20Nguyên_directadmin.md)
