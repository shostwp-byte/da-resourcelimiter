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

**DA-ResourceLimiter** là giải pháp quản trị tài nguyên gốc (Native Linux Daemon + DirectAdmin Evolution Plugin) viết bằng **Golang thuần (`CGO_ENABLED=0`, không phụ thuộc thư viện ngoài)**, kết hợp **Linux Cgroups v2**, **PHP-FPM / OpenLiteSpeed LSPHP PID Classifier**, **MariaDB 3-Tier Governor** và **GitHub Releases Self-Updater**.

## Yêu cầu Hệ thống

- **Hệ điều hành:** Debian 12, Ubuntu 22.04 / 24.04, AlmaLinux 8 / 9, Rocky Linux 8 / 9 (`x86_64` / `amd64` & `arm64`) đã bật **Cgroups v2 Unified Hierarchy** (`/sys/fs/cgroup/cgroup.controllers`).
- **Control Panel:** DirectAdmin (tương thích đầy đủ **Evolution Skin** ở cả chế độ *Icons Grid* & *Sidebar*, hỗ trợ đa tài khoản Admin trong `admin.list`).
- **Cơ sở dữ liệu:** MariaDB 10.5+ (hỗ trợ cột `MEMORY_USED` trong `information_schema.PROCESSLIST`).

---

## Cài đặt Nhanh 1-Click (DirectAdmin Production)

Chạy dưới quyền `root` trên máy chủ DirectAdmin:

```bash
# 1. Cài đặt từ Public GitHub Repository:
curl -fsSL https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/main/scripts/install.sh | bash

# 2. Cài đặt từ Private GitHub Repository (với Read-only Fine-Grained Token):
export GITHUB_TOKEN="github_pat_XXXXXXXXXXXXXXXXXXXX"
bash -c "$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/main/scripts/install.sh)"
```

Sau khi cài đặt hoàn tất:
- **Giao diện Quản trị (Admin Level):** `/CMD_PLUGINS_ADMIN/da_resource_limiter` — gồm 5 Tab:
  1. *Realtime Monitor* (theo dõi trực tiếp CPU, RAM vật lý, tiến trình, MySQL RAM/Conns và gỡ phạt nhanh).
  2. *Package Limits* (cấu hình mặc định `default.conf` và giới hạn theo từng gói Hosting Package).
  3. *User Overrides* (cấp giới hạn riêng cho tài khoản VIP/Custom, được bảo vệ không bị ghi đè khi đồng bộ Package).
  4. *Violation & OOM Logs* (nhật ký Kernel OOM Kill, truy vấn SQL ngốn RAM/chậm bị ngắt và lịch sử Penalty Box).
  5. *System & GitHub Update* (cấu hình Public/Private Token, kiểm tra bản mới, cập nhật 1-Click & khôi phục Snapshot).
- **Giao diện Khách hàng (User Level):** `/CMD_PLUGINS/da_resource_limiter` — hiển thị trực quan mức sử dụng CPU / RAM / Processes / MySQL thực tế và Top 5 truy vấn SQL bị ngắt để khách hàng chủ động tối ưu mã nguồn.

---

## Kiến trúc Bảo vệ Đa tầng

1. **Cô lập Cứng CPU, RAM & Chống Fork Bomb (Linux Cgroups v2):**
   - Quản lý tự động `/etc/systemd/system/user-<UID>.slice.d/50-da-limits.conf` (`CPUQuota`, `CPUWeight`, `MemoryHigh`, `MemoryMax`, `MemorySwapMax=0M`, `IOWeight`, `TasksMax`).
   - Đọc sự kiện chạm ngưỡng bóp mềm và tràn bộ nhớ trực tiếp từ `memory.events` (`high`, `oom_kill`) với chi phí CPU gần bằng 0.
2. **Đưa PHP-FPM & OpenLiteSpeed LSPHP vào Cgroup của User (`da-php.scope`):**
   - Quét và di chuyển tức thời các worker `php-fpm` / `lsphp` của khách hàng từ `system.slice` sang `/sys/fs/cgroup/user.slice/user-<UID>.slice/da-php.scope` (tuân thủ *No Internal Process Constraint* của Cgroups v2).
   - Chặn cứng việc gom nhầm tài khoản hệ thống (`root`, `diradmin`, `admin`, `nobody=65534`, dải hợp lệ `1000 <= UID <= 59999`).
   - Đồng bộ biến `DA_PHP_MAX_CHILDREN` và `DA_PHP_MEM_LIMIT` vào `user.conf` nhưng luôn bảo toàn nghiêm ngặt quyền sở hữu `diradmin:diradmin` (`0600`) của DirectAdmin.
3. **MariaDB 3-Tier Governor & Penalty Box:**
   - **Lớp 1:** Kiểm toán bộ đệm per-thread `/etc/my.cnf` (`da-resourced audit-mycnf`).
   - **Lớp 2:** Đồng bộ `ALTER USER ... WITH MAX_USER_CONNECTIONS ... MAX_STATEMENT_TIME ...` an toàn qua `--defaults-extra-file` (`0600`), không lộ thông tin xác thực trên `/proc`.
   - **Lớp 3:** Watchdog `1.5s` đọc `MEMORY_USED` trên `information_schema.PROCESSLIST`, ánh xạ chủ sở hữu theo *Longest-Prefix Match* (hỗ trợ chính xác cả username chứa dấu `_`), tự động `KILL QUERY` vượt ngưỡng và đưa tài khoản vi phạm lặp lại vào **Penalty Box** (lưu bền vững qua lần khởi động lại).
4. **Dual Unix Socket & Xác thực Nhân Linux `SO_PEERCRED`:**
   - **Admin Socket (`/var/run/da-resourced.sock`):** Xác thực trực tiếp UID không thể giả mạo từ nhân Linux (`SO_PEERCRED`) đối chiếu với `root`, `diradmin` và danh sách quản trị viên DirectAdmin (`/usr/local/directadmin/data/admin/admin.list` / `usertype=admin`).
   - **User Socket (`/var/run/da-resourced-user.sock`):** Chỉ cho phép truy vấn đọc và khoá chặt mỗi tài khoản Hosting chỉ xem được số liệu của chính UID tiến trình đang gọi.
5. **Cập nhật Nguyên tử từ GitHub Releases (Public & Private Repo):**
   - Xác thực mã băm `SHA-256`, tạo Snapshot Backup tại `/var/backups/da-resource-limiter/`, bảo toàn tuyệt đối thư mục dữ liệu `plugin/data/`, kiểm tra sức khoẻ Socket trong 10 giây và **Auto-Rollback** tức thì nếu bản cập nhật mới gặp sự cố.

---

## Lệnh Vận hành CLI (`da-resourced`) & Cập nhật / Gỡ bỏ

| Lệnh CLI | Mô tả |
| :--- | :--- |
| `da-resourced ping` | Kiểm tra trạng thái hoạt động, phiên bản và Uptime của Daemon qua Unix Socket. |
| `da-resourced stats` | Bảng theo dõi nhanh CPU %, RAM, Processes, MySQL RAM/Conns và Penalty của toàn bộ User. |
| `da-resourced stats <user> --json` | Xuất thông số thời gian thực chi tiết dạng JSON cho 1 tài khoản Hosting. |
| `da-resourced apply <user>` | Áp dụng tức thời Cgroup Slice, PHP tokens và giới hạn MariaDB cho `<user>`. |
| `da-resourced apply-all` | Đồng bộ lại giới hạn hàng loạt cho toàn bộ tài khoản Hosting trên máy chủ. |
| `da-resourced apply-package <pkg>` | Đồng bộ mọi User thuộc gói `<pkg>` (tự động giữ nguyên các VIP user bật `CUSTOM_OVERRIDE=yes`). |
| `da-resourced unblock <user>` | Gỡ trạng thái phạt MySQL Penalty Box ngay lập tức cho `<user>`. |
| `da-resourced audit-mycnf` | Kiểm tra thông số bộ nhớ `/etc/my.cnf` theo khuyến nghị Lớp 1. |
| `da-resourced check-update` | Kiểm tra phiên bản mới nhất trên GitHub Releases. |
| `da-resourced update` | Tự động tải gói phát hành mới, xác thực SHA-256 và cập nhật nguyên tử kèm Auto-Rollback. |
| `da-resourced rollback` | Khôi phục ngay lập tức về bản Snapshot Backup gần nhất. |

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
├── cmd/da-resourced/       # Entrypoint CLI & Systemd Daemon
├── internal/
│   ├── cgroup/             # Quản lý Systemd user-<UID>.slice, da-php.scope & đọc Cgroup v2 stats
│   ├── config/             # Lưu trữ phân cấp default.conf -> packages/*.conf -> users/*.conf
│   ├── dausers/            # Đồng bộ tài khoản DirectAdmin (1000..59999) & Longest-Prefix DB mapping
│   ├── engine/             # Điều phối trung tâm, xử lý IPC & xác thực Admin/User SO_PEERCRED
│   ├── fpm/                # Quét /proc di chuyển PHP-FPM/lsphp & đồng bộ an toàn user.conf
│   ├── ipc/                # Giao thức JSON & Dual Unix Domain Socket Server/Client
│   ├── logger/             # Nhật ký vi phạm JSONL tự động xoay vòng (Rotation)
│   ├── mysqlgov/           # MariaDB 3-Tier Governor, PROCESSLIST Watchdog & Penalty Box
│   ├── updater/            # GitHub Releases Updater (Public/Private Repo, SHA-256, Tar-Slip Safe)
│   └── version/            # Thông tin phiên bản nhúng lúc biên dịch
├── plugin/                 # Giao diện DirectAdmin Plugin (admin/, user/, hooks/, images/, templates/)
├── scripts/                # install.sh, update.sh, uninstall.sh, qa_verify.sh & da_hooks/
├── systemd/                # Cấu hình dịch vụ da-resourced.service (OOMScoreAdjust=-900)
└── docs/RUNBOOK.md         # Sổ tay triển khai, nghiệm thu & vận hành chi tiết
```

---

## Phát triển & Xuất bản Bản Phát hành Mới

```bash
# Chạy toàn bộ Unit Tests & kiểm tra Race Condition
make test

# Biên dịch tĩnh đa kiến trúc (CGO_ENABLED=0)
make build-linux-amd64
make build-linux-arm64

# Đẩy tag phiên bản mới để GitHub Actions tự động đóng gói & xuất bản GitHub Release
git tag -a vX.Y.Z -m "DA-ResourceLimiter vX.Y.Z"
git push origin main --tags
```

---

## Tài liệu Dự án

- [Sổ Tay Vận Hành & Triển Khai (`docs/RUNBOOK.md`)](./docs/RUNBOOK.md)
- [Kế Hoạch Phát Triển Từng Giai Đoạn & Cơ Chế GitHub Update (v1.1)](./plan/Kế%20Hoạch%20Phát%20Triển%20Từng%20Giai%20Đoạn%20&%20Cơ%20Chế%20GitHub%20Update.md)
- [Đặc Tả Kỹ Thuật gốc (v1.0)](./plan/Đặc%20Tả%20Kỹ%20Thuật%20&%20Kế%20Hoạch%20Phát%20Triển%20Plugin%20Giới%20Hạn%20Tài%20Nguyên_directadmin.md)
