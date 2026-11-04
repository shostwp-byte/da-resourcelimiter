# DA-ResourceLimiter (`v1.0.0`)

Hệ thống **Cô lập và Giới hạn Tài nguyên Đa tầng cho DirectAdmin** (thay thế độc lập không cần CloudLinux), kết hợp **Linux Cgroups v2**, **PHP-FPM / OpenLiteSpeed LSPHP PID Classifier**, **MariaDB 3-Tier Governor** và **GitHub Releases Self-Updater**.

---

## Cài đặt Nhanh 1-Click (DirectAdmin Production)

```bash
# 1. Cài đặt từ Public GitHub Repository:
curl -fsSL https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/main/scripts/install.sh | bash

# 2. Cài đặt từ Private GitHub Repository (với Read-only Fine-Grained Token):
export GITHUB_TOKEN="github_pat_XXXXXXXXXXXXXXXXXXXX"
bash -c "$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/main/scripts/install.sh)"
```

Sau khi cài đặt hoàn tất:
* **Giao diện Quản trị (Admin Level):** `/CMD_PLUGINS_ADMIN/da_resource_limiter` (5 Tabs: *Realtime Monitor*, *Package Limits*, *User Overrides*, *Violation & OOM Logs*, *System & GitHub Update*).
* **Giao diện Khách hàng (User Level):** `/CMD_PLUGINS/da_resource_limiter` (Biểu đồ thanh CPU/RAM/Processes/MySQL thời gian thực & Top 5 truy vấn SQL bị ngắt).

---

## Kiến trúc Bảo vệ Đa tầng

1. **Cô lập Cứng CPU, RAM & Chống Fork Bomb (Linux Cgroups v2):**
   * Quản lý tự động `/etc/systemd/system/user-<UID>.slice.d/50-da-limits.conf` (`CPUQuota`, `MemoryHigh`, `MemoryMax`, `MemorySwapMax=0M`, `IOWeight`, `TasksMax`).
   * Đọc sự kiện tràn bộ nhớ trực tiếp từ `memory.events` (`oom_kill`, `high`) với chi phí CPU gần bằng 0.
2. **Đưa PHP-FPM & OpenLiteSpeed LSPHP vào Cgroup của User (`da-php.scope`):**
   * Quét và di chuyển tức thời các worker `php-fpm` / `lsphp` của khách hàng từ `system.slice` sang `/sys/fs/cgroup/user.slice/user-<UID>.slice/da-php.scope` (tuân thủ *No Internal Process Constraint*).
   * Chặn cứng việc gom nhầm tài khoản hệ thống (`root`, `diradmin`, `admin`, `nobody=65534`).
3. **MariaDB 3-Tier Governor & Penalty Box:**
   * **Lớp 1:** Kiểm toán bộ đệm per-thread `/etc/my.cnf` (`da-resourced audit-mycnf`).
   * **Lớp 2:** Đồng bộ `ALTER USER ... WITH MAX_USER_CONNECTIONS ... MAX_STATEMENT_TIME ...` bảo mật qua `--defaults-extra-file` (`0600`), không lộ mật khẩu trên `/proc`.
   * **Lớp 3:** Watchdog `1.5s` đọc `MEMORY_USED` trên `information_schema.PROCESSLIST`, ánh xạ theo *Longest-Prefix Match* (hỗ trợ cả username có dấu `_`), tự động `KILL QUERY` nặng nhất và đưa tài khoản lạm dụng vào **Penalty Box** (có lưu trạng thái bền vững qua lần khởi động lại).
4. **Dual Unix Socket & Xác thực `SO_PEERCRED`:**
   * Socket quản trị `/var/run/da-resourced.sock` (`0660 root:diradmin`) tách biệt hoàn toàn với socket khách hàng `/var/run/da-resourced-user.sock` (sử dụng `SO_PEERCRED` của Linux Kernel khoá chặt mỗi khách hàng chỉ đọc được dữ liệu của chính UID đó).
5. **Cập nhật Nguyên tử từ GitHub Releases (Public & Private Repo):**
   * Xác thực mã băm `SHA-256`, tạo Snapshot Backup tại `/var/backups/da-resource-limiter/`, bảo toàn 100% thư mục `plugin/data/`, kiểm tra sức khoẻ Socket 10s và **Auto-Rollback** tức thì nếu phiên bản mới lỗi khởi động.

---

## Phát triển & Phát hành Bản Mới

```bash
# Chạy toàn bộ Unit Tests & kiểm tra Race Condition
make test

# Biên dịch tĩnh đa kiến trúc (CGO_ENABLED=0)
make build-linux-amd64
make build-linux-arm64

# Đẩy tag để GitHub Actions tự động biên dịch & xuất bản GitHub Release
git tag v1.0.0
git push origin main --tags
```

---

## Tài liệu Dự án

* [Sổ Tay Vận Hành & Triển Khai (`docs/RUNBOOK.md`)](./docs/RUNBOOK.md)
* [Kế Hoạch Phát Triển Từng Giai Đoạn & Cơ Chế GitHub Update (v1.1)](./plan/Kế%20Hoạch%20Phát%20Triển%20Từng%20Giai%20Đoạn%20&%20Cơ%20Chế%20GitHub%20Update.md)
* [Đặc Tả Kỹ Thuật gốc (v1.0)](./plan/Đặc%20Tả%20Kỹ%20Thuật%20&%20Kế%20Hoạch%20Phát%20Triển%20Plugin%20Giới%20Hạn%20Tài%20Nguyên_directadmin.md)
