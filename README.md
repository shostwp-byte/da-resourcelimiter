# DA-ResourceLimiter

Hệ thống Cô lập và Giới hạn Tài nguyên Đa tầng cho **DirectAdmin** (không phụ thuộc CloudLinux), tích hợp **Linux Cgroups v2**, **PHP-FPM / OpenLiteSpeed LSPHP PID Classifier**, **MariaDB 3-Tier Governor** và **GitHub Releases Self-Updater**.

## Tính năng cốt lõi

1. **Cô lập cứng tầng OS (Linux Cgroups v2 / `user-<UID>.slice`):**
   - Giới hạn `CPUQuota`, `MemoryHigh` (throttle mềm), `MemoryMax` (cô lập OOM Killer), `MemorySwapMax=0M` (chống ăn Swap gây nghẽn đĩa), `IOWeight` và `TasksMax` (chống Fork Bomb).
2. **Đưa PHP-FPM & LSPHP về đúng Cgroup của User (`da-php.scope`):**
   - Tự động di chuyển các worker tiến trình con của `php-fpm` / `lsphp` từ `system.slice` về `user-<UID>.slice/da-php.scope` tuân thủ *No Internal Process Constraint* của Cgroups v2.
   - Chặn triệt để việc gom nhầm các tài khoản hệ thống (`root`, `diradmin`, `nobody=65534`).
3. **Kiểm soát CPU & RAM của MariaDB 10.5+ theo từng User:**
   - Kết hợp `ALTER USER ... WITH MAX_USER_CONNECTIONS ... MAX_STATEMENT_TIME ...` và Watchdog thời gian thực (`1.5s`) đọc `MEMORY_USED` trên `information_schema.PROCESSLIST`, tự động `KILL QUERY` và kích hoạt **Penalty Box**.
4. **Cập nhật tự động an toàn từ GitHub Releases:**
   - Hỗ trợ cả **Public & Private Repository** (cấu hình GitHub Token quyền `0600`), kiểm chứng mã băm `SHA-256`, tạo Snapshot Backup, bảo toàn 100% dữ liệu `data/` và **Auto-Rollback** nếu phiên bản mới lỗi khởi động.

## Cấu trúc Dự án

- `cmd/da-resourced/` — Root Daemon & CLI (`serve`, `apply`, `apply-all`, `remove`, `stats`, `version`).
- `internal/config/` — Bộ quản lý cấu hình phân cấp (`default -> package -> user override`) & cấu hình Updater.
- `internal/dausers/` — Đồng bộ DirectAdmin Users <-> Linux UID & thuật toán *Longest-Prefix Match* cho DB User.
- `internal/cgroup/` — Quản lý `systemd` slice drop-in, `da-php.scope` và đọc chỉ số Cgroups v2 / `memory.events`.
- `internal/fpm/` — Bộ phân loại tiến trình `php-fpm` / `lsphp` và đồng bộ biến template DirectAdmin.
- `internal/ipc/` — Giao thức JSON qua Unix Domain Socket (`/var/run/da-resourced.sock`).
- `plugin/` — Giao diện DirectAdmin Plugin (Admin & User Level tương thích Evolution Skin).
- `plan/` — Đặc tả kỹ thuật & Kế hoạch phát triển từng giai đoạn.

## Biên dịch từ Mã nguồn

```bash
# Biên dịch binary tĩnh cho máy chủ Linux x86_64
make build-linux-amd64

# Biên dịch binary tĩnh cho máy chủ Linux ARM64
make build-linux-arm64

# Chạy toàn bộ Unit Tests
make test
```

## Tài liệu Kỹ thuật

- [Đặc Tả Kỹ Thuật gốc (v1.0)](./plan/Đặc%20Tả%20Kỹ%20Thuật%20&%20Kế%20Hoạch%20Phát%20Triển%20Plugin%20Giới%20Hạn%20Tài%20Nguyên_directadmin.md)
- [Kế Hoạch Phát Triển Từng Giai Đoạn & Cơ Chế GitHub Update (v1.1)](./plan/Kế%20Hoạch%20Phát%20Triển%20Từng%20Giai%20Đoạn%20&%20Cơ%20Chế%20GitHub%20Update.md)
