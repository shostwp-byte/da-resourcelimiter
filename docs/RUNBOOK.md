# SỔ TAY VẬN HÀNH & TRIỂN KHAI PRODUCTION (`RUNBOOK.md`)

**Dự án:** `DA-ResourceLimiter` (`v1.0.0`)  
**Repository:** https://github.com/shostwp-byte/da-resourcelimiter  

---

## 1. YÊU CẦU TIÊN QUYẾT TRÊN MÁY CHỦ DIRECTADMIN

1. **Hệ điều hành:** AlmaLinux 8/9, Rocky Linux 8/9, hoặc Ubuntu 22.04/24.04 LTS.
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

## 2. CÀI ĐẶT 1-CLICK TRÊN MÁY CHỦ MỚI

### Trường hợp A: Repository ở chế độ Public
Chạy lệnh sau dưới quyền `root`:
```bash
curl -fsSL https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/main/scripts/install.sh | bash
```

### Trường hợp B: Repository ở chế độ Private (Sử dụng GitHub Fine-Grained Token)
1. Trên GitHub, vào **Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Chọn Repository access: **Only select repositories** → `shostwp-byte/da-resourcelimiter`.
3. Mục **Repository permissions** → cấp duy nhất quyền **Contents: Read-only** (an toàn tuyệt đối, Token này không thể sửa code trên GitHub).
4. Chạy cài đặt kèm `GITHUB_TOKEN` (script sẽ tự động lưu Token này vào `/etc/da-resourced/updater.conf` với quyền `0600 root:root` để phục vụ One-Click Update về sau):
   ```bash
   export GITHUB_TOKEN="github_pat_XXXXXXXXXXXXXXXXXXXX"
   bash -c "$(curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" https://raw.githubusercontent.com/shostwp-byte/da-resourcelimiter/main/scripts/install.sh)"
   ```

### Kiểm tra tối ưu `/etc/my.cnf` (Tầng 1 MariaDB)
Sau khi cài đặt xong, chạy lệnh kiểm toán thông số bộ nhớ trên từng kết nối MySQL:
```bash
da-resourced audit-mycnf
```
Nếu có thông số `MISSING`, bổ sung đoạn cấu hình gợi ý vào nhóm `[mysqld]` trong `/etc/my.cnf` và khởi động lại `mariadb` vào khung giờ thấp điểm.

---

## 3. QUY TRÌNH PHÁT HÀNH BẢN MỚI & CẬP NHẬT TỪ GITHUB

### 3.1. Phát hành phiên bản mới lên GitHub Releases
Hệ thống tích hợp sẵn GitHub Actions (`.github/workflows/release.yml`). Mỗi khi bạn đẩy tag `v*` lên GitHub:
1. Dùng GitHub Desktop hoặc Git CLI tạo tag mới (ví dụ `v1.0.1` cho bản Stable, hoặc `v1.1.0-beta.1` cho bản Beta):
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```
2. GitHub Actions tự động:
   * Chạy toàn bộ Unit Tests, `go vet`, `shellcheck`, `php -l`.
   * Biên dịch tĩnh `da-resourced` cho cả `linux/amd64` và `linux/arm64`.
   * Đóng gói `.tar.gz`, tạo `manifest.json` + chữ ký băm `checksums.txt` (SHA-256) và xuất bản lên mục **Releases**.

### 3.2. Cập nhật trên các máy chủ DirectAdmin
* **Cách 1 — Qua Giao diện Admin DirectAdmin:**
  1. Truy cập **DirectAdmin Admin Level → Extra Features → DA Resource Limiter → Tab 5 (System & GitHub Update)**.
  2. Bấm **Check for Updates** để xem phiên bản mới & Changelog.
  3. Bấm **One-Click Update Now**. Hệ thống tự động kiểm tra SHA-256, tạo bản Snapshot Backup tại `/var/backups/da-resource-limiter/`, giữ nguyên 100% cấu hình trong `plugin/data/`, khởi động lại Daemon và tự động **Rollback** nếu Daemon mới không vượt qua bài kiểm tra Socket trong 10 giây.
* **Cách 2 — Qua dòng lệnh SSH (Root CLI):**
  ```bash
  da-resourced check-update
  da-resourced update
  # Hoặc cập nhật chỉ định phiên bản cụ thể:
  da-resourced update --version v1.0.1
  # Khôi phục bản sao lưu gần nhất bất cứ lúc nào:
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
| `da-resourced apply-all` | Đồng bộ hàng loạt cho toàn bộ tài khoản Hosting trên máy chủ. |
| `da-resourced apply-package <pkg>` | Đồng bộ lại mọi User thuộc gói `<pkg>` (tự động bỏ qua các VIP user đang bật `CUSTOM_OVERRIDE=yes`). |
| `da-resourced unblock <user>` | Gỡ trạng thái phạt MySQL Penalty Box ngay lập tức cho `<user>`. |
| `da-resourced audit-mycnf` | Kiểm tra cấu hình `/etc/my.cnf` theo khuyến nghị Lớp 1. |
| `da-resourced check-update` | Kiểm tra phiên bản mới nhất trên GitHub Releases. |
| `da-resourced update` | Tải về, xác thực SHA-256 và cập nhật nguyên tử kèm Auto-Rollback. |
| `da-resourced rollback` | Khôi phục ngay bản Snapshot Backup gần nhất. |

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
   * Đảm bảo socket `/var/run/da-resourced.sock` đang tồn tại (`ls -l /var/run/da-resourced*.sock`) và tài khoản quản trị đăng nhập nằm trong `/usr/local/directadmin/data/admin/admin.list` (xác thực nhân Linux `SO_PEERCRED`).
2. **Khách hàng phản ánh lỗi kết nối MySQL (`User ... has exceeded the 'max_user_connections' resource`):**
   * Vào **Tab 1** hoặc **Tab 3** kiểm tra xem User có đang gắn nhãn **Penalty Throttled** không, và mở **Tab 4 (Violation Logs)** lọc theo Username để gửi chính xác câu lệnh `SELECT` bị nghẽn cho khách hàng đánh thêm Index.
   * Nếu khách hàng vừa sửa xong code và cần mở khoá ngay mà không đợi hết 300 giây: bấm nút **Unblock Penalty** trên giao diện hoặc gõ `da-resourced unblock <username>`.
3. **Gỡ cài đặt hoàn toàn khỏi máy chủ:**
   ```bash
   # Gỡ dịch vụ & giới hạn nhưng vẫn sao lưu cấu hình data/ vào /var/backups/da-resource-limiter/:
   /usr/local/directadmin/plugins/da_resource_limiter/scripts/uninstall.sh

   # Gỡ sạch bao gồm cả lịch sử log và cấu hình:
   /usr/local/directadmin/plugins/da_resource_limiter/scripts/uninstall.sh --purge-data
   ```
