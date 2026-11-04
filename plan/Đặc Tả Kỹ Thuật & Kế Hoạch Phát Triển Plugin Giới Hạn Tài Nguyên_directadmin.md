# ĐẶC TẢ KỸ THUẬT & KẾ HOẠCH PHÁT TRIỂN DỰ ÁN
**Tên dự án:** Hệ thống Cô lập và Giới hạn Tài nguyên Đa tầng cho DirectAdmin (`DA-ResourceLimiter`)  
**Phiên bản tài liệu:** 1.0  
**Đối tượng tiếp nhận:** Đội ngũ System Admin, Linux Kernel/Cgroups Engineer, Backend Developer (PHP/Python/Go)  

---

## 1. TỔNG QUAN & MỤC TIÊU DỰ ÁN

### 1.1. Bài toán thực tế
Mặc định trên DirectAdmin (các bản không sử dụng CloudLinux hoặc không dùng Pro Pack):
1. **CPU & RAM của User:** Chưa được cô lập triệt để. Đặc biệt, các tiến trình con của `PHP-FPM` được fork từ master process (`root`) nên nằm trong `system.slice`, không chịu sự quản lý của `user-<UID>.slice`.
2. **MySQL / MariaDB:** Hoạt động dưới kiến trúc một tiến trình đa luồng (`mysqld`). Khi một User chạy truy vấn nặng (Unindexed Join, Sort lớn, Slow Query), luồng đó sẽ chiếm dụng toàn bộ CPU và RAM chung của máy chủ, gây hiệu ứng "Noisy Neighbor" làm sập hoặc treo các website của User khác.

### 1.2. Mục tiêu kỹ thuật
Xây dựng một **Plugin tích hợp sâu vào DirectAdmin** kèm **Background Daemon (`da-resourced`)** hoạt động độc lập, đảm bảo:
* **Cô lập cứng CPU và RAM thực (Physical RAM + Swap)** cho từng User (bao gồm cả SSH, Cronjob, PHP-FPM, Node.js/Python) thông qua `Linux Cgroups v2` (`systemd slices`).
* **Kiểm soát chặt CPU và RAM của MySQL/MariaDB** cho từng User thông qua kết hợp: *Per-User Limits cấp độ DB Engine* + *Real-time Watchdog Daemon* (cơ chế tương tự CloudLinux MySQL Governor).
* **Tự động hóa 100%** thông qua hệ thống Event Hooks của DirectAdmin (Tạo/Sửa/Xóa User, Đổi Package, Tạo Database/DB User).
* **Giao diện quản trị trực quan** cho Admin (cấu hình theo Package/User, xem lịch sử vi phạm) và giao diện theo dõi cho User (xem biểu đồ sử dụng tài nguyên thực tế).

---

## 2. KIẾN TRÚC HỆ THỐNG TỔNG THỂ (SYSTEM ARCHITECTURE)

```
+-----------------------------------------------------------------------------------+
|                            DIRECTADMIN CONTROL PANEL                              |
|  +-----------------------------+               +-------------------------------+  |
|  |   Plugin UI (Admin / User)  |               |   DirectAdmin Custom Hooks    |  |
|  |  - Quản lý Package/User     |               |  - user_create_post.sh        |  |
|  |  - Xem thống kê realtime    |               |  - user_modify_post.sh        |  |
|  |  - Xem log vi phạm (Penalty)|               |  - database_user_create_post  |  |
|  +--------------+--------------+               +---------------+---------------+  |
+-----------------|----------------------------------------------|------------------+
                  | (Giao tiếp qua Unix Domain Socket / CLI)     |
                  v                                              v
+-----------------------------------------------------------------------------------+
|                      CORE ENGINE: DA-RESOURCED (ROOT DAEMON)                      |
|  +-------------------------+  +------------------------+  +--------------------+  |
|  |   Cgroup v2 Controller  |  | PHP-FPM PID Classifier |  |  MariaDB Governor  |  |
|  | - Quản lý user-UID.slice|  | - Quét/Bắt sự kiện FPM |  | - Đọc PROCESSLIST  |  |
|  | - Áp đặt CPUQuota       |  | - Chuyển PID worker về |  | - Đo CPU/RAM/Time  |  |
|  | - Áp đặt MemoryMax/High |  |   đúng user-UID.slice  |  | - Kill Slow Query  |  |
|  | - Áp đặt IO/TasksMax    |  | - Áp giới hạn FPM Pool |  | - Penalty Box      |  |
|  +------------+------------+  +-----------+------------+  +---------+----------+  |
+---------------|---------------------------|-------------------------|-------------+
                |                           |                         |
                v                           v                         v
+-----------------------------------------------------------------------------------+
|                         TẦNG HỆ ĐIỀU HÀNH (LINUX KERNEL & DB)                     |
|     [ /sys/fs/cgroup/user.slice ]     [ PHP-FPM Pools ]     [ MariaDB 10.5+ ]     |
+-----------------------------------------------------------------------------------+
```

---

## 3. YÊU CẦU MÔI TRƯỜNG & TIÊN QUYẾT (PREREQUISITES)

Đội ngũ kỹ thuật cần chuẩn bị môi trường máy chủ chuẩn hóa như sau trước khi code:
1. **Hệ điều hành:** AlmaLinux 8/9, Rocky Linux 8/9, hoặc Ubuntu 22.04/24.04 LTS.
2. **Kernel & Cgroups:** Bắt buộc kích hoạt **Cgroups v2 (Unified Hierarchy)**.
   * Kiểm tra: `stat -fc %T /sys/fs/cgroup/` -> Phải trả về `cgroup2fs`.
   * Nếu chưa bật, thêm `systemd.unified_cgroup_hierarchy=1` vào `/etc/default/grub` và chạy `grub2-mkconfig`.
3. **Database Engine:** **MariaDB 10.5 trở lên** (Khuyến nghị MariaDB 10.6 hoặc 10.11 LTS).
   * *Lý do bắt buộc:* MariaDB hỗ trợ cột `MEMORY_USED`, `MAX_MEMORY_USED` trong `information_schema.PROCESSLIST` và cú pháp `MAX_STATEMENT_TIME`, `MAX_CONCURRENT_QUERIES` cho từng User.
4. **Webserver & PHP:** DirectAdmin CustomBuild 2.0 với PHP-FPM (khuyến nghị) hoặc FastCGI.

---

## 4. THIẾT KẾ CHI TIẾT CÁC PHÂN HỆ KỸ THUẬT

### PHÂN HỆ 1: CÔ LẬP CPU & RAM TẦNG OS (CGROUPS V2 & SYSTEMD SLICE)

#### 4.1.1. Nguyên lý hoạt động
Mỗi User trên Linux có một `UID` định danh duy nhất (ví dụ: user `vinahost` có `UID = 1005`). Systemd quản lý tài nguyên của user thông qua unit `user-1005.slice` nằm tại nhánh `/sys/fs/cgroup/user.slice/user-1005.slice/`.

#### 4.1.2. Cấu hình Systemd Drop-in cho từng User
Khi tạo hoặc cập nhật giới hạn cho User (UID `1005`), hệ thống tự động sinh file:  
`/etc/systemd/system/user-1005.slice.d/50-da-limits.conf`

Nội dung mẫu:
```ini
[Slice]
# 1. Quản lý CPU (100% = 1 vCore, 200% = 2 vCores)
CPUAccounting=yes
CPUWeight=100
CPUQuota=150%

# 2. Quản lý RAM (Tuyệt đối không cho phép ăn Swap để tránh Disk Thrashing)
MemoryAccounting=yes
MemoryHigh=1536M
MemoryMax=2048M
MemorySwapMax=0M

# 3. Quản lý Disk I/O (Tuỳ chọn mở rộng)
IOAccounting=yes
IOWeight=100

# 4. Chống Fork Bomb & giới hạn tổng số tiến trình/threads
TasksAccounting=yes
TasksMax=100
```

* **Giải thích hành vi kỹ thuật:**
  * `MemoryHigh=1536M`: Khi tổng RAM của User chạm mức 1.5GB, Kernel sẽ kích hoạt cơ chế *Memory Throttling* (bóp tốc độ cấp phát bộ nhớ và thu hồi page cache của riêng user đó), làm tiến trình của user chậm lại nhưng chưa bị chết đột ngột.
  * `MemoryMax=2048M`: Ngưỡng cứng (Hard Limit). Nếu vượt quá 2GB, Kernel OOM Killer sẽ chỉ tiêu diệt tiến trình bên trong `user-1005.slice`, tuyệt đối không ảnh hưởng tới hệ thống hay user khác.
  * `MemorySwapMax=0M`: Cấm user dùng Swap để lách luật giới hạn RAM.

---

### PHÂN HỆ 2: ĐƯA PHP-FPM VÀO CGROUP CỦA USER (QUAN TRỌNG NHẤT)

#### 4.2.1. Vấn đề kỹ thuật
Trong DirectAdmin, dịch vụ `php-fpm81.service`, `php-fpm82.service` chạy dưới `system.slice`. Khi có request vào web của user `1005`, master process sẽ fork ra worker process chạy dưới quyền UID `1005`, nhưng **Cgroup của worker đó vẫn nằm ở `/sys/fs/cgroup/system.slice/php-fpm82.service`**. Do đó, `user-1005.slice` sẽ không đếm được CPU và RAM của PHP!

#### 4.2.2. Giải pháp triển khai (Kết hợp 2 cơ chế)

**Cơ chế A: Khống chế tại Custom Template của DirectAdmin (Tầng cấu hình)**
Sao chép template gốc sang thư mục custom:
`/usr/local/directadmin/data/templates/custom/php-fpm.conf`

Thêm logic đọc biến tùy chỉnh từ file `user.conf` của DirectAdmin để khống chế số lượng worker và RAM mỗi tiến trình:
```ini
|*if DA_PHP_MAX_CHILDREN!=""|
pm.max_children = |DA_PHP_MAX_CHILDREN|
|*else|
pm.max_children = 10
|*endif|

|*if DA_PHP_MEM_LIMIT!=""|
php_admin_value[memory_limit] = |DA_PHP_MEM_LIMIT|
|*else|
php_admin_value[memory_limit] = 256M
|*endif|

pm = ondemand
pm.process_idle_timeout = 10s
pm.max_requests = 500
```

**Cơ chế B: Module `PHP-FPM PID Classifier` trong Daemon `da-resourced` (Tầng Kernel Cgroup)**
Daemon chạy ngầm (viết bằng Golang hoặc Python/C) thực hiện nhiệm vụ di chuyển tức thời các PHP-FPM worker vào đúng `user-<UID>.slice`:
1. Sử dụng **Netlink Process Connector (`PROC_CN_MCAST_LISTEN`)** hoặc `eBPF` (hoặc vòng lặp quét nhẹ `/proc` mỗi 1 giây đối với các tiến trình `php-fpm: pool <username>`).
2. Khi phát hiện một PID của `php-fpm` có `Real UID >= 1000` (thuộc về khách hàng) đang nằm trong `system.slice`:
3. Daemon tự động ghi `PID` đó vào file:
   `/sys/fs/cgroup/user.slice/user-<UID>.slice/cgroup.procs` *(Lưu ý: Trên Cgroup v2, để ghi PID vào leaf node hoặc slice, cần tạo một sub-cgroup con như `/sys/fs/cgroup/user.slice/user-<UID>.slice/php-fpm.scope/cgroup.procs` để tuân thủ quy tắc "No Internal Process Constraint" của Cgroups v2).*

> **LƯU Ý QUAN TRỌNG VỀ CGROUPS V2 ("No Internal Process Constraint"):**
> Trong Cgroups v2, một node trung gian (như `user-1005.slice`) không được chứa trực tiếp PID nếu nó đã có các cgroup con (như `user@1005.service`). Do đó, Daemon phải tạo một scope con:  
> `/sys/fs/cgroup/user.slice/user-1005.slice/da-php.scope/`  
> và đẩy toàn bộ PID của PHP-FPM, Cron, SSH của user `1005` vào `.../da-php.scope/cgroup.procs`. Vì `da-php.scope` là con của `user-1005.slice`, toàn bộ giới hạn `CPUQuota` và `MemoryMax` của `user-1005.slice` sẽ áp dụng tổng cộng lên cả SSH, Cron và PHP-FPM của user đó!

---

### PHÂN HỆ 3: KIỂM SOÁT CPU & RAM CỦA MYSQL/MARIADB THEO TỪNG USER

Phân hệ này được thiết kế theo kiến trúc **3 Lớp Phòng Thủ (3-Tier Defense)** để giải quyết triệt để bài toán MySQL dùng chung tiến trình.

#### Lớp 1: Cấu hình cứng Per-Thread Memory trong `/etc/my.cnf`
Đảm bảo mỗi kết nối không thể tự ý cấp phát lượng RAM khổng lồ:
```ini
[mysqld]
# Bật thu thập thông tin hiệu năng và bộ nhớ
performance_schema = ON

# Giới hạn mặc định toàn cục
max_connections = 500
max_user_connections = 20
max_statement_time = 15

# Kiểm soát bộ nhớ trên từng kết nối (Per-Thread Buffers)
sort_buffer_size = 2M
join_buffer_size = 2M
read_buffer_size = 1M
read_rnd_buffer_size = 1M

# Giới hạn bảng tạm trong RAM (Vượt quá sẽ chuyển xuống Disk)
tmp_table_size = 32M
max_heap_table_size = 32M
```

#### Lớp 2: Áp đặt giới hạn cấp độ Database Account (`ALTER USER`)
Trên DirectAdmin, mọi Database và DB User của khách hàng `vinahost` đều có tiền tố bắt buộc là `vinahost_` (hoặc chính là `vinahost`).
Khi tạo hoặc sửa giới hạn của User, Daemon thực thi câu lệnh SQL sau lên toàn bộ DB User thuộc sở hữu của tài khoản đó:

```sql
-- Tìm tất cả user thuộc khách hàng: SELECT User, Host FROM mysql.user WHERE User LIKE 'vinahost\_%' OR User = 'vinahost';
ALTER USER 'vinahost_wp'@'localhost' 
WITH 
  MAX_USER_CONNECTIONS 15          -- Tối đa 15 kết nối đồng thời
  MAX_STATEMENT_TIME 10            -- Query chạy quá 10s tự động bị huỷ (chống treo CPU)
  MAX_QUERIES_PER_HOUR 0
  MAX_UPDATES_PER_HOUR 0;
```

#### Lớp 3: Xây dựng `MariaDB Governor Watchdog` (Real-time CPU/RAM Limiter)
Đây là trái tim của hệ thống kiểm soát MySQL, nằm trong Daemon `da-resourced`, chạy vòng lặp mỗi **1.5 giây**:

1. **Truy vấn trạng thái tài nguyên thực tế của từng luồng MySQL:**
   Thực thi truy vấn siêu nhẹ vào bảng in-memory của MariaDB:
   ```sql
   SELECT 
       ID, 
       USER, 
       SUBSTRING_INDEX(USER, '_', 1) AS system_user,
       COMMAND, 
       TIME_MS, 
       MEMORY_USED, 
       MAX_MEMORY_USED,
       STATE, 
       INFO 
   FROM information_schema.PROCESSLIST 
   WHERE COMMAND != 'Sleep' 
     AND USER NOT IN ('root', 'da_admin', 'system user');
   ```
2. **Thuật toán tính toán tải (Aggregation theo `system_user`):**
   Daemon gom nhóm kết quả theo `system_user` (ví dụ `vinahost`) và tính toán:
   * `Total_Active_Threads`: Tổng số truy vấn đang chạy đồng thời (tương đương số vCore CPU mà user đó đang chiếm trong MySQL).
   * `Total_MySQL_RAM`: $\sum \text{MEMORY\_USED}$ của tất cả các luồng thuộc `system_user` đó.
   * `Accumulated_CPU_Time`: $\sum \text{TIME\_MS}$ của các truy vấn đang hoạt động.
3. **Cơ chế xử lý vi phạm (Enforcement & Penalty Box):**
   So sánh với cấu hình giới hạn của User (ví dụ: `MYSQL_MAX_MEM = 256MB`, `MYSQL_MAX_CONCURRENT_ACTIVE = 4` cores, `MYSQL_MAX_TIME_MS = 8000ms`):
   * **Mức độ 1 (Kill Query):** Nếu một truy vấn đơn lẻ vượt `MYSQL_MAX_TIME_MS` hoặc tổng RAM của User vượt `MYSQL_MAX_MEM` -> Gửi lệnh `KILL QUERY <ID>;` đối với truy vấn ngốn nhiều RAM/thời gian nhất của user đó và ghi vào file log `/var/log/da-resourced/mysql-kills.log`.
   * **Mức độ 2 (Penalty Box / Throttling):** Nếu một `system_user` bị Kill Query quá $N$ lần (ví dụ 5 lần) trong vòng 60 giây (dấu hiệu bị tấn công DDoS vào câu lệnh tìm kiếm hoặc code lỗi lặp vô tận):
     * Daemon đưa user vào trạng thái **Throttled (Phạt)** trong 300 giây.
     * Thực thi ngay lập tức: `ALTER USER 'vinahost_...'@'localhost' WITH MAX_USER_CONNECTIONS 2 MAX_STATEMENT_TIME 2; FLUSH USER_RESOURCES;`
     * Sau khi hết 300 giây phạt, Daemon tự động khôi phục lại `MAX_USER_CONNECTIONS` ban đầu.

---

## 5. CẤU TRÚC THƯ MỤC & MÃ NGUỒN DỰ ÁN

Dự án được chia làm 2 phần: **DirectAdmin Plugin** và **System Daemon**.

### 5.1. Cấu trúc thư mục DirectAdmin Plugin
Đặt tại `/usr/local/directadmin/plugins/da_resource_limiter/`

```text
/usr/local/directadmin/plugins/da_resource_limiter/
├── plugin.conf                     # Khai báo thông tin plugin với DirectAdmin
├── admin/
│   ├── index.html                  # Giao diện Admin: Quản lý Package, User, Xem trạng thái Daemon
│   ├── api.php                     # Xử lý Ajax lưu cấu hình, xem realtime stats
│   └── logs.html                   # Xem lịch sử OOM Kill & MySQL Query Kill
├── user/
│   ├── index.html                  # Giao diện User: Xem biểu đồ CPU, RAM, MySQL hiện tại
│   └── stats.php                   # API trả về dữ liệu sử dụng của chính User đó
├── hooks/
│   ├── admin_img.html              # Icon hiển thị trên trang chủ Admin
│   └── user_img.html               # Icon hiển thị trên trang chủ User
├── scripts/
│   ├── install.sh                  # Script cài đặt plugin, tạo systemd service, gán quyền
│   ├── uninstall.sh                # Script gỡ cài đặt, xoá slice limits
│   └── apply_limits.sh             # Script CLI để đồng bộ cấu hình
└── data/
    ├── default.conf                # Cấu hình mặc định cho user không thuộc package nào
    ├── packages/                   # Lưu cấu hình theo tên Package (vd: gold.conf)
    └── users/                      # Lưu cấu hình override riêng cho từng User (vd: vinahost.conf)
```

### 5.2. Định dạng file cấu hình dữ liệu (`data/users/<username>.conf`)
Sử dụng định dạng Key-Value chuẩn của DirectAdmin để dễ dàng parse bằng cả Bash, PHP và Go/Python:

```ini
ENABLED=yes
# Giới hạn OS (Cgroups v2)
CPU_QUOTA=150
MEM_HIGH_MB=1536
MEM_MAX_MB=2048
IO_WEIGHT=100
TASKS_MAX=100

# Giới hạn PHP-FPM
PHP_MAX_CHILDREN=12
PHP_MEM_LIMIT_MB=256

# Giới hạn MySQL/MariaDB
MYSQL_MAX_CONNECTIONS=20
MYSQL_MAX_ACTIVE_QUERIES=4
MYSQL_MAX_MEM_MB=256
MYSQL_MAX_STATEMENT_TIME_SEC=10
MYSQL_PENALTY_ENABLED=yes
```

---

## 6. THIẾT KẾ CƠ CHẾ GIAO TIẾP & BẢO MẬT (IPC & SECURITY)

Vì giao diện DirectAdmin Plugin chạy dưới quyền user `diradmin` (hoặc quyền của `user` đang đăng nhập), nó **không có quyền `root`** để ghi vào `/etc/systemd/system/`, `/sys/fs/cgroup/` hay chạy quyền `SUPER` trên MySQL.

**Giải pháp thiết kế chuẩn bảo mật:**
1. Không sử dụng `sudo` tràn lan cho user `diradmin`.
2. Daemon `da-resourced` chạy dưới quyền `root` sẽ mở một **Unix Domain Socket** tại:
   `/var/run/da-resourced.sock`
3. Phân quyền cho socket: `chown root:diradmin /var/run/da-resourced.sock` và `chmod 0660 /var/run/da-resourced.sock`.
4. Khi Admin bấm "Lưu cấu hình" trên giao diện Plugin, PHP script sẽ gửi một bản tin JSON qua `/var/run/da-resourced.sock`:
   ```json
   {
     "action": "apply_user_limits",
     "username": "vinahost"
   }
   ```
5. Daemon nhận lệnh, tự kiểm tra tính hợp lệ (chống Command Injection), đọc file cấu hình trong `/usr/local/directadmin/plugins/da_resource_limiter/data/users/vinahost.conf` (thư mục này chỉ `root` và `diradmin` có quyền ghi) và áp dụng xuống OS + MySQL.

---

## 7. TÍCH HỢP DIRECTADMIN EVENT HOOKS (TỰ ĐỘNG HÓA 100%)

Đội ngũ kỹ thuật cần cài đặt các script sau vào `/usr/local/directadmin/scripts/custom/` (hoặc dùng tính năng Hook thư mục mới của DirectAdmin):

| Tên file Hook | Thời điểm kích hoạt | Hành động kỹ thuật cần xử lý |
| :--- | :--- | :--- |
| `user_create_post.sh` | Ngay sau khi tạo User mới | 1. Đọc biến môi trường `$username` và `$package`.<br>2. Copy cấu hình từ `packages/$package.conf` sang `users/$username.conf`.<br>3. Gọi Daemon tạo `user-<UID>.slice.d/50-da-limits.conf` và reload systemd.<br>4. Cập nhật thông số PHP-FPM của user. |
| `user_modify_post.sh` | Khi Admin đổi Package hoặc sửa thông tin User | 1. Kiểm tra nếu `$package` thay đổi (và user không bật cờ `CUSTOM_OVERRIDE=yes`).<br>2. Cập nhật lại file `users/$username.conf` theo Package mới.<br>3. Gọi Daemon áp dụng lại Cgroups, PHP-FPM và MySQL Limits. |
| `user_destroy_post.sh` | Khi xóa User khỏi hệ thống | 1. Xoá thư mục `/etc/systemd/system/user-<UID>.slice.d/`.<br>2. Xoá file `users/$username.conf`.<br>3. Chạy `systemctl daemon-reload`. |
| `database_user_create_post.sh` | Khi User tạo thêm DB User mới trên giao diện DA | 1. Lấy biến môi trường `$user` (System User) và `$dbuser` (MySQL User vừa tạo).<br>2. Đọc cấu hình MySQL của `$user`.<br>3. Thực thi ngay câu lệnh `ALTER USER '$dbuser'@'localhost' WITH ...` để DB User mới tạo không bị lọt lưới. |

---

## 8. ĐẶC TẢ MÃ NGUỒN MẪU CHO CÁC MODULE CỐT LÕI (PROOF OF CONCEPT)

Dưới đây là mã nguồn khung (Blueprint) để đội ngũ kỹ thuật tham khảo và phát triển chi tiết.

### 8.1. Code mẫu: Script áp dụng giới hạn Cgroups v2 & MySQL (`apply_user_limits.sh`)

```bash
#!/usr/bin/env bash
# Đường dẫn: /usr/local/directadmin/plugins/da_resource_limiter/scripts/apply_limits.sh
# Chạy dưới quyền: root (được gọi bởi Daemon hoặc Hook)

set -euo pipefail

USERNAME="${1:-}"
if [[ -z "$USERNAME" ]]; then
    echo "Usage: $0 <username>"
    exit 1
fi

# Kiểm tra user tồn tại trên OS
if ! id "$USERNAME" &>/dev/null; then
    echo "Error: User $USERNAME does not exist."
    exit 1
fi

USER_UID=$(id -u "$USERNAME")
PLUGIN_DIR="/usr/local/directadmin/plugins/da_resource_limiter"
USER_CONF="${PLUGIN_DIR}/data/users/${USERNAME}.conf"
DEFAULT_CONF="${PLUGIN_DIR}/data/default.conf"

# Load cấu hình
if [[ -f "$USER_CONF" ]]; then
    source "$USER_CONF"
else
    source "$DEFAULT_CONF"
fi

# 1. Cấu hình Systemd Slice (Cgroups v2)
SLICE_DIR="/etc/systemd/system/user-${USER_UID}.slice.d"
mkdir -p "$SLICE_DIR"

cat <<EOF > "${SLICE_DIR}/50-da-limits.conf"
[Slice]
CPUAccounting=yes
CPUQuota=${CPU_QUOTA}%
MemoryAccounting=yes
MemoryHigh=${MEM_HIGH_MB}M
MemoryMax=${MEM_MAX_MB}M
MemorySwapMax=0M
IOAccounting=yes
IOWeight=${IO_WEIGHT}
TasksAccounting=yes
TasksMax=${TASKS_MAX}
EOF

systemctl daemon-reload
# Khởi tạo hoặc áp dụng trực tiếp lên slice nếu đang chạy
systemctl start "user-${USER_UID}.slice" || true

# 2. Tạo sub-cgroup cho PHP-FPM và các tiến trình nằm ngoài PAM
CGROUP_BASE="/sys/fs/cgroup/user.slice/user-${USER_UID}.slice"
if [[ -d "$CGROUP_BASE" ]]; then
    mkdir -p "${CGROUP_BASE}/da-php.scope"
fi

# 3. Áp dụng giới hạn MySQL/MariaDB cho toàn bộ DB User của khách hàng
DA_MYSQL_CONF="/usr/local/directadmin/conf/mysql.conf"
DB_ROOT_USER=$(grep '^user=' "$DA_MYSQL_CONF" | cut -d= -f2)
DB_ROOT_PASS=$(grep '^passwd=' "$DA_MYSQL_CONF" | cut -d= -f2)

MYSQL_CMD="mysql -u${DB_ROOT_USER} -p${DB_ROOT_PASS} -N -B"

# Lấy danh sách tất cả các MySQL user thuộc về USERNAME
DB_USERS=$($MYSQL_CMD -e "SELECT CONCAT(\"'\", User, \"'@'\", Host, \"'\") FROM mysql.user WHERE User = '${USERNAME}' OR User LIKE '${USERNAME}\_%';")

if [[ -n "$DB_USERS" ]]; then
    while IFS= read -r db_user_host; do
        [[ -z "$db_user_host" ]] && continue
        $MYSQL_CMD -e "ALTER USER ${db_user_host} WITH MAX_USER_CONNECTIONS ${MYSQL_MAX_CONNECTIONS} MAX_STATEMENT_TIME ${MYSQL_MAX_STATEMENT_TIME_SEC};"
    done <<< "$DB_USERS"
    $MYSQL_CMD -e "FLUSH USER_RESOURCES;"
fi

echo "Successfully applied OS & MySQL limits for user ${USERNAME} (UID: ${USER_UID})."
```

### 8.2. Logic Daemon: Đẩy PHP-FPM vào Cgroup & Giám sát MySQL (Python/Go Pseudocode)

```python
# Mô tả thuật toán cốt lõi của Daemon: da-resourced (Chạy bằng Python 3 hoặc Golang)
import os
import time
import pwd
import pymysql

CGROUP_ROOT = "/sys/fs/cgroup/user.slice"

def sync_php_fpm_pids():
    """
    Quét các worker process của PHP-FPM và đưa vào đúng Cgroup v2 của từng User
    """
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            proc_path = f"/proc/{pid}"
            # Đọc tên tiến trình
            with open(f"{proc_path}/comm", "r") as f:
                comm = f.read().strip()
            if not comm.startswith("php-fpm"):
                continue

            # Lấy UID sở hữu tiến trình
            stat_info = os.stat(proc_path)
            uid = stat_info.st_uid
            if uid < 1000:  # Bỏ qua master process (root) và system users
                continue

            # Kiểm tra cgroup hiện tại của PID
            with open(f"{proc_path}/cgroup", "r") as f:
                current_cg = f.read()
            
            target_scope_rel = f"user-{uid}.slice/da-php.scope"
            if target_scope_rel in current_cg:
                continue  # Đã nằm đúng cgroup

            # Đảm bảo slice và scope tồn tại
            target_dir = f"{CGROUP_ROOT}/user-{uid}.slice/da-php.scope"
            os.makedirs(target_dir, exist_ok=True)

            # Di chuyển PID vào da-php.scope
            with open(f"{target_dir}/cgroup.procs", "w") as f:
                f.write(pid)

        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue

def monitor_mariadb(db_conn, user_limits_cache):
    """
    Giám sát CPU (Active Threads/Time) và RAM (MEMORY_USED) của MariaDB theo từng User
    """
    with db_conn.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("""
            SELECT ID, USER, SUBSTRING_INDEX(USER, '_', 1) AS sys_user,
                   TIME_MS, MEMORY_USED, INFO
            FROM information_schema.PROCESSLIST
            WHERE COMMAND != 'Sleep' 
              AND USER NOT IN ('root', 'da_admin', 'system user')
        """)
        rows = cursor.fetchall()

    # Gom nhóm theo sys_user
    usage = {}
    for row in rows:
        u = row['sys_user']
        if u not in usage:
            usage[u] = {'mem': 0, 'threads': 0, 'queries': []}
        usage[u]['mem'] += int(row['MEMORY_USED'] or 0)
        usage[u]['threads'] += 1
        usage[u]['queries'].append(row)

    # Kiểm tra ngưỡng vi phạm
    for sys_user, data in usage.items():
        limits = user_limits_cache.get(sys_user, user_limits_cache['default'])
        max_mem_bytes = limits['MYSQL_MAX_MEM_MB'] * 1024 * 1024
        max_active = limits['MYSQL_MAX_ACTIVE_QUERIES']

        # Nếu vượt tổng RAM cho phép trong MySQL hoặc vượt số luồng chạy song song
        if data['mem'] > max_mem_bytes or data['threads'] > max_active:
            # Sắp xếp tìm query ngốn nhiều RAM hoặc chạy lâu nhất để Kill
            heaviest_query = sorted(
                data['queries'], 
                key=lambda x: (x['MEMORY_USED'], x['TIME_MS']), 
                reverse=True
            )[0]
            
            query_id = heaviest_query['ID']
            with db_conn.cursor() as cursor:
                cursor.execute(f"KILL QUERY {int(query_id)};")
            log_violation(sys_user, heaviest_query, data['mem'], data['threads'])
```

---

## 9. THIẾT KẾ GIAO DIỆN NGƯỜI DÙNG (UI/UX WIREFRAME & TÍNH NĂNG)

### 9.1. Giao diện Admin Level (`/CMD_PLUGINS_ADMIN/da_resource_limiter`)
Sử dụng Bootstrap 5 hoặc TailwindCSS tích hợp tương thích với giao diện **Evolution Skin** của DirectAdmin. Gồm 4 Tab:
1. **Tab 1 - Dashboard & Realtime Monitor:**
   * Hiển thị danh sách Top 10 User đang dùng nhiều CPU, RAM, và MySQL Memory nhất theo thời gian thực.
   * Đọc trực tiếp từ `/sys/fs/cgroup/user.slice/user-<UID>.slice/memory.current`, `cpu.stat` và socket của Daemon.
2. **Tab 2 - Cấu hình theo Package (Package Limits):**
   * Bảng liệt kê toàn bộ Hosting Package có trên DirectAdmin.
   * Cho phép chỉnh nhanh: `CPU (%)`, `RAM High (MB)`, `RAM Max (MB)`, `PHP Children`, `MySQL Max Conn`, `MySQL Max RAM (MB)`, `MySQL Max Time (s)`.
   * Nút **"Save & Sync All Users in Package"**.
3. **Tab 3 - Cấu hình từng User (User Overrides):**
   * Tìm kiếm theo tên User hoặc Domain.
   * Cho phép mở giới hạn riêng (Custom Override) cho các khách hàng VIP hoặc hạ giới hạn của các tài khoản đang bị lạm dụng.
   * Nút **"Reset về mặc định của Package"** và nút **"Unblock Penalty"** (nếu user đang bị khoá MySQL tạm thời).
4. **Tab 4 - Nhật ký vi phạm (Violation & OOM Logs):**
   * Bảng hiển thị: Thời gian | Username | Loại vi phạm (`Kernel OOM Killed`, `MySQL High Memory Kill`, `MySQL Slow Query Kill`, `Penalty Throttled`) | Chi tiết câu lệnh SQL hoặc tiến trình bị tiêu diệt.

### 9.2. Giao diện User Level (`/CMD_PLUGINS/da_resource_limiter`)
Cung cấp thông tin minh bạch để khách hàng tự tối ưu mã nguồn (giảm tải cho bộ phận Support):
1. **Thanh trạng thái (Progress Bars):**
   * CPU Usage: `45% / 150%`
   * Physical Memory (RAM): `620 MB / 2048 MB`
   * Active Processes: `8 / 100`
   * MySQL Memory & Connections: `12 MB / 256 MB` (`3 / 20 connections`)
2. **Cảnh báo thông minh:**
   * Hiển thị số lần chạm ngưỡng giới hạn (`MemoryHigh Throttled` hoặc `OOM Kills`) trong 24 giờ qua.
   * Bảng hiển thị **Top 5 câu lệnh SQL bị hệ thống ngắt** do chạy quá lâu hoặc ăn quá nhiều RAM (hiển thị kèm thời gian và nội dung câu lệnh `SELECT ...` để đội code của khách hàng tự kiểm tra và đánh Index).

---

## 10. LỘ TRÌNH PHÁT TRIỂN & NGHIỆM THU (DEVELOPMENT MILESTONES)

Dự án được chia thành **4 Giai đoạn (Phases)** với tổng thời gian dự kiến từ **3 đến 4 tuần**:

### Giai đoạn 1: Nghiên cứu & Xây dựng Core OS/DB Engine (Tuần 1)
* **Công việc:**
  * Chuẩn hóa môi trường test (AlmaLinux 8/9 + DirectAdmin + Cgroups v2 + MariaDB 10.6+).
  * Viết bộ script quản lý `user-<UID>.slice` và kiểm thử giới hạn CPU/RAM bằng công cụ `stress-ng`.
  * Phát triển module di chuyển PID của PHP-FPM vào `da-php.scope` và xác nhận RAM/CPU của PHP-FPM được tính chính xác vào `user-<UID>.slice`.
* **Tiêu chí nghiệm thu (DoD):**
  * Chạy 1 file PHP cố tình ngốn 4GB RAM (`str_repeat`) -> Chỉ tiến trình của user đó bị OOM Kill ở đúng mốc `MemoryMax=2GB`, các website khác phản hồi bình thường.

### Giai đoạn 2: Xây dựng Daemon `da-resourced` & MariaDB Watchdog (Tuần 2)
* **Công việc:**
  * Viết Daemon bằng Golang hoặc Python (chạy dưới dạng `systemd service` có `Restart=always`).
  * Xây dựng module `MariaDB Governor`: Đọc `information_schema.PROCESSLIST`, tính toán RAM/Threads theo prefix của User, thực thi `KILL QUERY` và cơ chế `Penalty Box`.
  * Xây dựng Unix Domain Socket `/var/run/da-resourced.sock` để giao tiếp với Plugin.
* **Tiêu chí nghiệm thu (DoD):**
  * Giả lập 1 User chạy 10 câu lệnh `BENCHMARK()` hoặc `SELECT` bảng lớn không có index -> Daemon tự động cắt các query vượt ngưỡng sau $X$ giây và đưa user vào Penalty Box mà CPU tổng của `mysqld` không bị treo 100%.

### Giai đoạn 3: Phát triển DirectAdmin Hooks & Giao diện Plugin (Tuần 3)
* **Công việc:**
  * Đóng gói cấu trúc thư mục chuẩn `/usr/local/directadmin/plugins/da_resource_limiter`.
  * Viết bộ Hooks (`user_create_post.sh`, `user_modify_post.sh`, `database_user_create_post.sh`).
  * Xây dựng giao diện Admin Level và User Level.
* **Tiêu chí nghiệm thu (DoD):**
  * Tạo mới 1 User trên DirectAdmin -> Tự động sinh đầy đủ cấu hình Cgroup Slice và giới hạn MySQL trong vòng < 2 giây.

### Giai đoạn 4: Kiểm thử tải (Stress Test), Đóng gói & Bàn giao (Tuần 4)
* **Công việc:**
  * Kiểm thử hiệu năng của chính Daemon `da-resourced` (đảm bảo bản thân Daemon chiếm **< 1% CPU** và **< 30MB RAM** trên máy chủ có 300–500 hosting accounts).
  * Viết script `install.sh` và `uninstall.sh` tự động hóa hoàn toàn (1-click install).
  * Viết tài liệu hướng dẫn vận hành cho bộ phận Support/SysAdmin.

---

## 11. KỊCH BẢN KIỂM THỬ NGHIỆM THU (QA / TEST CASES)

Bộ phận Kỹ thuật và QA phải vượt qua toàn bộ 5 kịch bản kiểm thử thực tế sau trước khi đưa lên môi trường Production:

| Mã TC | Kịch bản tấn công / Giả lập | Hành vi kỳ vọng của Hệ thống |
| :--- | :--- | :--- |
| **TC-01** | **PHP CPU Spike:** User chạy vòng lặp `while(true){}` trên 10 tab trình duyệt cùng lúc (Gói giới hạn `CPUQuota=100%`). | Tổng CPU của toàn bộ các tiến trình `php-fpm` thuộc user đó cộng lại bị khoá cứng ở mức `100%` (1 core), không thể ăn sang các core khác của máy chủ. |
| **TC-02** | **PHP/Cron Memory Leak:** User chạy script PHP hoặc Cronjob cấp phát mảng dữ liệu vượt quá `MemoryMax=1024M`. | Tiến trình vi phạm bị Kernel OOM Killer tiêu diệt ngay khi chạm 1024MB. Log ghi nhận sự kiện OOM trong `dmesg` / `journalctl` của slice đó. Dịch vụ `php-fpm` master và các user khác không bị gián đoạn. |
| **TC-03** | **SSH / Cron Fork Bomb:** User chạy lệnh `:(){ :|:& };:` qua SSH hoặc PHP `proc_open`. | Bị chặn đứng ngay lập tức khi tổng số tiến trình chạm ngưỡng `TasksMax=100`. |
| **TC-04** | **MySQL Slow / Heavy CPU Query:** User chạy câu lệnh SQL nặng kéo dài quá `MYSQL_MAX_STATEMENT_TIME_SEC=10`. | MariaDB tự động huỷ câu lệnh ở giây thứ 10 với mã lỗi `Query execution was interrupted (max_statement_time exceeded)`. |
| **TC-05** | **MySQL Memory Flood:** User mở 15 kết nối cùng lúc, mỗi kết nối chạy câu lệnh ngốn 30MB RAM bảng tạm (Tổng 450MB > Giới hạn 256MB của User). | Daemon `da-resourced` phát hiện tổng `MEMORY_USED` của các DB user thuộc `username_*` vượt 256MB -> Tự động `KILL QUERY` các luồng nặng nhất và ghi vào `mysql-kills.log`. |