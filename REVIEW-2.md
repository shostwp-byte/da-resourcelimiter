# Code Review lần 2 — remediation v1.0.4.1

Lần review này kiểm tra lại `da-resourcelimiter` tại `origin/main` = `766454f` (tag `v1.0.4.1` = `fed4d25`).
Phạm vi là các commit sửa theo REVIEW lần 1: `8cbd700` (security remediation), `fed4d25` (ci) và `766454f` (ui).
Diff gồm 38 file, khoảng +3.100/−750 dòng. Lần này cũng chỉ đọc code, không sửa code dự án.

## Đánh giá chung

Bản sửa làm kỹ và đi đúng hướng. Cả 3 mục **Cao** của lần 1 đã được xử lý trong code:

- **S1:** repo cập nhật được ghim. Muốn đổi phải ghi `ALLOW_CUSTOM_REPO=yes` lên đĩa.
  - Release được ký bằng Ed25519, khóa công khai nhúng trong binary.
  - Thứ tự kiểm tra trước khi chạy `update.sh` là đúng: chữ ký → SHA → giải nén.
  - Nhóm thao tác cập nhật chỉ cho root/`diradmin` gọi.
- **S2:** khối tải UI từ `main` đã bị bỏ. `install.sh` giờ fail-closed khi bundle thiếu file.
- **R1:** `Classifier.ScanOnce` đã có mutex, kèm test chạy đồng thời.

Hầu hết mục Trung bình/Thấp cũng đã sửa (bảng bên dưới). Không thấy lỗi biên dịch khi đọc code, không thấy
deadlock, và bộ đọc log ngược xử lý đúng các trường hợp biên.

Tuy vậy bản sửa sinh ra một số vấn đề mới. Ba vấn đề cần xử lý trước bản kế tiếp:

1. **N1 (Cao):** release v1.0.4.1 **không có `checksums.txt.sig`**, nhưng daemon v1.0.4.1 lại từ chối
   release không ký. Workflow vẫn publish khi thiếu secret ký. Nếu bản sau cũng không ký, mọi server v1.0.4.1
   sẽ không tự cập nhật được nữa.
2. **N2 (Trung bình, hồi quy):** cơ chế dọn drop-in mồ côi (sửa cho R5) sẽ **xóa giới hạn cgroup của mọi
   user** nếu thư mục users của DA tạm thời không đọc được.
3. **N3 (Trung bình, hồi quy):** validate mới `PENALTY ≤ MAX` loại user khỏi mọi cơ chế giới hạn sau khi
   nâng cấp, và có thể để user kẹt vĩnh viễn ở mức phạt.

## Trạng thái các phát hiện lần 1

| # | Trạng thái | Ghi chú |
|---|---|---|
| S1 | **Đã sửa** (*cần xác nhận UID chạy plugin*) | `config.go:492-527`, `service.go:265-368`, `engine.go:110-119, 666-704`. Kết quả phụ thuộc DA chạy plugin admin dưới UID nào (xem N11). Release thực tế chưa ký (N1). |
| S2 | **Đã sửa** | `install.sh:250-274` |
| S3 | **Đã sửa** | Token HMAC + Origin/Sec-Fetch-Site (`api.php:319-348, 452-463`). Đã thử bằng PHP các host giả như `srv.com.evil.com`, `srv.com:2222@evil.com` và đều bị chặn. Còn lỗi phụ N10, N12. |
| S4 | **Đã sửa** | Token truyền qua `curl -K -` từ stdin |
| S5 | **Một phần** | Đã kiểm tra UID trước khi decode, có semaphore, rate-limit, và đọc log theo khối 32 KB. Còn N8 và N16. |
| S6 | **Đã sửa** | Regex cho repo/tag, dùng `url.PathEscape` |
| S7 | **Đã sửa** | `update.sh:22-35, 61-88, 284-289`, `sanitizeTag` |
| S8 | **Một phần** | Đã thêm hardening nhưng có thể chặn ghi cgroup và socket MySQL (N7) |
| S9 | **Đã sửa** | `governor.go:256-283` kiểm tra chủ sở hữu và blocklist tài khoản hệ thống |
| S10 | **Một phần** | Đã pin SHA, thu hẹp `contents: write` và kiểm tra tag nằm trên `main`. Nhưng vẫn publish khi không có chữ ký (N1). |
| S11 | **Một phần** | README đã pin theo tag, nhưng chỉ kiểm tra SHA lấy từ cùng release |
| R1 | **Đã sửa** | `classifier.go:39-63`, test `classifier_test.go:116-131` |
| R2 | **Đã sửa** | Nhưng sinh ra N3 |
| R3 | **Đã sửa** | Cờ `inFlight`, thư mục stage có nonce, `flock` |
| R4 | **Một phần** | Đã tách goroutine, đặt timeout cho `mysql` và gom ALTER thành batch. Còn N4, N5, N9. |
| R5 | **Đã sửa** | Nhưng sinh ra N2 |
| R6 | **Một phần** | Đã dùng tên tạm ngẫu nhiên, `flock` và so sánh lại trước khi rename, nhưng DA không tôn trọng file khóa này |
| R7 | **Đã sửa** | Dùng `os.CreateTemp` |
| R8 | **Đã sửa** | Escape `\` rồi `"`, bỏ CR/LF, chỉ ghi file khi nội dung đổi |
| R9 | **Đã sửa** | Xóa cả thư mục `staging/<tag-nonce>` |
| R10 | **Một phần** | Đã kiểm lại comm/UID/starttime trước khi ghi, nhưng vẫn ghi `cgroup.procs` ngoài systemd |
| R11 | **Đã sửa** | Ngưỡng UID chỉnh được qua env, có log số tài khoản bị bỏ qua |
| Q1 | **Đã sửa** | CI đã chạy `gofmt -l` và `staticcheck` |
| Q2 | **Một phần** | Đã thêm test đồng thời, test orphan và test đọc ngược. Chưa có test cho N2, N3, N4. |
| Q3 | **Đã sửa** | Chỉ decode entity khi cần |
| Q4 | **Chấp nhận được** | Phiên bản vẫn nằm ở 3 nơi, nhưng CI và release bắt buộc chúng khớp nhau |

## Phát hiện mới

### Cao

| # | Vị trí | Kịch bản lỗi | Đề xuất sửa |
|---|---|---|---|
| N1 | `.github/workflows/release.yml:114-119, 154-156`, release `v1.0.4.1` | Khi thiếu secret `RELEASE_SIGNING_PRIVATE_KEY`, workflow chỉ in `::warning::` rồi **vẫn publish**. Release v1.0.4.1 thực tế chỉ có 4 asset (`checksums.txt`, 2 tarball, `manifest.json`), không có `.sig` (đã kiểm tra bằng `gh release view`). Daemon v1.0.4.1 có khóa công khai nhúng sẵn và từ chối release thiếu `.sig` (`service.go:266-270`). Vậy nếu bản kế tiếp cũng không ký, **không server nào tự cập nhật được**. Nếu không ai còn giữ khóa riêng ứng với pubkey trong `version.go:11` (*cần xác nhận với người bảo trì*), toàn bộ server v1.0.4.1 phải cập nhật tay qua SSH. | Workflow phải fail-closed: `exit 1` khi secret rỗng, và bắt buộc có `.sig` trong danh sách asset. Xác nhận ai đang giữ khóa riêng và nạp vào secret. Ký bổ sung `checksums.txt` của v1.0.4.1 và tải `.sig` lên, hoặc phát hành bản có ký. |

### Trung bình

| # | Vị trí | Kịch bản lỗi | Đề xuất sửa |
|---|---|---|---|
| N2 | `dausers.go:107-116, 146-149`, `cgroup.go:265-320`, `main.go:354-360`, `engine.go:213, 329-330` | **Hồi quy so với v1.0.4.** Có hai đường dẫn tới việc xóa drop-in của user đang hoạt động. (1) Nếu `os.ReadDir(daUsersDir)` gặp `ENOENT` (DA đang cài lại/restore, `/usr/local` mount trễ, env sai), `Reload()` trả `nil` với registry **rỗng**. Lần prune 30s kế tiếp coi mọi UID là mồ côi, xóa toàn bộ `50-da-limits.conf` rồi `daemon-reload`, nên mọi user mất giới hạn CPU/RAM. Khi thư mục xuất hiện lại cũng không có gì áp lại, vì vòng 30s chỉ prune, không apply; phải chờ SIGHUP hoặc restart. (2) Nếu `user.conf` của một user đọc lỗi (không phải ENOENT, ví dụ dòng dài hơn 64 KB làm bufio báo token too long), user đó bị bỏ khỏi registry rồi drop-in của họ cũng bị xóa. | Coi việc thiếu thư mục users là lỗi. Không prune khi registry rỗng hoặc khi số file sắp xóa vượt ngưỡng (ví dụ hơn 20%). Chỉ xóa UID vắng mặt qua 2 lần reload liên tiếp hoặc đã không còn trong `/etc/passwd`. Giữ nguyên user khi `user.conf` đọc lỗi. Thêm test cho các trường hợp này. |
| N3 | `config.go:128-133, 394-396`, `engine.go:173-177`, `governor.go:653-679` | **Hồi quy khi nâng cấp.** Rule mới `PENALTY_CONN ≤ MAX_CONNECTIONS` và `PENALTY_TIME ≤ MAX_STATEMENT_TIME` áp lên cấu hình cũ. Ví dụ `MYSQL_MAX_CONNECTIONS=1` với `PENALTY_CONN` mặc định là 2 sẽ làm `ResolveUserLimits` trả lỗi. Nếu giá trị lỗi nằm ở `default.conf` thì **mọi user** bị ảnh hưởng. Khi đó `ApplyAll` bỏ qua user, Classifier coi user là `!Enabled` nên không chuyển worker PHP vào slice, và `PollOnce` không kill query. Riêng `expirePenalties` đã xóa và lưu trạng thái penalty **trước** khi resolve, nên user kẹt vĩnh viễn ở mức phạt. Validate cũng chạy cả khi `ENABLED=no`, nên không tắt được user lỗi. Daemon vẫn khởi động bình thường, nên lỗi này âm thầm. | Khi đọc file, clamp `PENALTY = min(PENALTY, MAX)` và ghi cảnh báo thay vì trả lỗi; thêm migration trong `MigrateDefaultKeys`. Bỏ qua validate MySQL khi `Enabled=false`. Trong `expirePenalties`, chỉ xóa penalty sau khi khôi phục giới hạn thành công (gồm cả N14). |
| N4 | `mysqlgov/client.go:160-166, 184-190`, `governor.go:236-240, 344-348, 562-565` | `ExecBatch` gửi cả batch qua stdin cho `mysql` mà **không có `--force`**, nên `mysql` dừng ở câu lỗi đầu tiên. Nếu một DB user bị DA xóa giữa lúc `SELECT` và `ALTER` (ERROR 1396), thì mọi ALTER sau dòng đó và `FLUSH USER_RESOURCES` đều bị bỏ. Lỗi chỉ được ghi log, và `ApplyAll` chỉ chạy lại khi có SIGHUP hoặc restart. Batch `KILL QUERY` cũng vậy: một thread vừa kết thúc (ERROR 1094) làm các lệnh KILL còn lại trong vòng đó bị bỏ, dù comment trong code ghi "ignore benign race". | Thêm `--force` cho `ExecBatch` (giữ nguyên `QueryTSV`), parse stderr để log các dòng lỗi. Hoặc chia batch thành nhiều phần nhỏ và thử lại từng user khi lỗi. |
| N5 | `client.go:22, 153-158`, `main.go:259, 349` | Timeout 5s (`QueryTimeout`) áp cho **mỗi lần gọi `mysql`**, kể cả batch ALTER cho mọi user. Vì vậy ctx 2-3 phút của `ApplyAll` không có tác dụng. Khi có hàng nghìn `user@host` hoặc MariaDB đang tải cao, batch bị SIGKILL giữa chừng (*cần xác nhận trên server lớn*). | Cho `ExecBatch` timeout riêng, dài hơn hoặc tỷ lệ với số câu lệnh, hoặc chia batch (khoảng 200 câu mỗi lần). |
| N6 | `scripts/install.sh:203-222` | Phần kiểm tra chữ ký trong installer không có tác dụng bảo mật vì 3 lý do: (a) thiếu `.sig` thì bỏ qua im lặng, đúng như hiện trạng v1.0.4.1; (b) dùng chính binary `da-resourced` lấy từ tarball chưa được tin cậy để verify, nên kẻ chiếm repo chỉ cần đổi binary là luôn báo OK; (c) `tar -xzf` dưới quyền root chạy **trước** khi verify. | Bắt buộc có `.sig`. Ghim pubkey ngay trong script và verify bằng công cụ độc lập trước khi giải nén (`openssl pkeyutl -verify -rawin` với OpenSSL ≥ 3, hoặc `minisign`). Nếu chưa làm được thì ghi rõ trong README rằng installer chỉ kiểm tra SHA. |
| N7 | `systemd/da-resourced.service:22, 26, 29` (*cần xác nhận trên máy thật*) | (a) `ProtectKernelTunables=yes` mount `/sys` read-only. `ProtectControlGroups=no` chỉ có nghĩa là không thêm mount read-only riêng cho cgroup, chứ không đảm bảo `/sys/fs/cgroup` ghi được. Nếu `/sys/fs/cgroup` thành read-only, Classifier ghi `cgroup.procs` sẽ nhận EROFS: giới hạn PHP mất tác dụng âm thầm trong khi `ping` vẫn báo OK. (b) `PrivateTmp=yes` làm daemon không thấy `/tmp/mysql.sock` trên các bản cài DA/CustomBuild đặt socket ở đó, nên governor MySQL ngừng hoạt động. | Thêm `ReadWritePaths=/sys/fs/cgroup`, hoặc bỏ `ProtectKernelTunables`. Kiểm tra socket MySQL trong `install.sh`, hoặc bỏ `PrivateTmp`. Chạy thử trên server thật: kiểm tra một worker PHP đã nằm trong `da-php.scope`. |
| N8 | `ipc/server.go:152-166, 174, 211-251`, `engine.go:92-105` | Rate-limit đếm 20 kết nối mỗi 5s theo UID, nhưng **không giới hạn số kết nối đồng thời theo UID**. Deadline đọc là 15s, còn semaphore 64 slot dùng chung. Một tenant mở kết nối rồi không gửi gì sẽ giữ khoảng 60 slot. Thêm 1 tài khoản nữa là trang thống kê của mọi user khác báo "server busy". Ngoài ra, mỗi kết nối còn quét `/etc/passwd`, `admin.list` và `user.conf` (2 lần `IsAuthorizedAdminUID`) trước khi bị rate-limit. | Giới hạn 2-4 kết nối đồng thời mỗi UID. Đặt deadline khoảng 2s cho tới khi đọc xong request. Cache kết quả UID→admin vài giây. |
| N9 | `engine.go:125, 227, 319, 366-373, 543, 563, 610`, `ipc/server.go:174, 202`, `ipc/client.go:24`, `main.go:376-395` | Có ba vấn đề liên quan. (a) Handler IPC chờ `applyMu` bằng `Lock()` không theo ctx, vẫn giữ slot admin sau khi quá deadline. Trong lúc `ApplyAll` nền chạy vài phút mà DA restore hàng loạt user, từ request thứ 33 sẽ nhận "server busy" và các user đó không được áp giới hạn. Khi SIGTERM, `ipcServer.Wait()` treo tới `TimeoutStopSec`. (b) Client chờ 10s, server cho 15s, mà hook `apply-package` bọc `timeout 20s`. Khi client timeout, CLI fallback sang chạy cùng việc **ngay trong tiến trình CLI**, song song với daemon và ngoài `applyMu`, nên hai bên cùng ghi drop-in và `user.conf`. (c) ctx 5 phút của job nền được tạo **trước** khi chờ khóa. Lưu liên tiếp hai lần thì job thứ hai chỉ còn khoảng 1 phút, `daemon-reload` hết hạn và drop-in đã ghi mà systemd chưa nạp. Mỗi lần lưu tạo một goroutine `ApplyAll` mới (không gộp), không nằm trong `wg` và UI không thấy trạng thái. | Mỗi request có `context.WithTimeout` riêng. Thay `applyMu` bằng khóa nhận ctx (`chan struct{}` + `select`). CLI chỉ fallback khi không kết nối được socket, không fallback khi timeout. Dùng một worker duy nhất có cờ dirty cho `ApplyAll`, tạo ctx sau khi đã lấy khóa, và lưu trạng thái job để UI đọc được. |
| N10 | `plugin/admin/api.php:242-249, 280-305`, `api.raw` (`php -n`) (*cần xác nhận*) | Khi PHP chạy với `-n` mà không có extension posix (thường gặp với `/usr/bin/php` trên RHEL), hàm `getmyuid()` trả UID **chủ sở hữu file script** (diradmin) thay vì UID của tiến trình. File khóa CSRF được tạo bởi UID thật, nên mọi lần đọc sau đều thấy UID lệch, secret thành rỗng, và **mọi thao tác lưu/áp dụng trả 403**. Lỗi này fail-closed nhưng làm plugin admin ngừng hoạt động. | Khi không có posix, lấy UID thật bằng cách `stat` một file tạm vừa tạo, hoặc báo lỗi rõ ràng. Trả thông báo riêng khi secret rỗng. |

### Thấp

| # | Vị trí | Kịch bản lỗi | Đề xuất sửa |
|---|---|---|---|
| N11 | `engine.go:110-119`, `plugin/admin/index.html:787-822` (*cần xác nhận trên DA*) | Kết quả của S1 phụ thuộc DA chạy plugin admin dưới UID nào. Nếu là `diradmin` cho mọi admin, admin phụ vẫn gọi được `trigger_update`/`rollback_update`. Nhờ repo đã ghim và có chữ ký, tác động chỉ còn là kích hoạt bản chính thức, hạ cấp hoặc rollback. Nếu là UID của admin đang đăng nhập, nút Update/Rollback trên UI **luôn lỗi**, vì UI không đọc `root_only_actions` để ẩn chúng. | Kiểm chứng trên DA thật. Ẩn hoặc vô hiệu hóa nút theo `root_only_actions`. Nếu plugin chạy dưới diradmin, chỉ cho cập nhật qua CLI root. |
| N12 | `api.php:206-217, 296-303` | Origin check trả `null` (tức cho qua) khi không có `HTTP_HOST` và `SERVER_NAME`, kể cả khi Origin là một trang lạ; lúc đó chỉ còn token bảo vệ. Ngược lại, khi đứng sau proxy, request hợp lệ có thể bị 403. File key dự phòng trong `/tmp` có khe giữa `fopen('xb')` và `chmod 0600`, nên user local khác có thể đọc được secret. | Có Origin mà không có host thì từ chối. Cho cấu hình danh sách host hợp lệ. Gọi `umask(0077)` trước `fopen`, hoặc bỏ nhánh dự phòng `/tmp`. |
| N13 | `service.go:213-345`, `signing.go` | Chữ ký chỉ bao `checksums.txt`, không gắn với tag, và không có kiểm tra chống hạ cấp. Kẻ chiếm repo có thể đăng lại bản cũ có ký dưới một tag mới. | Sau khi giải nén, so `manifest.json.version` với `rel.TagName`. Từ chối hạ cấp nếu không có cờ CLI cho phép. |
| N14 | `governor.go:653-679` | `expirePenalties` xóa và lưu trạng thái penalty **trước** khi khôi phục giới hạn gốc, và bỏ qua lỗi khôi phục. Nếu MariaDB timeout đúng lúc đó, user kẹt ở mức phạt. | Chỉ xóa penalty sau khi `ApplyUserAccountLimits` thành công. |
| N15 | `dausers.go:101-189`, `main.go:355` | `Registry.Reload` không được tuần tự hóa. Lần reload định kỳ dùng snapshot cũ có thể ghi đè snapshot có user vừa được hook tạo, rồi prune xóa drop-in của user đó. Cửa sổ rất hẹp. | Thêm `reloadMu`, hoặc chạy reload và prune trong `applyMu`. |
| N16 | `logger.go:129-150, 210-219` | (a) `CountSince` lọc theo username trước khi xét mốc thời gian, nên với user không có vi phạm trong 24h, mỗi lần gọi `get_user_stats` vẫn quét đủ 4×10 MB, 2 lần. (b) Nếu log rotate giữa lúc đọc, cùng một nội dung bị đọc 2 lần và số đếm bị nhân đôi. | Trích timestamp cả với dòng không khớp để dừng ở mốc cắt, và cache vài giây. Mở sẵn mọi fd khi còn giữ khóa. |
| N17 | `engine.go:284-289`, `classifier.go:84-91` | `ApplyPackage` gọi `ScanOnce(uid)` cho từng user trong khi giữ `applyMu`, nên quét `/proc` N lần. Mỗi lần quét còn đọc `stat` của mọi PID, kể cả PID không phải PHP. | Gọi `ScanOnce(ctx, 0)` một lần sau vòng lặp. Chỉ đọc `stat` khi `comm` là PHP. |
| N18 | `scripts/update.sh:6, 266-302` (lỗi cũ còn tồn tại) | Với `set -e`, lỗi ở bước deploy (ví dụ đầy đĩa) làm script thoát mà không rollback, trạng thái kẹt ở `running`. `SNAP_FILE=$(create_snapshot_backup)` không kế thừa `-e`, nên nếu `tar` lỗi script vẫn tiếp tục. | Dùng `trap … ERR` để rollback và ghi trạng thái `failed`. Thêm `shopt -s inherit_errexit` hoặc kiểm tra `-s "$SNAP_FILE"`. |
| N19 | `install.sh:9, 340`, `config.go:496-505` | `GITHUB_REPO` (fork) truyền cho installer được ghi vào `updater.conf` nhưng thiếu `ALLOW_CUSTOM_REPO=yes`, nên daemon âm thầm quay về repo upstream. | Cảnh báo khi repo khác mặc định, hoặc ghi rõ trong tài liệu. |
| N20 | nhiều nơi | Các điểm nhỏ: (a) blocklist thiếu `debian-sys-maint` (`governor.go:24-35`). (b) `isActiveQueryCommand` giờ chỉ tính `Query`/`Execute`, đây là thay đổi hành vi chưa được ghi lại (`governor.go:772-779`). (c) file khóa `.user.conf.da-limiter.lock` nằm lại trong thư mục user của DA (`classifier.go:246`). (d) UI không xóa token CSRF cũ sau 403 (`index.html:1098-1110`). (e) mock trong `governor_test.go:29-31` trả mọi user cho mọi query nên không kiểm tra được bộ lọc theo user. | (a) Thêm `debian-sys-maint` vào blocklist. (b) Ghi lại thay đổi này. (c) Chuyển file khóa sang `/run/da-resourced/locks/`. (d) Xóa token và thử lại một lần sau 403. (e) Cho mock lọc theo user. |

## Kiểm tra đã chạy

| Bước | Kết quả |
|---|---|
| `php -l` cho `api.php`, `stats.php` | Pass (PHP 8.5.11) |
| Kiểm tra CRLF trong `scripts/ plugin/ systemd/ Makefile` | Pass |
| Chạy thử `verify_same_origin_post()` với các header giả | Chặn đúng các host giả; xác nhận N12 (không có host thì cho qua) |
| Danh sách asset của release v1.0.4.1 (`gh release view`) | Không có `checksums.txt.sig` (N1) |
| Log Actions của release | Có warning thiếu secret ký; CI và Release đều xanh |
| `go vet`, `go test -race`, `staticcheck`, `shellcheck` | **Không chạy được**: máy review không có Go/ShellCheck. Đọc code không thấy lỗi biên dịch. |

**Chưa test được:** daemon trên DA/MariaDB thật (N2, N5, N7, N10, N11), cách DA truyền header cho plugin (N12),
và việc ai đang giữ khóa ký riêng (N1).

## Đề xuất thứ tự xử lý

1. **N1:** xác nhận khóa ký, nạp secret, cho workflow fail-closed, bổ sung `.sig` cho v1.0.4.1. Việc này phải
   xong trước khi phát hành bản tiếp theo.
2. **N2, N3:** chặn prune khi registry rỗng; clamp thay vì từ chối giá trị penalty; sửa thứ tự trong `expirePenalties` (N14).
3. **N7:** kiểm chứng sandbox systemd trên server thật (cgroup có ghi được không, socket MySQL có thấy không).
4. **N4, N5, N9:** dùng `--force` và chia batch, khóa nhận ctx, CLI chỉ fallback khi không kết nối được.
5. **N6, N8, N10, N11:** verify chữ ký độc lập trong installer, giới hạn kết nối theo UID, xử lý trường hợp
   thiếu posix, ẩn nút root-only.
6. Các mục Thấp còn lại.
