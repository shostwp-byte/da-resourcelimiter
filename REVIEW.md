# Code Review lần 1 — nhánh `wnreview`

Review `da-resourcelimiter` tại `8b762f7` (`main`, sau tag v1.0.4): plugin DirectAdmin gồm daemon Go chạy
root (`da-resourced`), cgroups v2, governor MariaDB, bộ cập nhật qua GitHub Releases, hook DA, relay PHP
và giao diện Evolution. Khoảng 9.900 dòng, không có dependency ngoài stdlib.
Review này chỉ đọc code, không sửa code dự án.

## Đánh giá chung

Thiết kế nền tảng khá chắc cho một plugin chạy root:

- **Xác thực socket:** dùng `SO_PEERCRED`, nên người dùng thường chỉ đọc được số liệu của chính UID
  mình (`engine.go:521-564`). Tên user trong request không được tin ở socket khách hàng.
- **Chống injection:** định danh qua `ValidateIdentifier`, SQL được escape, hook shell luôn quote biến,
  `mysql` nhận SQL qua stdin và mật khẩu qua file `0600`, nên không lộ trong `/proc/<pid>/cmdline`.
- **Updater:** có kiểm tra SHA-256, giải nén chống path traversal và bỏ qua symlink
  (`service.go:477-539`), bỏ header `Authorization` khi redirect sang host khác, có snapshot và tự rollback.
- **Giao diện:** mọi giá trị động trong `index.html` đều qua `esc()` hoặc `textContent`, không thấy XSS.
  Heredoc dùng dấu nháy đơn nên shell không bung biến.

Có 3 mục **Cao**:

1. **S1:** bất kỳ admin DirectAdmin nào (kể cả admin phụ, không phải root) đều lên được root. Chỉ cần
   đổi repo cập nhật sang repo của họ rồi bấm "Cập nhật". Checksum nằm cùng release nên không chứng minh
   được nguồn gốc.
2. **S2:** `install.sh` với bản release mới nhất (v1.0.4) luôn tải HTML chưa được kiểm tra từ nhánh
   `main` ghi đè giao diện admin và user.
3. **R1:** `Classifier.classifiedOK` là map không có mutex nhưng bị truy cập từ hai goroutine, nên daemon
   có thể crash (`fatal error: concurrent map ...`).

Hạn chế của lần review này: máy review không có Go và ShellCheck (xem phần "Kiểm tra đã chạy"), nên các
phát hiện về Go đều do đọc code và đối chiếu luồng gọi, chưa chạy thật.

## Phát hiện

### Bảo mật

| # | Mức | Vị trí | Kịch bản lỗi | Đề xuất sửa |
|---|---|---|---|---|
| S1 | **Cao** | `engine.go:482-513`, `config.go:458-483`, `updater/service.go:185-285`, `update.sh:217-241` | Admin phụ trong `admin.list` được daemon coi là admin (`IsAuthorizedAdminUID`, `engine.go:310-340`). Họ gọi `save_updater_config` với `github_repo` là repo của họ, rồi `trigger_update`. Daemon tải tarball cùng `checksums.txt` từ chính release đó (SHA-256 chỉ chống hỏng file, không chống giả mạo), rồi `systemd-run` chạy `scripts/update.sh` **lấy từ tarball** dưới root (`service.go:271-279`). Kết quả là root trên server hosting. Cùng đường này cũng mở ra nếu tài khoản GitHub của repo bị chiếm. | Ghim repo cập nhật trong binary hoặc chỉ cho đổi bằng CLI root, không qua IPC. Ký release (Ed25519, public key nhúng trong binary, kiểm tra trước khi chạy `update.sh`). Cân nhắc chỉ cho root/`diradmin` gọi nhóm `save_updater_config`, `trigger_update`, `rollback_update`. |
| S2 | **Cao** | `install.sh:210-220` | Khối "sync Evolution Skin" chạy khi bundle thiếu `plugin/images/admin_icon.svg`. Tag v1.0.4 chưa có file này (đã kiểm tra bằng `git ls-tree v1.0.4`), nên **mọi lần cài từ release mới nhất** đều `curl` 6 file từ `raw.githubusercontent.com/.../main/` (cả `admin/index.html`, `user/index.html`) và ghi đè bản đã xác thực, không có checksum. Các file này là script chạy dưới DA và là JS trong phiên admin; JS có thể gọi `trigger_update` (xem S1). Hệ quả phụ: bản cài ra không khớp với version (UI của `main` + daemon v1.0.4). | Bỏ khối này. Phát hành lại release có đủ file. Nếu bắt buộc thì tải đúng tag, kiểm tra checksum, và fail-closed. |
| S3 | Trung bình (*cần xác nhận*) | `plugin/admin/api.php:186-207`, `index.html:765-780` | Relay chỉ yêu cầu `POST` cho hành động ghi, không có CSRF token, `Origin` hay `Referer` riêng. Nếu DirectAdmin core không chặn, một trang ngoài do admin mở có thể gửi form `POST` tới `/CMD_PLUGINS_ADMIN/da_resource_limiter/api.raw` với `payload_b64=...` (do `POST` env và `QUERY_STRING` đều được nhận), từ đó đổi giới hạn hoặc nối vào S1. Chưa kiểm tra được cơ chế chống CSRF của DA trên server thật. | Thêm kiểm tra `HTTP_ORIGIN`/`HTTP_REFERER` cùng host, hoặc token nhúng trong HTML và kiểm tra ở `api.php`. Với `trigger_update`, nên cần xác nhận lại mật khẩu. |
| S4 | Trung bình | `install.sh:131-135, 165-168, 213`, `README.md:35` | `GITHUB_TOKEN` được đưa vào tham số dòng lệnh của `curl -H "Authorization: Bearer …"`. Trên server hosting nhiều user, `ps`/`/proc/<pid>/cmdline` cho mọi user thấy token (trừ khi `hidepid`) trong thời gian cài. Token của repo private bị lộ. | Truyền header qua `curl -K -` (config từ stdin) hoặc `-H @file` với file `0600`. Ghi chú trong README. |
| S5 | Trung bình (*cần xác nhận khi chạy thật*) | `ipc/server.go:62-69, 113-147`, `logger/logger.go:112-204`, `engine.go:604-622` | Socket khách hàng `0666`, mỗi kết nối tạo goroutine, không giới hạn số kết nối hay tần suất. Mỗi `get_user_stats` gọi `Logger.Query` (50) và `CountSince` (1000), và `readMatchingFileReverse` đọc **toàn bộ** file JSONL (tối đa 4 file × 10 MB) vào RAM (`allLines`). Một user hosting chạy vòng lặp PHP mở 100 kết nối là đẩy daemon root (`OOMScoreAdjust=-900`) ngốn RAM/CPU. Ngoài ra JSON được parse trước khi kiểm tra UID (`server.go:126-137`). | Semaphore giới hạn kết nối đồng thời, rate-limit theo UID, kiểm tra UID trước khi decode, đọc log ngược từ cuối file (hoặc cache kết quả vài giây). |
| S6 | Thấp | `config.go:462-464`, `updater/service.go:342, 364`, `engine.go:728-733` | Kiểm tra `github_repo` chỉ cần chứa `/`, không có `..` và khoảng trắng; `target_version` không kiểm tra gì. Cả hai được ghép vào đường dẫn API GitHub (`/repos/%s/releases/tags/%s`) cùng `Authorization` token. Giá trị như `a/b?x=1` hoặc `%2e%2e/...` có thể trỏ sang endpoint khác. Chỉ GET, nên tác động thấp. | Regex chặt `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$` cho repo và `^v?[0-9A-Za-z.+-]+$` cho tag. Dùng `url.PathEscape`. |
| S7 | Thấp | `update.sh:28-37, 229-230, 248`, `service.go:573-584` | (a) `TARGET_VER` (tên tag lấy từ GitHub) được ghép thẳng vào `sed -i "s/^version=.*/version=${clean_ver}/"` và JSON status. Tag hợp lệ có thể chứa `/`, `;`, `$`, `"` nên làm hỏng `sed`/JSON; với GNU sed còn có thể dùng lệnh `e`. Bị chặn bớt vì kẻ tạo tag đã có quyền cao hơn (S1). (b) `rm -rf "$(dirname "$STAGE_DIR")"` không kiểm tra `STAGE_DIR` nằm dưới `/var/lib/da-resourced/staging`; chạy tay với tham số lạ sẽ xóa thư mục cha. (c) `sanitizeTag("..")` trả về `..`, nên `os.RemoveAll(StagingRoot/..)` xóa `/var/lib/da-resourced`; git không cho tên tag đó nhưng JSON từ repo tùy chọn thì có (S1). | Validate tag ở Go và ở script bằng một regex semver. Kiểm tra tiền tố staging trước khi `rm -rf`. Loại `.` và `..` trong `sanitizeTag`. |
| S8 | Thấp | `systemd/da-resourced.service:6-16` | Daemon chạy root không có hardening nào, trong khi nhận dữ liệu từ hai socket `0666`. | Thêm `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`, `ProtectKernelModules=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`… (loại bỏ các mục cần ghi `/etc/systemd`, `/sys/fs/cgroup`, dữ liệu DA). |
| S9 | Thấp | `governor.go:170-191`, `engine.go:195-212` | `apply_db_user` không kiểm tra DB user thuộc `daUsername`. Hook luôn truyền tên có tiền tố, nhưng lệnh gọi tay (CLI root hoặc socket admin) áp `MAX_USER_CONNECTIONS`/`MAX_STATEMENT_TIME` lên bất kỳ tài khoản nào, kể cả `da_admin` mà chính daemon dùng. Chỉ admin gọi được (api.php không whitelist action này). | Dùng `Registry.ResolveDBUser(dbUser)` và từ chối khi chủ sở hữu khác `daUsername`; chặn danh sách tài khoản hệ thống. |
| S10 | Thấp | `.github/workflows/release.yml:8-9, 17, 22`, `ci.yml:18, 21` | Action pin theo tag (`@v4`), không theo SHA. `contents: write` đặt ở mức workflow. Mọi tag `v*` push lên bất kỳ commit nào đều build và publish release, không kiểm tra commit nằm trên `main` hay CI đã xanh. | Pin SHA, hạ `contents: write` xuống job publish, kiểm tra tag nằm trên `main`, bật tag protection. |
| S11 | Thấp | `README.md:31-35` | Khuyến nghị `curl … /main/scripts/install.sh \| bash`: chính script cài đặt không được xác thực và không pin theo tag/commit. | Hướng dẫn tải script từ tag release, kèm checksum. |

### Độ tin cậy, race, mất dữ liệu

| # | Mức | Vị trí | Kịch bản lỗi | Đề xuất sửa |
|---|---|---|---|---|
| R1 | **Cao** | `fpm/classifier.go:32, 71, 112, 125, 130-134`, `engine.go:109-111`, `cmd/da-resourced/main.go:276-279` | `classifiedOK` là `map` thường, không có mutex. `ScanOnce` chạy ở goroutine chính mỗi 1 giây, và `Engine.ApplyUser` (gọi từ mỗi goroutine kết nối IPC khi admin lưu/áp dụng giới hạn, từ hook `user_create_post` / `user_modify_post`, hay `apply-package`) gọi `ScanOnce` lần nữa. Hai lần quét chạy song song đọc, ghi, xóa và `range` cùng một map, nên Go runtime báo `fatal error: concurrent map iteration and map write` và daemon thoát (không `recover` được). `Restart=always` kéo daemon lên sau 2s nhưng trạng thái trong RAM mất và giám sát gián đoạn. Test `-race` hiện tại không có test đồng thời nên không bắt được. Đã tự đọc code để xác nhận luồng gọi. | Thêm `sync.Mutex` bao quanh `ScanOnce` (hoặc cả map). Thêm test chạy `ScanOnce` song song với `go test -race`. |
| R2 | Trung bình | `config.go:76-114`, `governor.go:469-521` | `Validate()` bỏ qua toàn bộ trường penalty (`MySQLPenaltyThreshold/WindowSec/DurationSec/Conn/TimeSec`). Ngoài ra `ResolveUserLimits` không gọi `Validate()` cho giá trị đọc từ file. Hệ quả: `PENALTY_THRESHOLD ≤ 0` phạt ngay ở vi phạm đầu tiên; `DURATION ≤ 0` hết hạn tức thì; `PENALTY_CONN=0`/`TIME_SEC=0` được MariaDB hiểu là "không giới hạn" (`MAX_USER_CONNECTIONS 0`, `MAX_STATEMENT_TIME 0`), nghĩa là user bị "phạt" lại được nới giới hạn. | Validate khoảng giá trị cho các trường penalty (≥ 1), kể cả khi đọc từ file; coi giá trị 0 là lỗi cấu hình. |
| R3 | Trung bình | `updater/service.go:177-261, 264-285` | `StageRelease` luôn `os.RemoveAll(stageDir)` rồi tải lại, không có mutex hay kiểm tra job đang chạy. Bấm "Cập nhật" hai lần (hoặc hai admin) khiến lần gọi thứ hai xóa và ghi lại thư mục mà `update.sh` của lần đầu đang `cp`/`install` từ đó: cài dở dang, rồi rollback. `flock` trong `update.sh` chỉ bảo vệ phía script, sau khi đã stage xong. `writeJobStatus("staging")` cũng ghi đè trạng thái `running`. | Mutex trong `Service` và từ chối khi `update_status.json` đang `staging`/`running`; hoặc đặt tên thư mục stage kèm nonce. |
| R4 | Trung bình | `cmd/da-resourced/main.go:259-288`, `engine.go:121-163`, `server.go:124`, `mysqlgov/client.go:112-134` | Một vòng lặp duy nhất chạy FPM scan, `PollOnce` (spawn `mysql`), OOM check và `ApplyAll` khi `SIGHUP`. `mysql` chỉ có `--connect-timeout=3` và ctx không có timeout, nên khi MariaDB treo (lúc cần governor nhất) thì cả FPM classify và OOM check đều đứng. `ApplyAll` với hàng trăm user spawn 2 tiến trình `mysql` mỗi user nên vài phút; qua IPC thì vượt `SetDeadline(15s)` và timeout 15s của `api.php`, UI báo lỗi dù việc vẫn đang chạy. | `context.WithTimeout` cho mỗi lần chạy `mysql`; chạy mỗi tác vụ ở goroutine riêng; `ApplyAll` chạy nền và trả về job id/trạng thái; gom ALTER của nhiều user vào một batch. |
| R5 | Trung bình (*cần xác nhận thứ tự hook*) | `engine.go:215-234`, `scripts/da_hooks/user_destroy_post.sh`, `dausers/dausers.go:63-144` | Hook `user_destroy_post` chạy sau khi DA đã xóa user. `RemoveUser` không `Reload()` registry trước khi `LookupByName`; registry tự reload mỗi 30s và đường CLI fallback còn `Reload()` trước, nên user đã biến mất khỏi `/etc/passwd` thì `RemoveUserSlice` bị bỏ qua. File `/etc/systemd/system/user-<UID>.slice.d/50-da-limits.conf` bị bỏ lại, và nếu UID đó cấp lại cho user khác thì thừa hưởng giới hạn cũ. | Lưu UID vào ngay khi áp giới hạn (hoặc quét `user-*.slice.d/50-da-limits.conf` mồ côi so với registry) và dọn khi reload. |
| R6 | Thấp | `fpm/classifier.go:172-256` | `SyncDAUserPHPConf` đọc-sửa-ghi `user.conf` của DirectAdmin không khóa. Nếu DA ghi file giữa lúc đọc và `Rename` thì thay đổi của DA bị mất. Tên file tạm cố định `user.conf.da-limiter.tmp` nên hai lần gọi đồng thời (SIGHUP + IPC) có thể đè nhau. | Khóa (`flock`) theo file; tên tạm có hậu tố ngẫu nhiên; so sánh lại nội dung trước khi rename. |
| R7 | Thấp | `cgroup/cgroup.go:150-157` | Tương tự: `StageUserSlice` dùng tên tạm cố định `50-da-limits.conf.tmp`; hai `ApplyAll` chồng nhau (SIGHUP và `save_default_limits` với `sync_users`) cho một lần `Rename` lỗi `ENOENT`, user bị "skip" trong log. | Dùng `os.CreateTemp` như `config.atomicWriteFile`, hoặc mutex toàn Engine cho các thao tác Apply. |
| R8 | Thấp | `mysqlgov/client.go:78-89` | Mật khẩu trong `mysql.conf` chỉ escape dấu `"` mà không escape `\`. Trong option file, `\` trong giá trị có nháy là ký tự escape, nên mật khẩu chứa `\` sẽ sai và governor mất kết nối DB (chỉ khi dùng nhánh dựng file từ `mysql.conf`). Nhánh này còn ghi lại file và `rename` ở **mỗi** lần gọi (mỗi 1,5s). | Escape `\` thành `\\`; chỉ ghi lại khi nội dung đổi. |
| R9 | Thấp | `update.sh:248`, `updater/service.go:255-260` | Sau khi thành công, script `rm -rf "$(dirname "$STAGE_DIR")"`. `STAGE_DIR` là `.../staging/<tag>/unpacked/da-resource-limiter`, nên chỉ `unpacked` bị xóa; tarball (≤ 150 MB) và `checksums.txt` ở lại `.../staging/<tag>/` và tích lũy theo từng bản cập nhật. | Xóa thư mục stage gốc theo đường dẫn do daemon truyền vào, sau khi kiểm tra tiền tố (S7). |
| R10 | Thấp (*cần xác nhận trên máy thật*) | `fpm/classifier.go:87-126`, `cgroup/cgroup.go:166-182` | Classifier di chuyển worker PHP sang `user-<UID>.slice/da-php.scope` bằng cách ghi trực tiếp `cgroup.procs`, ngoài sự quản lý của systemd. Worker mới sinh ra vẫn nằm ở cgroup của service cho tới lần quét kế tiếp (tới 1s), PID có thể được tái sử dụng giữa lúc đọc `comm`/UID và lúc ghi, và systemd có thể đặt lại cgroup khi reload/restart service PHP-FPM. | Dùng `Delegate=`/drop-in cho dịch vụ PHP-FPM hoặc `systemd-run --scope`; kiểm chứng trên server thật. |
| R11 | Thấp | `dausers/dausers.go:17-20` | `MaxValidUID = 59999` cố định: user có UID ≥ 60000 (một số cấu hình CloudLinux/LVE) bị bỏ qua mà không báo. Tài khoản `usertype=admin` cũng bị loại ngầm khỏi giới hạn. | Đưa ngưỡng ra cấu hình, ghi log số tài khoản bị bỏ qua. |

### Chất lượng code, test, tài liệu

| # | Mức | Vị trí | Kịch bản lỗi | Đề xuất sửa |
|---|---|---|---|---|
| Q1 | Thấp (*cần xác nhận*) | `engine.go:36-52`, `config.go:19-47`, `.github/workflows/ci.yml` | CI chạy `go vet` và `go test -race` nhưng không chạy `gofmt`/`staticcheck`. Căn cột của một số struct (`Engine`, `ResourceLimits`) cho thấy chưa chạy `gofmt` (đọc từ khoảng trắng, chưa chạy `gofmt` thật). | Thêm bước `gofmt -l .` (fail khi có output) và `staticcheck`. |
| Q2 | Thấp | `internal/*/_test.go` (14 test) | Không có test đồng thời cho `Classifier` (R1), không test `StageRelease` hai lần liên tiếp (R3), không test phần penalty khi cấu hình lệch (R2), không test `api.php` hay `update.sh`. | Bổ sung các test trên; chạy `shellcheck` và bats cho `update.sh`. |
| Q3 | Thấp | `plugin/admin/api.php:28, 37, 94` | `html_entity_decode` được áp dụng lên `QUERY_STRING`, `POST` và `payload`. Giá trị hợp lệ chứa `&amp;` hoặc `&lt;` bị đổi nghĩa. Với dữ liệu hiện tại (tên, số, base64) chưa gây lỗi. | Chỉ decode khi DA thực sự encode; ghi chú lý do. |
| Q4 | Thấp | `plugin.conf:5`, `version/version.go:11`, `release.yml` | Số phiên bản nằm ở 3 nơi (`plugin.conf`, `version.go`, ldflags trong workflow); `plugin.conf` được `sed` lúc build nhưng `version.go` mặc định lệch nếu build tay. | Một nguồn duy nhất (ldflags) và kiểm tra trong CI. |

## Kiểm tra đã chạy

Đối chiếu với `.github/workflows/ci.yml` (`ubuntu-latest`, Go 1.22):

| Bước CI | Kết quả |
|---|---|
| Kiểm tra LF (không CRLF trong `scripts/ plugin/ systemd/ Makefile`) | Pass (chạy `grep -rlU $'\r'`, không có kết quả) |
| `php -l plugin/admin/api.php` và `plugin/user/stats.php` | Pass (PHP 8.5.11) |
| `go vet ./...` | **Không chạy được**: máy review không có Go |
| `go test -race ./...` | **Không chạy được**: máy review không có Go |
| `make build-linux-amd64/arm64` | **Không chạy được**: không có Go |
| ShellCheck (`scripts/**/*.sh`, `*.raw`, `*/index.html`) | **Không chạy được**: máy không có `shellcheck` |

Phần đã làm thay: đọc toàn bộ mã Go, shell, PHP và HTML/JS (`internal/*`, `cmd/`, `scripts/`, `plugin/`,
`systemd/`, `.github/workflows/`), lần theo luồng gọi cho R1, R3, R4, R5 và kiểm tra bằng `git ls-tree`
rằng tag v1.0.4 thiếu `plugin/images/admin_icon.svg` (S2).

**Chưa test được:** daemon trên DirectAdmin thật (S3, S5, R5, R10), MariaDB thật (R2, R4, R8),
`go test -race` để tái hiện R1, và hành vi chống CSRF của DirectAdmin (S3).

## Đề xuất thứ tự xử lý

1. **R1:** thêm mutex cho `Classifier`, một thay đổi nhỏ, tránh crash daemon.
2. **S2:** bỏ khối tải file từ `main` trong `install.sh`; phát hành lại bản có đủ file.
3. **S1 (và S3):** ghim hoặc khóa việc đổi repo cập nhật, ký release, giới hạn nhóm hành động cập nhật cho
   root/`diradmin`, thêm kiểm tra `Origin`.
4. **R2, R3, R4:** validate penalty, chặn cập nhật đồng thời, đặt timeout và tách tác vụ nền.
5. **S4, S5, R5:** token qua stdin, giới hạn kết nối/tần suất, dọn drop-in mồ côi.
6. Các mục Thấp còn lại (S6-S11, R6-R11, Q1-Q4).
