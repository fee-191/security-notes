# Chương 2 — Hệ điều hành Linux

## Nhập môn — hiểu nôm na trước khi đi sâu

Chương này nói về cách hệ điều hành Linux hoạt động bên trong: ai được làm gì, tiến trình ra đời và bị giết ra sao, file để ở đâu, log ghi thế nào, và làm sao khóa máy lại cho an toàn. Vì hầu hết máy chủ trên thế giới (web server, database, container, cloud) đều chạy Linux, nên với một kỹ sư an toàn thông tin, hiểu rõ Linux gần như là điều kiện sống còn: kẻ tấn công và người phòng thủ đều "đánh nhau" ngay trên những cơ chế này. Phần dưới đây giải thích từng khái niệm lớn của chương bằng ngôn ngữ đời thường trước, để khi đọc phần kỹ thuật sâu bạn đã có sẵn bức tranh tổng thể.

### User space và kernel space — nói đơn giản
Hãy tưởng tượng kernel (nhân Linux) là **ban quản lý tòa nhà** giữ mọi chìa khóa và điều khiển thang máy, điện nước. Các chương trình bình thường của bạn (trình duyệt, web server) sống ở "user space" — như khách thuê, không được tự ý chạm vào hệ thống điện. Mỗi khi cần gì (đọc file, mở mạng), khách phải gọi xuống lễ tân bằng một **system call (syscall)**, và ban quản lý sẽ kiểm tra xem bạn có quyền không. **Vì sao cần?** Tách biệt như vậy để một chương trình lỗi hoặc độc hại không thể trực tiếp phá phần cứng hay đọc trộm bộ nhớ chương trình khác — đây là hàng rào bảo mật gốc của cả hệ thống.

### Cây thư mục FHS — nói đơn giản
FHS là **quy ước "cái gì để ở đâu"** trên Linux: file cấu hình nằm trong `/etc`, log nằm trong `/var/log`, chương trình hệ thống nằm trong `/usr/bin`, v.v. **Nó giải quyết vấn đề gì?** Nếu mỗi máy để file một kiểu thì không ai viết được công cụ giám sát chung. Nhờ chuẩn này, ta biết chắc "muốn canh kẻ xấu sửa cấu hình thì theo dõi `/etc`".

### Mô hình quyền (permissions) — nói đơn giản
Mỗi file có một bộ "ai được đọc / ghi / chạy" chia cho ba nhóm: **chủ sở hữu, nhóm, và mọi người khác**. Giống như một căn phòng có ba loại chìa: chìa của chủ, chìa của đồng nghiệp cùng phòng, và chìa để ngoài hành lang. Có thêm vài "bit đặc biệt" như **SUID** (cho phép chạy chương trình với quyền của chủ file, kể cả quyền root). **Vì sao quan trọng với bảo mật?** Cấu hình quyền sai là một trong những cách leo thang đặc quyền phổ biến nhất — một file SUID viết ẩu có thể biến người dùng thường thành root.

### `/etc/passwd`, `/etc/shadow` và hash mật khẩu — nói đơn giản
`/etc/passwd` là **danh bạ tài khoản** (ai tên gì, dùng shell nào), ai cũng đọc được. Mật khẩu thật thì không để ở đó — chúng được băm (hash) và cất riêng trong `/etc/shadow` mà chỉ root mới mở được. **Hash** giống như xay một quả táo: từ mật khẩu ra một chuỗi rối, nhưng không thể "xay ngược" lại thành mật khẩu. **Vì sao tách hai file?** Để danh bạ vẫn công khai cho hệ thống dùng, nhưng phần nhạy cảm (mật khẩu) thì giấu kỹ, tránh bị lấy về bẻ khóa.

### `sudo`, PAM — nói đơn giản
- **sudo** là cách để người dùng thường "mượn quyền" làm một việc cụ thể với tư cách root mà không cần biết mật khẩu root, và mọi lần mượn đều bị ghi sổ. Giống như mượn thẻ ra vào kho có người ký nhận. **Vì sao cần?** An toàn và truy vết được hơn nhiều so với chia sẻ mật khẩu admin cho cả đội.
- **PAM** là **bộ phận kiểm tra giấy tờ dùng chung**: thay vì mỗi ứng dụng (ssh, login, sudo) tự viết code kiểm tra mật khẩu, tất cả gọi chung PAM. **Lợi ích?** Muốn thêm quy tắc (khóa tài khoản sau 5 lần sai, ép mật khẩu mạnh) thì chỉ chỉnh một chỗ là cả hệ thống áp dụng.

### Tiến trình (process) — nói đơn giản
Một **tiến trình** là một chương trình đang chạy, giống như một "công nhân" đang làm việc, có số hiệu (PID) và một danh tính (chạy dưới quyền ai). Tiến trình mới sinh ra bằng cách "nhân bản" cha rồi "thay ruột" thành chương trình khác (`fork` rồi `execve`). Hệ thống còn có **tín hiệu (signal)** để ra lệnh cho tiến trình, ví dụ "dừng lại" hay "tự kết thúc". **Vì sao quan trọng?** Khi điều tra sự cố, ta cần biết tiến trình nào đang chạy, con của ai, dưới quyền gì — một web server bỗng đẻ ra một shell là dấu hiệu kinh điển của bị tấn công.

### `/proc`, namespaces, cgroups — nói đơn giản
- **`/proc`** là một "thư mục ảo" — cửa sổ nhìn vào ruột của kernel và từng tiến trình (đang chạy file nào, mở kết nối mạng nào). Rất quý khi điều tra.
- **Namespaces** là cách kernel **dựng vách ngăn ảo** để một nhóm tiến trình tưởng mình có máy riêng (mạng riêng, danh sách tiến trình riêng). Đây chính là nền tảng của **container** (Docker). Giống như chia một văn phòng lớn thành nhiều phòng kín bằng vách ngăn.
- **cgroups** là **đồng hồ đo và van khóa tài nguyên**: giới hạn một dịch vụ chỉ được dùng tối đa bao nhiêu CPU/RAM. **Vì sao cần?** Để một dịch vụ bị lạm dụng không ngốn hết tài nguyên kéo sập cả máy.

### systemd — nói đơn giản
**systemd** là **người quản lý dịch vụ** của máy: nó khởi động các dịch vụ khi bật máy, tự bật lại khi chúng chết, và cho ta khóa chặt từng dịch vụ. Giống như quản lý ca làm việc trong nhà máy. **Vì sao thay cái cũ?** Nó chạy dịch vụ song song (boot nhanh hơn), giám sát chặt hơn, và cho phép "hardening" (siết an toàn) từng dịch vụ chỉ bằng vài dòng cấu hình.

### Logging (rsyslog, journald, logrotate) — nói đơn giản
**Log** là **camera an ninh của hệ thống** — ghi lại ai đăng nhập, lệnh gì đã chạy, lỗi gì xảy ra. `rsyslog` và `journald` là hai cách thu thập log; `logrotate` lo việc dọn log cũ để không lấp đầy ổ đĩa. **Vì sao tối quan trọng?** Khi có sự cố, log là bằng chứng. Vì vậy ta thường đẩy log sang một máy tập trung (SIEM) ngay lập tức — để kẻ tấn công có xóa log trên máy nạn nhân cũng không xóa được bản đã gửi đi.

### Quản lý gói (apt, dnf) — nói đơn giản
Đây là **"cửa hàng ứng dụng" có kiểm định** của Linux: cài, gỡ, cập nhật phần mềm bằng một lệnh, và quan trọng là kiểm tra **chữ ký số** để chắc chắn gói không bị tráo trên đường tải về. **Vì sao quan trọng?** Cập nhật vá lỗi kịp thời và đảm bảo nguồn gốc phần mềm là nền tảng của một hệ thống an toàn.

### cron — nói đơn giản
**cron** là **đồng hồ hẹn giờ** chạy lệnh tự động theo lịch (mỗi phút, mỗi đêm 2h...). **Vì sao cần quan tâm?** Nó tiện cho việc tự động hóa, nhưng cũng là chỗ ưa thích để kẻ xấu cài "cửa hậu" chạy ngầm định kỳ — nên đây là nơi cần soi khi điều tra.

### Bash: file descriptor, redirection, pipe — nói đơn giản
Khi chạy lệnh, mỗi tiến trình có ba "đường ống" mặc định: **đầu vào** (stdin), **đầu ra** (stdout) và **đầu ra lỗi** (stderr). **Redirection** là bẻ những đường ống này đi nơi khác (ví dụ ghi kết quả ra file), còn **pipe** (`|`) là nối đầu ra của lệnh này vào đầu vào của lệnh kia như nối ống nước. **Vì sao cần?** Đây là cách ghép các lệnh nhỏ thành công cụ xử lý mạnh — xương sống của mọi script tự động hóa và phân tích log.

### Công cụ xử lý text (grep, awk, sed...) — nói đơn giản
Đây là **bộ đồ nghề lọc và bóc tách văn bản**: `grep` tìm dòng chứa từ khóa, `awk` cắt theo cột, `sed` thay thế, `sort`/`uniq` sắp xếp và đếm. **Giải quyết vấn đề gì?** Log thường dài hàng triệu dòng; những công cụ này giúp lọc ra "10 địa chỉ IP đăng nhập sai nhiều nhất" chỉ trong một dòng lệnh — kỹ năng điều tra hằng ngày.

### Hardening (sshd, fail2ban, firewall, SELinux/AppArmor) — nói đơn giản
**Hardening** là **khóa cửa, lắp song sắt** cho máy: cấu hình SSH an toàn, dùng `fail2ban` tự chặn IP dò mật khẩu, dùng firewall (netfilter) chỉ mở đúng cổng cần thiết, và dùng SELinux/AppArmor để giới hạn cả khi một dịch vụ bị chiếm thì nó cũng không làm gì quá phạm vi cho phép. **Vì sao cần?** Mặc định một hệ thống thường mở khá rộng; hardening thu hẹp "bề mặt tấn công" để kẻ xấu có ít cửa hơn.

Nắm được mấy ý trên rồi thì phần dưới đây sẽ đi sâu vào chi tiết kỹ thuật.

> Tài liệu tham chiếu kỹ thuật cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps). Mọi cấu trúc dữ liệu được mô tả tới mức trường/byte; mọi công cụ đều có ví dụ thực tế chạy được. Lệnh và output mẫu lấy trên môi trường Linux phổ biến (Debian/Ubuntu, RHEL/Rocky); một vài con số phụ thuộc phiên bản kernel/distro sẽ được ghi chú rõ.

---

## 2.1. Kiến trúc tổng quan và ranh giới user space / kernel space

Trước khi đi vào từng cơ chế, cần nắm mô hình phân tầng vì gần như mọi quyết định bảo mật trên Linux đều xoay quanh ranh giới giữa **user space** và **kernel space**.

```
+---------------------------------------------------------------+
|  USER SPACE (ring 3 trên x86-64)                              |
|   bash, sshd, nginx, python ...                               |
|   thư viện: glibc (libc.so.6), libssl ...                     |
|        |  system call (syscall instruction)                   |
+--------|------------------------------------------------------+
         v
+---------------------------------------------------------------+
|  KERNEL SPACE (ring 0)                                        |
|   - syscall dispatcher (bảng sys_call_table)                  |
|   - scheduler (CFS/EEVDF tùy phiên bản)                       |
|   - VFS -> ext4/xfs/btrfs                                     |
|   - net stack (socket -> TCP/IP -> netfilter)                 |
|   - LSM hooks (SELinux/AppArmor)                              |
|   - quản lý process, memory (page table), namespaces, cgroups |
+---------------------------------------------------------------+
```

**Vì sao thiết kế tách ring 3 / ring 0?** CPU x86-64 có 4 mức đặc quyền (ring 0–3); Linux chỉ dùng ring 0 (kernel) và ring 3 (user). Tách biệt để code user space không thể trực tiếp truy cập phần cứng, bảng trang của process khác, hay cấu trúc kernel — mọi yêu cầu phải đi qua **syscall**, nơi kernel kiểm tra quyền. Đây là hàng rào bảo mật gốc của toàn hệ thống.

**Syscall ở mức instruction (x86-64, Linux):**

| Thanh ghi | Vai trò khi gọi syscall |
|---|---|
| `rax` | Số hiệu syscall (vd. `read`=0, `write`=1, `open`=2, `execve`=59) |
| `rdi` | Tham số 1 |
| `rsi` | Tham số 2 |
| `rdx` | Tham số 3 |
| `r10` | Tham số 4 (lưu ý: KHÔNG phải `rcx` như ABI gọi hàm thường) |
| `r8`  | Tham số 5 |
| `r9`  | Tham số 6 |
| `rax` (sau lệnh) | Giá trị trả về (âm = `-errno`) |

Lệnh `syscall` chuyển CPU sang ring 0, nhảy tới địa chỉ trong MSR `LSTAR`. Quan sát chuỗi syscall của một tiến trình là kỹ thuật điều tra trọng yếu:

```bash
strace -f -e trace=openat,connect,execve -s 200 curl -s https://example.com -o /dev/null
```

`-f` theo cả tiến trình con, `-e trace=` lọc nhóm syscall, `-s 200` in tới 200 ký tự chuỗi. Output mẫu:

```
execve("/usr/bin/curl", ["curl","-s","https://example.com",...], 0x7ffd...) = 0
openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 5
connect(6, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EINPROGRESS (Operation now in progress)
```

**Lưu ý bảo mật:** seccomp-bpf (dùng bởi container runtime, systemd `SystemCallFilter=`) lọc chính các số `rax` này. Hiểu bảng syscall giúp viết/đọc seccomp profile và phát hiện hành vi bất thường (vd. một web server bỗng gọi `execve`).

---

## 2.2. Filesystem Hierarchy Standard (FHS)

FHS (chuẩn hiện hành 3.0) quy định ý nghĩa từng thư mục gốc. **Vì sao cần chuẩn?** Để công cụ, script và admin biết chắc file ở đâu mà không phụ thuộc distro — điều cốt yếu khi viết rule giám sát (vd. theo dõi ghi vào `/etc`, `/bin`).

| Đường dẫn | Mục đích | Ghi được lúc runtime? | Quan tâm bảo mật |
|---|---|---|---|
| `/` | Gốc | — | — |
| `/bin`, `/sbin` | Binary thiết yếu (thường symlink vào `/usr/bin`) | Không nên | Ghi vào đây = thay binary hệ thống |
| `/usr` | Phần lớn chương trình, thư viện (`/usr/bin`, `/usr/lib`, `/usr/local`) | Read-only được khuyến nghị | Theo dõi thay đổi |
| `/etc` | File cấu hình hệ thống (text) | Có | `/etc/passwd`, `/etc/shadow`, `/etc/cron*` — mục tiêu hàng đầu |
| `/var` | Dữ liệu biến đổi: `/var/log`, `/var/spool`, `/var/lib` | Có | Log nằm ở đây; cần bảo vệ tính toàn vẹn |
| `/tmp` | Tạm, xóa khi reboot, thường `sticky bit` | Có (ai cũng) | Mục tiêu race condition / symlink attack |
| `/var/tmp` | Tạm nhưng giữ qua reboot | Có | Payload dai dẳng |
| `/home` | Thư mục người dùng | Có (chủ sở hữu) | `.ssh/`, `.bash_history` |
| `/root` | Home của root | root | — |
| `/proc` | Pseudo-FS: trạng thái kernel/process | Một phần | `/proc/<pid>/maps`, `/environ` lộ secret |
| `/sys` | Pseudo-FS: device/kernel object (sysfs) | Một phần | cgroup, module |
| `/dev` | Device node (devtmpfs) | — | `/dev/mem`, `/dev/kmem` rất nhạy cảm |
| `/boot` | Kernel, initramfs, bootloader | Hiếm | Tampering = rootkit |
| `/run` | Runtime state (tmpfs, mất khi reboot) | Có | PID file, socket |
| `/opt` | Phần mềm bên thứ ba | Có | — |
| `/mnt`, `/media` | Điểm mount | — | — |

```bash
stat -f /            # xem filesystem chứa /
findmnt -t ext4,xfs  # liệt kê mount kèm option (ro, nosuid, nodev)
```

**Lưu ý bảo mật:** mount với cờ `nosuid,nodev,noexec` cho `/tmp`, `/var/tmp`, `/home` là biện pháp hardening cơ bản — vô hiệu hóa SUID, device node, và thực thi binary từ những vùng người dùng ghi được.

---

## 2.3. Mô hình quyền: 12 bit, đọc `ls -l` từng ký tự, octal, umask

### 2.3.1. Cấu trúc 12 bit quyền

Mỗi inode lưu một trường `st_mode` 16-bit; trong đó **12 bit thấp** là quyền truy cập (4 bit cao còn lại mã hóa loại file). 12 bit chia làm 4 nhóm 3 bit:

```
 bit:  11 10  9 | 8 7 6 | 5 4 3 | 2 1 0
       SUID SGID STK| r w x | r w x | r w x
       <--special-->|<owner>|<group>|<other>
```

| Nhóm | Bit | Tên | Giá trị octal | Ý nghĩa lên FILE | Ý nghĩa lên THƯ MỤC |
|---|---|---|---|---|---|
| Special | 11 | SUID | 4000 | Chạy với UID của chủ sở hữu file | (vô nghĩa) |
| Special | 10 | SGID | 2000 | Chạy với GID của nhóm chủ | File mới kế thừa GID thư mục |
| Special | 9 | Sticky | 1000 | (xưa: giữ text trong swap, nay bỏ) | Chỉ chủ file mới xóa được file trong dir |
| Owner | 8/7/6 | r/w/x | 0400/0200/0100 | đọc / ghi / thực thi | liệt kê / tạo-xóa / cd vào |
| Group | 5/4/3 | r/w/x | 0040/0020/0010 | tương tự | tương tự |
| Other | 2/1/0 | r/w/x | 0004/0002/0001 | tương tự | tương tự |

**Vì sao `x` trên thư mục khác `r`?** `r` cho phép đọc danh sách tên file; `x` cho phép "đi qua" (traverse) để truy cập một file đã biết tên bên trong. Có thể có `x` mà không `r`: bạn vào được `/dir/file` nếu biết tên, nhưng không `ls` được.

### 2.3.2. Đọc `ls -l` từng ký tự

```
-rwxr-xr--   1 root  staff   8192 Jun 19 10:00 tool
drwxr-x---   2 alice alice   4096 Jun 19 10:00 secret
crw-rw----   1 root  tty     5, 0 Jun 19 10:00 /dev/tty
-rwsr-xr-x   1 root  root   55672 Jun 19 10:00 /usr/bin/passwd
```

Chuỗi 10 ký tự đầu, ví dụ `-rwsr-xr-x`:

| Vị trí | Ký tự | Ý nghĩa |
|---|---|---|
| 1 | `-` | Loại file: `-`=file thường, `d`=dir, `l`=symlink, `c`=char dev, `b`=block dev, `s`=socket, `p`=named pipe (FIFO) |
| 2–4 | `rws` | Owner: r, w, và `s` = SUID bật + x bật (nếu SUID bật nhưng x tắt thì là `S` hoa) |
| 5–7 | `r-x` | Group |
| 8–10 | `r-x` | Other |

Quy tắc ký tự đặc biệt:
- Cột execute owner: `x`+SUID → `s`; SUID không có x → `S`.
- Cột execute group: `x`+SGID → `s`; SGID không có x → `S`.
- Cột execute other: `x`+sticky → `t`; sticky không có x → `T`.

Ví dụ `/tmp`:
```
drwxrwxrwt 18 root root 4096 Jun 19 11:00 /tmp
                       ^ chữ 't' = sticky bit
```
Sticky trên `/tmp` ngăn user A xóa file của user B dù `/tmp` có `w` cho mọi người.

Với device node `crw-rw----`, cột "size" hiển thị **major, minor** (vd. `5, 0`) thay vì kích thước byte — vì `c`/`b` là device.

### 2.3.3. Octal và `chmod`

```bash
chmod 4755 /usr/local/bin/myprog   # SUID + rwxr-xr-x
chmod u+s,g-w file                 # ký hiệu tượng trưng
chmod 1777 /tmp                    # sticky + rwx cho tất cả
stat -c '%a %A %U:%G' /usr/bin/passwd
# 4755 -rwsr-xr-x root:root
```

`%a` in octal, `%A` in chuỗi rwx, tiện cho audit hàng loạt.

**Săn SUID/SGID — kỹ thuật điều tra bắt buộc:**
```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %p\n' 2>/dev/null
```
- `-xdev`: không vượt sang filesystem khác (tránh quét NFS, /proc).
- `-perm -4000`: khớp khi *có ít nhất* bit SUID (dấu `-` = "chứa các bit này").
- `-printf '%M %u %p\n'`: in mode, owner, path.

Output mẫu:
```
-rwsr-xr-x root /usr/bin/sudo
-rwsr-xr-x root /usr/bin/passwd
-rwsr-xr-x root /usr/bin/su
```

**Lưu ý bảo mật:** mọi binary SUID-root là một bề mặt leo thang đặc quyền. Một binary SUID gọi shell, đọc file tùy ý, hoặc cho ghi file tùy ý đều có thể bị lạm dụng (tham khảo dự án GTFOBins). Lập baseline danh sách SUID và cảnh báo khi xuất hiện entry mới.

### 2.3.4. `umask`

`umask` là **mặt nạ loại bỏ** quyền cho file/dir mới tạo. Quyền cuối = quyền yêu cầu mặc định AND NOT(umask).

- Default cho file: `0666` (không bao giờ tự cấp x cho file mới).
- Default cho dir: `0777`.

| umask | File mới | Dir mới | Diễn giải |
|---|---|---|---|
| `022` | `644` | `755` | other/group không ghi |
| `027` | `640` | `750` | other không truy cập gì |
| `077` | `600` | `700` | chỉ chủ sở hữu |

```bash
umask              # in hiện tại, vd 0022
umask 027
touch a; mkdir b; stat -c '%a %n' a b
# 640 a
# 750 b
```
**Lưu ý:** umask được kế thừa từ shell/PAM (`/etc/login.defs` `UMASK`, `pam_umask`). Dịch vụ chạy với umask lỏng có thể tạo file log/secret world-readable. Hardening server thường đặt `027` hoặc `077`.

### 2.3.5. ACL — POSIX Access Control Lists

Mô hình rwx 3 nhóm không đủ khi cần "user X có quyền riêng ngoài owner/group". ACL bổ sung entry chi tiết, lưu trong extended attribute `system.posix_acl_access`.

```bash
setfacl -m u:bob:rwx,g:devs:r-x file.txt   # cấp bob rwx, nhóm devs r-x
setfacl -d -m u:bob:rwx /shared            # default ACL: file mới trong dir kế thừa
getfacl file.txt
```
Output `getfacl`:
```
# file: file.txt
# owner: alice
# group: alice
user::rw-
user:bob:rwx          <- ACL entry tường minh
group::r--
mask::rwx             <- mask: trần quyền tối đa cho named user/group
other::r--
```
**`mask` quan trọng:** quyền hiệu lực của `user:bob` = ACL entry AND mask. Nếu `setfacl -m m::r--`, bob bị giới hạn còn `r--` dù entry ghi `rwx`. Khi có ACL, `ls -l` hiển thị dấu `+`:
```
-rw-rwxr--+ 1 alice alice 0 Jun 19 file.txt
```
Cột "group" trong `ls -l` lúc này hiển thị **mask**, không phải quyền group thật — điểm hay gây nhầm khi audit.

**Lưu ý bảo mật:** ACL không hiện trong `ls -l` cơ bản (chỉ dấu `+`). Quét quyền chỉ bằng `find -perm` sẽ bỏ sót cấp phát qua ACL. Dùng `getfacl -R` khi điều tra quyền nhạy cảm.

---

## 2.4. `/etc/passwd`, `/etc/shadow`, hash mật khẩu

### 2.4.1. `/etc/passwd` — 7 trường, phân tách bằng `:`

```
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
alice:x:1000:1000:Alice Nguyen,,,:/home/alice:/bin/bash
```

| # | Trường | Ví dụ | Ý nghĩa |
|---|---|---|---|
| 1 | username | `alice` | Tên đăng nhập |
| 2 | password | `x` | `x` = hash ở `/etc/shadow`; `*`/`!` = khóa; trường rỗng = không cần mật khẩu (NGUY HIỂM) |
| 3 | UID | `1000` | User ID. 0 = root; 1–999 system; ≥1000 user thường (tùy `login.defs`) |
| 4 | GID | `1000` | Primary group ID |
| 5 | GECOS | `Alice Nguyen,,,` | Tên đầy đủ/comment (các trường con cách bằng dấu phẩy) |
| 6 | home | `/home/alice` | Thư mục nhà |
| 7 | shell | `/bin/bash` | Shell đăng nhập; `/usr/sbin/nologin` hoặc `/bin/false` để chặn login |

**Vì sao tách shadow?** `/etc/passwd` phải world-readable (`644`) để map UID↔tên cho mọi tiến trình; nếu hash nằm đây, ai cũng đọc được để bẻ offline. Hash được dời sang `/etc/shadow` chỉ `root` đọc.

```bash
getent passwd alice     # hỏi qua NSS (gồm cả LDAP/SSSD), không chỉ file
awk -F: '$3==0 {print $1}' /etc/passwd   # tìm mọi tài khoản UID 0 (chỉ nên có root)
```
**Lưu ý bảo mật:** nhiều tài khoản UID 0 = nhiều "root ẩn". Trường password rỗng (field 2 trống) cho phép login không mật khẩu. Cả hai là dấu hiệu xâm nhập điển hình.

### 2.4.2. `/etc/shadow` — 9 trường

Quyền điển hình `640 root:shadow` (hoặc `600`).

```
alice:$6$xQk2...salt...$hashpart...:19800:0:99999:7:14:20000:
```

| # | Trường | Ví dụ | Ý nghĩa |
|---|---|---|---|
| 1 | username | `alice` | Khớp với passwd |
| 2 | password hash | `$6$salt$hash` | Hash hoặc trạng thái đặc biệt (xem dưới) |
| 3 | last change | `19800` | Ngày đổi mật khẩu lần cuối, tính bằng **số ngày kể từ 1970-01-01** (epoch days) |
| 4 | min | `0` | Số ngày tối thiểu trước khi được đổi lại |
| 5 | max | `99999` | Số ngày tối đa mật khẩu còn hiệu lực |
| 6 | warn | `7` | Cảnh báo trước hết hạn (ngày) |
| 7 | inactive | `14` | Số ngày sau hết hạn vẫn cho login |
| 8 | expire | `20000` | Ngày tài khoản bị vô hiệu hoàn toàn (epoch days) |
| 9 | reserved | (rỗng) | Dành riêng |

Trạng thái đặc biệt của trường 2:
- `*` hoặc `!` → tài khoản không thể đăng nhập bằng mật khẩu.
- `!$6$...` → mật khẩu **bị khóa** (`passwd -l` thêm `!` vào đầu hash); xóa `!` là mở khóa.
- Trống → đăng nhập không cần mật khẩu.

### 2.4.3. Định dạng hash `$id$salt$hash`

Trường hash dùng cú pháp **Modular Crypt Format (MCF)**: `$id$[params]$salt$hash`.

| `id` | Thuật toán | Ghi chú |
|---|---|---|
| `1` | MD5-crypt | Yếu, đã lỗi thời |
| `2a`/`2b`/`2y` | bcrypt | Mạnh; thường thấy ở app, ít ở shadow |
| `5` | SHA-256 crypt | Có `rounds=` tùy chọn |
| `6` | SHA-512 crypt | Mặc định nhiều distro Linux |
| `y` | yescrypt | Mặc định Debian 11+/Ubuntu mới; memory-hard, mạnh nhất trong nhóm |

Ví dụ bóc tách một bản ghi SHA-512:
```
$6$rounds=656000$YxZ.Hk1aB2c3D4e$M9...rất.dài...hashbase64...
 |  |              |                |
 |  |              |                +-- hash (định dạng base64 đặc biệt của crypt)
 |  |              +------------------- salt (tới 16 ký tự)
 |  +--------------------------------- tham số tùy chọn (rounds)
 +------------------------------------ id thuật toán = 6 (SHA-512)
```
**Vì sao có salt?** Salt ngẫu nhiên khiến hai user cùng mật khẩu có hash khác nhau, vô hiệu hóa rainbow table. **Vì sao có `rounds`?** Tăng chi phí tính toán làm brute-force/đoán offline chậm đi.

```bash
# Tạo hash thử nghiệm (yescrypt nếu hệ hỗ trợ)
openssl passwd -6 'MatKhau!'      # SHA-512
mkpasswd -m yescrypt 'MatKhau!'   # gói whois cung cấp mkpasswd
chage -l alice                    # xem chính sách tuổi thọ mật khẩu (đọc shadow)
```
**Lưu ý bảo mật:** hash MD5 (`$1$`) phải được nâng cấp. Nếu `/etc/shadow` bị lộ, attacker chạy `hashcat`/`john` offline; chế độ hashcat: `1800` cho `$6$`, `1700` cho SHA-512 thô, yescrypt cần phiên bản hashcat mới. Phòng thủ: chính sách mật khẩu mạnh + phát hiện đọc trái phép `/etc/shadow` qua auditd.

### 2.4.4. `sudo`, `/etc/sudoers`

`sudo` cho phép chạy lệnh với quyền user khác (mặc định root) **mà không chia sẻ mật khẩu root**, đồng thời ghi log mọi lệnh — đó là lý do tồn tại của nó so với `su`.

Cú pháp dòng trong `/etc/sudoers` (luôn sửa bằng `visudo` để check cú pháp trước khi lưu):
```
user    host = (runas_user:runas_group)   [TAG:] command
```
Ví dụ:
```
# who    where     (as-whom)        what
root     ALL=(ALL:ALL) ALL
%admin   ALL=(ALL)     ALL
alice    web01=(www-data) /usr/bin/systemctl restart nginx
bob      ALL=(root)    NOPASSWD: /usr/bin/journalctl
%dev     ALL=(ALL)     /usr/bin/apt update, /usr/bin/apt upgrade
```
Phân tích `alice web01=(www-data) /usr/bin/systemctl restart nginx`:
- `alice`: chủ thể.
- `web01`: chỉ áp dụng trên host tên `web01`.
- `(www-data)`: chạy với tư cách user `www-data`.
- lệnh được phép: chỉ đúng `systemctl restart nginx`.

TAG thông dụng: `NOPASSWD:` (không hỏi mật khẩu), `NOEXEC:` (chặn binary spawn lệnh con).

```bash
sudo -l            # liệt kê quyền sudo của user hiện tại
sudo -ll           # chi tiết hơn
```
**Lưu ý bảo mật:** quy tắc quá rộng dễ bị lạm dụng. `(ALL) NOPASSWD: /usr/bin/vim` cho phép `:!sh` thành root. Tránh wildcard và editor/interpreter trong sudoers. Đặt file drop-in vào `/etc/sudoers.d/` (phải `440`, không có khoảng trắng trong tên).

### 2.4.5. PAM — Pluggable Authentication Modules

PAM tách logic xác thực khỏi ứng dụng: `sshd`, `login`, `sudo` không tự code kiểm mật khẩu mà gọi PAM, cấu hình tại `/etc/pam.d/<service>`. Mỗi dòng:
```
<type>   <control>   <module>   [arguments]
```

| `type` | Vai trò |
|---|---|
| `auth` | Xác minh danh tính (mật khẩu, token) |
| `account` | Kiểm tra tài khoản hợp lệ (hết hạn, giờ login) |
| `password` | Đổi credential (cập nhật mật khẩu) |
| `session` | Thiết lập/giải phóng phiên (mount home, log, ulimit) |

| `control` | Hành vi |
|---|---|
| `requisite` | Fail → dừng ngay, trả về thất bại |
| `required` | Fail → ghi nhận thất bại nhưng vẫn chạy hết stack (không lộ module nào fail) |
| `sufficient` | Success → trả về thành công ngay (nếu chưa có `required` nào fail) |
| `optional` | Kết quả thường bị bỏ qua |
| `[success=1 default=ignore]` | Cú pháp điều khiển nhảy bước nâng cao |

Ví dụ `/etc/pam.d/sshd` (rút gọn) với hardening lockout:
```
auth     required   pam_faillock.so preauth silent deny=5 unlock_time=900
auth     [success=1 default=bad]  pam_unix.so
auth     [default=die]  pam_faillock.so authfail deny=5 unlock_time=900
account  required   pam_faillock.so
session  required   pam_limits.so
```
`pam_faillock` khóa tài khoản sau 5 lần sai trong cửa sổ, mở lại sau 900 giây. `pam_limits` áp `/etc/security/limits.conf` (giới hạn process, file descriptor — chống fork bomb).

**Lưu ý bảo mật:** sai thứ tự `sufficient`/`required` có thể tạo bypass xác thực. Thêm `pam_pwquality` để ép độ phức tạp mật khẩu. Module lạ trong `/etc/pam.d/` (vd. pam backdoor ghi mật khẩu ra file) là kỹ thuật persistence cần soi.

---

## 2.5. Tiến trình (Process)

### 2.5.1. Định danh và thuộc tính

Mỗi tiến trình có `task_struct` trong kernel. Các thuộc tính cốt lõi:

| Thuộc tính | Ý nghĩa |
|---|---|
| PID | Process ID (1 = `init`/systemd) |
| PPID | Parent PID |
| RUID/EUID | Real / Effective UID — EUID quyết định quyền; SUID làm EUID khác RUID |
| RGID/EGID | Real / Effective GID |
| SUID/SGID (saved) | UID/GID lưu để có thể tạm bỏ rồi lấy lại đặc quyền |
| Supplementary groups | Danh sách nhóm phụ |

```bash
ps -eo pid,ppid,ruid,euid,stat,comm
id alice
cat /proc/self/status | grep -E '^(Uid|Gid|Groups):'
```

### 2.5.2. Trạng thái tiến trình (cột STAT)

| Ký tự | Tên | Ý nghĩa |
|---|---|---|
| `R` | Running/Runnable | Đang chạy hoặc sẵn sàng chạy trên CPU |
| `S` | Interruptible sleep | Ngủ chờ sự kiện, có thể bị tín hiệu đánh thức |
| `D` | Uninterruptible sleep | Ngủ trong I/O kernel, KHÔNG nhận tín hiệu (kể cả `kill -9`) |
| `T` | Stopped | Bị dừng bởi `SIGSTOP`/`SIGTSTP` hoặc đang debug |
| `t` | Traced | Dừng bởi debugger |
| `Z` | Zombie | Đã chết, chờ cha gọi `wait()` để thu mã thoát |
| `X` | Dead | (hiếm khi thấy) |

Hậu tố trong `ps` (cột STAT): `s`=session leader, `+`=foreground group, `l`=multi-threaded, `<`=ưu tiên cao, `N`=nice thấp.

**Vì sao `D` không kill được?** Tiến trình đang nằm trong đường dẫn I/O của kernel; đánh thức bằng signal có thể làm hỏng trạng thái thiết bị/filesystem. `D` kéo dài thường báo hiệu NFS treo hoặc đĩa lỗi.

**Zombie:** không tiêu tốn tài nguyên ngoài một entry trong bảng process; xuất hiện nhiều `Z` nghĩa là tiến trình cha không `wait()`. Diệt zombie = diệt/sửa tiến trình cha.

### 2.5.3. Bảng tín hiệu (signals)

Tín hiệu là cơ chế thông báo bất đồng bộ. Số hiệu phổ biến (kiến trúc x86/ARM thông dụng — vài số khác trên alpha/mips, cần kiểm chứng theo `kill -l`):

| Số | Tên | Mặc định | Bắt/chặn được? | Mô tả |
|---|---|---|---|---|
| 1 | SIGHUP | Terminate | Có | Mất terminal; quy ước "reload config" cho daemon |
| 2 | SIGINT | Terminate | Có | Ctrl-C |
| 3 | SIGQUIT | Core dump | Có | Ctrl-\\ |
| 9 | SIGKILL | Terminate | **KHÔNG** | Buộc kill, không thể bắt/chặn/ignore |
| 11 | SIGSEGV | Core dump | Có | Truy cập bộ nhớ sai |
| 13 | SIGPIPE | Terminate | Có | Ghi vào pipe không còn đầu đọc |
| 15 | SIGTERM | Terminate | Có | Yêu cầu kết thúc lịch sự (mặc định của `kill`) |
| 17 | SIGCHLD | Ignore | Có | Con thay đổi trạng thái |
| 18 | SIGCONT | Continue | — | Tiếp tục tiến trình đã dừng |
| 19 | SIGSTOP | Stop | **KHÔNG** | Dừng tiến trình, không thể bắt |
| 20 | SIGTSTP | Stop | Có | Ctrl-Z |

```bash
kill -l               # liệt kê toàn bộ tên/số tín hiệu
kill -TERM 1234       # gửi SIGTERM
kill -HUP $(pidof nginx)   # reload nginx mà không downtime
kill -9 1234          # SIGKILL (chỉ khi cần thiết)
```
**Vì sao `SIGKILL`/`SIGSTOP` không bắt được?** Để admin/kernel luôn có cách dừng tiến trình bất trị; nếu bắt được, malware có thể tự bảo vệ vô hạn.

### 2.5.4. `fork()` + `execve()` — cách tiến trình ra đời

```
parent
  | fork()           -> tạo bản sao (copy-on-write) page table; trả về PID con cho cha, 0 cho con
  +--> child (bản sao)
         | execve("/bin/ls", argv, envp)
         |   -> thay thế toàn bộ image bộ nhớ bằng /bin/ls, GIỮ NGUYÊN PID & các fd mở
         v
       /bin/ls đang chạy
```

- `fork()` nhân đôi tiến trình; nhờ **copy-on-write**, bộ nhớ chỉ bị copy thật khi một bên ghi → fork rẻ.
- `execve()` nạp chương trình mới đè lên không gian địa chỉ hiện tại; **các file descriptor mở vẫn được kế thừa** trừ khi gắn cờ `O_CLOEXEC`. Đây là nền của shell redirection (mục 2.10).
- Sau khi con thoát, cha gọi `wait()`/`waitpid()` lấy mã thoát; chưa gọi thì con thành zombie.

**Lưu ý bảo mật:** chuỗi `fork`+`execve("/bin/sh")` từ một tiến trình không phải shell (vd. web server, daemon) là chỉ dấu RCE kinh điển — viết rule EDR/auditd cho `execve` của shell có parent là dịch vụ mạng.

### 2.5.5. `/proc` — cửa sổ vào kernel và tiến trình

`/proc/<pid>/` là pseudo-filesystem do kernel sinh động.

| Đường dẫn | Nội dung | Giá trị điều tra |
|---|---|---|
| `/proc/<pid>/cmdline` | Dòng lệnh đầy đủ (đối số ngăn bằng NUL `\0`) | Lệnh thật dù `ps` bị giả mạo argv |
| `/proc/<pid>/exe` | Symlink tới binary thực thi | Phát hiện binary đã bị xóa (`(deleted)`) — malware fileless |
| `/proc/<pid>/cwd` | Symlink thư mục làm việc | — |
| `/proc/<pid>/environ` | Biến môi trường (NUL-separated) | Lộ secret/token |
| `/proc/<pid>/maps` | Vùng bộ nhớ đã map (địa chỉ, quyền, file backing) | Phát hiện code injection |
| `/proc/<pid>/fd/` | Symlink mọi file descriptor mở | Tìm socket, file log đang ghi |
| `/proc/<pid>/status` | UID/GID, capabilities, seccomp, namespace | Audit đặc quyền |
| `/proc/<pid>/root` | Symlink root filesystem của process (khác nếu chroot/container) | Phát hiện chroot |

```bash
tr '\0' ' ' < /proc/$$/cmdline; echo      # đọc cmdline, đổi NUL thành space
ls -l /proc/$(pidof nginx | cut -d' ' -f1)/exe
grep -E 'Cap(Eff|Prm)|Seccomp' /proc/self/status
```
Phát hiện binary bị xóa nhưng vẫn chạy (kỹ thuật ẩn của malware):
```bash
ls -l /proc/*/exe 2>/dev/null | grep deleted
```

### 2.5.6. Namespaces — nền tảng container

Namespace ảo hóa một loại tài nguyên kernel sao cho tiến trình trong namespace tưởng mình sở hữu riêng.

| Namespace | Cô lập | Tham số `clone()`/`unshare` |
|---|---|---|
| PID | Cây PID (process trong NS thấy PID 1 riêng) | `CLONE_NEWPID` |
| NET | Giao diện mạng, bảng route, iptables, port | `CLONE_NEWNET` |
| MNT | Bảng mount | `CLONE_NEWNS` |
| UTS | hostname, domainname | `CLONE_NEWUTS` |
| IPC | SysV IPC, POSIX message queue | `CLONE_NEWIPC` |
| USER | Ánh xạ UID/GID (root trong NS = unprivileged ngoài) | `CLONE_NEWUSER` |
| CGROUP | Gốc cây cgroup nhìn thấy | `CLONE_NEWCGROUP` |
| TIME | Đồng hồ boottime/monotonic | `CLONE_NEWTIME` |

```bash
lsns                              # liệt kê mọi namespace và process chủ
unshare --net --pid --fork --mount-proc bash   # tạo shell trong net+pid namespace mới
readlink /proc/self/ns/net        # in inode namespace, vd net:[4026531992]
nsenter -t <pid> -n ss -tlnp      # nhảy vào net namespace của container để xem socket
```
**Vì sao quan trọng với bảo mật?** Container = namespaces + cgroups + capabilities + seccomp/LSM. `CLONE_NEWUSER` cho phép "rootless container" nhưng từng là nguồn nhiều CVE leo thang đặc quyền. Khi điều tra container, dùng `nsenter` để soi từ host mà không cần shell trong container.

### 2.5.7. cgroups — giới hạn và đo tài nguyên

cgroups (v2 là mặc định trên hệ hiện đại) gom tiến trình thành cây và áp giới hạn CPU/RAM/IO. cgroup v2 mount tại `/sys/fs/cgroup`, một cây thống nhất.

```bash
systemd-cgls                      # cây cgroup theo unit systemd
cat /sys/fs/cgroup/system.slice/nginx.service/memory.max
cat /sys/fs/cgroup/.../cpu.max    # vd "200000 100000" = 2 CPU (quota/period micro giây)
```
File `memory.max` đặt trần RAM; vượt → OOM kill trong cgroup đó. `pids.max` chặn fork bomb. systemd phơi các giới hạn này qua `MemoryMax=`, `CPUQuota=`, `TasksMax=` trong unit.

**Lưu ý bảo mật:** cgroups là cơ chế **chống cạn kiệt tài nguyên** (availability), không phải cô lập bảo mật như namespaces. Đặt `TasksMax=`/`MemoryMax=` cho dịch vụ public-facing để một service bị lạm dụng không kéo sập cả host.

---

## 2.6. systemd — init, unit, dịch vụ, timer

systemd là PID 1 trên đa số distro hiện đại, quản lý vòng đời dịch vụ qua **unit**. **Vì sao thay sysvinit?** Khởi động song song theo phụ thuộc (nhanh hơn), giám sát tiến trình (tự restart), socket/timer activation, theo dõi qua cgroup, log có cấu trúc (journald).

### 2.6.1. Cấu trúc một service unit

File `/etc/systemd/system/myapp.service`:
```ini
[Unit]
Description=My App API
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=notify
User=myapp
Group=myapp
ExecStart=/usr/local/bin/myapp --port 8080
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
# Hardening:
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/myapp
CapabilityBoundingSet=
SystemCallFilter=@system-service
MemoryMax=512M
TasksMax=256

[Install]
WantedBy=multi-user.target
```

| Section | Directive | Ý nghĩa |
|---|---|---|
| `[Unit]` | `After=` | Thứ tự khởi động (không tạo phụ thuộc cứng) |
| | `Requires=` | Phụ thuộc cứng: nếu dependency fail thì unit này cũng fail |
| | `Wants=` | Phụ thuộc mềm (khuyến nghị, không bắt buộc) |
| `[Service]` | `Type=` | Mô hình khởi động (xem bảng dưới) |
| | `ExecStart=` | Lệnh chạy chính |
| | `Restart=` | `no`/`on-failure`/`always`/`on-abnormal` |
| | `User=`/`Group=` | Hạ quyền — KHÔNG chạy root nếu không cần |
| `[Install]` | `WantedBy=` | Target sẽ "kéo" unit khi `enable` |

Các `Type=`:

| Type | Khi nào systemd coi là "đã khởi động xong" |
|---|---|
| `simple` | Ngay sau khi `ExecStart` được fork (mặc định nếu không có `Type`) |
| `exec` | Sau khi binary thực sự `execve` thành công |
| `forking` | Khi tiến trình cha thoát (daemon kiểu cũ tự background) — cần `PIDFile=` |
| `oneshot` | Tiến trình chạy xong rồi thoát (job cài đặt); thường kèm `RemainAfterExit=yes` |
| `notify` | Khi process gửi `sd_notify(READY=1)` qua socket — chính xác nhất |
| `dbus` | Khi service chiếm được tên trên D-Bus |

```bash
systemctl daemon-reload                 # nạp lại sau khi sửa unit
systemctl enable --now myapp.service     # bật khi boot + start ngay
systemctl status myapp.service
systemctl cat myapp.service              # in unit hiệu lực (gồm drop-in)
systemd-analyze security myapp.service   # chấm điểm hardening (exposure score)
```
**Lưu ý bảo mật:** `systemd-analyze security` cho điểm phơi nhiễm 0–10; các directive `ProtectSystem=strict`, `PrivateTmp=`, `NoNewPrivileges=`, `SystemCallFilter=`, `CapabilityBoundingSet=` giảm điểm. Đây là cách hardening dịch vụ rất hiệu quả mà không cần container.

### 2.6.2. Timer unit (thay cron)

`backup.timer`:
```ini
[Unit]
Description=Nightly backup

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
```
Cặp với `backup.service` (`Type=oneshot`). `OnCalendar` dùng cú pháp `DOW YYYY-MM-DD HH:MM:SS`. `Persistent=true` chạy bù nếu máy tắt lúc đến hạn. `RandomizedDelaySec` rải tải.
```bash
systemctl list-timers --all       # xem lần chạy kế tiếp & gần nhất
```
**Lợi thế bảo mật so với cron:** chạy trong cgroup, log vào journald, kế thừa toàn bộ hardening của `[Service]` — điều cron không có.

---

## 2.7. Logging: rsyslog, journald, auth.log, logrotate

### 2.7.1. Mô hình syslog: facility + severity

Mỗi thông điệp syslog mang một **PRI** = facility×8 + severity. Trên dây (RFC 5424) PRI nằm trong dấu `< >` đầu gói.

Facility (chọn lọc):

| Số | Facility |
|---|---|
| 0 | kern |
| 1 | user |
| 2 | mail |
| 3 | daemon |
| 4 | auth (security/authorization) |
| 5 | syslog |
| 10 | authpriv (auth nhạy cảm) |
| 16–23 | local0–local7 (tùy ứng dụng) |

Severity (thấp = nặng hơn):

| Số | Tên | Nghĩa |
|---|---|---|
| 0 | emerg | Hệ thống không dùng được |
| 1 | alert | Cần xử lý ngay |
| 2 | crit | Nguy kịch |
| 3 | err | Lỗi |
| 4 | warning | Cảnh báo |
| 5 | notice | Bình thường nhưng đáng chú ý |
| 6 | info | Thông tin |
| 7 | debug | Gỡ lỗi |

Ví dụ tính PRI: facility `authpriv`(10) + severity `info`(6) = 10×8+6 = **86** → gói bắt đầu `<86>`.

Định dạng RFC 5424:
```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
<86>1 2026-06-19T02:30:01.003Z web01 sshd 1234 - - Accepted publickey for alice
```

| Trường | Ví dụ | Ý nghĩa |
|---|---|---|
| PRI | `<86>` | facility×8+severity |
| VERSION | `1` | Phiên bản giao thức |
| TIMESTAMP | `2026-06-19T02:30:01.003Z` | ISO 8601, có mili giây + offset/Z |
| HOSTNAME | `web01` | Máy phát |
| APP-NAME | `sshd` | Ứng dụng |
| PROCID | `1234` | Thường là PID |
| MSGID | `-` | Loại message (`-` = none) |
| STRUCTURED-DATA | `-` | Cặp key=value chuẩn |
| MSG | `Accepted publickey...` | Nội dung |

### 2.7.2. rsyslog — cấu hình lọc & chuyển tiếp

`/etc/rsyslog.d/50-default.conf` (cú pháp truyền thống `facility.severity   đích`):
```
auth,authpriv.*                 /var/log/auth.log
*.info;mail.none;authpriv.none  /var/log/syslog
*.emerg                         :omusrmsg:*
# Chuyển tiếp tới SIEM qua TCP (RELP/TLS khuyến nghị cho production)
*.* @@siem.internal:6514
```
- `auth,authpriv.*` → tất cả severity của hai facility này.
- `mail.none` → loại trừ facility mail.
- `@@host:port` = TCP (một `@` = UDP, mất gói khi tải cao).

```bash
logger -p authpriv.warning "Test message from logger"   # bơm 1 message
systemctl restart rsyslog
```
**Lưu ý bảo mật:** chuyển log tới SIEM tập trung càng sớm càng tốt — attacker xóa log cục bộ không xóa được bản đã rời máy. Ưu tiên TCP/TLS (RELP) để không mất sự kiện và để bảo mật đường truyền.

### 2.7.3. journald

systemd-journald lưu log **nhị phân, có cấu trúc, đánh index**. Mỗi entry là tập field (kèm trường tin cậy do kernel cung cấp như `_UID`, `_PID`, `_SYSTEMD_UNIT` — ứng dụng không giả mạo được).

```bash
journalctl -u sshd.service           # log của một unit
journalctl -p err -b                 # severity >= err, từ lần boot này
journalctl --since "2026-06-19 02:00" --until "02:30"
journalctl _UID=1000 -o json-pretty  # lọc theo field tin cậy, xuất JSON
journalctl -k                        # log kernel (dmesg)
journalctl -f                        # follow realtime
```
**Persistent journal:** mặc định một số distro lưu ở `/run/log/journal` (volatile, mất khi reboot). Đặt `Storage=persistent` trong `/etc/systemd/journald.conf` và tạo `/var/log/journal` để giữ qua reboot — bắt buộc cho điều tra sự cố.

**Lưu ý bảo mật:** bật **Forward Secure Sealing (FSS)** chống sửa log:
```bash
journalctl --setup-keys     # tạo sealing key; kẻ tấn công sửa journal sẽ bị phát hiện khi verify
journalctl --verify
```

### 2.7.4. `/var/log/auth.log` — đọc và đối chiếu

Các dòng tiêu biểu (Debian/Ubuntu; trên RHEL là `/var/log/secure`):
```
Jun 19 02:30:01 web01 sshd[1234]: Accepted publickey for alice from 203.0.113.5 port 51514 ssh2: ED25519 SHA256:abc...
Jun 19 02:31:10 web01 sshd[1240]: Failed password for invalid user admin from 198.51.100.9 port 40222 ssh2
Jun 19 02:32:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
Jun 19 02:33:00 web01 sshd[1255]: Disconnected from authenticating user root 198.51.100.9 port 40250 [preauth]
```
- `Accepted publickey ... ED25519 SHA256:...` → fingerprint khóa đăng nhập (đối chiếu allowlist).
- `Failed password for invalid user admin` → tên không tồn tại = quét brute-force.
- `sudo: alice : ... COMMAND=` → audit lệnh đặc quyền.

```bash
# Top IP gây đăng nhập thất bại
grep "Failed password" /var/log/auth.log \
 | grep -oE 'from [0-9.]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head
```

### 2.7.5. logrotate

Ngăn log lấp đầy đĩa và lưu trữ có vòng đời. `/etc/logrotate.d/nginx`:
```
/var/log/nginx/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid)
    endscript
}
```

| Directive | Ý nghĩa |
|---|---|
| `daily` | Xoay mỗi ngày (`weekly`/`monthly`/`size 100M`) |
| `rotate 14` | Giữ 14 bản cũ rồi xóa |
| `compress`/`delaycompress` | Nén bản cũ; trì hoãn nén bản gần nhất (để đang-mở-fd vẫn ghi được) |
| `create 0640 www-data adm` | Tạo log mới với quyền/chủ chỉ định |
| `postrotate ... kill -USR1` | Báo nginx mở lại file log (vì nginx vẫn giữ fd cũ trỏ tới file đã đổi tên) |

**Vì sao cần `postrotate`/USR1?** Tiến trình giữ **inode** qua file descriptor; đổi tên file không đổi inode nó đang ghi → log mới sẽ rơi vào file cũ đã rename. Tín hiệu `USR1` (quy ước của nginx) buộc reopen log. **Lưu ý bảo mật:** `rotate` quá ít hoặc xóa quá nhanh có thể tiêu hủy bằng chứng — căn theo chính sách lưu trữ và đẩy về SIEM trước khi xóa.

---

## 2.8. Quản lý gói: apt và dnf

### 2.8.1. apt (Debian/Ubuntu, `.deb`)

```bash
apt update                       # cập nhật danh sách gói từ repo (tải Release/Packages)
apt full-upgrade                 # nâng cấp, cho phép gỡ gói nếu cần giải phụ thuộc
apt install --no-install-recommends nginx=1.24.0-1
apt-mark hold nginx              # ghim phiên bản
apt list --installed
dpkg -l | grep nginx             # truy vấn DB gói cấp thấp
dpkg -V                          # verify checksum file đã cài (phát hiện tampering)
apt-get -s upgrade               # mô phỏng, không thực thi
```
Cơ chế tin cậy: repo có file `Release` được ký GPG (`Release.gpg`/`InRelease`); khóa công khai nằm ở `/etc/apt/trusted.gpg.d/` hoặc tham chiếu `signed-by=` trong file `.sources`. apt kiểm chữ ký và hash trước khi cài → chống gói giả mạo qua mạng.

### 2.8.2. dnf (RHEL/Fedora/Rocky, `.rpm`)

```bash
dnf check-update
dnf install nginx
dnf history                      # xem lịch sử giao dịch
dnf history undo <id>            # rollback một giao dịch
dnf needs-restarting -r          # dịch vụ cần restart sau update (gói dnf-utils)
rpm -qa | grep nginx
rpm -V nginx                     # verify: cột S(size) M(mode) 5(md5) ... khác baseline
rpm -qf /usr/sbin/nginx          # file này thuộc gói nào
```
RPM ký từng gói bằng GPG; `gpgcheck=1` trong `.repo` ép kiểm.

**Lưu ý bảo mật cho cả hai:** chỉ dùng repo HTTPS đã ký; cố định phiên bản (`hold`/version lock) cho hệ thống quan trọng; `dpkg -V` / `rpm -V` là công cụ kiểm tính toàn vẹn nhanh để phát hiện binary bị thay. Thiết lập `unattended-upgrades` (Debian) / `dnf-automatic` cho bản vá bảo mật tự động.

---

## 2.9. cron — 5 trường thời gian

`crontab -e` của user, hoặc file hệ thống `/etc/crontab` và `/etc/cron.d/*` (có thêm trường USER thứ 6).

```
┌──────── phút        (0–59)
│ ┌────── giờ         (0–23)
│ │ ┌──── ngày tháng  (1–31)
│ │ │ ┌── tháng       (1–12)
│ │ │ │ ┌ thứ trong tuần (0–7; 0 và 7 đều = CN)
│ │ │ │ │
* * * * *  command
```

| Trường | Khoảng | Ký tự đặc biệt |
|---|---|---|
| phút | 0–59 | `*` mọi giá trị; `*/5` mỗi 5; `1,15` danh sách; `0-30` khoảng |
| giờ | 0–23 | như trên |
| ngày | 1–31 | như trên |
| tháng | 1–12 | hoặc tên `jan`–`dec` |
| DOW | 0–7 | hoặc `sun`–`sat` |

Ví dụ:
```cron
*/5 * * * *  /usr/local/bin/health-check.sh           # mỗi 5 phút
0 2 * * 1-5  /usr/local/bin/backup.sh                 # 02:00 T2–T6
30 3 1 * *   root /usr/local/bin/monthly.sh           # (file /etc/cron.d) trường thứ 6 = user
@reboot      /usr/local/bin/startup.sh                 # khi khởi động (macro)
```
Macro: `@reboot @daily @hourly @weekly @monthly @yearly`.

**Lưu ý bảo mật:** cron là điểm persistence ưa thích. Soi: `crontab -l` của mọi user (`/var/spool/cron/crontabs/*` Debian, `/var/spool/cron/*` RHEL), `/etc/crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}`. Entry với `@reboot`, lệnh tải/encode lạ, hoặc trỏ tới `/tmp` rất đáng ngờ. `cron` ghi vào syslog (`cron` facility) — đối chiếu thời điểm chạy với hoạt động đáng ngờ.

---

## 2.10. Bash: file descriptor, redirection, pipe

### 2.10.1. Ba file descriptor chuẩn

Mỗi tiến trình mở sẵn 3 fd; chúng chỉ là số nguyên trỏ vào bảng fd trong kernel:

| fd | Tên | Mặc định |
|---|---|---|
| 0 | stdin | Bàn phím / terminal |
| 1 | stdout | Terminal |
| 2 | stderr | Terminal |

**Vì sao tách stdout và stderr?** Để có thể ghi kết quả "sạch" (1) đi nơi này và lỗi (2) đi nơi khác — không trộn dữ liệu với thông báo lỗi khi xử lý tự động.

### 2.10.2. Redirection — bảng đầy đủ

| Cú pháp | Hành vi |
|---|---|
| `> file` | stdout ghi đè vào file (rút gọn của `1>`) |
| `>> file` | stdout nối thêm |
| `2> file` | stderr ghi đè |
| `2>> file` | stderr nối thêm |
| `&> file` / `>& file` | cả stdout+stderr (bashism) |
| `> file 2>&1` | stdout vào file, RỒI stderr trỏ "tới chỗ 1 đang trỏ" |
| `2>&1 > file` | (THỨ TỰ SAI) stderr trỏ tới terminal, rồi stdout mới đổi sang file |
| `< file` | stdin đọc từ file |
| `<<EOF ... EOF` | here-document |
| `<<<"chuoi"` | here-string |
| `2>/dev/null` | vứt lỗi |
| `n>&-` | đóng fd n |

**Vì sao thứ tự `2>&1` quan trọng?** Redirection xử lý trái→phải. `2>&1` nghĩa "fd 2 = bản sao đích hiện tại của fd 1". Nếu fd 1 chưa đổi (vẫn terminal), stderr cũng ra terminal. Phải đặt `> file` TRƯỚC để fd 1 trỏ vào file, rồi `2>&1` mới sao đúng.

```bash
make 2>build-errors.log              # tách lỗi build ra file riêng
./script.sh > out.log 2>&1           # gộp đúng cách: cả hai vào out.log
./script.sh &>out.log                # tương đương (bash)
diff <(sort a.txt) <(sort b.txt)     # process substitution: mỗi <() là một fd /dev/fd/N
exec 3>/var/log/app.audit            # mở fd tùy chỉnh 3
echo "event" >&3                     # ghi qua fd 3
```

### 2.10.3. Pipe

`cmd1 | cmd2`: kernel tạo một pipe (buffer kernel ~64KB); stdout của `cmd1` (fd 1) nối vào stdin của `cmd2` (fd 0). Hai tiến trình chạy **đồng thời**; `cmd1` chặn khi buffer đầy, `cmd2` chặn khi rỗng — đây là cơ chế backpressure.

```bash
set -o pipefail     # mã thoát của pipeline = lệnh đầu tiên fail (không chỉ lệnh cuối)
cmd1 | cmd2 ; echo ${PIPESTATUS[@]}   # mảng mã thoát từng đoạn pipe
```
**Lưu ý:** mặc định mã thoát của pipeline chỉ là của lệnh cuối — `grep x file | wc -l` trả về 0 dù `grep` không tìm thấy. `pipefail` rất quan trọng trong script bảo mật để không "nuốt" lỗi.

---

## 2.11. Công cụ xử lý text: grep, awk, sed, cut, sort, uniq — phân tích log thực chiến

Đây là bộ công cụ điều tra log hàng ngày. Dưới đây là một pipeline hoàn chỉnh phân tích `auth.log`, giải thích từng đoạn.

### 2.11.1. grep — lọc dòng

```bash
grep -E "Failed password|Invalid user" /var/log/auth.log
grep -c "Accepted" /var/log/auth.log          # đếm dòng khớp
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' file   # CHỈ in phần khớp (IPv4)
grep -v "cron" file                            # đảo: bỏ dòng khớp
grep -i -A3 -B1 error log                      # không phân biệt hoa, in 3 dòng sau, 1 trước
```
`-E` bật regex mở rộng, `-o` chỉ in chuỗi khớp (không cả dòng), `-v` invert, `-c` đếm, `-A/-B/-C` ngữ cảnh.

### 2.11.2. awk — xử lý theo trường

awk chia mỗi dòng thành các trường `$1..$NF` theo `FS` (mặc định khoảng trắng). Cấu trúc: `awk 'PATTERN { ACTION }'`.

```bash
# Đếm số đăng nhập SSH thành công theo user
awk '/Accepted/ {for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' /var/log/auth.log \
  | sort | uniq -c | sort -rn
```
- `/Accepted/`: pattern, chỉ xử lý dòng có "Accepted".
- vòng `for` tìm từ `for`, in từ ngay sau (chính là username) — bền vững dù cột xê dịch.
- `NF` = số trường, `$(i+1)` = trường kế.

```bash
# Tổng byte truyền theo IP từ access log nginx (trường 1 = IP, trường 10 = bytes)
awk '{sum[$1]+=$10} END {for(ip in sum) printf "%-16s %d\n", ip, sum[ip]}' access.log \
  | sort -k2 -rn | head
```
`sum[$1]+=$10` dùng mảng kết hợp (associative array); khối `END` chạy sau khi đọc hết file.

### 2.11.3. sed — stream editor

```bash
sed -n '100,150p' big.log               # chỉ in dòng 100–150
sed 's/[0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}/[IP]/g' log   # ẩn danh hóa IP
sed -i.bak 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed '/^#/d;/^$/d' config                 # xóa dòng comment và dòng trống
```
`-n` tắt in tự động, `p` in; `s/old/new/g` thay thế toàn cục; `-i.bak` sửa tại chỗ và lưu backup `.bak`; `d` xóa dòng.

### 2.11.4. cut — cắt theo cột/ký tự

```bash
cut -d: -f1,7 /etc/passwd          # trường 1 và 7, phân tách bằng ':'
cut -d' ' -f1-3 access.log         # 3 trường đầu
cut -c1-15 /var/log/syslog         # 15 ký tự đầu (cột timestamp)
```
`-d` đặt delimiter, `-f` chọn trường, `-c` chọn theo ký tự.

### 2.11.5. sort & uniq — sắp xếp và đếm trùng

```bash
sort -t: -k3 -n /etc/passwd        # sort theo UID (trường 3), số học
sort -k2 -rn data                  # trường 2, số, giảm dần
uniq -c                            # đếm dòng liên tiếp giống nhau (BẮT BUỘC sort trước)
uniq -d                            # chỉ in dòng có lặp
```
**Vì sao `sort` trước `uniq`?** `uniq` chỉ gộp các dòng giống nhau **liền kề**; phải `sort` để gom chúng lại trước.

### 2.11.6. Pipeline thực chiến — "Top 10 IP brute-force SSH"

```bash
grep "Failed password" /var/log/auth.log \
  | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | awk '{print $2}' \
  | sort \
  | uniq -c \
  | sort -rn \
  | head -n 10
```
Diễn giải từng tầng:
1. `grep "Failed password"` → giữ dòng đăng nhập thất bại.
2. `grep -oE 'from <IPv4>'` → trích đúng cụm `from 198.51.100.9`.
3. `awk '{print $2}'` → bỏ chữ `from`, còn IP.
4. `sort` → gom IP giống nhau lại liền kề (chuẩn bị cho uniq).
5. `uniq -c` → đếm số lần mỗi IP (gắn số đếm vào đầu dòng).
6. `sort -rn` → sắp xếp giảm dần theo số đếm.
7. `head -n 10` → 10 IP tấn công nhiều nhất.

Output mẫu:
```
    412 198.51.100.9
    207 203.0.113.77
     95 192.0.2.44
```
Kết quả này nuôi trực tiếp vào allowlist/blocklist hoặc cảnh báo (xem fail2ban, 2.12.3).

---

## 2.12. Hardening: sshd, fail2ban, netfilter, SELinux/AppArmor

### 2.12.1. `sshd_config` — từng directive

File `/etc/ssh/sshd_config`; áp dụng bằng `systemctl reload sshd`. Cấu hình hardening mẫu:

```sshdconfig
Port 22
Protocol 2
AddressFamily inet

# Xác thực
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
AuthenticationMethods publickey

# Giới hạn người dùng
AllowGroups ssh-users
AllowUsers alice@203.0.113.0/24

# Mã hóa (chỉ thuật toán mạnh)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Giảm bề mặt
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
```

| Directive | Tác dụng bảo mật |
|---|---|
| `PermitRootLogin no` | Buộc đăng nhập user thường rồi `sudo` → có audit trail; chặn brute-force trực tiếp root |
| `PasswordAuthentication no` | Chỉ cho khóa công khai → loại bỏ brute-force mật khẩu |
| `MaxAuthTries 3` | Ngắt kết nối sau 3 lần sai |
| `LoginGraceTime 30` | Đóng kết nối chưa xác thực sau 30s (chống giữ slot) |
| `AuthenticationMethods publickey` | Có thể ép đa yếu tố: `publickey,keyboard-interactive` |
| `AllowGroups`/`AllowUsers` | Allowlist ai được SSH (ngầm deny phần còn lại) |
| `KexAlgorithms`/`Ciphers`/`MACs` | Loại thuật toán yếu; `-etm` (encrypt-then-MAC) an toàn hơn |
| `LogLevel VERBOSE` | Ghi cả fingerprint khóa dùng đăng nhập (rất hữu ích điều tra) |

```bash
sshd -t                  # kiểm cú pháp trước khi reload (TRÁNH tự khóa mình)
sshd -T | grep -i permitroot   # in cấu hình hiệu lực thực tế
```
**Lưu ý bảo mật:** luôn `sshd -t` và giữ một phiên đang mở khi reload, phòng cấu hình sai khóa luôn truy cập. Cân nhắc đổi không gửi version banner và đặt `Match` block cho cấu hình theo nhóm/địa chỉ.

### 2.12.2. fail2ban — chặn brute-force động

fail2ban đọc log, dùng regex (`failregex`) phát hiện thất bại, rồi gọi action (thường chèn rule firewall) ban IP một thời gian.

`/etc/fail2ban/jail.local`:
```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = nftables-multiport
ignoreip = 127.0.0.1/8 203.0.113.0/24

[sshd]
enabled  = true
port     = ssh
backend  = systemd
maxretry = 3
bantime  = 24h
```

| Tham số | Ý nghĩa |
|---|---|
| `findtime` | Cửa sổ thời gian đếm thất bại (10 phút) |
| `maxretry` | Số thất bại trong `findtime` để bị ban (3) |
| `bantime` | Thời gian ban (`-1` = vĩnh viễn); có thể bật ban tăng dần |
| `backend = systemd` | Đọc từ journald thay vì file log |
| `ignoreip` | Allowlist không bao giờ ban |

```bash
fail2ban-client status sshd       # xem IP đang bị ban và thống kê
fail2ban-client set sshd unbanip 198.51.100.9
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf   # test failregex
```
Một `failregex` (trong `filter.d/sshd.conf`) ví dụ khớp dòng thất bại:
```
^.*Failed (?:password|publickey) for .* from <HOST>
```
`<HOST>` là macro fail2ban thay bằng regex IP và trích địa chỉ để ban.

**Lưu ý bảo mật:** đặt `ignoreip` cho dải quản trị để không tự khóa. fail2ban chống brute-force nhưng KHÔNG thay thế việc tắt password auth — kết hợp cả hai.

### 2.12.3. Netfilter: iptables và nftables

Cả hai cấu hình framework `netfilter` trong kernel. Gói đi qua các **hook** theo đường:

```
            PREROUTING            FORWARD            POSTROUTING
gói vào --> [raw->mangle->nat] --> routing? --yes--> [mangle->filter] --> [mangle->nat] --> ra
                                      |
                                      | (đích là máy này)
                                      v
                                   INPUT [mangle->filter] --> tiến trình local
                                                                  |
                                                               OUTPUT [...] --> POSTROUTING
```

**iptables** (cú pháp truyền thống) — chính sách deny-by-default cho INPUT:
```bash
iptables -P INPUT DROP                 # policy mặc định: chặn
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT      # cho loopback
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # cho kết nối đã thiết lập
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 5/min -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j LOG --log-prefix "DROP_IN: " --log-level 4
```
Phân tích rule SSH:
- `-A INPUT`: nối vào chain INPUT.
- `-p tcp --dport 22`: TCP đích port 22.
- `-m conntrack --ctstate NEW`: chỉ gói khởi tạo kết nối mới.
- `-m limit --limit 5/min`: tối đa 5 kết nối mới/phút (chống brute-force/flood).
- `-j ACCEPT`: cho qua.

**Vì sao cần rule `ESTABLISHED,RELATED`?** Stateful: một khi kết nối ra/vào hợp lệ được thiết lập, gói phản hồi thuộc trạng thái `ESTABLISHED` được cho qua mà không cần mở port riêng — nền của tường lửa stateful.

**nftables** (thay thế hiện đại, một công cụ `nft` cho IPv4/IPv6) — `/etc/nftables.conf`:
```nft
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        tcp dport 22 ct state new limit rate 5/minute accept
        tcp dport 443 accept
        ip protocol icmp icmp type echo-request limit rate 1/second accept
        log prefix "nft-drop: " counter
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
```
```bash
nft -f /etc/nftables.conf      # nạp
nft list ruleset               # xem toàn bộ rule (kèm counter)
nft list table inet filter
```
**Vì sao nftables thay iptables?** Một framework duy nhất cho v4/v6/arp/bridge, cú pháp set/map gọn (vd. blocklist hàng nghìn IP trong một `set` hiệu năng cao), atomic reload, dễ scripting.

**Lưu ý bảo mật:** mặc định `policy drop` cho INPUT/FORWARD; chỉ mở port cần thiết; rate-limit cổng quản trị; log gói bị drop để điều tra. Lưu rule để tồn tại qua reboot (`netfilter-persistent save` hoặc service `nftables`).

### 2.12.4. SELinux và AppArmor — Mandatory Access Control (MAC)

Quyền rwx truyền thống là **DAC** (Discretionary): chủ sở hữu tự quyết, root bỏ qua mọi thứ. **MAC** áp chính sách hệ thống mà ngay cả root cũng bị ràng buộc — nếu một dịch vụ bị chiếm, MAC giới hạn thiệt hại. Cả hai cài hook qua **LSM** trong kernel.

**SELinux (RHEL/Fedora)** — mọi tiến trình và file có **security context** dạng `user:role:type:level`:
```
system_u:system_r:httpd_t:s0          <- tiến trình httpd
unconfined_u:object_r:httpd_sys_content_t:s0   <- file web nginx phục vụ
```
Quyết định dựa trên **type enforcement**: domain `httpd_t` chỉ được làm những gì policy cho phép trên các type liên quan.

```bash
getenforce                 # Enforcing / Permissive / Disabled
setenforce 0               # tạm chuyển Permissive (chỉ log, không chặn)
ps -eZ | grep nginx        # xem context tiến trình (cờ -Z)
ls -Z /var/www/html        # xem context file
ausearch -m AVC -ts recent # tìm sự kiện bị SELinux chặn (AVC denial)
# Sửa context cho thư mục web tùy biến:
semanage fcontext -a -t httpd_sys_content_t "/srv/www(/.*)?"
restorecon -Rv /srv/www
setsebool -P httpd_can_network_connect on   # bật boolean (cho phép httpd kết nối ra ngoài)
```
AVC denial trong log:
```
type=AVC msg=audit(...): avc:  denied  { read } for  pid=1234 comm="nginx"
 name="secret.txt" scontext=system_u:system_r:httpd_t:s0
 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file
```
Đọc: domain `httpd_t` bị từ chối `read` file mang type `user_home_t` — đúng tinh thần "web server không được đọc file home". **KHÔNG** vô hiệu hóa SELinux để "cho chạy"; thay vào đó sửa context hoặc boolean.

**AppArmor (Ubuntu/SUSE)** — profile theo **đường dẫn** (dễ đọc hơn SELinux). `/etc/apparmor.d/usr.sbin.myapp`:
```
#include <tunables/global>
/usr/sbin/myapp {
  #include <abstractions/base>
  capability net_bind_service,
  network inet stream,
  /etc/myapp/** r,
  /var/lib/myapp/** rw,
  /var/log/myapp.log w,
  /usr/sbin/myapp mr,
  deny /home/** rwx,
}
```
Mỗi dòng = một quy tắc đường dẫn + quyền (`r w m`=mmap exec `ix/px`...). `deny /home/** rwx` chặn tuyệt đối truy cập home.

```bash
aa-status                       # profile nào đang enforce/complain
aa-complain /usr/sbin/myapp     # chế độ chỉ-log (học hành vi)
aa-enforce  /usr/sbin/myapp     # bật chặn
journalctl | grep apparmor      # xem denial (ALLOWED/DENIED)
```
**Vì sao path-based vs type-based?** AppArmor dễ viết/đọc (theo path) nhưng yếu khi file đổi tên/hardlink; SELinux gắn nhãn vào inode nên chặt chẽ hơn nhưng dốc học hơn. Cả hai đều là lớp phòng thủ then chốt: khi RCE xảy ra trong một dịch vụ đã được giam (confined), payload bị chặn ở những thao tác ngoài profile/policy.

---

## 2.13. Tổng kết tư duy phòng thủ trên Linux

- **Ranh giới đặc quyền** là gốc: user/kernel (syscall, seccomp), DAC (rwx/ACL/SUID), MAC (SELinux/AppArmor), capabilities, namespaces. Mỗi lớp thu hẹp thiệt hại khi lớp trên bị phá.
- **Tối thiểu quyền**: dịch vụ chạy user riêng, `NoNewPrivileges`, firewall deny-by-default, sudoers hẹp, mount `nosuid/noexec`.
- **Khả năng quan sát**: log có cấu trúc (journald + auditd), đẩy tập trung tới SIEM trước khi attacker xóa, đọc thành thạo `auth.log`/AVC bằng grep/awk.
- **Toàn vẹn**: `dpkg -V`/`rpm -V`, FSS cho journal, baseline SUID/cron để phát hiện thay đổi.
- **Mọi cấu hình hardening** (sshd, fail2ban, nftables, systemd unit, SELinux) đều có file/cú pháp cụ thể ở trên — dùng làm khuôn mẫu kiểm chứng được trên hệ thật.
