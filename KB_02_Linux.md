# Chương 2 — Hệ điều hành Linux

## Tổng quan

Gần như mọi máy chủ mình từng phải vá lỗi hay lục log sự cố — web server, database, container — đều chạy Linux, nên dấu vết tấn công cũng nằm ngay trong các cơ chế của chính hệ điều hành này. Chương này nhìn Linux qua đúng góc đó: không học để quản trị hệ thống, mà học để biết ai vừa làm gì, bằng quyền nào, và tại sao lại được phép làm vậy.

Điểm xuất phát là ranh giới gốc của mọi hệ Unix: **kernel** chạy ở ring 0 độc quyền phần cứng, còn tiến trình ứng dụng bị nhốt trong **user space** và phải xin qua **syscall** mỗi khi cần tài nguyên — hàng rào này cô lập lỗi và mã độc khỏi phần cứng lẫn khỏi tiến trình khác. Trên nền đó Linux tổ chức file theo chuẩn **FHS** (cấu hình ở `/etc`, log ở `/var/log`) để công cụ và rule giám sát hoạt động độc lập với distro, rồi kiểm soát ai được làm gì bằng **mô hình quyền rwx** cùng các bit đặc biệt SUID/SGID/sticky — một binary SUID-root cấu hình sai vẫn là đường leo thang đặc quyền kinh điển. Danh tính người dùng nằm ở `/etc/passwd`, còn mật khẩu chỉ tồn tại dưới dạng hash trong `/etc/shadow` mà chỉ root đọc được; việc cấp quyền chạy lệnh có kiểm soát thì giao cho **sudo** và **PAM**, hai lớp vừa phân quyền tối thiểu vừa ghi log truy vết.

Lớp tiếp theo là vòng đời tiến trình: một **process** sinh ra qua `fork()` rồi nạp chương trình mới bằng `execve()`, mang theo danh tính bảo mật riêng — khi điều tra, một web server bất ngờ sinh ra shell con chính là chỉ dấu xâm nhập kinh điển. `/proc` phơi bày trạng thái kernel theo từng tiến trình nên là mỏ dữ liệu điều tra, còn **namespaces** và **cgroups** là hai cơ chế cô lập và giới hạn tài nguyên mà mọi container Docker đều dựng trên đó. Toàn bộ vòng đời dịch vụ trên máy, từ khởi động tới giám sát và tự phục hồi, do **systemd** quản lý qua các unit — và cũng chính systemd cho phép hardening từng dịch vụ bằng các directive khai báo.

Phần còn lại của chương là lớp vận hành và điều tra thường nhật, mỗi mảng khá độc lập nên mình gom thành một danh sách ngắn:

- **Logging** qua `rsyslog`/`journald` ghi lại mọi sự kiện nhạy cảm, còn `logrotate` giữ cho đĩa không bị log lấp đầy — nhưng log chỉ có giá trị điều tra thật khi được đẩy khỏi máy trước khi attacker kịp dọn dấu vết cục bộ.
- Trình quản lý gói (`apt`, `dnf`) không chỉ cài phần mềm, nó còn xác minh **chữ ký số** trên đường tải — nền tảng để tin được nguồn gốc mọi thứ đang chạy trên máy.
- **cron** tiện cho tự động hóa bao nhiêu thì cũng hấp dẫn kẻ tấn công bấy nhiêu: một dòng crontab lạ là chỗ giấu backdoor chạy định kỳ rất kín, nên luôn nằm trong danh sách cần kiểm khi điều tra.
- Dưới các câu lệnh vẫn là file descriptor, redirection và pipe của bash ghép thành pipeline, cùng bộ công cụ xử lý text `grep`/`awk`/`sed`/`sort`/`uniq` — thứ giúp truy vấn nhanh trên log dài hàng triệu dòng chỉ bằng một dòng lệnh.
- Cuối cùng là **hardening**: SSH cấu hình chặt, `fail2ban` tự khóa IP dò mật khẩu, firewall chỉ mở đúng cổng cần, và SELinux/AppArmor giới hạn hành vi dịch vụ ngay cả khi nó đã bị chiếm quyền.

> Lệnh và output mẫu trong chương đều chạy thật trên Debian/Ubuntu hoặc RHEL/Rocky; chỗ nào phụ thuộc phiên bản kernel/distro thì có ghi chú riêng.

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
connect(6, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.10")}, 16) = -1 EINPROGRESS (Operation now in progress)
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

Tín hiệu là cơ chế thông báo asynchronous. Số hiệu phổ biến (kiến trúc x86/ARM thông dụng — vài số khác trên alpha/mips, cần kiểm chứng theo `kill -l`):

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
`sum[$1]+=$10` dùng associative array; khối `END` chạy sau khi đọc hết file.

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
Kết quả này nuôi trực tiếp vào allowlist/blocklist hoặc cảnh báo (xem fail2ban, 2.12.2).

---

## 2.12. Hardening: sshd, fail2ban, netfilter, SELinux/AppArmor

### 2.12.1. `sshd_config` — từng directive

File `/etc/ssh/sshd_config`; áp dụng bằng `systemctl reload sshd`. Cấu hình hardening mẫu:

```ini
Port 22
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

**Bốn bảng (table) của iptables — mỗi bảng một nhiệm vụ, đừng trộn:**

| Bảng | Sinh ra để làm gì | Chain có mặt | Khi nào đụng tới |
|---|---|---|---|
| `filter` | Cho/chặn gói — tường lửa đúng nghĩa | INPUT, FORWARD, OUTPUT | 90% thời gian; bảng mặc định khi không có `-t` |
| `nat` | Đổi địa chỉ/port (SNAT/DNAT/MASQUERADE) | PREROUTING, OUTPUT, POSTROUTING | Máy làm gateway/port-forward; chỉ gói `NEW` đi qua |
| `mangle` | Sửa header gói (TTL, TOS/DSCP, mark) | Cả 5 chain | Đánh dấu gói cho QoS/policy routing — hiếm dùng |
| `raw` | Xử lý TRƯỚC conntrack (`NOTRACK`) | PREROUTING, OUTPUT | Loại trừ traffic khối lượng lớn khỏi bảng conntrack |

**Chain là gì?** Danh sách rule gắn vào một hook; gói khớp rule nào trước thì theo verdict (`ACCEPT`/`DROP`/`REJECT`/nhảy chain con) của rule đó — không khớp gì thì theo **policy** của chain. Ngoài 5 chain dựng sẵn có thể tạo chain riêng (`iptables -N ssh-guard`) rồi `-j ssh-guard` để gom rule theo chủ đề — dễ đọc và dễ đếm (mỗi rule có counter riêng, xem bằng `iptables -L -v -n`).

**Cấu trúc một rule đọc cho quen:** `iptables -t <bảng> -A <chain> <match...> -j <verdict>` — match là các điều kiện AND với nhau (`-p tcp --dport 22`, `-s 203.0.113.0/24`, `-i eth0`, `-m conntrack --ctstate NEW`...), verdict là hành động khi khớp toàn bộ.

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

**Vài rule thực dụng hay cần đến:**
```bash
# Chặn một IP / một dải IP (chèn lên ĐẦU chain bằng -I để khớp trước mọi ACCEPT)
iptables -I INPUT -s 198.51.100.9 -j DROP
iptables -I INPUT -s 185.177.72.0/24 -j DROP

# Giới hạn SSH kiểu "cửa sổ trượt" bằng module recent:
# quá 4 kết nối NEW tới port 22 trong 60s từ cùng nguồn -> drop
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --name ssh --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --name ssh --update --seconds 60 --hitcount 4 -j DROP

# Xem rule kèm counter (số gói/byte đã khớp) — cách nhanh biết rule có "ăn" không
iptables -L INPUT -v -n --line-numbers
# Xóa rule theo số dòng
iptables -D INPUT 3
```
Chặn danh sách IP dài (hàng trăm/nghìn entry) thì đừng xếp rule tuần tự — mỗi gói phải duyệt qua từng rule. Dùng `ipset` (với iptables) hoặc `set` (nftables, ví dụ dưới): tra cứu hash O(1), một rule duy nhất tham chiếu cả tập.

**Quan hệ iptables ↔ nftables (đọc kỹ kẻo tưởng mình đang dùng cái này mà hóa ra cái kia):** trên distro hiện đại (Debian 10+, Ubuntu 20.04+, RHEL 8+), lệnh `iptables` thường chỉ là lớp vỏ dịch cú pháp cũ sang backend nftables — gọi là **iptables-nft**. Kiểm tra bằng `iptables -V`: in `(nf_tables)` là vỏ nft, in `(legacy)` là backend cũ. Hệ quả thực tế: rule do `iptables` tạo và rule do `nft` tạo nằm chung kernel nhưng **không hiển thị trong công cụ của nhau** đầy đủ — audit firewall phải xem bằng `nft list ruleset` (nó thấy được cả hai) chứ đừng chỉ `iptables -L` rồi kết luận "máy không có rule". Docker/Kubernetes và fail2ban vẫn hay chèn rule qua lớp iptables — thêm lý do để audit bằng `nft list ruleset`.

**nftables** (thay thế hiện đại, một công cụ `nft` cho IPv4/IPv6) — `/etc/nftables.conf`:
```nft
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    set blocklist {
        type ipv4_addr
        flags interval
        elements = { 198.51.100.9, 185.177.72.0/24 }
    }
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ip saddr @blocklist drop
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
nft -f /etc/nftables.conf      # nạp (atomic: hoặc toàn bộ hoặc không gì cả)
nft list ruleset               # xem toàn bộ rule (kèm counter)
nft list table inet filter
nft add element inet filter blocklist { 203.0.113.99 }   # thêm IP vào set khi đang chạy
```
**Vì sao nftables thay iptables?** Một framework duy nhất cho v4/v6/arp/bridge (bảng `inet` áp cả IPv4+IPv6 một lần — iptables phải duy trì song song `ip6tables`), cú pháp set/map gọn (blocklist hàng nghìn IP trong một `set` tra cứu hash thay vì duyệt tuần tự), atomic reload (không có khoảnh khắc "nửa ruleset cũ nửa mới"), dễ scripting.

**Lưu rule bền vững qua reboot** — rule iptables/nft chỉ sống trong kernel memory, reboot là mất sạch:
```bash
# Hướng nftables (khuyến nghị): rule là FILE cấu hình, service nạp lúc boot
nft list ruleset > /etc/nftables.conf   # hoặc tự soạn file rồi nft -f kiểm
systemctl enable --now nftables

# Hướng iptables truyền thống (Debian/Ubuntu)
apt install iptables-persistent         # lưu ở /etc/iptables/rules.v4 và rules.v6
netfilter-persistent save
# RHEL-family: dnf install iptables-services; service iptables save
```
Điểm hay của hướng nftables: `/etc/nftables.conf` là một file text — đưa vào git, review diff như code, `nft -c -f` (check) trước khi áp.

**Lưu ý bảo mật:** mặc định `policy drop` cho INPUT/FORWARD; chỉ mở port cần thiết; rate-limit cổng quản trị; log gói bị drop để điều tra. Sửa firewall từ xa thì tự phòng thân: chạy trong `tmux`/để sẵn một phiên SSH đang mở, hoặc đặt job hoàn tác kiểu `echo 'nft -f /etc/nftables.conf.known-good' | at now + 5 minutes` rồi hủy khi xác nhận còn vào được — khóa mình ngoài máy chủ vì một rule DROP là lỗi kinh điển.

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

## 2.13. Chẩn đoán hiệu năng & tài nguyên — dashboard nói "cao ở đâu", lệnh nói "process nào gây ra"

Vì sao mục này nằm trong sổ tay bảo mật? Thứ nhất, **availability** là một trụ của tam giác CIA — máy sập vì cạn tài nguyên cũng là sự cố an toàn thông tin. Thứ hai, rất nhiều dấu hiệu xâm nhập biểu hiện đầu tiên dưới dạng bất thường tài nguyên: cryptominer = CPU cao bất thường, DoS = load/network vọt, còn **đĩa đầy thì log ngừng ghi** — attacker được tặng không gian mù. Kỹ năng "nhìn con số bất thường → tìm ra process gây ra" dùng chung cho cả vận hành lẫn điều tra.

Phương pháp luận mình dùng: **hai tầng, mỗi tầng trả lời một câu hỏi khác nhau.**
- Tầng metric/dashboard (Prometheus + node_exporter, vẽ bằng Grafana — hoặc bất kỳ stack nào tương đương): trả lời "**cao ở đâu, từ lúc nào, xu hướng ra sao**". Metric là số liệu tổng hợp — nó không biết process nào gây ra.
- Tầng lệnh trên máy (SSH vào): trả lời "**process nào, file nào, kết nối nào gây ra**". Lệnh nhìn được từng process nhưng không có lịch sử.

Hai tầng bù nhau: chỉ có dashboard thì biết bệnh mà không biết thủ phạm; chỉ có lệnh thì bắt được hiện trạng mà không biết "cao từ bao giờ, có chu kỳ không". Quy trình khi có cảnh báo: dashboard khoanh vùng trục nào (CPU/RAM/disk/I-O/network/load) → SSH vào → chạy đúng nhóm lệnh của trục đó.

> Bộ lệnh dưới cần gói `sysstat` (cấp `mpstat`/`iostat`/`pidstat`/`sar`), cùng `htop`, `iotop`, `ncdu`: `apt install sysstat htop iotop ncdu`.

### 2.13.1. Tổng quan 30 giây — chạy trước khi nghĩ

Sáu lệnh, chạy theo thứ tự, cho bức tranh tổng thể trước khi đào sâu:

```bash
uptime                    # load average 1/5/15 phút — so với số core
free -h                   # RAM: nhìn cột available, không phải used
df -h                     # mount nào sắp đầy
top                       # (hoặc htop) tổng CPU/RAM + process nổi nhất
dmesg -T | tail -30       # kernel vừa kêu gì: OOM-kill, I/O error, segfault
systemctl --failed        # service nào đang chết
```
30 giây này thường đã khoanh được trục có vấn đề; phần còn lại là đào sâu theo từng trục dưới đây.

### 2.13.2. Trục CPU — đọc theo *mode*, không chỉ theo %

Con số "CPU 90%" chưa nói lên gì; câu hỏi đúng là **90% đó thuộc mode nào**. `mpstat` (gói sysstat) tách CPU theo mode, từng core:

```bash
mpstat -P ALL 1 3        # mỗi giây một mẫu, 3 lần, mọi core
```
```
CPU    %usr  %nice   %sys %iowait  %irq  %soft %steal  %idle
all   72.31   0.00   5.12    0.75  0.00   0.51   9.87  11.44
  0   88.00   0.00   4.00    0.00  0.00   1.00  17.00   7.00
```

| Cột | Là thời gian CPU dành cho | Cao kéo dài nghĩa là |
|---|---|---|
| `%usr` | Code ứng dụng (user space) | Một app thật sự ăn CPU → tìm bằng `htop`/`pidstat`; nếu không nhận ra process thì nghi cryptominer |
| `%sys` | Kernel (syscall, driver) | App gọi syscall dày đặc (I/O nhỏ, fork liên tục) — soi bằng `strace`/`perf` |
| `%iowait` | *Ngồi không* chờ I/O đĩa | Nghẽn ở ĐĨA chứ không phải CPU — nhảy sang trục Disk I/O (2.13.5), thêm CPU không giải quyết gì |
| `%steal` | Bị hypervisor lấy phục vụ VM khác | Trên VM cloud: noisy neighbor / nhà cung cấp bóp CPU (hết credit burstable). Không sửa được từ trong VM — đổi shape/host hoặc chấp nhận |
| `%irq`/`%soft` | Ngắt cứng/mềm (thường là network) | `%soft` cao bất thường kèm traffic lớn → nghi flood |
| `%idle` | Rảnh | — |

`%iowait` và `%steal` là hai cái bẫy kinh điển: cả hai đều làm "CPU cao" trên dashboard nhưng thủ phạm không phải CPU. Tìm process theo CPU:

```bash
ps aux --sort=-%cpu | head -12    # ảnh chụp hiện tại
pidstat 1 5                       # theo thời gian — thấy được process "nhấp nhô"
```
`pidstat` hơn `ps` ở chỗ lấy mẫu liên tục: process chỉ spike từng đợt sẽ hiện ra thay vì lọt khe giữa hai lần chạy `ps`.

### 2.13.3. Trục RAM — PSI thay cho "used cao"

**Cái bẫy lớn nhất của trục RAM: "used cao" thường KHÔNG phải vấn đề.** Linux chủ động dùng RAM rảnh làm page cache (đọc lại file khỏi chạm đĩa), và nhiều app (JVM, Elasticsearch, database) cấp phát heap lớn rồi giữ luôn — đó là hành vi thiết kế, không phải rò rỉ. Con số cần nhìn trong `free -h` là **`available`** (ước lượng RAM có thể cấp ngay cho tiến trình mới, đã tính phần cache thu hồi được), không phải `used`.

Vậy khi nào là thiếu RAM *thật*? Kernel trả lời trực tiếp qua **PSI — Pressure Stall Information** (kernel ≥ 4.20): thay vì đo "đang dùng bao nhiêu", PSI đo **tổng thời gian tiến trình bị đình trệ vì chờ tài nguyên** — tức đo đúng cái ta quan tâm là "có ai đang khổ vì thiếu RAM không".

```bash
cat /proc/pressure/memory
```
```
some avg10=0.00 avg60=0.00 avg300=0.00 total=0
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
```
- `some` = % thời gian có **ít nhất một** task bị đình trệ vì thiếu memory; `full` = % thời gian **mọi** task không-idle đều đình trệ (cả máy khựng).
- `avg10/60/300` = trung bình trượt 10 giây / 1 phút / 5 phút.
- Đọc: toàn 0.00 → RAM ổn bất kể `used` bao nhiêu. `some avg10` dương kéo dài → bắt đầu thiếu; `full` dương → máy đang khựng thấy rõ, thường ngay trước OOM-kill. Cùng định dạng đó có `/proc/pressure/cpu` và `/proc/pressure/io` — node_exporter thu được cả ba, làm panel cảnh báo tốt hơn hẳn % used.

Chuỗi kiểm tra đầy đủ:
```bash
free -h                           # nhìn available; swap đã dùng bao nhiêu
cat /proc/pressure/memory         # PSI — thước đo "thiếu thật"
vmstat 1 5                        # cột si/so: swap-in/out (KB/s) đang diễn ra
ps aux --sort=-%mem | head -12    # process ăn RAM nhất (cột RSS)
dmesg -T | grep -iE "oom|killed process"   # kernel đã phải xử ai chưa
```
- `si`/`so` dương liên tục = máy đang swap qua lại (thrashing) — hiệu năng rơi tự do dù "chưa hết RAM".
- OOM-kill trong `dmesg` là bằng chứng đã quá muộn: kernel chọn giết process điểm `oom_score` cao nhất. Nếu nạn nhân là service quan trọng, cân nhắc `MemoryMax=` (cgroup, mục 2.5.7) cho các service còn lại thay vì tăng RAM theo phản xạ.

### 2.13.4. Trục dung lượng đĩa — df nói dối ở hai chỗ

```bash
df -h                             # mount nào đầy — nhưng chưa đủ, đọc tiếp
df -i                             # INODE: hết inode cũng báo "No space left" dù còn hàng chục GB
sudo du -xh --max-depth=1 / 2>/dev/null | sort -h | tail -15   # thư mục nào to (-x: không lạc sang mount khác)
ncdu -x /                         # như du nhưng duyệt tương tác — drill-down rất nhanh
sudo lsof +L1 | grep -i deleted   # file ĐÃ XÓA nhưng process còn giữ fd
docker system df                  # Docker chiếm bao nhiêu (image/container/volume/build cache)
journalctl --disk-usage           # journal chiếm bao nhiêu
```
Hai chỗ `df -h` "nói dối":
1. **Hết inode**: filesystem có số inode hữu hạn; hàng triệu file nhỏ (session file, cache, mail queue) ăn hết inode trong khi dung lượng còn thừa — lỗi vẫn là "No space left on device". `df -i` lộ ngay (`IUse%` 100%).
2. **File đã xóa nhưng chưa giải phóng**: xóa file chỉ gỡ tên khỏi thư mục; **inode và data còn nguyên chừng nào còn process giữ file descriptor mở** (chính cơ chế đã gặp ở logrotate, mục 2.7.5). Triệu chứng kinh điển: `rm` file log 20GB mà `df` không nhúc nhích. `lsof +L1` (liệt kê file có link count 0) chỉ đích danh process; xử đúng là reload/restart process đó (hoặc signal reopen-log kiểu `USR1`), không phải đi xóa tiếp.

Máy chạy Docker thì thủ phạm quen mặt là `/var/lib/docker`: image cũ mỗi lần deploy chồng thêm, build cache, container log. `docker system df -v` liệt kê chi tiết. Dọn có chủ đích (`docker image prune -a --filter "until=168h"` — chỉ image, có mốc thời gian) chứ **đừng phang `docker system prune` trên máy có volume dữ liệu** — thêm nhầm `--volumes` là mất data thật.

**Góc bảo mật:** đĩa đầy = log ngừng ghi = mù điều tra; vì thế "đĩa gần đầy" đáng được coi là cảnh báo an ninh chứ không chỉ vận hành. Chiều ngược lại, attacker cũng biết điều đó — một dạng anti-forensics là cố tình ghi đầy đĩa trước khi hành động.

### 2.13.5. Trục Disk I/O — đĩa "bận" khác đĩa "đầy"

Đĩa còn trống vẫn có thể nghẽn vì **băng thông I/O bão hòa** — triệu chứng lộ ra ở `%iowait` (2.13.2) và app "chậm không rõ lý do".

```bash
iostat -xz 1 5                    # -x: thống kê mở rộng; -z: ẩn thiết bị im lặng
```
```
Device   r/s   w/s   rkB/s   wkB/s  await  %util
sda      1.2  310.5    48.0  42817.3  38.20  97.40
```
- `%util` = % thời gian thiết bị có I/O đang xử lý. Gần 100% kéo dài = đĩa kín lịch. (Với SSD/NVMe xử lý song song, `%util` 100% chưa chắc đã là trần thật — đọc kèm `await`.)
- `await` = thời gian trung bình một request hoàn thành, **tính cả thời gian xếp hàng** (ms). Đây là con số app "cảm nhận" được: `%util` cao mà `await` thấp thì đĩa bận nhưng vẫn kịp thở; cả hai cùng cao là bão hòa thật.
- `r/s`, `w/s`, `rkB/s`, `wkB/s`: hình dạng tải — nghìn request nhỏ hay ít request to, đọc hay ghi.

Tìm thủ phạm:
```bash
sudo iotop -o                     # -o: chỉ hiện process ĐANG có I/O
pidstat -d 1 5                    # kB đọc/ghi theo process theo thời gian
cat /proc/pressure/io             # PSI cho I/O — đọc y hệt PSI memory
```
Thủ phạm hay gặp: job backup/nén chạy giờ cao điểm, database thiếu index quét cả bảng, log ghi quá dày, và swap thrashing (khi đó gốc bệnh là RAM — quay lại 2.13.3).

### 2.13.6. Trục network — nhìn drop/error, đừng nhìn % băng thông

```bash
ss -tulpn                         # cổng đang NGHE + process — soi bề mặt phơi ra ngoài
ss -s                             # tổng kết nối theo trạng thái (estab, timewait...)
ss -tan state established | wc -l # đếm kết nối đang mở
ip -s link                        # counter RX/TX: errors, dropped, overrun theo interface
sar -n DEV 1 5                    # throughput từng interface theo thời gian
```
`ip -s link` in hai khối RX/TX; cột đáng nhìn là `errors`/`dropped`:
```
RX: bytes  packets errors dropped overrun mcast
    9.1G   8123456      0   12043       0     0
```
- Băng thông chạm trần hiếm khi là vấn đề thật trên server thường; **drop/error tăng đều mới là bệnh** (buffer tràn, NIC/driver lỗi, máy không kịp nhận → gói rớt, retransmit, độ trễ tăng). Cảnh báo nên đặt trên *tốc độ tăng* của counter drop, không phải % băng thông.
- `ss -s` với `estab` vọt bất thường + nguồn phân tán là hình dạng của DoS/flood; `ss -tulpn` xuất hiện cổng nghe lạ là chỉ dấu backdoor (đối chiếu baseline).

### 2.13.7. Trục load — load cao không đồng nghĩa thiếu CPU

**Load average trên Linux đếm cả process `R` (chờ CPU) lẫn process `D` (uninterruptible — kẹt I/O, mục 2.5.2).** Đây là điểm dễ hiểu sai nhất: load 20 trên máy 4 core có thể là 20 process tranh CPU, mà cũng có thể là CPU rảnh tênh và 20 process đang treo chờ một cái NFS chết.

```bash
uptime && nproc                   # load Ở ĐÂU so với SỐ CORE — load/core > 1 kéo dài mới đáng ngại
vmstat 1 5                        # cột r = chờ CPU; b = blocked; wa = %iowait
ps -eo state,pid,comm | grep "^D" # điểm danh process trạng thái D
```
Đọc phán quyết: load cao + `r` cao + `%usr` cao → thiếu CPU thật. Load cao + `b` cao + nhiều process `D` + `wa` cao → kẹt I/O (đĩa hỏng, NFS treo, storage cloud bị bóp) — quay về trục Disk I/O, và nhớ process `D` không giết được bằng `kill -9` (2.5.2).

### 2.13.8. Bảng tra nhanh: triệu chứng → lệnh đầu tiên

| Dashboard/panel báo | Chạy trước tiên | Đang trả lời câu hỏi |
|---|---|---|
| CPU cao | `mpstat -P ALL 1`, `htop` | Mode nào? Process nào? |
| RAM cao / PSI memory | `cat /proc/pressure/memory`, `ps aux --sort=-%mem` | Thiếu thật hay chỉ used cao? Ai ăn? |
| Đĩa đầy | `df -h; df -i`, `du -xh --max-depth=1 /`, `lsof +L1` | Đầy dung lượng, hết inode, hay file ma? |
| Disk I/O / PSI io | `iostat -xz 1`, `iotop -o` | Bão hòa chưa? Process nào ghi? |
| Network | `ip -s link`, `ss -tulpn` | Drop/error hay chỉ nhiều traffic? Cổng lạ? |
| Load cao / procs blocked | `vmstat 1`, `ps -eo state,pid,comm \| grep "^D"` | Thiếu CPU hay kẹt I/O? |

Kinh nghiệm của mình: viết hẳn bảng này thành runbook nội bộ (panel nào đỏ → dán nguyên khối lệnh nào) — lúc sự cố 2 giờ sáng không ai nhớ nổi cờ của `iostat`.

---

## 2.14. Tổng kết tư duy phòng thủ trên Linux

- **Ranh giới đặc quyền** là gốc: user/kernel (syscall, seccomp), DAC (rwx/ACL/SUID), MAC (SELinux/AppArmor), capabilities, namespaces. Mỗi lớp thu hẹp thiệt hại khi lớp trên bị phá.
- **Tối thiểu quyền**: dịch vụ chạy user riêng, `NoNewPrivileges`, firewall deny-by-default, sudoers hẹp, mount `nosuid/noexec`.
- **Khả năng quan sát**: log có cấu trúc (journald + auditd), đẩy tập trung tới SIEM trước khi attacker xóa, đọc thành thạo `auth.log`/AVC bằng grep/awk.
- **Toàn vẹn**: `dpkg -V`/`rpm -V`, FSS cho journal, baseline SUID/cron để phát hiện thay đổi.
- **Sẵn sàng cũng là bảo mật**: cạn tài nguyên (CPU/RAM/đĩa/I-O) vừa là sự cố vừa là triệu chứng tấn công; chẩn đoán hai tầng "dashboard nói cao ở đâu, lệnh nói process nào gây ra" (2.13) là kỹ năng dùng chung cho vận hành lẫn điều tra.
- **Mọi cấu hình hardening** (sshd, fail2ban, nftables, systemd unit, SELinux) đều có file/cú pháp cụ thể ở trên — dùng làm khuôn mẫu kiểm chứng được trên hệ thật.


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*

- **Runbook là thứ đáng viết nhất mà mình đã trì hoãn lâu nhất.** Hồi mới nhận việc trực máy chủ, mỗi lần panel Grafana chuyển đỏ là mình lại google lại cờ của `iostat`. Sau mình ngồi viết hẳn một runbook "panel nào đỏ → dán nguyên khối lệnh nào" (chính là khung của mục 2.13) và dùng nó gần như hằng ngày. Bài học: kiến thức chẩn đoán chỉ có giá trị khi nó nằm sẵn dưới dạng lệnh copy-paste được lúc 2 giờ sáng, không phải dạng "mình nhớ là có tool đó".
- **Mình từng hiểu sai "RAM used cao = sắp chết".** Có lần thấy máy báo RAM dùng ~90% là mình lo sốt vó, định đề xuất nâng RAM. Sau mới hiểu app (kiểu JVM/search engine) giữ heap là hành vi thiết kế, và Linux tận dụng RAM rảnh làm cache. Từ ngày biết PSI (`/proc/pressure/memory`), mình gần như không nhìn % used nữa: PSI bằng 0 thì kệ used bao nhiêu; PSI dương kéo dài mới là lúc hành động. Đổi một con số theo dõi mà đỡ hẳn cảnh báo giả.
- **Lần đầu thấy `%steal` mình tưởng máy hỏng.** Một VM cloud chậm bất thường, `%usr` thấp mà máy vẫn ì — hóa ra `%steal` hai chữ số: hypervisor đang chia CPU cho hàng xóm ồn ào. Không có gì để "sửa" từ trong VM cả; cái sửa được là biết đọc đúng cột để khỏi mất một buổi đi soi app oan.
- **Đầy đĩa vì Docker image tích luỹ.** Trên máy chạy Docker, thủ phạm đầy đĩa hay gặp nhất là `/var/lib/docker`: mỗi lần build/deploy chồng thêm một image mới mà image cũ không ai dọn. Cách xử lý là cron dọn định kỳ bằng `docker image prune` có filter thời gian — và tuyệt đối không `docker system prune` bừa trên máy có volume dữ liệu, thêm nhầm một cờ `--volumes` là mất data thật. Một bẫy đi kèm: `rm` file log to mà `df` không giảm — file chưa thực sự chết vì process còn giữ fd, `lsof +L1` chỉ đích danh.
- **Về firewall, cú lừa lớn nhất với mình là iptables-nft.** `iptables -L` trên máy này, `nft list ruleset` trên máy kia ra hai bức tranh khác nhau làm mình loạn một hồi, cho tới khi hiểu `iptables` giờ thường chỉ là vỏ dịch sang nftables (`iptables -V` in `(nf_tables)`). Giờ audit firewall mình mặc định xem `nft list ruleset` cho đủ, kể cả rule do Docker hay fail2ban chèn.
- **Đang tìm hiểu tiếp:** nối cảnh báo từ SIEM sang firewall để tự thêm IP vào nftables set theo ngưỡng (kiểu fail2ban nhưng lấy tín hiệu từ log tập trung thay vì log cục bộ) — mới ở mức thử nghiệm, chưa dám cho tự chặn trên production vì sợ ban nhầm dải NAT của người dùng thật.
