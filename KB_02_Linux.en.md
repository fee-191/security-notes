# Chapter 2 — The Linux Operating System

## Overview

This chapter examines the inner workings of the Linux operating system from an information-security perspective: privilege separation, the process lifecycle, filesystem organization, logging, and hardening measures. The bulk of server infrastructure (web servers, databases, containers, cloud) runs on Linux; consequently both attack and defense play out directly against the mechanisms described here. This section summarizes the core concepts to frame the detailed technical material that follows.

### User space and kernel space
The **kernel** runs at ring 0 with exclusive access to the hardware and to system data structures. Application processes run in **user space** (ring 3) and cannot directly touch the hardware or another process's memory. Every resource request (reading a file, opening a socket) must go through a **system call (syscall)**, where the kernel checks permissions. This boundary is the root security barrier: it isolates faults and malicious code from the hardware and from the address space of other processes.

### The FHS directory tree
The **Filesystem Hierarchy Standard (FHS)** standardizes the location of each type of file: configuration in `/etc`, logs in `/var/log`, system binaries in `/usr/bin`. This standard lets tools, scripts, and monitoring rules operate independently of the distribution. Security implication: the fixed location of sensitive resources (e.g., `/etc`) makes it possible to identify precisely which objects need integrity monitoring.

### The permission model
Every file carries three sets of **read / write / execute (rwx)** permissions for three classes: **owner, group, and others (other)**. Three special bits are added: **SUID**, **SGID**, and the **sticky bit**; of these, SUID lets a process run with the permissions of the file's owner (possibly root). Misconfigured permissions — especially a poorly written SUID-root binary — are among the most common privilege-escalation vectors.

### `/etc/passwd`, `/etc/shadow`, and password hashes
`/etc/passwd` is the world-readable account database (name, UID, shell). Passwords are not stored here; they are **hashed** and placed in `/etc/shadow`, which only root can read. A hash is a one-way transformation: the original password cannot be computed back from it. Splitting the two files keeps the account table public for UID↔name mapping while isolating sensitive data from access for offline cracking.

### `sudo`, PAM
- **sudo**: lets a user execute specified commands with another user's privileges (root by default) without sharing the root password; every invocation is logged. Compared with `su`, sudo provides least privilege and an audit trail.
- **PAM (Pluggable Authentication Modules)**: separates authentication logic from the application. Instead of each service (ssh, login, sudo) implementing its own credential check, they all call PAM. Additional rules (lock the account after N failures, enforce password complexity) are declared centrally and applied system-wide.

### Processes
A **process** is a program in execution, identified by a PID and carrying a security identity (effective UID/GID). A new process is created via `fork()` (cloning the parent process) followed by `execve()` (loading a new program image). **Signals** are an asynchronous control mechanism (requests to stop, terminate, reload). During an investigation, a process's parent-child relationship, identity, and syscall sequence are key data points: a web server spawning a shell is a classic indicator of compromise.

### `/proc`, namespaces, cgroups
- **`/proc`**: a pseudo-filesystem that exposes kernel and per-process state (the running binary, file descriptors, network connections); it is a critical forensic data source.
- **Namespaces**: a kernel mechanism that virtualizes resources (network, PID tree, mounts, etc.) so that a group of processes sees what looks like its own private system. This is the foundation of **containers** (Docker).
- **cgroups**: limit and measure resources (CPU, RAM, IO, number of processes) per group. The primary goal is to protect availability: preventing an abused service from exhausting the entire host's resources.

### systemd
**systemd** is the init process (PID 1) on most modern distributions, managing the service lifecycle through **units**. Compared with sysvinit, systemd starts services in parallel according to their dependencies, restarts failed services automatically, monitors them through cgroups, and allows per-service hardening through declarative directives (limiting privileges, syscalls, filesystem access).

### Logging (rsyslog, journald, logrotate)
**Logs** record system events: logins, privileged commands, errors. `rsyslog` and `journald` are two log-collection systems; `logrotate` manages the lifecycle of log files to prevent the disk from filling up. Logs are forensic evidence, so they should be forwarded to a centralized system (SIEM) as early as possible: a log copy that has left the machine is not deleted when an attacker cleans up local logs.

### Package management (apt, dnf)
A package manager installs, removes, and updates software with a unified set of commands, and it verifies **digital signatures** to ensure the integrity and provenance of packages in transit. Timely patching and control over software sources are foundations of a secure system.

### cron
**cron** executes commands on a predefined schedule (by minute, hour, day). Beyond its automation value, cron is a favored persistence location for malware (running a backdoor periodically); cron configurations are therefore objects that must be examined during an investigation.

### Bash: file descriptors, redirection, pipes
Every process opens three standard **file descriptors**: stdin (0), stdout (1), stderr (2). **Redirection** redirects these streams to a file or another descriptor; a **pipe** (`|`) connects one command's stdout to the next command's stdin. This mechanism lets small commands be combined into powerful processing pipelines — the basis of automation scripts and log analysis.

### Text-processing tools (grep, awk, sed, etc.)
A suite of tools for filtering and extracting text: `grep` finds lines by pattern, `awk` processes by column/field, `sed` substitutes lines, `sort`/`uniq` sort and count. On logs that can run to millions of lines, these tools allow fast queries (for example, listing the IPs with the most failed logins) in a single command line — a daily investigative skill.

### Hardening (sshd, fail2ban, firewall, SELinux/AppArmor)
**Hardening** is a set of measures that shrink the attack surface: configuring SSH securely, using `fail2ban` to automatically block password-guessing IPs, using a firewall (netfilter) to open only the necessary ports, and applying **Mandatory Access Control** (SELinux/AppArmor) to constrain a service's behavior even after it is compromised. Default configurations are usually permissive; hardening brings the system back to the principle of least privilege.

> A technical reference for security engineers (Blue Team / AppSec / DevSecOps). Every data structure is described down to the field/byte level; every tool comes with a runnable, real-world example. Sample commands and output are taken from common Linux environments (Debian/Ubuntu, RHEL/Rocky); a few figures that depend on the kernel/distribution version are noted explicitly.

---

## 2.1. Overall architecture and the user space / kernel space boundary

Before diving into each mechanism, it is essential to understand the layered model, because nearly every security decision on Linux revolves around the boundary between **user space** and **kernel space**.

```
+---------------------------------------------------------------+
|  USER SPACE (ring 3 on x86-64)                               |
|   bash, sshd, nginx, python ...                               |
|   libraries: glibc (libc.so.6), libssl ...                   |
|        |  system call (syscall instruction)                   |
+--------|------------------------------------------------------+
         v
+---------------------------------------------------------------+
|  KERNEL SPACE (ring 0)                                       |
|   - syscall dispatcher (sys_call_table)                      |
|   - scheduler (CFS/EEVDF depending on version)               |
|   - VFS -> ext4/xfs/btrfs                                     |
|   - net stack (socket -> TCP/IP -> netfilter)                |
|   - LSM hooks (SELinux/AppArmor)                             |
|   - process, memory (page table), namespaces, cgroups mgmt   |
+---------------------------------------------------------------+
```

**Why the ring 3 / ring 0 split?** The x86-64 CPU has four privilege levels (rings 0–3); Linux uses only ring 0 (kernel) and ring 3 (user). They are separated so that user-space code cannot directly access the hardware, another process's page tables, or kernel structures — every request must go through a **syscall**, where the kernel checks permissions. This is the root security barrier of the whole system.

**Syscalls at the instruction level (x86-64, Linux):**

| Register | Role during a syscall |
|---|---|
| `rax` | Syscall number (e.g., `read`=0, `write`=1, `open`=2, `execve`=59) |
| `rdi` | Argument 1 |
| `rsi` | Argument 2 |
| `rdx` | Argument 3 |
| `r10` | Argument 4 (note: NOT `rcx` as in the ordinary function-call ABI) |
| `r8`  | Argument 5 |
| `r9`  | Argument 6 |
| `rax` (after the instruction) | Return value (negative = `-errno`) |

The `syscall` instruction switches the CPU to ring 0 and jumps to the address in the `LSTAR` MSR. Observing a process's syscall sequence is a critical investigative technique:

```bash
strace -f -e trace=openat,connect,execve -s 200 curl -s https://example.com -o /dev/null
```

`-f` follows child processes too, `-e trace=` filters a group of syscalls, `-s 200` prints up to 200 characters of strings. Sample output:

```
execve("/usr/bin/curl", ["curl","-s","https://example.com",...], 0x7ffd...) = 0
openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 5
connect(6, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EINPROGRESS (Operation now in progress)
```

**Security note:** seccomp-bpf (used by container runtimes and by systemd's `SystemCallFilter=`) filters precisely these `rax` numbers. Understanding the syscall table helps in writing/reading seccomp profiles and detecting anomalous behavior (e.g., a web server suddenly calling `execve`).

---

## 2.2. Filesystem Hierarchy Standard (FHS)

The FHS (current standard, 3.0) defines the meaning of each top-level directory. **Why have a standard?** So that tools, scripts, and admins can be certain where files reside without depending on the distribution — essential when writing monitoring rules (e.g., tracking writes to `/etc`, `/bin`).

| Path | Purpose | Writable at runtime? | Security concern |
|---|---|---|---|
| `/` | Root | — | — |
| `/bin`, `/sbin` | Essential binaries (often symlinked into `/usr/bin`) | Should not be | Writing here = replacing a system binary |
| `/usr` | Most programs and libraries (`/usr/bin`, `/usr/lib`, `/usr/local`) | Read-only recommended | Watch for changes |
| `/etc` | System configuration files (text) | Yes | `/etc/passwd`, `/etc/shadow`, `/etc/cron*` — top targets |
| `/var` | Variable data: `/var/log`, `/var/spool`, `/var/lib` | Yes | Logs live here; integrity must be protected |
| `/tmp` | Temporary, cleared on reboot, usually `sticky bit` | Yes (anyone) | Target of race-condition / symlink attacks |
| `/var/tmp` | Temporary but preserved across reboots | Yes | Persistent payloads |
| `/home` | User directories | Yes (the owner) | `.ssh/`, `.bash_history` |
| `/root` | root's home | root | — |
| `/proc` | Pseudo-FS: kernel/process state | Partly | `/proc/<pid>/maps`, `/environ` leak secrets |
| `/sys` | Pseudo-FS: device/kernel objects (sysfs) | Partly | cgroups, modules |
| `/dev` | Device nodes (devtmpfs) | — | `/dev/mem`, `/dev/kmem` are highly sensitive |
| `/boot` | Kernel, initramfs, bootloader | Rarely | Tampering = rootkit |
| `/run` | Runtime state (tmpfs, lost on reboot) | Yes | PID files, sockets |
| `/opt` | Third-party software | Yes | — |
| `/mnt`, `/media` | Mount points | — | — |

```bash
stat -f /            # show the filesystem containing /
findmnt -t ext4,xfs  # list mounts with options (ro, nosuid, nodev)
```

**Security note:** mounting `/tmp`, `/var/tmp`, and `/home` with the `nosuid,nodev,noexec` flags is a basic hardening measure — it disables SUID, device nodes, and binary execution from user-writable areas.

---

## 2.3. The permission model: 12 bits, reading `ls -l` character by character, octal, umask

### 2.3.1. The 12-bit permission structure

Every inode stores a 16-bit `st_mode` field; the **low 12 bits** are the access permissions (the remaining 4 high bits encode the file type). The 12 bits are divided into four 3-bit groups:

```
 bit:  11 10  9 | 8 7 6 | 5 4 3 | 2 1 0
       SUID SGID STK| r w x | r w x | r w x
       <--special-->|<owner>|<group>|<other>
```

| Group | Bit | Name | Octal value | Meaning on a FILE | Meaning on a DIRECTORY |
|---|---|---|---|---|---|
| Special | 11 | SUID | 4000 | Run with the file owner's UID | (meaningless) |
| Special | 10 | SGID | 2000 | Run with the owning group's GID | New files inherit the directory's GID |
| Special | 9 | Sticky | 1000 | (historically: keep text in swap; now obsolete) | Only the file owner may delete a file in the dir |
| Owner | 8/7/6 | r/w/x | 0400/0200/0100 | read / write / execute | list / create-delete / cd into |
| Group | 5/4/3 | r/w/x | 0040/0020/0010 | same | same |
| Other | 2/1/0 | r/w/x | 0004/0002/0001 | same | same |

**Why is `x` on a directory different from `r`?** `r` allows reading the list of file names; `x` allows "traversing" (passing through) to access a file already known by name inside it. You can have `x` without `r`: you can reach `/dir/file` if you know its name, but you cannot `ls` the directory.

### 2.3.2. Reading `ls -l` character by character

```
-rwxr-xr--   1 root  staff   8192 Jun 19 10:00 tool
drwxr-x---   2 alice alice   4096 Jun 19 10:00 secret
crw-rw----   1 root  tty     5, 0 Jun 19 10:00 /dev/tty
-rwsr-xr-x   1 root  root   55672 Jun 19 10:00 /usr/bin/passwd
```

The first 10-character string, for example `-rwsr-xr-x`:

| Position | Character | Meaning |
|---|---|---|
| 1 | `-` | File type: `-`=regular file, `d`=dir, `l`=symlink, `c`=char dev, `b`=block dev, `s`=socket, `p`=named pipe (FIFO) |
| 2–4 | `rws` | Owner: r, w, and `s` = SUID set + x set (if SUID is set but x is off, it shows a capital `S`) |
| 5–7 | `r-x` | Group |
| 8–10 | `r-x` | Other |

Special-character rules:
- Owner execute column: `x`+SUID → `s`; SUID without x → `S`.
- Group execute column: `x`+SGID → `s`; SGID without x → `S`.
- Other execute column: `x`+sticky → `t`; sticky without x → `T`.

Example, `/tmp`:
```
drwxrwxrwt 18 root root 4096 Jun 19 11:00 /tmp
                       ^ the letter 't' = sticky bit
```
The sticky bit on `/tmp` prevents user A from deleting user B's files even though `/tmp` has `w` for everyone.

With a device node `crw-rw----`, the "size" column shows the **major, minor** numbers (e.g., `5, 0`) instead of a byte size — because `c`/`b` are devices.

### 2.3.3. Octal and `chmod`

```bash
chmod 4755 /usr/local/bin/myprog   # SUID + rwxr-xr-x
chmod u+s,g-w file                 # symbolic notation
chmod 1777 /tmp                    # sticky + rwx for everyone
stat -c '%a %A %U:%G' /usr/bin/passwd
# 4755 -rwsr-xr-x root:root
```

`%a` prints octal, `%A` prints the rwx string — handy for bulk audits.

**Hunting SUID/SGID — a mandatory investigative technique:**
```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%M %u %p\n' 2>/dev/null
```
- `-xdev`: do not cross into other filesystems (avoids scanning NFS, /proc).
- `-perm -4000`: matches when *at least* the SUID bit is set (the `-` sign means "contains these bits").
- `-printf '%M %u %p\n'`: prints the mode, owner, path.

Sample output:
```
-rwsr-xr-x root /usr/bin/sudo
-rwsr-xr-x root /usr/bin/passwd
-rwsr-xr-x root /usr/bin/su
```

**Security note:** every SUID-root binary is a privilege-escalation surface. A SUID binary that spawns a shell, reads arbitrary files, or writes arbitrary files can be abused (see the GTFOBins project). Establish a baseline list of SUID binaries and alert when a new entry appears.

### 2.3.4. `umask`

`umask` is a **removal mask** of permissions for newly created files/directories. The final permission = the default requested permission AND NOT(umask).

- Default for a file: `0666` (a new file never gets the x bit automatically).
- Default for a directory: `0777`.

| umask | New file | New dir | Interpretation |
|---|---|---|---|
| `022` | `644` | `755` | other/group cannot write |
| `027` | `640` | `750` | other has no access at all |
| `077` | `600` | `700` | owner only |

```bash
umask              # print the current value, e.g. 0022
umask 027
touch a; mkdir b; stat -c '%a %n' a b
# 640 a
# 750 b
```
**Note:** umask is inherited from the shell/PAM (`/etc/login.defs` `UMASK`, `pam_umask`). A service running with a loose umask may create world-readable log/secret files. Server hardening typically sets `027` or `077`.

### 2.3.5. ACLs — POSIX Access Control Lists

The 3-class rwx model is insufficient when you need "user X has separate permissions beyond owner/group". ACLs add fine-grained entries, stored in the extended attribute `system.posix_acl_access`.

```bash
setfacl -m u:bob:rwx,g:devs:r-x file.txt   # grant bob rwx, the devs group r-x
setfacl -d -m u:bob:rwx /shared            # default ACL: new files in the dir inherit it
getfacl file.txt
```
`getfacl` output:
```
# file: file.txt
# owner: alice
# group: alice
user::rw-
user:bob:rwx          <- explicit ACL entry
group::r--
mask::rwx             <- mask: the ceiling of permissions for named users/groups
other::r--
```
**The `mask` is important:** the effective permissions of `user:bob` = the ACL entry AND the mask. If `setfacl -m m::r--`, bob is limited to `r--` even though the entry says `rwx`. When an ACL is present, `ls -l` shows a `+` sign:
```
-rw-rwxr--+ 1 alice alice 0 Jun 19 file.txt
```
The "group" column in `ls -l` now shows the **mask**, not the actual group permissions — a common source of confusion during audits.

**Security note:** ACLs do not appear in a basic `ls -l` (only the `+` sign). Scanning permissions with `find -perm` alone will miss grants made through ACLs. Use `getfacl -R` when investigating sensitive permissions.

---

## 2.4. `/etc/passwd`, `/etc/shadow`, password hashes

### 2.4.1. `/etc/passwd` — 7 fields, separated by `:`

```
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
alice:x:1000:1000:Alice Nguyen,,,:/home/alice:/bin/bash
```

| # | Field | Example | Meaning |
|---|---|---|---|
| 1 | username | `alice` | Login name |
| 2 | password | `x` | `x` = hash is in `/etc/shadow`; `*`/`!` = locked; empty field = no password required (DANGEROUS) |
| 3 | UID | `1000` | User ID. 0 = root; 1–999 system; ≥1000 ordinary users (depends on `login.defs`) |
| 4 | GID | `1000` | Primary group ID |
| 5 | GECOS | `Alice Nguyen,,,` | Full name/comment (sub-fields separated by commas) |
| 6 | home | `/home/alice` | Home directory |
| 7 | shell | `/bin/bash` | Login shell; `/usr/sbin/nologin` or `/bin/false` to block login |

**Why split out shadow?** `/etc/passwd` must be world-readable (`644`) so any process can map UID↔name; if hashes were here, anyone could read them for offline cracking. Hashes are moved to `/etc/shadow`, which only `root` can read.

```bash
getent passwd alice     # query through NSS (includes LDAP/SSSD), not just the file
awk -F: '$3==0 {print $1}' /etc/passwd   # find every UID-0 account (only root should exist)
```
**Security note:** multiple UID-0 accounts = multiple "hidden roots". An empty password field (field 2 blank) allows passwordless login. Both are classic indicators of compromise.

### 2.4.2. `/etc/shadow` — 9 fields

Typical permissions `640 root:shadow` (or `600`).

```
alice:$6$xQk2...salt...$hashpart...:19800:0:99999:7:14:20000:
```

| # | Field | Example | Meaning |
|---|---|---|---|
| 1 | username | `alice` | Matches passwd |
| 2 | password hash | `$6$salt$hash` | Hash or a special state (see below) |
| 3 | last change | `19800` | Date the password was last changed, in **days since 1970-01-01** (epoch days) |
| 4 | min | `0` | Minimum number of days before it may be changed again |
| 5 | max | `99999` | Maximum number of days the password remains valid |
| 6 | warn | `7` | Warning before expiry (days) |
| 7 | inactive | `14` | Number of days after expiry during which login is still allowed |
| 8 | expire | `20000` | Date the account is fully disabled (epoch days) |
| 9 | reserved | (empty) | Reserved |

Special states of field 2:
- `*` or `!` → the account cannot log in with a password.
- `!$6$...` → the password is **locked** (`passwd -l` prepends `!` to the hash); removing the `!` unlocks it.
- Empty → login requires no password.

### 2.4.3. The `$id$salt$hash` hash format

The hash field uses the **Modular Crypt Format (MCF)** syntax: `$id$[params]$salt$hash`.

| `id` | Algorithm | Notes |
|---|---|---|
| `1` | MD5-crypt | Weak, obsolete |
| `2a`/`2b`/`2y` | bcrypt | Strong; common in apps, rare in shadow |
| `5` | SHA-256 crypt | Optional `rounds=` |
| `6` | SHA-512 crypt | Default on many Linux distributions |
| `y` | yescrypt | Default on Debian 11+/recent Ubuntu; memory-hard, the strongest of the group |

Example of dissecting a SHA-512 record:
```
$6$rounds=656000$YxZ.Hk1aB2c3D4e$M9...very.long...hashbase64...
 |  |              |                |
 |  |              |                +-- hash (crypt's special base64 encoding)
 |  |              +------------------- salt (up to 16 characters)
 |  +--------------------------------- optional parameter (rounds)
 +------------------------------------ algorithm id = 6 (SHA-512)
```
**Why a salt?** A random salt makes two users with the same password have different hashes, defeating rainbow tables. **Why `rounds`?** Increasing the computational cost makes offline brute-force/guessing slower.

```bash
# Generate a test hash (yescrypt if the system supports it)
openssl passwd -6 'MatKhau!'      # SHA-512
mkpasswd -m yescrypt 'MatKhau!'   # mkpasswd is provided by the whois package
chage -l alice                    # view the password-aging policy (reads shadow)
```
**Security note:** MD5 hashes (`$1$`) must be upgraded. If `/etc/shadow` is leaked, an attacker runs `hashcat`/`john` offline; hashcat modes: `1800` for `$6$`, `1700` for raw SHA-512, and yescrypt requires a recent hashcat version. Defense: a strong password policy + detection of unauthorized reads of `/etc/shadow` via auditd.

### 2.4.4. `sudo`, `/etc/sudoers`

`sudo` lets you run a command with another user's privileges (root by default) **without sharing the root password**, while logging every command — that is its reason for existing compared with `su`.

The line syntax in `/etc/sudoers` (always edit with `visudo` to check syntax before saving):
```
user    host = (runas_user:runas_group)   [TAG:] command
```
Examples:
```
# who    where     (as-whom)        what
root     ALL=(ALL:ALL) ALL
%admin   ALL=(ALL)     ALL
alice    web01=(www-data) /usr/bin/systemctl restart nginx
bob      ALL=(root)    NOPASSWD: /usr/bin/journalctl
%dev     ALL=(ALL)     /usr/bin/apt update, /usr/bin/apt upgrade
```
Breaking down `alice web01=(www-data) /usr/bin/systemctl restart nginx`:
- `alice`: the subject.
- `web01`: applies only on the host named `web01`.
- `(www-data)`: runs as the user `www-data`.
- the permitted command: exactly `systemctl restart nginx`.

Common TAGs: `NOPASSWD:` (do not prompt for a password), `NOEXEC:` (prevent the binary from spawning child commands).

```bash
sudo -l            # list the current user's sudo permissions
sudo -ll           # more detail
```
**Security note:** overly broad rules are easily abused. `(ALL) NOPASSWD: /usr/bin/vim` allows `:!sh` to become root. Avoid wildcards and editors/interpreters in sudoers. Place drop-in files in `/etc/sudoers.d/` (must be `440`, with no whitespace in the name).

### 2.4.5. PAM — Pluggable Authentication Modules

PAM separates authentication logic from the application: `sshd`, `login`, and `sudo` do not code their own password checks but call PAM, configured in `/etc/pam.d/<service>`. Each line:
```
<type>   <control>   <module>   [arguments]
```

| `type` | Role |
|---|---|
| `auth` | Verify identity (password, token) |
| `account` | Check the account is valid (expiry, login hours) |
| `password` | Change a credential (update the password) |
| `session` | Set up/tear down a session (mount home, logging, ulimit) |

| `control` | Behavior |
|---|---|
| `requisite` | Fail → stop immediately and return failure |
| `required` | Fail → record the failure but still run the rest of the stack (does not reveal which module failed) |
| `sufficient` | Success → return success immediately (if no prior `required` has failed) |
| `optional` | The result is usually ignored |
| `[success=1 default=ignore]` | Advanced step-skipping control syntax |

Example `/etc/pam.d/sshd` (abbreviated) with lockout hardening:
```
auth     required   pam_faillock.so preauth silent deny=5 unlock_time=900
auth     [success=1 default=bad]  pam_unix.so
auth     [default=die]  pam_faillock.so authfail deny=5 unlock_time=900
account  required   pam_faillock.so
session  required   pam_limits.so
```
`pam_faillock` locks the account after 5 failures within the window and reopens it after 900 seconds. `pam_limits` applies `/etc/security/limits.conf` (limits on processes, file descriptors — protects against fork bombs).

**Security note:** an incorrect `sufficient`/`required` order can create an authentication bypass. Add `pam_pwquality` to enforce password complexity. An unfamiliar module in `/etc/pam.d/` (e.g., a PAM backdoor that writes passwords to a file) is a persistence technique worth scrutinizing.

---

## 2.5. Processes

### 2.5.1. Identity and attributes

Each process has a `task_struct` in the kernel. The core attributes:

| Attribute | Meaning |
|---|---|
| PID | Process ID (1 = `init`/systemd) |
| PPID | Parent PID |
| RUID/EUID | Real / Effective UID — EUID determines permissions; SUID makes EUID differ from RUID |
| RGID/EGID | Real / Effective GID |
| SUID/SGID (saved) | UID/GID saved so privileges can be temporarily dropped and regained |
| Supplementary groups | List of secondary groups |

```bash
ps -eo pid,ppid,ruid,euid,stat,comm
id alice
cat /proc/self/status | grep -E '^(Uid|Gid|Groups):'
```

### 2.5.2. Process state (the STAT column)

| Character | Name | Meaning |
|---|---|---|
| `R` | Running/Runnable | Running on the CPU or ready to run |
| `S` | Interruptible sleep | Sleeping while awaiting an event; can be woken by a signal |
| `D` | Uninterruptible sleep | Sleeping inside kernel I/O; does NOT receive signals (even `kill -9`) |
| `T` | Stopped | Stopped by `SIGSTOP`/`SIGTSTP` or under debugging |
| `t` | Traced | Stopped by a debugger |
| `Z` | Zombie | Dead, waiting for the parent to call `wait()` to reap the exit code |
| `X` | Dead | (rarely seen) |

Suffixes in `ps` (the STAT column): `s`=session leader, `+`=foreground group, `l`=multi-threaded, `<`=high priority, `N`=low priority (nice).

**Why can't `D` be killed?** The process is in the kernel's I/O path; waking it with a signal could corrupt the device/filesystem state. A prolonged `D` often signals a hung NFS or a failing disk.

**Zombies:** consume no resources beyond one entry in the process table; many `Z` entries mean the parent process is not calling `wait()`. To kill a zombie, kill/fix the parent process.

### 2.5.3. The signal table

A signal is an asynchronous notification mechanism. Common numbers (common x86/ARM architectures — a few differ on alpha/mips, verify with `kill -l`):

| Number | Name | Default | Catchable/blockable? | Description |
|---|---|---|---|---|
| 1 | SIGHUP | Terminate | Yes | Terminal lost; by convention "reload config" for daemons |
| 2 | SIGINT | Terminate | Yes | Ctrl-C |
| 3 | SIGQUIT | Core dump | Yes | Ctrl-\\ |
| 9 | SIGKILL | Terminate | **NO** | Forced kill; cannot be caught/blocked/ignored |
| 11 | SIGSEGV | Core dump | Yes | Invalid memory access |
| 13 | SIGPIPE | Terminate | Yes | Write to a pipe with no reader |
| 15 | SIGTERM | Terminate | Yes | Polite termination request (the default of `kill`) |
| 17 | SIGCHLD | Ignore | Yes | A child changed state |
| 18 | SIGCONT | Continue | — | Resume a stopped process |
| 19 | SIGSTOP | Stop | **NO** | Stop the process; cannot be caught |
| 20 | SIGTSTP | Stop | Yes | Ctrl-Z |

```bash
kill -l               # list all signal names/numbers
kill -TERM 1234       # send SIGTERM
kill -HUP $(pidof nginx)   # reload nginx with no downtime
kill -9 1234          # SIGKILL (only when necessary)
```
**Why can't `SIGKILL`/`SIGSTOP` be caught?** So the admin/kernel always has a way to stop an unruly process; if they could be caught, malware could protect itself indefinitely.

### 2.5.4. `fork()` + `execve()` — how a process is born

```
parent
  | fork()           -> create a copy-on-write copy of the page table; returns the child PID to the parent, 0 to the child
  +--> child (the copy)
         | execve("/bin/ls", argv, envp)
         |   -> replace the entire memory image with /bin/ls, KEEPING the PID & open fds
         v
       /bin/ls running
```

- `fork()` duplicates the process; thanks to **copy-on-write**, memory is only truly copied when one side writes → fork is cheap.
- `execve()` loads a new program over the current address space; **open file descriptors are still inherited** unless the `O_CLOEXEC` flag is set. This is the basis of shell redirection (section 2.10).
- After the child exits, the parent calls `wait()`/`waitpid()` to retrieve the exit code; until it does, the child becomes a zombie.

**Security note:** a `fork`+`execve("/bin/sh")` chain from a non-shell process (e.g., a web server, a daemon) is a classic RCE indicator — write EDR/auditd rules for an `execve` of a shell whose parent is a network service.

### 2.5.5. `/proc` — a window into the kernel and processes

`/proc/<pid>/` is a pseudo-filesystem generated dynamically by the kernel.

| Path | Contents | Investigative value |
|---|---|---|
| `/proc/<pid>/cmdline` | Full command line (arguments separated by NUL `\0`) | The real command even if `ps` argv is spoofed |
| `/proc/<pid>/exe` | Symlink to the executable binary | Detects deleted binaries (`(deleted)`) — fileless malware |
| `/proc/<pid>/cwd` | Symlink to the working directory | — |
| `/proc/<pid>/environ` | Environment variables (NUL-separated) | Leaks secrets/tokens |
| `/proc/<pid>/maps` | Mapped memory regions (address, permissions, backing file) | Detects code injection |
| `/proc/<pid>/fd/` | Symlinks to every open file descriptor | Find sockets, the log file being written |
| `/proc/<pid>/status` | UID/GID, capabilities, seccomp, namespace | Privilege audit |
| `/proc/<pid>/root` | Symlink to the process's root filesystem (differs under chroot/container) | Detects chroot |

```bash
tr '\0' ' ' < /proc/$$/cmdline; echo      # read cmdline, turn NUL into spaces
ls -l /proc/$(pidof nginx | cut -d' ' -f1)/exe
grep -E 'Cap(Eff|Prm)|Seccomp' /proc/self/status
```
Detect a deleted-but-still-running binary (a malware hiding technique):
```bash
ls -l /proc/*/exe 2>/dev/null | grep deleted
```

### 2.5.6. Namespaces — the foundation of containers

A namespace virtualizes one type of kernel resource so that processes inside the namespace believe they own it privately.

| Namespace | Isolates | `clone()`/`unshare` parameter |
|---|---|---|
| PID | The PID tree (processes in the NS see their own PID 1) | `CLONE_NEWPID` |
| NET | Network interfaces, routing table, iptables, ports | `CLONE_NEWNET` |
| MNT | The mount table | `CLONE_NEWNS` |
| UTS | hostname, domainname | `CLONE_NEWUTS` |
| IPC | SysV IPC, POSIX message queues | `CLONE_NEWIPC` |
| USER | UID/GID mapping (root in the NS = unprivileged outside) | `CLONE_NEWUSER` |
| CGROUP | The root of the visible cgroup tree | `CLONE_NEWCGROUP` |
| TIME | The boottime/monotonic clock | `CLONE_NEWTIME` |

```bash
lsns                              # list every namespace and its owning process
unshare --net --pid --fork --mount-proc bash   # create a shell in new net+pid namespaces
readlink /proc/self/ns/net        # print the namespace inode, e.g. net:[4026531992]
nsenter -t <pid> -n ss -tlnp      # enter a container's net namespace to view its sockets
```
**Why does this matter for security?** A container = namespaces + cgroups + capabilities + seccomp/LSM. `CLONE_NEWUSER` enables "rootless containers" but has historically been the source of many privilege-escalation CVEs. When investigating a container, use `nsenter` to inspect it from the host without needing a shell inside the container.

### 2.5.7. cgroups — limiting and measuring resources

cgroups (v2 is the default on modern systems) group processes into a tree and apply CPU/RAM/IO limits. cgroup v2 mounts at `/sys/fs/cgroup` as a single unified tree.

```bash
systemd-cgls                      # the cgroup tree by systemd unit
cat /sys/fs/cgroup/system.slice/nginx.service/memory.max
cat /sys/fs/cgroup/.../cpu.max    # e.g. "200000 100000" = 2 CPUs (quota/period in microseconds)
```
`memory.max` sets a RAM ceiling; exceeding it → an OOM kill within that cgroup. `pids.max` blocks fork bombs. systemd exposes these limits through `MemoryMax=`, `CPUQuota=`, and `TasksMax=` in the unit.

**Security note:** cgroups are a **resource-exhaustion-prevention** mechanism (availability), not security isolation like namespaces. Set `TasksMax=`/`MemoryMax=` for public-facing services so an abused service cannot bring down the whole host.

---

## 2.6. systemd — init, units, services, timers

systemd is PID 1 on most modern distributions, managing the service lifecycle through **units**. **Why replace sysvinit?** Parallel startup according to dependencies (faster), process supervision (auto-restart), socket/timer activation, monitoring via cgroups, and structured logging (journald).

### 2.6.1. The structure of a service unit

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

| Section | Directive | Meaning |
|---|---|---|
| `[Unit]` | `After=` | Startup order (does not create a hard dependency) |
| | `Requires=` | Hard dependency: if the dependency fails, this unit fails too |
| | `Wants=` | Soft dependency (recommended, not required) |
| `[Service]` | `Type=` | Startup model (see the table below) |
| | `ExecStart=` | The main command to run |
| | `Restart=` | `no`/`on-failure`/`always`/`on-abnormal` |
| | `User=`/`Group=` | Drop privileges — do NOT run as root if not needed |
| `[Install]` | `WantedBy=` | The target that "pulls in" the unit when `enable`d |

The `Type=` values:

| Type | When systemd considers it "fully started" |
|---|---|
| `simple` | Right after `ExecStart` is forked (the default if no `Type`) |
| `exec` | After the binary actually `execve`s successfully |
| `forking` | When the parent process exits (old-style daemons that self-background) — needs `PIDFile=` |
| `oneshot` | The process runs to completion and exits (a setup job); usually paired with `RemainAfterExit=yes` |
| `notify` | When the process sends `sd_notify(READY=1)` over a socket — the most accurate |
| `dbus` | When the service acquires a name on D-Bus |

```bash
systemctl daemon-reload                 # reload after editing a unit
systemctl enable --now myapp.service     # enable at boot + start now
systemctl status myapp.service
systemctl cat myapp.service              # print the effective unit (including drop-ins)
systemd-analyze security myapp.service   # score the hardening (exposure score)
```
**Security note:** `systemd-analyze security` gives an exposure score from 0–10; directives such as `ProtectSystem=strict`, `PrivateTmp=`, `NoNewPrivileges=`, `SystemCallFilter=`, and `CapabilityBoundingSet=` lower the score. This is a highly effective way to harden a service without needing a container.

### 2.6.2. Timer units (replacing cron)

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
Paired with `backup.service` (`Type=oneshot`). `OnCalendar` uses the syntax `DOW YYYY-MM-DD HH:MM:SS`. `Persistent=true` runs a missed job if the machine was off when it was due. `RandomizedDelaySec` spreads out the load.
```bash
systemctl list-timers --all       # see the next and most recent runs
```
**Security advantages over cron:** runs in a cgroup, logs to journald, and inherits all of the `[Service]` hardening — which cron does not have.

---

## 2.7. Logging: rsyslog, journald, auth.log, logrotate

### 2.7.1. The syslog model: facility + severity

Every syslog message carries a **PRI** = facility×8 + severity. On the wire (RFC 5424) the PRI sits inside `< >` at the start of the packet.

Facility (selected):

| Number | Facility |
|---|---|
| 0 | kern |
| 1 | user |
| 2 | mail |
| 3 | daemon |
| 4 | auth (security/authorization) |
| 5 | syslog |
| 10 | authpriv (sensitive auth) |
| 16–23 | local0–local7 (application-defined) |

Severity (lower = more severe):

| Number | Name | Meaning |
|---|---|---|
| 0 | emerg | System is unusable |
| 1 | alert | Action needed immediately |
| 2 | crit | Critical |
| 3 | err | Error |
| 4 | warning | Warning |
| 5 | notice | Normal but noteworthy |
| 6 | info | Informational |
| 7 | debug | Debugging |

Example PRI calculation: facility `authpriv`(10) + severity `info`(6) = 10×8+6 = **86** → the packet begins with `<86>`.

RFC 5424 format:
```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
<86>1 2026-06-19T02:30:01.003Z web01 sshd 1234 - - Accepted publickey for alice
```

| Field | Example | Meaning |
|---|---|---|
| PRI | `<86>` | facility×8+severity |
| VERSION | `1` | Protocol version |
| TIMESTAMP | `2026-06-19T02:30:01.003Z` | ISO 8601, with milliseconds + offset/Z |
| HOSTNAME | `web01` | The emitting machine |
| APP-NAME | `sshd` | The application |
| PROCID | `1234` | Usually the PID |
| MSGID | `-` | Message type (`-` = none) |
| STRUCTURED-DATA | `-` | Standard key=value pairs |
| MSG | `Accepted publickey...` | The content |

### 2.7.2. rsyslog — filtering & forwarding configuration

`/etc/rsyslog.d/50-default.conf` (traditional syntax `facility.severity   destination`):
```
auth,authpriv.*                 /var/log/auth.log
*.info;mail.none;authpriv.none  /var/log/syslog
*.emerg                         :omusrmsg:*
# Forward to a SIEM over TCP (RELP/TLS recommended for production)
*.* @@siem.internal:6514
```
- `auth,authpriv.*` → all severities of these two facilities.
- `mail.none` → exclude the mail facility.
- `@@host:port` = TCP (a single `@` = UDP, which loses packets under high load).

```bash
logger -p authpriv.warning "Test message from logger"   # inject one message
systemctl restart rsyslog
```
**Security note:** forward logs to a centralized SIEM as early as possible — an attacker deleting local logs cannot delete a copy that has left the machine. Prefer TCP/TLS (RELP) so no events are lost and so the transport is secured.

### 2.7.3. journald

systemd-journald stores logs in a **binary, structured, indexed** form. Each entry is a set of fields (including trusted fields supplied by the kernel such as `_UID`, `_PID`, `_SYSTEMD_UNIT` — which applications cannot spoof).

```bash
journalctl -u sshd.service           # logs of one unit
journalctl -p err -b                 # severity >= err, since this boot
journalctl --since "2026-06-19 02:00" --until "02:30"
journalctl _UID=1000 -o json-pretty  # filter by a trusted field, output JSON
journalctl -k                        # kernel logs (dmesg)
journalctl -f                        # follow in real time
```
**Persistent journal:** by default some distributions store it in `/run/log/journal` (volatile, lost on reboot). Set `Storage=persistent` in `/etc/systemd/journald.conf` and create `/var/log/journal` to retain it across reboots — mandatory for incident investigation.

**Security note:** enable **Forward Secure Sealing (FSS)** to detect log tampering:
```bash
journalctl --setup-keys     # create a sealing key; an attacker editing the journal is detected at verify time
journalctl --verify
```

### 2.7.4. `/var/log/auth.log` — reading and correlating

Representative lines (Debian/Ubuntu; on RHEL it is `/var/log/secure`):
```
Jun 19 02:30:01 web01 sshd[1234]: Accepted publickey for alice from 203.0.113.5 port 51514 ssh2: ED25519 SHA256:abc...
Jun 19 02:31:10 web01 sshd[1240]: Failed password for invalid user admin from 198.51.100.9 port 40222 ssh2
Jun 19 02:32:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
Jun 19 02:33:00 web01 sshd[1255]: Disconnected from authenticating user root 198.51.100.9 port 40250 [preauth]
```
- `Accepted publickey ... ED25519 SHA256:...` → the fingerprint of the login key (cross-check against an allowlist).
- `Failed password for invalid user admin` → a non-existent name = brute-force scanning.
- `sudo: alice : ... COMMAND=` → audit of a privileged command.

```bash
# Top IPs causing failed logins
grep "Failed password" /var/log/auth.log \
 | grep -oE 'from [0-9.]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head
```

### 2.7.5. logrotate

Prevents logs from filling the disk and archives them with a lifecycle. `/etc/logrotate.d/nginx`:
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

| Directive | Meaning |
|---|---|
| `daily` | Rotate every day (`weekly`/`monthly`/`size 100M`) |
| `rotate 14` | Keep 14 old copies, then delete |
| `compress`/`delaycompress` | Compress old copies; defer compressing the most recent one (so a still-open fd can keep writing) |
| `create 0640 www-data adm` | Create the new log with the specified permissions/owner |
| `postrotate ... kill -USR1` | Tell nginx to reopen the log file (since nginx still holds the old fd pointing to the renamed file) |

**Why is `postrotate`/USR1 needed?** A process holds the **inode** through a file descriptor; renaming the file does not change the inode it is writing to → new logs would fall into the old, renamed file. The `USR1` signal (nginx's convention) forces it to reopen the log. **Security note:** too small a `rotate` value, or deleting too quickly, can destroy evidence — calibrate to the retention policy and push to a SIEM before deleting.

---

## 2.8. Package management: apt and dnf

### 2.8.1. apt (Debian/Ubuntu, `.deb`)

```bash
apt update                       # refresh the package list from the repo (download Release/Packages)
apt full-upgrade                 # upgrade, allowing package removal if needed to resolve dependencies
apt install --no-install-recommends nginx=1.24.0-1
apt-mark hold nginx              # pin the version
apt list --installed
dpkg -l | grep nginx             # query the low-level package DB
dpkg -V                          # verify the checksums of installed files (detect tampering)
apt-get -s upgrade               # simulate, do not execute
```
The trust mechanism: the repo has a `Release` file signed with GPG (`Release.gpg`/`InRelease`); the public key lives in `/etc/apt/trusted.gpg.d/` or is referenced via `signed-by=` in the `.sources` file. apt checks signatures and hashes before installing → protecting against forged packages over the network.

### 2.8.2. dnf (RHEL/Fedora/Rocky, `.rpm`)

```bash
dnf check-update
dnf install nginx
dnf history                      # view the transaction history
dnf history undo <id>            # roll back a transaction
dnf needs-restarting -r          # services needing a restart after the update (dnf-utils package)
rpm -qa | grep nginx
rpm -V nginx                     # verify: columns S(size) M(mode) 5(md5) ... differing from the baseline
rpm -qf /usr/sbin/nginx          # which package this file belongs to
```
RPM signs each package with GPG; `gpgcheck=1` in the `.repo` enforces the check.

**Security note for both:** use only signed HTTPS repos; pin versions (`hold`/version lock) for critical systems; `dpkg -V` / `rpm -V` are quick integrity-checking tools to detect replaced binaries. Set up `unattended-upgrades` (Debian) / `dnf-automatic` for automatic security patches.

---

## 2.9. cron — 5 time fields

A user's `crontab -e`, or the system files `/etc/crontab` and `/etc/cron.d/*` (which have an additional 6th USER field).

```
┌──────── minute       (0–59)
│ ┌────── hour         (0–23)
│ │ ┌──── day of month (1–31)
│ │ │ ┌── month        (1–12)
│ │ │ │ ┌ day of week  (0–7; both 0 and 7 = Sunday)
│ │ │ │ │
* * * * *  command
```

| Field | Range | Special characters |
|---|---|---|
| minute | 0–59 | `*` any value; `*/5` every 5; `1,15` a list; `0-30` a range |
| hour | 0–23 | as above |
| day | 1–31 | as above |
| month | 1–12 | or the names `jan`–`dec` |
| DOW | 0–7 | or `sun`–`sat` |

Examples:
```cron
*/5 * * * *  /usr/local/bin/health-check.sh           # every 5 minutes
0 2 * * 1-5  /usr/local/bin/backup.sh                 # 02:00 Mon–Fri
30 3 1 * *   root /usr/local/bin/monthly.sh           # (in /etc/cron.d) the 6th field = user
@reboot      /usr/local/bin/startup.sh                 # at boot (macro)
```
Macros: `@reboot @daily @hourly @weekly @monthly @yearly`.

**Security note:** cron is a favored persistence point. Inspect: every user's `crontab -l` (`/var/spool/cron/crontabs/*` on Debian, `/var/spool/cron/*` on RHEL), `/etc/crontab`, and `/etc/cron.{d,hourly,daily,weekly,monthly}`. Entries with `@reboot`, unfamiliar download/encode commands, or that point to `/tmp` are highly suspicious. `cron` logs to syslog (the `cron` facility) — correlate run times with suspicious activity.

---

## 2.10. Bash: file descriptors, redirection, pipes

### 2.10.1. The three standard file descriptors

Every process opens three fds; they are just integers pointing into the kernel's fd table:

| fd | Name | Default |
|---|---|---|
| 0 | stdin | Keyboard / terminal |
| 1 | stdout | Terminal |
| 2 | stderr | Terminal |

**Why separate stdout and stderr?** So that "clean" results (1) can go one way and errors (2) another — without mixing data with error messages during automated processing.

### 2.10.2. Redirection — the full table

| Syntax | Behavior |
|---|---|
| `> file` | stdout overwrites the file (shorthand for `1>`) |
| `>> file` | stdout appends |
| `2> file` | stderr overwrites |
| `2>> file` | stderr appends |
| `&> file` / `>& file` | both stdout+stderr (a bashism) |
| `> file 2>&1` | stdout into the file, THEN stderr points to "wherever 1 currently points" |
| `2>&1 > file` | (WRONG ORDER) stderr points to the terminal, then stdout is redirected to the file |
| `< file` | stdin reads from the file |
| `<<EOF ... EOF` | here-document |
| `<<<"string"` | here-string |
| `2>/dev/null` | discard errors |
| `n>&-` | close fd n |

**Why does the order of `2>&1` matter?** Redirection is processed left→right. `2>&1` means "fd 2 = a copy of fd 1's current destination". If fd 1 has not been changed (still the terminal), stderr also goes to the terminal. You must put `> file` FIRST so fd 1 points to the file, then `2>&1` copies the correct destination.

```bash
make 2>build-errors.log              # split build errors into a separate file
./script.sh > out.log 2>&1           # the correct merge: both go to out.log
./script.sh &>out.log                # equivalent (bash)
diff <(sort a.txt) <(sort b.txt)     # process substitution: each <() is an fd /dev/fd/N
exec 3>/var/log/app.audit            # open a custom fd 3
echo "event" >&3                     # write through fd 3
```

### 2.10.3. Pipe

`cmd1 | cmd2`: the kernel creates a pipe (a kernel buffer ~64KB); `cmd1`'s stdout (fd 1) connects to `cmd2`'s stdin (fd 0). The two processes run **concurrently**; `cmd1` blocks when the buffer is full and `cmd2` blocks when it is empty — this is the backpressure mechanism.

```bash
set -o pipefail     # the pipeline's exit code = the first command that fails (not just the last)
cmd1 | cmd2 ; echo ${PIPESTATUS[@]}   # an array of each pipe segment's exit code
```
**Note:** by default the pipeline's exit code is only that of the last command — `grep x file | wc -l` returns 0 even if `grep` found nothing. `pipefail` is very important in security scripts so errors are not "swallowed".

---

## 2.11. Text-processing tools: grep, awk, sed, cut, sort, uniq — practical log analysis

This is the daily log-investigation toolkit. Below is a complete pipeline analyzing `auth.log`, with each segment explained.

### 2.11.1. grep — filter lines

```bash
grep -E "Failed password|Invalid user" /var/log/auth.log
grep -c "Accepted" /var/log/auth.log          # count matching lines
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' file   # print ONLY the matching part (IPv4)
grep -v "cron" file                            # invert: drop matching lines
grep -i -A3 -B1 error log                      # case-insensitive, print 3 lines after, 1 before
```
`-E` enables extended regex, `-o` prints only the matching string (not the whole line), `-v` inverts, `-c` counts, `-A/-B/-C` give context.

### 2.11.2. awk — process by field

awk splits each line into fields `$1..$NF` by `FS` (whitespace by default). Structure: `awk 'PATTERN { ACTION }'`.

```bash
# Count successful SSH logins per user
awk '/Accepted/ {for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' /var/log/auth.log \
  | sort | uniq -c | sort -rn
```
- `/Accepted/`: a pattern, processes only lines containing "Accepted".
- the `for` loop finds the word `for` and prints the word right after it (which is the username) — robust even if the columns shift.
- `NF` = the number of fields, `$(i+1)` = the next field.

```bash
# Total bytes transferred per IP from an nginx access log (field 1 = IP, field 10 = bytes)
awk '{sum[$1]+=$10} END {for(ip in sum) printf "%-16s %d\n", ip, sum[ip]}' access.log \
  | sort -k2 -rn | head
```
`sum[$1]+=$10` uses an associative array; the `END` block runs after the whole file is read.

### 2.11.3. sed — stream editor

```bash
sed -n '100,150p' big.log               # print only lines 100–150
sed 's/[0-9]\{1,3\}\(\.[0-9]\{1,3\}\)\{3\}/[IP]/g' log   # anonymize IPs
sed -i.bak 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed '/^#/d;/^$/d' config                 # delete comment lines and blank lines
```
`-n` disables automatic printing, `p` prints; `s/old/new/g` substitutes globally; `-i.bak` edits in place and saves a `.bak` backup; `d` deletes a line.

### 2.11.4. cut — cut by column/character

```bash
cut -d: -f1,7 /etc/passwd          # fields 1 and 7, separated by ':'
cut -d' ' -f1-3 access.log         # the first 3 fields
cut -c1-15 /var/log/syslog         # the first 15 characters (the timestamp column)
```
`-d` sets the delimiter, `-f` selects fields, `-c` selects by character.

### 2.11.5. sort & uniq — sorting and counting duplicates

```bash
sort -t: -k3 -n /etc/passwd        # sort by UID (field 3), numerically
sort -k2 -rn data                  # field 2, numeric, descending
uniq -c                            # count consecutive identical lines (MUST sort first)
uniq -d                            # print only lines that have duplicates
```
**Why `sort` before `uniq`?** `uniq` only collapses **adjacent** identical lines; you must `sort` to bring them together first.

### 2.11.6. A practical pipeline — "Top 10 SSH brute-force IPs"

```bash
grep "Failed password" /var/log/auth.log \
  | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | awk '{print $2}' \
  | sort \
  | uniq -c \
  | sort -rn \
  | head -n 10
```
Explanation of each stage:
1. `grep "Failed password"` → keep failed-login lines.
2. `grep -oE 'from <IPv4>'` → extract exactly the `from 198.51.100.9` portion.
3. `awk '{print $2}'` → drop the word `from`, leaving the IP.
4. `sort` → bring identical IPs adjacent (preparing for uniq).
5. `uniq -c` → count how many times each IP occurs (prepends the count to the line).
6. `sort -rn` → sort descending by the count.
7. `head -n 10` → the 10 most active attacking IPs.

Sample output:
```
    412 198.51.100.9
    207 203.0.113.77
     95 192.0.2.44
```
This result feeds directly into an allowlist/blocklist or an alert (see fail2ban, 2.12.3).

---

## 2.12. Hardening: sshd, fail2ban, netfilter, SELinux/AppArmor

### 2.12.1. `sshd_config` — directive by directive

File `/etc/ssh/sshd_config`; apply with `systemctl reload sshd`. A sample hardened configuration:

```sshdconfig
Port 22
Protocol 2
AddressFamily inet

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
AuthenticationMethods publickey

# User restrictions
AllowGroups ssh-users
AllowUsers alice@203.0.113.0/24

# Cryptography (strong algorithms only)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Reduce the surface
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
```

| Directive | Security effect |
|---|---|
| `PermitRootLogin no` | Forces login as an ordinary user then `sudo` → an audit trail; blocks direct brute-forcing of root |
| `PasswordAuthentication no` | Public keys only → eliminates password brute-forcing |
| `MaxAuthTries 3` | Disconnect after 3 failures |
| `LoginGraceTime 30` | Close an unauthenticated connection after 30s (prevents holding a slot) |
| `AuthenticationMethods publickey` | Can enforce multi-factor: `publickey,keyboard-interactive` |
| `AllowGroups`/`AllowUsers` | Allowlist who may SSH (implicitly deny the rest) |
| `KexAlgorithms`/`Ciphers`/`MACs` | Remove weak algorithms; `-etm` (encrypt-then-MAC) is safer |
| `LogLevel VERBOSE` | Logs even the fingerprint of the key used to log in (very useful for investigation) |

```bash
sshd -t                  # check the syntax before reloading (AVOID locking yourself out)
sshd -T | grep -i permitroot   # print the actual effective configuration
```
**Security note:** always `sshd -t` and keep an open session while reloading, in case a misconfiguration locks out access. Consider not sending a version banner and using `Match` blocks for group/address-specific configuration.

### 2.12.2. fail2ban — dynamic brute-force blocking

fail2ban reads logs, uses a regex (`failregex`) to detect failures, then invokes an action (typically inserting a firewall rule) to ban the IP for a period.

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

| Parameter | Meaning |
|---|---|
| `findtime` | The time window for counting failures (10 minutes) |
| `maxretry` | The number of failures within `findtime` to be banned (3) |
| `bantime` | The ban duration (`-1` = permanent); incremental banning can be enabled |
| `backend = systemd` | Read from journald instead of a log file |
| `ignoreip` | Allowlist that is never banned |

```bash
fail2ban-client status sshd       # see currently banned IPs and statistics
fail2ban-client set sshd unbanip 198.51.100.9
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf   # test failregex
```
An example `failregex` (in `filter.d/sshd.conf`) matching a failure line:
```
^.*Failed (?:password|publickey) for .* from <HOST>
```
`<HOST>` is a fail2ban macro that it replaces with an IP regex and uses to extract the address to ban.

**Security note:** set `ignoreip` for the admin range so you do not lock yourself out. fail2ban defends against brute-force but does NOT replace disabling password auth — combine both.

### 2.12.3. Netfilter: iptables and nftables

Both configure the kernel's `netfilter` framework. Packets traverse a set of **hooks** along this path:

```
            PREROUTING            FORWARD            POSTROUTING
packet in -> [raw->mangle->nat] --> routing? --yes--> [mangle->filter] --> [mangle->nat] --> out
                                      |
                                      | (destined for this machine)
                                      v
                                   INPUT [mangle->filter] --> local process
                                                                  |
                                                               OUTPUT [...] --> POSTROUTING
```

**iptables** (traditional syntax) — a deny-by-default policy for INPUT:
```bash
iptables -P INPUT DROP                 # default policy: block
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT      # allow loopback
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # allow established connections
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 5/min -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j LOG --log-prefix "DROP_IN: " --log-level 4
```
Breaking down the SSH rule:
- `-A INPUT`: append to the INPUT chain.
- `-p tcp --dport 22`: TCP destined for port 22.
- `-m conntrack --ctstate NEW`: only packets initiating a new connection.
- `-m limit --limit 5/min`: at most 5 new connections/minute (anti brute-force/flood).
- `-j ACCEPT`: allow it through.

**Why is the `ESTABLISHED,RELATED` rule needed?** Stateful: once a valid inbound/outbound connection is established, the reply packets in the `ESTABLISHED` state are allowed through without opening a separate port — the foundation of a stateful firewall.

**nftables** (the modern replacement, a single `nft` tool for IPv4/IPv6) — `/etc/nftables.conf`:
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
nft -f /etc/nftables.conf      # load
nft list ruleset               # view all rules (with counters)
nft list table inet filter
```
**Why does nftables replace iptables?** A single framework for v4/v6/arp/bridge, concise set/map syntax (e.g., a blocklist of thousands of IPs in one high-performance `set`), atomic reloads, and easier scripting.

**Security note:** default to `policy drop` for INPUT/FORWARD; open only the necessary ports; rate-limit the admin port; log dropped packets for investigation. Save the rules so they survive a reboot (`netfilter-persistent save` or the `nftables` service).

### 2.12.4. SELinux and AppArmor — Mandatory Access Control (MAC)

Traditional rwx permissions are **DAC** (Discretionary): the owner decides, and root bypasses everything. **MAC** applies a system policy that even root is bound by — if a service is compromised, MAC limits the damage. Both install hooks through **LSM** in the kernel.

**SELinux (RHEL/Fedora)** — every process and file has a **security context** of the form `user:role:type:level`:
```
system_u:system_r:httpd_t:s0          <- the httpd process
unconfined_u:object_r:httpd_sys_content_t:s0   <- a web file nginx serves
```
Decisions are based on **type enforcement**: the `httpd_t` domain may only do what the policy permits on the related types.

```bash
getenforce                 # Enforcing / Permissive / Disabled
setenforce 0               # temporarily switch to Permissive (logs only, does not block)
ps -eZ | grep nginx        # view a process's context (the -Z flag)
ls -Z /var/www/html        # view a file's context
ausearch -m AVC -ts recent # find events blocked by SELinux (AVC denials)
# Fix the context for a custom web directory:
semanage fcontext -a -t httpd_sys_content_t "/srv/www(/.*)?"
restorecon -Rv /srv/www
setsebool -P httpd_can_network_connect on   # turn on a boolean (allow httpd to connect out)
```
An AVC denial in the log:
```
type=AVC msg=audit(...): avc:  denied  { read } for  pid=1234 comm="nginx"
 name="secret.txt" scontext=system_u:system_r:httpd_t:s0
 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file
```
Read it: the `httpd_t` domain was denied `read` on a file of type `user_home_t` — exactly in the spirit of "a web server must not read home files". Do NOT disable SELinux just "to make it run"; instead fix the context or the boolean.

**AppArmor (Ubuntu/SUSE)** — profiles by **path** (easier to read than SELinux). `/etc/apparmor.d/usr.sbin.myapp`:
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
Each line = a path rule + permissions (`r w m`=mmap exec `ix/px`...). `deny /home/** rwx` absolutely blocks access to home.

```bash
aa-status                       # which profiles are enforcing/complaining
aa-complain /usr/sbin/myapp     # log-only mode (learn behavior)
aa-enforce  /usr/sbin/myapp     # turn on blocking
journalctl | grep apparmor      # view denials (ALLOWED/DENIED)
```
**Why path-based vs type-based?** AppArmor is easy to write/read (by path) but weak when files are renamed/hardlinked; SELinux attaches labels to the inode, making it stricter but with a steeper learning curve. Both are key defensive layers: when an RCE occurs in a confined service, the payload is blocked at any operations outside the profile/policy.

---

## 2.13. Summary of the defensive mindset on Linux

- **Privilege boundaries** are the root: user/kernel (syscall, seccomp), DAC (rwx/ACL/SUID), MAC (SELinux/AppArmor), capabilities, namespaces. Each layer narrows the damage when the layer above is breached.
- **Least privilege**: services run as their own user, `NoNewPrivileges`, a deny-by-default firewall, narrow sudoers, `nosuid/noexec` mounts.
- **Observability**: structured logs (journald + auditd), pushed centrally to a SIEM before an attacker deletes them, and fluent reading of `auth.log`/AVC with grep/awk.
- **Integrity**: `dpkg -V`/`rpm -V`, FSS for the journal, baselines of SUID/cron to detect changes.
- **Every hardening configuration** (sshd, fail2ban, nftables, systemd unit, SELinux) has a concrete file/syntax above — use them as verifiable templates on a real system.
