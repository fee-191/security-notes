# Chapter 14 — Virtualization & Containers

## Overview

This chapter covers two models for isolating workloads on a single physical host: **virtualization** and **containers**. The isolation boundary between VMs or containers is itself the security boundary: when an attacker compromises one workload and **escapes** (breaks out of it), the entire host and all other workloads on it are threatened. A security engineer needs to understand by what mechanisms these boundaries are built and where they can break.

**Virtualization & Hypervisors.** Virtualization is the technique of emulating a complete computer inside another computer. Each **virtual machine (VM)** runs its own operating system with an independent kernel. The **hypervisor** is the software layer that partitions the real hardware (CPU, RAM, disk) among the VMs and enforces isolation between them. The problem it solves: running multiple independent operating systems on a single set of hardware, with safe isolation and optimized cost.

**Proxmox & VMware.** **Proxmox VE** (open source, built on Linux/KVM) and **VMware ESXi/vSphere** (commercial) are datacenter-grade hypervisors. They provide **backup**, **snapshots** (capturing a state for rollback), and **live migration** (vMotion — moving a running VM between hosts). This is the operational foundation of most modern infrastructure.

**Containers & Docker.** A container packages an application together with all its library dependencies into an immutable unit that runs identically in any environment. Unlike VMs, containers **share the host kernel**, so they start in milliseconds and consume very few resources. **Docker** is the most popular tool for building, packaging, and running containers. The security implication: because they share a kernel, a container's isolation boundary is thinner than a VM's.

The foundational kernel mechanisms:
- **Namespaces**: isolate the *view* of resources (PID, network, mount, hostname, etc.) — a container only sees its own slice of the world.
- **cgroups**: limit the *amount* of resources (RAM, CPU, PID count) each container may use, preventing one container from exhausting host resources.
- **Image / layer / registry**: an *image* is an immutable packaged unit made of multiple stacked *layers* (reuse, dedup); a *registry* (e.g. Docker Hub) is the image store; a *Dockerfile* describes the steps to build an image.

**Trivy.** A tool that scans images to detect libraries affected by CVEs, misconfigurations, and hardcoded secrets. Integrated into the **CI/CD** pipeline to gate (block) non-compliant images before deployment.

**Container escape.** The scenario where an attacker breaks out of namespace/cgroup isolation to reach the host and other containers. Because containers share the host kernel, loose configurations (`--privileged` mode, mistakenly mounting `docker.sock`, granting excessive capabilities) open the path to escape. Understanding the escape paths is the prerequisite to closing them.

**Kubernetes (K8s).** A large-scale container orchestrator across many nodes: scheduling, self-healing, load-based scaling, and non-disruptive rolling updates. The key security concepts: **RBAC** (authorization by subject/verb/resource), **NetworkPolicy** (L3/L4 firewall between Pods), **Secret** (storing keys/passwords — by default only base64-encoded, not truly encrypted, so encryption-at-rest must be enabled), and **Pod Security Standards** (constraints that force containers to run safely, e.g. forbidding running as root).

**Falco.** A real-time runtime detection tool for containers and Kubernetes: it monitors **syscalls** and alerts on anomalous behavior (opening a shell inside a container, reading `/etc/shadow`, etc.). It is a detection layer that complements preventive measures (RBAC, firewall), and typically forwards alerts to a SIEM.

> An in-depth reference for security engineers (Blue Team / AppSec / DevSecOps). Each section follows the sequence: *what it is* → *internal mechanism* (down to the bit/byte/step/parameter level) → *real-world example* → *security notes*.

---

## 14.1. Virtualization foundations: why, and where the isolation lives

### 14.1.1. The root problem — CPU privilege (protection rings)

x86/x86-64 CPUs provide four privilege levels (privilege rings), encoded in the 2-bit `CPL` (Current Privilege Level) held in the low 2 bits of the `CS` segment register:

| Ring | CPL (2 bits) | Traditional role |
|------|-------------|----------------------|
| 0    | `00`        | Kernel — full access to privileged instructions (`HLT`, `LGDT`, `MOV CR3`, IN/OUT, etc.) |
| 1    | `01`        | Almost never used (some legacy drivers) |
| 2    | `10`        | Almost never used |
| 3    | `11`        | User space — may not run privileged instructions |

The classic virtualization problem: a guest OS is written to run at Ring 0 (it thinks it owns the hardware). If you let the guest actually run at Ring 0, it takes over the machine. If you demote the guest to Ring 1/3, its privileged instructions must be "trapped" so the hypervisor can handle them on its behalf. The original x86 did NOT satisfy the Popek–Goldberg criteria because it had a class of instructions that are "sensitive but unprivileged" — for example `POPF` at Ring 3 silently skips writing the `IF` flag instead of raising a fault. This is why three techniques emerged: **binary translation**, **paravirtualization**, and **hardware-assisted (VT-x/AMD-V)**.

### 14.1.2. Type 1 vs Type 2 hypervisors

| Criterion | Type 1 (bare-metal) | Type 2 (hosted) |
|----------|--------------------|------------------|
| Location | Runs directly on hardware, is the kernel | Runs as a process on a host OS |
| Examples | VMware ESXi, Proxmox VE (KVM), Microsoft Hyper-V, Xen | VMware Workstation/Player, VirtualBox, plain QEMU |
| CPU scheduling | Hypervisor schedules vCPUs onto pCPUs itself | Relies on the host OS scheduler |
| Overhead | Low (short path to hardware) | Higher (through an extra OS layer) |
| Attack surface | Thin hypervisor (a few MB to a few tens of MB) | An entire full host OS → large surface |
| Used for | Datacenter, production | Lab, dev on a laptop |

Note that KVM is a hybrid case: KVM is a **Linux kernel module** (`kvm.ko` + `kvm-intel.ko`/`kvm-amd.ko`) that turns Linux itself into a Type 1 hypervisor. Proxmox VE bundles Linux + KVM + QEMU + LXC. So "Proxmox = Type 1" in the sense that the host kernel becomes the hypervisor, even though it is itself a full Debian install.

### 14.1.3. Hardware-assisted virtualization: VT-x / AMD-V and VMCS

> Note: this section drills down to the hardware level. If you only need the big picture, skim it and skip to 14.2.

Intel VT-x adds two new operating modes (not new rings):

- **VMX root mode**: where the hypervisor (VMM) runs. It adds the instructions `VMXON`, `VMLAUNCH`, `VMRESUME`, `VMEXIT`, `VMREAD`, `VMWRITE`, `VMPTRLD`.
- **VMX non-root mode**: where the guest runs. The guest still sees its own full Rings 0–3, but every "sensitive" event causes a **VM-exit** that transfers control back to root mode.

The transition state is stored in the **VMCS** (Virtual Machine Control Structure) — a 4 KB, page-aligned region made up of 6 logical areas:

| VMCS area | Main contents |
|-----------|----------------|
| Guest-state area | Guest state saved on VM-exit and reloaded on VM-entry (RIP, RSP, CR0/CR3/CR4, segments, RFLAGS, etc.) |
| Host-state area | Host state reloaded on VM-exit |
| VM-execution control | Bitmap specifying which instructions/events cause an exit (e.g. the "HLT exiting", "use I/O bitmaps", "enable EPT" bits) |
| VM-exit control | Behavior on exit (save/restore MSRs, etc.) |
| VM-entry control | Behavior on entry (injecting events/interrupts into the guest) |
| VM-exit information | The reason for the exit (exit reason, exit qualification) — read by the hypervisor to know why |

When a VM-exit occurs, the CPU writes the reason code (Basic Exit Reason — 16 bits) into the VMCS. For example, exit reason `0` = NMI, `1` = external interrupt, `12` = HLT, `30` = I/O instruction, `48` = EPT violation. The hypervisor reads it with `VMREAD` to dispatch handling.

### 14.1.4. Memory virtualization: shadow page tables vs EPT/NPT

> Note: this section keeps drilling down, into the MMU mechanism. If you only need the big picture, skim it and skip to 14.2.

The guest has its own page tables translating **GVA → GPA** (Guest Virtual → Guest Physical). But the GPA is not a real RAM address (HPA — Host Physical Address). An additional translation layer GPA → HPA is needed.

The old way (shadow page tables): the hypervisor maintains a "shadow" table that translates GVA → HPA directly, synchronizing it every time the guest modifies its own page tables (by trapping write-faults to the page table) → very expensive.

The new way — **EPT** (Intel Extended Page Tables) / **NPT/RVI** (AMD Nested Page Tables): the hardware performs the two-level translation. The MMU walks the guest page tables (GVA→GPA) and then the EPT tables (GPA→HPA) entirely in hardware. The EPT table is a 4-level structure (PML4 → PDPT → PD → PT), with each entry being 64 bits.

The structure of an **EPT entry (leaf-level PTE)**, 64 bits (key bits described):

| Bit | Size | Meaning | Example |
|-----|-----------|---------|-------|
| 0   | 1 bit | Read access allowed | 1 = guest may read this GPA |
| 1   | 1 bit | Write access | 1 = guest may write |
| 2   | 1 bit | Execute access | 0 = no execute (prevents running code) |
| 3–5 | 3 bits | EPT memory type (like PAT: WB=6, UC=0) | 6 = write-back |
| 6   | 1 bit | Ignore PAT | 0 |
| 7   | 1 bit | (at PD/PDPT level) large page | 1 = 2 MB/1 GB page |
| 12–51 | 40 bits | Physical frame number (HPA >> 12) | host page address |

An **EPT violation** (exit reason 48) occurs when the guest makes an access that violates the R/W/X permissions in the EPT — this is the foundational mechanism for memory isolation between VMs: VM A has no EPT entry whatsoever pointing into VM B's RAM.

> Security note: this two-level translation layer is the strongest hardware isolation boundary between VMs. The most serious vulnerabilities (for example the Foreshadow/L1TF class of attacks, or the VENOM bug CVE-2015-3456 in QEMU's floppy controller) all aim to break this boundary. Patching the microcode + patching the hypervisor is mandatory.

### 14.1.5. Paravirtualization (PV) and virtio

Instead of fully emulating hardware (which costs VM-exits), PV modifies the guest so it "knows it is virtualized" and calls the hypervisor directly via a **hypercall**. Xen is the classic example. In KVM, the practical model is **virtio**: the guest uses the `virtio-net`, `virtio-blk`, `virtio-scsi` drivers to talk to the host over a **virtqueue** — a shared-memory ring buffer made of 3 parts:

```
Descriptor Table  ->  array of elements {addr(64bit), len(32bit), flags(16bit), next(16bit)}
Available Ring    ->  guest pushes the index of a descriptor "ready for the host"
Used Ring         ->  host pushes the index of a descriptor "finished processing"
```

This mechanism reduces the number of VM-exits (batching I/O, notifying in bulk), so throughput is near-native. This is why Linux VMs on KVM/Proxmox should use the `virtio-scsi` disk bus and the `virtio` NIC model instead of emulating `e1000`/`IDE`.

By now we have seen virtualization build its isolation boundary in hardware (VT-x/EPT) with a separate kernel for each VM. Containers take a different path: they share the host kernel. Section 14.4 puts the two models side by side to make the isolation trade-off clear; before that, 14.2–14.3 walk through two real-world hypervisors, Proxmox and VMware.

---

## 14.2. Proxmox VE

### 14.2.1. Architecture

Proxmox VE = Debian + Ubuntu kernel + KVM/QEMU (for VMs) + LXC (for OS containers). The core components:

- **pve-cluster (`pmxcfs`)**: a distributed filesystem mounted at `/etc/pve`, synchronized via **Corosync**. All configuration files (VMs, ACLs, storage) live here and are automatically replicated between nodes.
- **Corosync**: the cluster communication layer, using the **Totem** protocol (a virtual token ring) over UDP/multicast or unicast. It decides quorum.
- **pvedaemon / pveproxy**: the REST API (port 8006/TCP, HTTPS) and the web UI.
- **qemu-server**, **pve-container**: manage VMs and LXC.

### 14.2.2. A real VM configuration file

Each VM has a file `/etc/pve/qemu-server/<vmid>.conf`. A real example:

```ini
# /etc/pve/qemu-server/100.conf
boot: order=scsi0;net0
cores: 4
cpu: host
memory: 8192
name: web-prod-01
net0: virtio=DE:AD:BE:EF:00:01,bridge=vmbr0,firewall=1
scsi0: local-lvm:vm-100-disk-0,size=40G,iothread=1
scsihw: virtio-scsi-single
machine: q35
bios: ovmf            # UEFI instead of SeaBIOS
efidisk0: local-lvm:vm-100-disk-1,size=4M
agent: 1              # enable the QEMU guest agent
smbios1: uuid=...
```

Explanation of the key parameters:
- `cpu: host` — exposes all physical CPU flags to the guest (fastest, but hinders live-migration between different CPU generations). Use `cpu: x86-64-v2-AES` if migration compatibility is needed.
- `net0: ...,firewall=1` — enables the Proxmox firewall for this NIC (see 14.2.4).
- `iothread=1` — gives the disk a dedicated I/O thread, reducing contention with the vCPU.
- `machine: q35` — a modern PCIe chipset (required for passthrough).

### 14.2.3. Snapshots & backups

Proxmox snapshots depend on the storage backend:
- **LVM-thin / ZFS / qcow2**: support snapshots (copy-on-write). ZFS snapshots are block-level and nearly instantaneous.
- **Thick LVM / raw over iSCSI**: CANNOT snapshot at the storage level.

Real commands:

```bash
# Create a snapshot that includes RAM (vmstate) so you can roll back to the running state
qm snapshot 100 before-upgrade --vmstate 1 --description "Before patching the kernel"

# List
qm listsnapshot 100

# Roll back
qm rollback 100 before-upgrade

# zstd-compressed backup to a Proxmox Backup Server or NFS
vzdump 100 --storage pbs-main --mode snapshot --compress zstd
```

`--mode snapshot` uses QEMU's **dirty bitmap** mechanism: only the blocks changed since the previous backup are sent (incremental), making backups fast and small.

### 14.2.4. Proxmox Firewall — the mechanism

The Proxmox firewall is a layer that generates **iptables/nftables** rules from configuration files at three levels: datacenter (`/etc/pve/firewall/cluster.fw`), node (`/etc/pve/nodes/<node>/host.fw`), and VM (`/etc/pve/firewall/<vmid>.fw`). Example:

```ini
# /etc/pve/firewall/100.fw
[OPTIONS]
enable: 1
policy_in: DROP

[RULES]
IN SSH(ACCEPT) -source 10.0.0.0/24 -log nolog
IN ACCEPT -p tcp -dport 443 -source +web_clients
```

> Security note: Proxmox LXC containers share the kernel with the host (they are not real VMs). An LXC running **privileged** (`unprivileged: 0`) has its root user mapped straight to UID 0 on the host → an escape is very dangerous. Always prefer `unprivileged: 1` (user namespace remap, so root in the container = a high UID like 100000 on the host). For untrusted workloads, use a VM (KVM) instead of LXC.

---

## 14.3. VMware vSphere/ESXi

### 14.3.1. ESXi architecture

ESXi is a Type 1 hypervisor with a proprietary kernel, the **VMkernel** (POSIX-like but not Linux). Important processes:
- **VMM**: one instance per VM, using VT-x/EPT.
- **VMX (the `vmx` process)**: handles device emulation, non-high-performance I/O, and console connections.
- **hostd**: the local management agent (the API for the direct vSphere Client).
- **vpxa**: the agent that connects to vCenter Server.

A VM is defined by a `<vm>.vmx` file (text), with its disk being a `<vm>.vmdk` (descriptor) + `-flat.vmdk` (data) or `-sparse`.

### 14.3.2. VMFS, snapshot delta disks

VMFS is a clustered filesystem with distributed locking (SCSI reservations / ATS — Atomic Test and Set). When a snapshot is created, ESXi freezes the base disk (read-only) and creates a **delta disk** (`-000001.vmdk`) that records all new changes using a redo-log mechanism. The snapshot chain is a tree; each delta points back to its parent. Deleting a snapshot = consolidation (merging the delta back into the base).

> Security / operational note: a delta disk grows without bound if a snapshot is left for a long time → the datastore fills up → every VM on the datastore hangs. A snapshot is NOT a backup. On the security side, the most serious ESXi vulnerabilities are usually in the **SLP** service (CVE-2021-21974 — the ESXiArgs ransomware) and **OpenSLP** on port 427; disabling SLP and closing the management ports are basic hardening measures.

### 14.3.3. Cluster: HA, DRS, vMotion

- **vMotion**: moves a running VM between hosts. Mechanism: pre-copy all of the RAM over the network, then iteratively copy the "dirty" pages (iterative pre-copy), and finally freeze for a few tens of milliseconds to copy the remaining dirty pages and hand over control. A dedicated vMotion network is required (encryption is recommended — Encrypted vMotion).
- **HA (High Availability)**: if a host dies, its VMs are restarted on another host (not zero-downtime).
- **DRS**: automatically balances load using vMotion.

---

## 14.4. VM vs Container — a comparison from the ground up

A diagram of the two models' stacks shows the core difference: a VM replicates an entire kernel + OS for each workload (isolation via the hypervisor/hardware), while containers share one host kernel (isolation via that kernel's own namespaces/cgroups).

```
          VIRTUAL MACHINES                         CONTAINERS
  +------+ +------+ +------+             +------+ +------+ +------+
  | App  | | App  | | App  |            | App  | | App  | | App  |
  | Libs | | Libs | | Libs |            | Libs | | Libs | | Libs |
  +------+ +------+ +------+             +------+ +------+ +------+
  |Guest | |Guest | |Guest | <- separate |   Container Runtime  |
  |  OS  | |  OS  | |  OS  |    kernel   |   (containerd/CRI-O) |
  +------+-+------+-+------+   per VM    +----------------------+
  |       Hypervisor      |             | Host kernel (SHARED) | <- 1 kernel
  +-----------------------+             +----------------------+    for all
  |  Host OS (Type 2) /   |             |        Host OS       |
  |    none (Type 1)      |             +----------------------+
  +-----------------------+             |   Physical hardware  |
  |    Physical hardware  |             +----------------------+
  +-----------------------+
```

A VM's isolation boundary lies in the hypervisor + VT-x/EPT (each VM has an independent kernel); a container's boundary is namespaces + cgroups + capabilities on a shared kernel — thinner, with the escape surface being the entire syscall set of the host kernel.

| Criterion | Virtual Machine | Container |
|----------|-----------------|-----------|
| Isolated by | VT-x/EPT (hardware), a separate kernel per VM | namespaces + cgroups + capabilities (SHARED host kernel) |
| Kernel | One independent kernel per VM | All containers share one host kernel |
| Startup | Seconds → minutes (boot an OS) | Milliseconds (just a process + namespace) |
| RAM overhead | High (a full OS per VM) | Very low (just the binary + libs) |
| Escape attack surface | The hypervisor (thin) | The entire kernel syscall set → larger surface |
| Security boundary | Strong (safe by default for multi-tenant) | Weaker — should NOT be treated as a security boundary for untrusted tenants without adding gVisor/Kata |

The key security takeaway: containers share the kernel. A kernel vulnerability (for example Dirty COW CVE-2016-5195, Dirty Pipe CVE-2022-0847) exploited inside a container can escalate straight to the host. This is why "a container is not a VM in terms of isolation." For untrusted workloads, use **gVisor** (a user-space kernel that intercepts syscalls) or **Kata Containers** (each container in its own KVM microVM).

---

## 14.5. Docker internals

### 14.5.1. Namespaces — what they isolate

A namespace is a Linux kernel mechanism that isolates a **global resource** so that processes inside only see their own view. Each namespace has a file under `/proc/<pid>/ns/`. There are 8 types (on modern kernels):

| Namespace | Isolates | What the container sees differently from the host |
|-----------|--------|------------------------------|
| **PID** | The process tree | The first process in the container is PID 1; it does not see host PIDs |
| **NET** | The network stack | Its own interfaces, routing tables, iptables, ports, `/proc/net` |
| **MNT** | Mount points | Its own directory tree (the image's rootfs), no host mounts visible |
| **UTS** | hostname & domainname | Its own `hostname` (UTS = Unix Time-sharing System) |
| **IPC** | System V IPC, POSIX message queues | Its own shared memory / semaphores |
| **USER** | UID/GID mapping | root (UID 0) inside the container can be mapped to an unprivileged UID on the host |
| **CGROUP** | The view of the cgroup hierarchy | Hides the host's real cgroup paths |
| **TIME** | CLOCK_MONOTONIC/BOOTTIME offsets | (rarely used) skews the boot clock |

A practical observation:

```bash
# Run a container and inspect its namespaces
docker run -d --name demo alpine sleep 3600
PID=$(docker inspect -f '{{.State.Pid}}' demo)
ls -l /proc/$PID/ns/
# lrwxrwxrwx ... net -> 'net:[4026532567]'   <- namespace inode
# lrwxrwxrwx ... pid -> 'pid:[4026532569]'

# Compare with the host: a different inode number => a different namespace
ls -l /proc/1/ns/net
# net -> 'net:[4026531840]'   <- a completely different inode

# Create a namespace yourself with unshare (no Docker needed)
sudo unshare --pid --fork --mount-proc bash
# In the new shell: ps aux shows only a few processes, and bash is PID 1
```

The underlying syscalls: `clone()` with the flags `CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWCGROUP`; `unshare()` detaches a namespace for the current process; `setns()` joins an existing namespace (this is exactly what `docker exec` and `nsenter` use).

### 14.5.2. cgroups v1 vs v2 — resource limits

cgroups (control groups) **limit and account for** resources (CPU, RAM, I/O, PID count). Namespaces isolate the *view*; cgroups limit the *amount*.

**cgroups v1**: each controller (cpu, memory, blkio, pids, etc.) is its OWN hierarchy, mounted under `/sys/fs/cgroup/<controller>/`. Complex, because a process lives in multiple trees.

**cgroups v2**: a single unified hierarchy at `/sys/fs/cgroup/`, where each cgroup enables controllers via the `cgroup.subtree_control` file. This is the default on modern distros (systemd).

A real example of limits with cgroup v2:

```bash
# Docker creates a cgroup at /sys/fs/cgroup/system.slice/docker-<id>.scope/
docker run -d --name limited --memory=256m --cpus=1.5 nginx

ID=$(docker inspect -f '{{.Id}}' limited)
CG=/sys/fs/cgroup/system.slice/docker-$ID.scope

cat $CG/memory.max        # 268435456  (256*1024*1024 bytes)
cat $CG/cpu.max           # 150000 100000  -> (quota 150000us / period 100000us) = 1.5 CPU
cat $CG/pids.max          # limit on the number of PIDs (anti fork-bomb)
```

Explanation of `cpu.max`: the format is `<quota> <period>`, in microseconds. `150000 100000` means that in each 100 ms period, the process may use at most 150 ms of CPU-time → equivalent to 1.5 cores. When it exceeds this, the scheduler **throttles** (blocks) the process until the next period.

`memory.max` is a hard limit. Exceeding it → the kernel **OOM killer** kills a process in the cgroup (see `dmesg`, exit code 137 = 128 + SIGKILL(9)).

> Security note: NOT setting limits → a container can devour all the host's RAM/CPU (an internal DoS). Set `--memory`, `--cpus`, `--pids-limit` for every workload. `--pids-limit` blocks fork bombs.

### 14.5.3. OverlayFS — lower / upper / merged

A Docker image consists of multiple read-only **layers**. When running a container, Docker stacks them using the **overlay2** storage driver, which is based on the kernel's OverlayFS:

```
              merged/   (what the container sees = the union)
                 ^
        +--------+--------+
        |                 |
     upperdir         lowerdir(s)
   (read-write,     (read-only, the image layers
    the container's   stacked, lowest one at the bottom)
    changes)
        |
     workdir  (used by the kernel to perform an atomic copy-up)
```

The **copy-up** mechanism: when the container writes to a file that lives in a lowerdir (read-only), the kernel copies that file up to the upperdir before writing. The lowerdir is never modified → the image is immutable, and many containers share the same layers (saving disk). Deleting a file in the lower → creates a **whiteout** (a special character device file `c 0 0`) in the upper to "hide" that file in merged.

```bash
docker inspect -f '{{json .GraphDriver.Data}}' limited | python3 -m json.tool
# {
#   "LowerDir": "/var/lib/docker/overlay2/<l1>/diff:/var/lib/docker/overlay2/<l2>/diff",
#   "UpperDir": "/var/lib/docker/overlay2/<id>/diff",
#   "MergedDir": "/var/lib/docker/overlay2/<id>/merged",
#   "WorkDir": "/var/lib/docker/overlay2/<id>/work"
# }
mount | grep overlay   # shows a filesystem of type 'overlay'
```

> Security note: "deleted" data in a lower layer STILL resides in the image (it is only hidden by a whiteout). `docker history` and unpacking each layer (`tar`) can recover a secret that was `RUN rm`'d in a later instruction. This is the classic secret-leak bug — you must use a multi-stage build or BuildKit secrets, never COPY a secret and then delete it.

### 14.5.4. Image, layer, digest — the format

A Docker/OCI image consists of: a **manifest** (JSON), a **config** (JSON), and the **layer blobs** (tar.gz). Each object is identified by a **digest** = `sha256:` + the SHA-256 hash of the content (content-addressable). Because the address = the hash, the content is immutable: changing 1 byte → changes the digest → it becomes a different object.

An **OCI Image Manifest** (abbreviated example):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": 7023,
    "digest": "sha256:b5b2b2c5...e3a"
  },
  "layers": [
    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 32654, "digest": "sha256:9f0c...4d" },
    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "size": 16724, "digest": "sha256:3c3a...91" }
  ]
}
```

| Field | Meaning |
|--------|---------|
| `config.digest` | Points to the image config JSON (contains ENV, CMD, history, `rootfs.diff_ids`) |
| `layers[].digest` | The digest of the (compressed) layer blob — used to pull/dedup |
| `rootfs.diff_ids` (in the config) | The digest of the **uncompressed** layer — used to match layers on disk |

The difference between an **image tag and a digest**: `nginx:1.25` is a *mutable* tag (the publisher can re-push it). `nginx@sha256:abc...` is an *immutable* digest. For supply-chain security, **pin by digest** in production.

```bash
docker pull nginx@sha256:0d17b565c37bcbd895e9d92315a05c1c3c9a29f762b011a10c54a66cd53c9b31
docker inspect --format '{{index .RepoDigests 0}}' nginx
```

### 14.5.5. Dockerfile — each instruction & caching

Each instruction creates (or does not create) a layer. BuildKit caches based on the instruction's content + the context.

| Instruction | Role | Creates a layer? | Caching/security note |
|-------------|---------|-----------|--------------------------|
| `FROM` | Base image | (inherited) | Pin the digest. Use a minimal image (alpine/distroless) |
| `RUN` | Run a build command | Yes | Combine `apt-get update && install && rm -rf /var/lib/apt/lists/*` in one RUN |
| `COPY` | Copy from the context | Yes | Cache is invalidated if a source file changes (by checksum) |
| `ADD` | Like COPY + untar + URL | Yes | Avoid — COPY is clearer, ADD URL is surprising |
| `ENV` | Environment variable | Metadata | Do NOT put secrets in ENV (they end up in the image config, readable by anyone) |
| `ARG` | Build-time variable | Metadata | Also stored in history if misused; do not use for secrets |
| `USER` | Change the running user | Metadata | Set non-root BEFORE the ENTRYPOINT |
| `WORKDIR` | Working directory | Metadata | |
| `EXPOSE` | Documents a port | Metadata | Just a note, does not actually open a port |
| `ENTRYPOINT` | Fixed command at runtime | Metadata | Use the exec form `["nginx","-g","daemon off;"]` to receive signals correctly (PID 1) |
| `CMD` | Default arguments | Metadata | Overridden by `docker run ... <cmd>` |
| `HEALTHCHECK` | Liveness check | Metadata | |

**Caching**: a build proceeds sequentially; if one instruction is a cache hit, subsequent instructions keep using the cache until a change is encountered. Therefore, put the things that rarely change (installing dependencies) FIRST and the things that change often (copying source code) LAST:

```dockerfile
# Wrong order: every code change forces re-installing deps
COPY . .
RUN npm ci

# Right: separate package.json -> the npm ci cache is kept when only src changes
COPY package*.json ./
RUN npm ci
COPY . .
```

A real **multi-stage build** (Go) — keep only the binary, drop the toolchain:

```dockerfile
# ---- Build stage ----
FROM golang:1.22 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app ./cmd/server

# ---- Runtime stage: distroless, non-root ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app /app
USER 65532:65532          # distroless's nonroot uid
ENTRYPOINT ["/app"]
```

Why distroless: there is no shell, no package manager, no coreutils → an attacker who gets into the container has no `sh`, `curl`, or `cat` to work with; the attack surface is small; fewer CVEs from superfluous libraries.

A **BuildKit secret** (leaves no trace in the layers):

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN=$(cat /run/secrets/npmtoken) npm ci
```
```bash
DOCKER_BUILDKIT=1 docker build --secret id=npmtoken,src=./.npmtoken -t app .
```
The secret is temporarily mounted into the RUN and not written into a layer.

**`.dockerignore`** — prevents accidentally pulling secrets/superfluous files into the context:

```
.git
node_modules
*.pem
*.key
.env
Dockerfile
```

### 14.5.6. Registry & content trust

- **Docker Registry / OCI Distribution**: an HTTP API (`/v2/`). A pull = GET the manifest by tag/digest, then GET each layer blob by digest.
- **Cosign / Notary (DCT)**: sign images. `cosign sign` creates a signature stored alongside the image; `cosign verify` checks it before deployment.

```bash
cosign generate-key-pair
cosign sign --key cosign.key registry.example.com/app@sha256:...
cosign verify --key cosign.pub registry.example.com/app@sha256:...
```

> Supply-chain security note: enable an admission policy that only allows signed images (cosign + Kyverno/Gatekeeper), pin digests, and scan before pushing.

---

## 14.6. Scanning images with Trivy

Trivy scans for: OS package + application library vulnerabilities (reading the lockfile), misconfigurations (Dockerfile/K8s/Terraform), hardcoded secrets, and licenses.

```bash
# Scan an image, report only HIGH/CRITICAL, fail CI if any CRITICAL exists
trivy image --severity HIGH,CRITICAL --exit-code 1 \
      --ignore-unfixed nginx:1.25

# Scan a filesystem / Dockerfile misconfig
trivy fs --scanners vuln,secret,misconfig .

# Export SARIF for GitLab/GitHub code scanning
trivy image --format sarif -o trivy.sarif app:latest
```

Explanation of the parameters:
- `--ignore-unfixed`: skip CVEs without a patch yet (reduces noise, focuses on what is fixable).
- `--exit-code 1`: return an error code so the CI pipeline fails → a security gate.
- `--scanners vuln,secret,misconfig`: enable multiple scanners at once.

Sample output (abbreviated):

```
nginx:1.25 (debian 12.4)
Total: 2 (HIGH: 1, CRITICAL: 1)
┌────────────┬────────────────┬──────────┬───────────────┬───────────────┐
│  Library   │ Vulnerability  │ Severity │ Installed Ver │ Fixed Version │
├────────────┼────────────────┼──────────┼───────────────┼───────────────┤
│ libssl3    │ CVE-2024-XXXX  │ CRITICAL │ 3.0.11-1      │ 3.0.13-1      │
│ zlib1g     │ CVE-2023-YYYY  │ HIGH     │ 1:1.2.13      │               │ (unfixed)
└────────────┴────────────────┴──────────┴───────────────┴───────────────┘
```

GitLab CI integration (the correct DevSecOps environment):

```yaml
trivy_scan:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 0 --format sarif -o gl-trivy.sarif "$IMAGE"
    - trivy image --exit-code 1 --severity CRITICAL "$IMAGE"
  artifacts:
    reports: { container_scanning: gl-trivy.sarif }
```

---

## 14.7. Container escape — concrete mechanisms

A container escape = breaking out of namespace/cgroup isolation to reach the host. Three common classes:

### 14.7.1. `--privileged`

`docker run --privileged` disables nearly all isolation: it grants **all capabilities**, disables the default seccomp/AppArmor, and gives access to **every device** in `/dev`. The consequence: the container sees the host's disk (`/dev/sda`) → mount it → read/write the host's rootfs.

```bash
# Inside a privileged container
fdisk -l                       # see the host's /dev/sda
mkdir /hostroot
mount /dev/sda1 /hostroot      # mount the host rootfs
echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /hostroot/etc/sudoers
# or write /hostroot/root/.ssh/authorized_keys -> full escape
```

A classic variant uses cgroup v1's `release_agent` (when privileged + cgroup v1): write into the `release_agent` file a script that runs with host privileges when the cgroup becomes empty → execute a command on the host.

### 14.7.2. Mounting `docker.sock`

`/var/run/docker.sock` is the Unix socket that talks to the Docker daemon (which runs as root). Anyone who can access the socket = controls the daemon = can create a new privileged container that mounts the host's `/` → root on the host.

```bash
# If the container was mistakenly mounted with -v /var/run/docker.sock:/var/run/docker.sock
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
# now you are root on the host
```

This is why you must NEVER mount docker.sock into an untrusted container (a CI runner, an app). It is equivalent to handing over root on the host.

### 14.7.3. `CAP_SYS_ADMIN` and excess capabilities

Linux splits root privileges into many **capabilities** (a bitmask in the process's credentials). Docker by default keeps a small set and drops the dangerous parts. `CAP_SYS_ADMIN` is the "new root" — it allows `mount`, `pivot_root`, namespace operations, etc. → a common escape path.

```bash
# View the capabilities currently held in the container
grep Cap /proc/1/status
# CapEff: 00000000a80425fb   <- bitmask, decode it:
capsh --decode=00000000a80425fb
# cap_chown,cap_dac_override,...,cap_net_raw,cap_setuid,...

# Principle: drop everything, then add back only what you need
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx
```

**Combined container defenses:**

| Measure | Command / effect |
|-----------|------------------|
| Non-root | `USER 65532` in the Dockerfile + `--user 65532` |
| Read-only rootfs | `--read-only` (only write to declared volumes/tmpfs) |
| Drop caps | `--cap-drop=ALL` then add the minimum |
| No new privileges | `--security-opt=no-new-privileges` (blocks setuid privilege escalation) |
| Seccomp | Docker by default blocks a range of dangerous syscalls; write a custom profile |
| AppArmor/SELinux | MAC restricting file/capability access |
| User namespace | `--userns-remap` → container root = a high UID on the host |
| No privileged | Do NOT use `--privileged`; do not mount docker.sock |

An example seccomp profile in JSON (a minimal allowlist):

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    { "names": ["read","write","openat","close","fstat","mmap","execve",
                "brk","arch_prctl","exit_group"],
      "action": "SCMP_ACT_ALLOW" }
  ]
}
```
```bash
docker run --security-opt seccomp=./profile.json myapp
```
`SCMP_ACT_ERRNO` = a syscall not in the allowlist returns `EPERM` instead of executing.

---

## 14.8. Kubernetes

### 14.8.1. Architecture: control plane & nodes

```
                 CONTROL PLANE (master)
   +-----------------------------------------------+
   |  kube-apiserver  <--->  etcd (key-value store) |
   |        ^   ^                                    |
   |        |   +-- kube-scheduler                   |
   |        +------ kube-controller-manager          |
   +-----------------------------------------------+
                 |  (API: HTTPS 6443)
        +--------+----------------+
        |                         |
     NODE 1                    NODE 2
   kubelet                   kubelet
   kube-proxy                kube-proxy
   container runtime (CRI)   container runtime
   (containerd/CRI-O)        (containerd/CRI-O)
        |
     Pods (1..n containers/pod)
```

| Component | Role | Security detail |
|-----------|---------|-------------------|
| **kube-apiserver** | The single entry point into the cluster; every operation goes through the REST API; authentication + authz + admission | Port 6443/TCP TLS. The number 1 target |
| **etcd** | Stores ALL cluster state (including Secrets) as key-value | Must be encrypted at rest + mTLS + only the apiserver may access it |
| **kube-scheduler** | Decides which node a Pod runs on (by resources, taint/toleration, affinity) | |
| **kube-controller-manager** | The reconcile loop that brings the actual state to the desired state | |
| **kubelet** | The agent on each node; talks to the CRI to run Pods; reports status | The kubelet API (10250) must be authenticated — if opened anonymously = node RCE |
| **kube-proxy** | Installs iptables/IPVS rules to implement Services (load balancing to Pods) | |
| **CRI runtime** | containerd / CRI-O that actually runs containers via runc | |

**The flow of a request** (e.g. `kubectl apply -f deploy.yaml`):

1. kubectl → HTTPS POST to the apiserver (port 6443), with a client cert/token.
2. **Authentication**: the apiserver determines "who" (cert CN, ServiceAccount JWT, OIDC).
3. **Authorization (RBAC)**: checks "is this user allowed to perform the verb `create` on the resource `deployments` in this namespace?".
4. **Admission controllers**: mutating (modify the object, e.g. inject a sidecar, set defaults) then validating (accept/reject, e.g. OPA/Gatekeeper, Pod Security).
5. The apiserver writes the object into **etcd**.
6. The controller-manager sees the new Deployment → creates a ReplicaSet → creates Pod objects.
7. The scheduler assigns the Pod to a node (writes `nodeName`).
8. That node's kubelet watches and sees its Pod → calls the CRI → containerd → runc creates the container.

### 14.8.2. Core objects (real manifests)

**Pod** — the smallest unit, one or more containers sharing a NET namespace (same IP, same localhost) and volumes:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
  - name: nginx
    image: nginx@sha256:0d17b565...   # pin the digest
    ports: [{ containerPort: 8080 }]
    resources:
      requests: { cpu: "100m", memory: "128Mi" }
      limits:   { cpu: "500m", memory: "256Mi" }
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
```

`100m` = 100 millicores = 0.1 CPU. `128Mi` = 128 mebibytes = 128*2^20 bytes. `requests` is used by the scheduler to reserve space; `limits` is the cgroup hard cap.

**Deployment** (manages a ReplicaSet, rolling update):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, namespace: app }
spec:
  replicas: 3
  selector: { matchLabels: { app: web } }
  strategy:
    type: RollingUpdate
    rollingUpdate: { maxSurge: 1, maxUnavailable: 0 }
  template:
    metadata: { labels: { app: web } }
    spec:
      containers:
      - name: web
        image: registry.example.com/web@sha256:...
```

The relationship: a **Deployment** → creates/manages a **ReplicaSet** → keeps the correct number of **Pods**. Rolling update: create a new ReplicaSet, gradually scale up the new Pods, gradually scale down the old Pods according to `maxSurge`/`maxUnavailable`.

**Service** — a stable IP/DNS for a set of Pods (Pod IPs change constantly):

| Type | Mechanism | Use when |
|------|--------|----------|
| **ClusterIP** | An intra-cluster virtual IP, kube-proxy DNATs to the Pods | Internal services (default) |
| **NodePort** | Opens the same port (30000–32767) on EVERY node | Simple external access |
| **LoadBalancer** | Asks the cloud provider to create an external LB pointing to the NodePort | Cloud production |
| **ExternalName** | Returns a DNS CNAME | Pointing to an external service |

```yaml
apiVersion: v1
kind: Service
metadata: { name: web, namespace: app }
spec:
  type: ClusterIP
  selector: { app: web }     # selects Pods by label
  ports:
  - port: 80           # the Service's port (ClusterIP:80)
    targetPort: 8080   # the target container port
```

The kube-proxy mechanism (iptables mode): for each Service it creates a chain `KUBE-SERVICES` → `KUBE-SVC-xxx` → random DNAT (uniform probability) to one of the `KUBE-SEP-xxx` (each SEP = one Pod endpoint). This is L4 load balancing.

**Ingress** — L7 HTTP(S) routing (host/path) into Services, implemented by an Ingress Controller (nginx, traefik):

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations: { nginx.ingress.kubernetes.io/ssl-redirect: "true" }
spec:
  tls: [{ hosts: ["app.example.com"], secretName: web-tls }]
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend: { service: { name: web, port: { number: 80 } } }
```

**ConfigMap & Secret**:

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: app-cfg, namespace: app }
data:
  LOG_LEVEL: "info"
  config.yaml: |
    server: { port: 8080 }
---
apiVersion: v1
kind: Secret
metadata: { name: db-cred, namespace: app }
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=   # base64("supersecret") — NOT encrypted
```

### 14.8.3. RBAC — Role / RoleBinding

RBAC answers: "what `verb` may a subject (user/group/ServiceAccount) perform on what `resource`, and where". `Role`/`RoleBinding` = scoped to one namespace; `ClusterRole`/`ClusterRoleBinding` = cluster-wide.

```yaml
# Role: read-only on pods & logs in the app namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: pod-reader, namespace: app }
rules:
- apiGroups: [""]                 # "" = the core group
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: bind-pod-reader, namespace: app }
subjects:
- kind: ServiceAccount
  name: viewer
  namespace: app
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

Checking actual permissions:

```bash
kubectl auth can-i create deployments --namespace app --as system:serviceaccount:app:viewer
# no
kubectl auth can-i get pods --namespace app --as system:serviceaccount:app:viewer
# yes
```

> Security note: avoid `verbs: ["*"]` and `resources: ["*"]`. Especially dangerous: the `create` permission on `pods` (which can create a Pod that mounts the host or is privileged in order to escape), the `get`/`create` permissions on `secrets`, the `escalate`/`bind` permissions on RBAC, and the `create` permission on `pods/exec`. Grant by least-privilege.

### 14.8.4. NetworkPolicy

By default in K8s every Pod can talk to every Pod (a flat network). A NetworkPolicy (requires CNI support: Calico, Cilium, etc.) applies an L3/L4 firewall by label. The rule: once a policy selects a Pod, that Pod switches to **default-deny** for the declared direction.

```yaml
# Default-deny all ingress in the app namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-ingress, namespace: app }
spec:
  podSelector: {}            # applies to ALL pods
  policyTypes: ["Ingress"]
---
# Allow only the frontend to call backend:8080
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-frontend-to-backend, namespace: app }
spec:
  podSelector: { matchLabels: { app: backend } }
  policyTypes: ["Ingress"]
  ingress:
  - from:
    - podSelector: { matchLabels: { app: frontend } }
    ports:
    - { protocol: TCP, port: 8080 }
```

> Note: a NetworkPolicy only takes effect if the installed CNI enforces it. On a cluster using a CNI that does not support it (e.g. plain flannel), the manifest is accepted but blocks NOTHING → a false sense of safety. Verify with a real test (`kubectl exec` curl between pods).

### 14.8.5. Secret — base64 ≠ encryption & etcd encryption

The `data` field of a Secret is only **base64-encoded** (to hold binary data in YAML), NOT encrypted:

```bash
echo 'c3VwZXJzZWNyZXQ=' | base64 -d     # supersecret  <- anyone can decode it
```

By default, Secrets sit in etcd as **plaintext** (only base64). Anyone who can read etcd (an etcd backup, a control-plane node) = can read every secret. Enable **encryption at rest** with an `EncryptionConfiguration` for the apiserver:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources: ["secrets"]
  providers:
  - aescbc:                 # or aesgcm; best is kms: (external KMS)
      keys:
      - name: key1
        secret: <32-byte base64 key>
  - identity: {}            # fallback to read old, not-yet-encrypted data
```
The apiserver flag: `--encryption-provider-config=/etc/kubernetes/enc.yaml`. The recommended provider is `kms:` (envelope encryption with an HSM/cloud KMS) rather than keeping the key in a file.

> Security note: beyond etcd encryption, restrict who can `get secrets` via RBAC; avoid turning a Secret into an ENV (it leaks via `/proc/<pid>/environ`, crash dumps, logs) — prefer mounting it as a file (tmpfs). Consider external secrets (Vault, the External Secrets Operator).

### 14.8.6. Pod Security Standards (PSS) & Admission

PSS replaces PodSecurityPolicy (removed in v1.25). Three levels:

| Level | Allows |
|-----|----------|
| **privileged** | Unrestricted (for system use only) |
| **baseline** | Blocks clearly dangerous configurations (privileged, hostNetwork, hostPID, adding dangerous capabilities) |
| **restricted** | The strictest: requires runAsNonRoot, drop ALL caps, seccomp RuntimeDefault, no privilege escalation |

Enable it with a namespace label (Pod Security Admission — built-in):

```bash
kubectl label namespace app \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted
```
A Pod that does not meet `restricted` will be REJECTED by the apiserver at creation.

**Custom admission controller — OPA/Gatekeeper** (for policies more complex than PSS):

```yaml
# ConstraintTemplate: define the policy in Rego
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata: { name: k8sallowedrepos }
spec:
  crd:
    spec:
      names: { kind: K8sAllowedRepos }
      validation:
        openAPIV3Schema:
          type: object
          properties: { repos: { type: array, items: { type: string } } }
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8sallowedrepos
      violation[{"msg": msg}] {
        c := input.review.object.spec.containers[_]
        not startswith(c.image, input.parameters.repos[_])
        msg := sprintf("image %v not from a trusted registry", [c.image])
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata: { name: only-trusted-registry }
spec:
  match: { kinds: [{ apiGroups: [""], kinds: ["Pod"] }] }
  parameters: { repos: ["registry.example.com/"] }
```
Gatekeeper is a **validating admission webhook**: the apiserver calls it (HTTPS) before storing an object; it returns allow/deny + a reason. Kyverno is an equivalent choice that uses YAML instead of Rego.

### 14.8.7. ServiceAccount tokens & the kubelet API — attack surface

Each Pod (by default) has a ServiceAccount token attached at `/var/run/secrets/kubernetes.io/serviceaccount/token` (a JWT). If an attacker compromises a Pod, this token can be used to call the apiserver with that SA's privileges.

JWT structure (3 Base64URL parts separated by `.`): `header.payload.signature`.

| Part | Contents |
|------|----------|
| header | `{"alg":"RS256","kid":"..."}` — the signing algorithm + key id |
| payload (claims) | `iss`, `sub` (e.g. `system:serviceaccount:app:viewer`), `aud`, `exp`, `kubernetes.io` (namespace, pod, sa) |
| signature | RS256 signed by the apiserver's private key — prevents forgery |

A modern token is a **bound token** (projected): it has a short `exp`, and is bound to the Pod's lifecycle and a specific audience.

> Hardening: set `automountServiceAccountToken: false` for Pods that do not need to call the API; lock down the kubelet API (`--anonymous-auth=false`, `--authorization-mode=Webhook`); block the cloud metadata endpoint (169.254.169.254) with a NetworkPolicy to prevent theft of the node's IAM credentials.

---

## 14.9. Falco — runtime threat detection

Falco is an engine that detects anomalous behavior **in real time** by reading the kernel's **syscalls** (via an eBPF probe or a kernel module) and matching them against rules. It sees: new processes, file opens, network connections, exec into a container, etc.

Architecture: kernel → (eBPF/modern_ebpf probe) → ring buffer → libsinsp parses into "container-context events" → rule engine → output (stderr/JSON/gRPC/Falcosidekick → Slack, SIEM).

A real Falco rule:

```yaml
- rule: Shell into a container (suspicious)
  desc: Detect bash/sh spawned inside a container
  condition: >
    spawned_process and container
    and proc.name in (bash, sh, zsh)
    and not container.image.repository in (allowed_debug_images)
  output: >
    Shell opened in container (user=%user.name container=%container.name
    image=%container.image.repository proc=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

Explanation of the fields:
- `condition`: an expression over sysdig fields (`proc.name`, `container.id`, `fd.name`, `evt.type`, etc.). `spawned_process` is a macro = `evt.type=execve and evt.dir=<`.
- `output`: the log template; `%proc.cmdline` and so on are interpolated from the event.
- `priority`: the severity level.

Useful default rules: "Write below /etc", "Read sensitive file (`/etc/shadow`)", "Container drift (a new binary not in the image)", "Outbound connection to C2", "Launch privileged container".

```bash
# Try it inside a container and watch the events
docker exec -it web sh        # -> Falco fires the alert "Shell into a container"
cat /etc/shadow               # -> "Read sensitive file"
```

> Security note: Falco is a **detective control** (detection) that complements **preventive controls** (PSS, seccomp, NetworkPolicy). The eBPF probe needs kernel support (BTF). Send the output to a SIEM and set alerts; rules need tuning to reduce false positives (whitelist legitimate debug images).

---

## 14.10. Combined hardening checklist

| Layer | Key controls |
|-----|------------------|
| Hypervisor (ESXi/Proxmox) | Patch the hypervisor + microcode (L1TF/MDS); segregate the management network; disable SLP; encrypt vMotion; unprivileged LXC |
| Image | Distroless/minimal, multi-stage, non-root USER, pin digest, cosign signing, Trivy scan gating CI, .dockerignore, BuildKit secrets |
| Container runtime | `--cap-drop=ALL`, `--read-only`, `no-new-privileges`, seccomp/AppArmor, no `--privileged`, no mounting docker.sock, `--pids-limit`, userns-remap |
| K8s control plane | etcd mTLS + encryption at rest (KMS), apiserver authz=RBAC, audit log enabled, kubelet auth |
| K8s workload | restricted securityContext, PSS=restricted, resource limits, NetworkPolicy default-deny, RBAC least-privilege, automountServiceAccountToken=false |
| Admission | Pod Security + Gatekeeper/Kyverno (only signed images from a trusted registry) |
| Runtime detect | Falco + Falcosidekick → SIEM; apiserver audit log → SIEM |
| Supply chain | SBOM (syft), sign + verify (cosign), pin digest, periodically re-scan running images |
