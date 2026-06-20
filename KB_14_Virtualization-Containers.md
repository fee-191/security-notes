# Chương 14 — Ảo hóa & Container (Docker, Kubernetes, Proxmox, VMware)

## Nhập môn — hiểu nôm na trước khi đi sâu

Chương này nói về cách chúng ta "nhét nhiều máy tính (hoặc nhiều ứng dụng) vào trong một máy tính vật lý" mà chúng không giẫm chân lên nhau — đó chính là **ảo hóa** và **container**. Vì sao dân an toàn thông tin phải quan tâm? Bởi vì ranh giới ngăn cách giữa các "máy ảo" hay "container" này chính là bức tường bảo vệ: nếu kẻ tấn công chiếm được một cái và "thoát" ra ngoài (gọi là *escape*), nó có thể chiếm luôn cả máy chủ và mọi thứ chạy trên đó. Hiểu các bức tường này được dựng lên bằng gì, và chúng có thể vỡ ở đâu, là kiến thức nền tảng để phòng thủ. Dưới đây là phần "giải nghĩa bình dân" cho từng khái niệm lớn của chương.

### Ảo hóa (Virtualization) & Hypervisor — nói đơn giản

- **Ảo hóa** là việc giả lập ra một "máy tính trong máy tính". Hãy tưởng tượng một tòa chung cư: tòa nhà là máy chủ vật lý, mỗi căn hộ là một **máy ảo (VM)** có tường riêng, cửa khóa riêng, người ở không biết hàng xóm là ai. Mỗi VM tưởng mình đang sở hữu một máy tính thật với hệ điều hành riêng.
- **Hypervisor** là "ban quản lý tòa nhà" — phần mềm đứng giữa chia phần cứng thật (CPU, RAM, đĩa) cho các căn hộ và đảm bảo không ai lấn sang phòng người khác. Nó giải quyết vấn đề: làm sao chạy nhiều hệ điều hành độc lập trên một dàn phần cứng mà vẫn cô lập an toàn, tiết kiệm chi phí máy móc.

### Proxmox & VMware (ESXi/vSphere) — nói đơn giản

- **Proxmox VE** và **VMware ESXi/vSphere** đều là những "ban quản lý tòa nhà" (hypervisor) chuyên nghiệp dùng trong trung tâm dữ liệu. Proxmox là phần mềm mã nguồn mở (miễn phí, dựa trên Linux), còn VMware là sản phẩm thương mại phổ biến trong doanh nghiệp.
- Vì sao cần: thay vì mua 20 máy chủ vật lý cho 20 ứng dụng, ta mua vài máy mạnh rồi dùng Proxmox/VMware chia thành 20 máy ảo. Chúng còn cho phép sao lưu (*backup*), chụp ảnh trạng thái (*snapshot*) để quay lui khi sự cố, và di chuyển máy ảo đang chạy từ máy chủ này sang máy chủ khác mà không tắt máy (*vMotion*). Đây là xương sống vận hành của hầu hết hệ thống hiện đại.

### Container & Docker — nói đơn giản

- **Container** giống như một "hộp cơm phần" đóng gói sẵn: ứng dụng cùng tất cả thư viện nó cần được gói chung vào một gói gọn nhẹ, mang đi đâu chạy cũng giống y nhau. Khác với máy ảo (mỗi căn hộ có hệ điều hành riêng nặng nề), container chia sẻ chung "bếp" — tức là *kernel* (lõi hệ điều hành) của máy chủ — nên khởi động cực nhanh (mili giây) và tốn ít tài nguyên.
- **Docker** là công cụ phổ biến nhất để tạo, đóng gói và chạy container. Vì sao cần: nó chấm dứt câu nói kinh điển "máy tôi chạy được mà" — vì gói cơm phần giống hệt nhau dù chạy trên laptop lập trình viên hay máy chủ thật. Đổi lại, do dùng chung "bếp", bức tường cô lập của container *mỏng hơn* máy ảo, nên về mặt bảo mật cần cẩn thận hơn.
- **Namespaces & cgroups** là hai cơ chế của Linux dựng nên bức tường đó: **namespaces** làm cho container chỉ "nhìn thấy" phần thế giới của riêng nó (tiến trình, mạng, thư mục riêng — như đeo kính chỉ thấy phòng mình); còn **cgroups** giới hạn *lượng* tài nguyên nó được dùng (tối đa bao nhiêu RAM, bao nhiêu CPU — như định mức điện nước mỗi phòng), tránh một container ngốn hết máy.
- **Image, layer & registry**: một *image* là "bản thiết kế hộp cơm" được xếp thành nhiều *layer* (lớp) chồng lên nhau để tái sử dụng và tiết kiệm. *Registry* là "siêu thị" lưu trữ các image để tải về (ví dụ Docker Hub). *Dockerfile* là "công thức nấu ăn" mô tả từng bước dựng nên image.

### Trivy (quét lỗ hổng) — nói đơn giản

- **Trivy** là công cụ "soi" image container để tìm lỗ hổng: thư viện cũ dính lỗi bảo mật đã công bố (CVE), cấu hình sai, hay lỡ tay nhét mật khẩu vào trong gói. Hãy hình dung nó như máy soi hành lý ở sân bay, rà trước khi cho lên máy bay.
- Vì sao cần: phần lớn image dựa trên hàng trăm thư viện của người khác; chỉ cần một thư viện dính lỗi là cả ứng dụng có nguy cơ. Quét tự động trong quy trình **CI/CD** (dây chuyền tự động build và triển khai phần mềm) giúp chặn gói "bẩn" ngay từ cửa, trước khi nó lên môi trường thật.

### Container escape — nói đơn giản

- **Container escape** là kịch bản đáng sợ nhất: kẻ tấn công đang ở trong một container tìm cách "phá tường" để thoát ra máy chủ thật, từ đó kiểm soát luôn các container khác. Giống như tên trộm vào được một căn phòng rồi đục tường sang phòng kế hoặc xuống tận hầm tòa nhà.
- Vì sao quan trọng: vì container dùng chung kernel với máy chủ, một cấu hình lỏng lẻo (chạy chế độ `--privileged` cấp toàn quyền, gắn nhầm "ổ khóa" `docker.sock`, hay cấp dư quyền hệ thống) có thể mở toang cánh cửa thoát đó. Hiểu các con đường escape giúp ta bịt chúng lại trước.

### Kubernetes (K8s) — nói đơn giản

- **Kubernetes** là "nhạc trưởng" điều phối hàng trăm, hàng nghìn container chạy trên nhiều máy chủ: tự quyết định container nào chạy ở đâu, tự khởi động lại cái chết, tự nhân bản khi tải tăng, tự cập nhật phiên bản mới mà không gián đoạn. Nếu Docker là "nấu một hộp cơm", thì Kubernetes là "điều hành cả chuỗi nhà ăn công nghiệp".
- Vì sao cần: khi hệ thống lớn lên, không ai đủ sức bật/tắt thủ công từng container trên từng máy. Kubernetes tự động hóa việc đó. Đi kèm nó là vài khái niệm an ninh quan trọng: **RBAC** (phân quyền ai được làm gì — như thẻ ra vào theo cấp bậc), **NetworkPolicy** (tường lửa quy định pod nào được nói chuyện với pod nào), **Secret** (nơi cất mật khẩu/khóa — nhưng lưu ý mặc định nó chỉ *mã hóa giả* bằng base64, ai cũng đọc được nếu không bật mã hóa thật), và **Pod Security Standards** (bộ quy tắc bắt buộc container phải chạy an toàn, ví dụ không được chạy quyền root).

### Falco — nói đơn giản

- **Falco** là "camera an ninh thời gian thực" cho container và Kubernetes: nó quan sát mọi hành động mà ứng dụng yêu cầu hệ điều hành làm (*syscall*) và báo động ngay khi thấy điều bất thường — ví dụ ai đó bất ngờ mở shell chui vào container, hay đọc trộm file mật khẩu `/etc/shadow`.
- Vì sao cần: các biện pháp như phân quyền hay tường lửa là "khóa cửa phòng ngừa", nhưng nếu kẻ xấu vẫn lọt qua, ta cần thứ *phát hiện* hành vi xấu đang diễn ra để kịp phản ứng. Falco chính là lớp phát hiện đó, thường gửi cảnh báo về hệ thống giám sát tập trung (SIEM).

Nắm được mấy ý trên rồi thì phần dưới đây sẽ đi sâu vào chi tiết kỹ thuật.

> Tài liệu tham chiếu chuyên sâu cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps). Mỗi mục đi theo trình tự: LÀ GÌ → CƠ CHẾ BÊN TRONG (tới mức bit/byte/bước/tham số) → VÍ DỤ THỰC TẾ → LƯU Ý BẢO MẬT.

---

## 14.1. Nền tảng ảo hóa: vì sao và cô lập ở đâu

### 14.1.1. Bài toán gốc — đặc quyền CPU (protection rings)

CPU x86/x86-64 cung cấp bốn mức đặc quyền (privilege rings), được mã hóa trong 2 bit `CPL` (Current Privilege Level) nằm ở 2 bit thấp của thanh ghi đoạn `CS`:

| Ring | CPL (2 bit) | Vai trò truyền thống |
|------|-------------|----------------------|
| 0    | `00`        | Kernel — toàn quyền lệnh đặc quyền (`HLT`, `LGDT`, `MOV CR3`, IN/OUT...) |
| 1    | `01`        | Hầu như không dùng (một số driver cũ) |
| 2    | `10`        | Hầu như không dùng |
| 3    | `11`        | User space — không được chạy lệnh đặc quyền |

Vấn đề ảo hóa cổ điển: một guest OS được viết để chạy ở Ring 0 (nó nghĩ nó sở hữu phần cứng). Nếu để guest chạy thật ở Ring 0 thì nó chiếm máy. Nếu hạ guest xuống Ring 1/3 thì các lệnh đặc quyền của nó phải bị "bẫy" (trap) để hypervisor xử lý thay. x86 nguyên thủy KHÔNG đáp ứng tiêu chí Popek–Goldberg vì có một nhóm lệnh "nhạy cảm nhưng không trap" (sensitive but unprivileged) — ví dụ `POPF` khi ở Ring 3 sẽ âm thầm bỏ qua việc ghi cờ `IF` thay vì gây fault. Đây là lý do ra đời ba kỹ thuật: **binary translation**, **paravirtualization**, và **hardware-assisted (VT-x/AMD-V)**.

### 14.1.2. Hypervisor Type 1 vs Type 2

| Tiêu chí | Type 1 (bare-metal) | Type 2 (hosted) |
|----------|--------------------|------------------|
| Vị trí | Chạy trực tiếp trên phần cứng, là kernel | Chạy như tiến trình trên OS host |
| Ví dụ | VMware ESXi, Proxmox VE (KVM), Microsoft Hyper-V, Xen | VMware Workstation/Player, VirtualBox, QEMU thuần |
| Lập lịch CPU | Hypervisor tự lập lịch vCPU lên pCPU | Dựa vào scheduler của host OS |
| Overhead | Thấp (đường truy cập phần cứng ngắn) | Cao hơn (qua một lớp OS) |
| Bề mặt tấn công | Hypervisor mỏng (vài MB tới vài chục MB) | Cả host OS đầy đủ → bề mặt lớn |
| Dùng cho | Datacenter, production | Lab, dev trên laptop |

Lưu ý KVM là trường hợp lai: KVM là một **module kernel Linux** (`kvm.ko` + `kvm-intel.ko`/`kvm-amd.ko`) biến chính Linux thành hypervisor Type 1. Proxmox VE đóng gói Linux + KVM + QEMU + LXC. Vì vậy "Proxmox = Type 1" theo nghĩa kernel host trở thành hypervisor, dù bản thân nó là một bản Debian đầy đủ.

### 14.1.3. Hardware-assisted virtualization: VT-x / AMD-V và VMCS

Intel VT-x thêm hai chế độ vận hành mới (không phải ring mới):

- **VMX root mode**: nơi hypervisor (VMM) chạy. Có thêm các lệnh `VMXON`, `VMLAUNCH`, `VMRESUME`, `VMEXIT`, `VMREAD`, `VMWRITE`, `VMPTRLD`.
- **VMX non-root mode**: nơi guest chạy. Guest vẫn thấy đủ Ring 0–3 của riêng nó, nhưng mọi sự kiện "nhạy cảm" gây **VM-exit** chuyển điều khiển về root mode.

Trạng thái chuyển đổi được lưu trong cấu trúc **VMCS** (Virtual Machine Control Structure) — một vùng 4KB căn theo trang, gồm 6 vùng logic:

| Vùng VMCS | Nội dung chính |
|-----------|----------------|
| Guest-state area | Trạng thái guest được lưu khi VM-exit, nạp lại khi VM-entry (RIP, RSP, CR0/CR3/CR4, segment, RFLAGS...) |
| Host-state area | Trạng thái host nạp lại khi VM-exit |
| VM-execution control | Bitmap quy định lệnh/sự kiện nào gây exit (ví dụ bit "HLT exiting", "use I/O bitmaps", "enable EPT") |
| VM-exit control | Hành vi khi exit (lưu/khôi phục MSR...) |
| VM-entry control | Hành vi khi entry (tiêm sự kiện/interrupt vào guest) |
| VM-exit information | Lý do exit (exit reason, exit qualification) — hypervisor đọc để biết tại sao |

Khi VM-exit xảy ra, CPU ghi mã lý do (Basic Exit Reason — 16 bit) vào VMCS. Ví dụ exit reason `0` = NMI, `1` = external interrupt, `12` = HLT, `30` = I/O instruction, `48` = EPT violation. Hypervisor đọc bằng `VMREAD` để dispatch xử lý.

### 14.1.4. Ảo hóa bộ nhớ: shadow page tables vs EPT/NPT

Guest có bảng phân trang riêng dịch **GVA → GPA** (Guest Virtual → Guest Physical). Nhưng GPA không phải địa chỉ RAM thật (HPA — Host Physical Address). Cần thêm một lớp dịch GPA → HPA.

Cách cũ (shadow page tables): hypervisor duy trì một bảng "bóng" dịch thẳng GVA → HPA, đồng bộ mỗi khi guest sửa bảng trang của nó (bắt write-fault vào page table) → rất tốn kém.

Cách mới — **EPT** (Intel Extended Page Tables) / **NPT/RVI** (AMD Nested Page Tables): phần cứng làm dịch hai cấp. MMU đi qua bảng trang guest (GVA→GPA) rồi qua bảng EPT (GPA→HPA) hoàn toàn bằng phần cứng. Bảng EPT là cấu trúc 4 cấp (PML4 → PDPT → PD → PT), mỗi mục 64 bit.

Cấu trúc một **EPT entry (PTE cấp lá)** 64 bit (mô tả các bit quan trọng):

| Bit | Kích thước | Ý nghĩa | Ví dụ |
|-----|-----------|---------|-------|
| 0   | 1 bit | Read access cho phép | 1 = guest đọc được GPA này |
| 1   | 1 bit | Write access | 1 = guest ghi được |
| 2   | 1 bit | Execute access | 0 = không thực thi (chống chạy code) |
| 3–5 | 3 bit | EPT memory type (giống PAT: WB=6, UC=0) | 6 = write-back |
| 6   | 1 bit | Ignore PAT | 0 |
| 7   | 1 bit | (cấp PD/PDPT) large page | 1 = trang 2MB/1GB |
| 12–51 | 40 bit | Physical frame number (HPA >> 12) | địa chỉ trang host |

**EPT violation** (exit reason 48) xảy ra khi guest truy cập vi phạm quyền R/W/X trong EPT — đây là cơ chế nền cho cô lập bộ nhớ giữa các VM: VM A không có bất kỳ EPT entry nào trỏ vào RAM của VM B.

> Lưu ý bảo mật: chính lớp dịch hai cấp này là biên giới cô lập phần cứng mạnh nhất giữa các VM. Các lỗ hổng nghiêm trọng (ví dụ họ tấn công kiểu Foreshadow/L1TF, hay lỗi VENOM CVE-2015-3456 ở floppy controller QEMU) đều nhắm vào việc phá vỡ ranh giới này. Vá microcode + vá hypervisor là bắt buộc.

### 14.1.5. Paravirtualization (PV) và virtio

Thay vì giả lập phần cứng đầy đủ (tốn VM-exit), PV sửa guest để nó "biết mình đang ảo hóa" và gọi thẳng hypervisor qua **hypercall**. Xen là đại diện kinh điển. Trong KVM, mô hình thực tế là **virtio**: guest dùng driver `virtio-net`, `virtio-blk`, `virtio-scsi` nói chuyện với host qua **virtqueue** — vùng nhớ chia sẻ dạng ring buffer gồm 3 phần:

```
Descriptor Table  ->  mảng phần tử {addr(64bit), len(32bit), flags(16bit), next(16bit)}
Available Ring    ->  guest đẩy index descriptor "đã sẵn sàng cho host"
Used Ring         ->  host đẩy index descriptor "đã xử lý xong"
```

Cơ chế này giảm số VM-exit (gom nhiều I/O, "notify" theo lô), nên throughput gần native. Đây là lý do máy ảo Linux trên KVM/Proxmox nên dùng disk bus `virtio-scsi` và NIC model `virtio` thay vì giả lập `e1000`/`IDE`.

---

## 14.2. Proxmox VE

### 14.2.1. Kiến trúc

Proxmox VE = Debian + kernel Ubuntu + KVM/QEMU (cho VM) + LXC (cho container hệ điều hành). Các thành phần cốt lõi:

- **pve-cluster (`pmxcfs`)**: một filesystem phân tán gắn ở `/etc/pve`, đồng bộ qua **Corosync**. Mọi file cấu hình (VM, ACL, storage) nằm ở đây và tự nhân bản giữa các node.
- **Corosync**: lớp truyền thông cluster, dùng giao thức **Totem** (token ring ảo) qua UDP/multicast hoặc unicast. Quyết định quorum.
- **pvedaemon / pveproxy**: API REST (cổng 8006/TCP, HTTPS) và web UI.
- **qemu-server**, **pve-container**: quản lý VM và LXC.

### 14.2.2. File cấu hình VM thực tế

Mỗi VM có file `/etc/pve/qemu-server/<vmid>.conf`. Ví dụ thật:

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
bios: ovmf            # UEFI thay vì SeaBIOS
efidisk0: local-lvm:vm-100-disk-1,size=4M
agent: 1              # bật QEMU guest agent
smbios1: uuid=...
```

Giải thích tham số quan trọng:
- `cpu: host` — phơi toàn bộ cờ CPU vật lý cho guest (nhanh nhất, nhưng cản trở live-migrate giữa CPU khác đời). Dùng `cpu: x86-64-v2-AES` nếu cần tương thích migrate.
- `net0: ...,firewall=1` — bật firewall Proxmox cho NIC này (xem 14.2.4).
- `iothread=1` — tách luồng I/O riêng cho disk, giảm chèn ép vCPU.
- `machine: q35` — chipset PCIe hiện đại (cần cho passthrough).

### 14.2.3. Snapshot & backup

Proxmox snapshot phụ thuộc storage backend:
- **LVM-thin / ZFS / qcow2**: hỗ trợ snapshot (copy-on-write). ZFS snapshot ở mức block, gần như tức thời.
- **LVM dày / raw trên iSCSI**: KHÔNG snapshot được ở mức storage.

Lệnh thật:

```bash
# Tạo snapshot có lưu RAM (vmstate) để rollback về trạng thái đang chạy
qm snapshot 100 before-upgrade --vmstate 1 --description "Trước khi vá kernel"

# Liệt kê
qm listsnapshot 100

# Rollback
qm rollback 100 before-upgrade

# Backup nén zstd ra Proxmox Backup Server hoặc NFS
vzdump 100 --storage pbs-main --mode snapshot --compress zstd
```

`--mode snapshot` dùng cơ chế **dirty bitmap** của QEMU: chỉ các block thay đổi kể từ backup trước được gửi (incremental), giúp backup nhanh và nhỏ.

### 14.2.4. Proxmox Firewall — cơ chế

Firewall Proxmox là một lớp sinh ra rule **iptables/nftables** từ file cấu hình ở ba mức: datacenter (`/etc/pve/firewall/cluster.fw`), node (`/etc/pve/nodes/<node>/host.fw`), và VM (`/etc/pve/firewall/<vmid>.fw`). Ví dụ:

```ini
# /etc/pve/firewall/100.fw
[OPTIONS]
enable: 1
policy_in: DROP

[RULES]
IN SSH(ACCEPT) -source 10.0.0.0/24 -log nolog
IN ACCEPT -p tcp -dport 443 -source +web_clients
```

> Lưu ý bảo mật: LXC container của Proxmox dùng chung kernel với host (không phải VM thật). Một LXC chạy **privileged** (`unprivileged: 0`) có user root ánh xạ thẳng UID 0 trên host → escape rất nguy hiểm. Luôn ưu tiên `unprivileged: 1` (user namespace remap, root trong container = UID cao như 100000 trên host). Với workload không tin cậy, dùng VM (KVM) thay vì LXC.

---

## 14.3. VMware vSphere/ESXi

### 14.3.1. Kiến trúc ESXi

ESXi là hypervisor Type 1 với kernel độc quyền **VMkernel** (POSIX-like nhưng không phải Linux). Tiến trình quan trọng:
- **VMM**: một instance trên mỗi VM, dùng VT-x/EPT.
- **VMX (`vmx` process)**: xử lý giả lập thiết bị, I/O không hiệu năng cao, kết nối console.
- **hostd**: agent quản lý local (API cho vSphere Client trực tiếp).
- **vpxa**: agent kết nối tới vCenter Server.

File định nghĩa VM là `<vm>.vmx` (text), disk là `<vm>.vmdk` (descriptor) + `-flat.vmdk` (dữ liệu) hoặc `-sparse`.

### 14.3.2. VMFS, snapshot delta disk

VMFS là filesystem cụm có khóa phân tán (SCSI reservations / ATS - Atomic Test and Set). Khi tạo snapshot, ESXi đóng băng disk gốc (read-only) và tạo **delta disk** (`-000001.vmdk`) ghi mọi thay đổi mới theo cơ chế redo-log. Chuỗi snapshot là một cây; mỗi delta trỏ về parent. Xóa snapshot = consolidate (merge delta vào base).

> Lưu ý bảo mật / vận hành: delta disk phình to vô hạn nếu để snapshot lâu ngày → đầy datastore → toàn bộ VM trên datastore treo. Snapshot KHÔNG phải backup. Về bảo mật, các lỗ hổng nghiêm trọng của ESXi thường ở dịch vụ **SLP** (CVE-2021-21974 — ransomware ESXiArgs) và **OpenSLP** cổng 427; vô hiệu hóa SLP và đóng cổng quản lý là biện pháp cứng hóa cơ bản.

### 14.3.3. Cluster: HA, DRS, vMotion

- **vMotion**: di chuyển VM đang chạy giữa host. Cơ chế: copy trước toàn bộ RAM qua mạng, rồi lặp copy các trang "dirty" (pre-copy iterative), cuối cùng đóng băng vài chục ms để copy phần dirty còn lại và chuyển quyền. Cần mạng vMotion riêng (khuyến nghị mã hóa — Encrypted vMotion).
- **HA (High Availability)**: nếu host chết, VM được khởi động lại trên host khác (không phải zero-downtime).
- **DRS**: cân bằng tải tự động bằng vMotion.

---

## 14.4. VM vs Container — so sánh tới gốc

| Tiêu chí | Virtual Machine | Container |
|----------|-----------------|-----------|
| Cô lập bằng | VT-x/EPT (phần cứng), kernel riêng mỗi VM | namespaces + cgroups + capabilities (kernel host CHUNG) |
| Kernel | Mỗi VM 1 kernel độc lập | Tất cả container dùng chung 1 kernel host |
| Khởi động | Giây → phút (boot OS) | Mili giây (chỉ là tiến trình + namespace) |
| Overhead RAM | Cao (full OS mỗi VM) | Rất thấp (chỉ binary + lib) |
| Bề mặt tấn công escape | Hypervisor (mỏng) | Toàn bộ kernel syscall → bề mặt lớn hơn |
| Ranh giới bảo mật | Mạnh (mặc định an toàn cho multi-tenant) | Yếu hơn — KHÔNG nên coi là biên giới bảo mật cho tenant không tin cậy nếu không có thêm gVisor/Kata |

Điểm mấu chốt bảo mật: container chia sẻ kernel. Một lỗ hổng kernel (ví dụ Dirty COW CVE-2016-5195, Dirty Pipe CVE-2022-0847) bị khai thác trong container có thể leo thẳng lên host. Đây là lý do "container không phải VM về mặt cô lập". Với workload không tin cậy, dùng **gVisor** (kernel user-space chặn syscall) hoặc **Kata Containers** (mỗi container một microVM KVM).

---

## 14.5. Docker internals

### 14.5.1. Namespaces — cô lập gì

Namespace là cơ chế kernel Linux cô lập một **tài nguyên toàn cục** sao cho tiến trình bên trong chỉ thấy view riêng. Mỗi namespace có một file ở `/proc/<pid>/ns/`. Có 8 loại (kernel hiện đại):

| Namespace | Cô lập | Container thấy gì khác host |
|-----------|--------|------------------------------|
| **PID** | Cây tiến trình | Tiến trình đầu tiên trong container là PID 1; không thấy PID host |
| **NET** | Stack mạng | Interface, bảng định tuyến, iptables, cổng, `/proc/net` riêng |
| **MNT** | Mount point | Cây thư mục riêng (rootfs của image), không thấy mount host |
| **UTS** | hostname & domainname | `hostname` riêng (UTS = Unix Time-sharing System) |
| **IPC** | System V IPC, POSIX message queue | Shared memory / semaphore riêng |
| **USER** | UID/GID mapping | root (UID 0) trong container có thể map sang UID không-đặc-quyền trên host |
| **CGROUP** | View của cgroup hierarchy | Ẩn đường dẫn cgroup thật của host |
| **TIME** | CLOCK_MONOTONIC/BOOTTIME offset | (ít dùng) lệch đồng hồ boot |

Quan sát thực tế:

```bash
# Chạy container, xem các namespace của nó
docker run -d --name demo alpine sleep 3600
PID=$(docker inspect -f '{{.State.Pid}}' demo)
ls -l /proc/$PID/ns/
# lrwxrwxrwx ... net -> 'net:[4026532567]'   <- inode namespace
# lrwxrwxrwx ... pid -> 'pid:[4026532569]'

# So sánh với host: số inode khác nhau => khác namespace
ls -l /proc/1/ns/net
# net -> 'net:[4026531840]'   <- inode khác hẳn

# Tự tạo namespace bằng unshare (không cần Docker)
sudo unshare --pid --fork --mount-proc bash
# Trong shell mới: ps aux chỉ thấy vài tiến trình, bash là PID 1
```

Syscall nền: `clone()` với cờ `CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWCGROUP`; `unshare()` tách namespace cho tiến trình hiện tại; `setns()` gia nhập namespace có sẵn (đây chính là cái `docker exec` và `nsenter` dùng).

### 14.5.2. cgroups v1 vs v2 — giới hạn tài nguyên

cgroups (control groups) **giới hạn và hạch toán** tài nguyên (CPU, RAM, I/O, PID count). Namespace cô lập *view*, cgroups giới hạn *lượng*.

**cgroups v1**: mỗi controller (cpu, memory, blkio, pids...) là một cây phân cấp RIÊNG, gắn ở `/sys/fs/cgroup/<controller>/`. Phức tạp vì một tiến trình ở nhiều cây.

**cgroups v2**: một cây thống nhất (unified hierarchy) ở `/sys/fs/cgroup/`, mỗi cgroup bật controller qua file `cgroup.subtree_control`. Đây là mặc định trên distro hiện đại (systemd).

Ví dụ giới hạn thật với cgroup v2:

```bash
# Docker tạo cgroup ở /sys/fs/cgroup/system.slice/docker-<id>.scope/
docker run -d --name limited --memory=256m --cpus=1.5 nginx

ID=$(docker inspect -f '{{.Id}}' limited)
CG=/sys/fs/cgroup/system.slice/docker-$ID.scope

cat $CG/memory.max        # 268435456  (256*1024*1024 byte)
cat $CG/cpu.max           # 150000 100000  -> (quota 150000us / period 100000us) = 1.5 CPU
cat $CG/pids.max          # giới hạn số PID (chống fork bomb)
```

Giải thích `cpu.max`: định dạng `<quota> <period>`, đơn vị microgiây. `150000 100000` nghĩa là mỗi chu kỳ 100ms, tiến trình được dùng tối đa 150ms CPU-time → tương đương 1.5 lõi. Khi vượt, scheduler **throttle** (chặn) tiến trình tới chu kỳ sau.

`memory.max` là hard limit. Vượt qua → kernel **OOM killer** giết tiến trình trong cgroup (xem `dmesg`, exit code 137 = 128+SIGKILL(9)).

> Lưu ý bảo mật: KHÔNG đặt giới hạn → một container có thể nuốt hết RAM/CPU host (DoS nội bộ). Đặt `--memory`, `--cpus`, `--pids-limit` cho mọi workload. `--pids-limit` chặn fork bomb.

### 14.5.3. OverlayFS — lower / upper / merged

Docker image gồm nhiều **layer** chỉ-đọc. Khi chạy container, Docker xếp chồng chúng bằng **overlay2** storage driver dựa trên OverlayFS của kernel:

```
              merged/   (cái container nhìn thấy = union)
                 ^
        +--------+--------+
        |                 |
     upperdir         lowerdir(s)
   (read-write,     (read-only, các image layer
    thay đổi của      xếp chồng, lower nhất ở cuối)
    container)
        |
     workdir  (kernel dùng để thực hiện copy-up nguyên tử)
```

Cơ chế **copy-up**: khi container ghi vào một file đang nằm ở lowerdir (read-only), kernel sao chép file đó lên upperdir rồi mới ghi. Lowerdir không bao giờ thay đổi → image bất biến, nhiều container chia sẻ chung layer (tiết kiệm đĩa). Xóa file ở lower → tạo một **whiteout** (file thiết bị ký tự đặc biệt `c 0 0`) ở upper để "che" file đó trong merged.

```bash
docker inspect -f '{{json .GraphDriver.Data}}' limited | python3 -m json.tool
# {
#   "LowerDir": "/var/lib/docker/overlay2/<l1>/diff:/var/lib/docker/overlay2/<l2>/diff",
#   "UpperDir": "/var/lib/docker/overlay2/<id>/diff",
#   "MergedDir": "/var/lib/docker/overlay2/<id>/merged",
#   "WorkDir": "/var/lib/docker/overlay2/<id>/work"
# }
mount | grep overlay   # thấy filesystem type 'overlay'
```

> Lưu ý bảo mật: dữ liệu "đã xóa" ở layer dưới VẪN nằm trong image (chỉ bị whiteout che). `docker history` và việc giải nén từng layer (`tar`) có thể phục hồi secret bị `RUN rm` ở instruction sau. Đây là lỗi rò rỉ secret kinh điển — phải dùng multi-stage build hoặc BuildKit secrets, không bao giờ COPY secret rồi xóa.

### 14.5.4. Image, layer, digest — định dạng

Một Docker/OCI image gồm: **manifest** (JSON), **config** (JSON), và các **layer blob** (tar.gz). Mỗi đối tượng được định danh bằng **digest** = `sha256:` + hash SHA-256 của nội dung (content-addressable). Vì địa chỉ = hash, nội dung bất biến: đổi 1 byte → đổi digest → là object khác.

**OCI Image Manifest** (ví dụ rút gọn):

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

| Trường | Ý nghĩa |
|--------|---------|
| `config.digest` | Trỏ tới image config JSON (chứa ENV, CMD, history, `rootfs.diff_ids`) |
| `layers[].digest` | Digest của layer blob (đã nén) — dùng để pull/dedup |
| `rootfs.diff_ids` (trong config) | Digest của layer **chưa nén** — dùng để khớp layer trên đĩa |

Khác biệt **image tag vs digest**: `nginx:1.25` là tag *có thể thay đổi* (publisher push lại). `nginx@sha256:abc...` là digest *bất biến*. Để bảo mật supply chain, **pin theo digest** trong production.

```bash
docker pull nginx@sha256:0d17b565c37bcbd895e9d92315a05c1c3c9a29f762b011a10c54a66cd53c9b31
docker inspect --format '{{index .RepoDigests 0}}' nginx
```

### 14.5.5. Dockerfile — từng instruction & caching

Mỗi instruction tạo (hoặc không) một layer. BuildKit cache theo nội dung instruction + ngữ cảnh.

| Instruction | Vai trò | Tạo layer? | Ghi chú caching/bảo mật |
|-------------|---------|-----------|--------------------------|
| `FROM` | Base image | (kế thừa) | Pin digest. Dùng image tối thiểu (alpine/distroless) |
| `RUN` | Chạy lệnh build | Có | Gộp `apt-get update && install && rm -rf /var/lib/apt/lists/*` trong 1 RUN |
| `COPY` | Sao chép từ context | Có | Cache invalidate nếu file nguồn đổi (theo checksum) |
| `ADD` | Như COPY + giải nén tar + URL | Có | Tránh — COPY rõ ràng hơn, ADD URL gây bất ngờ |
| `ENV` | Biến môi trường | Metadata | KHÔNG đặt secret ở ENV (nằm trong image config, ai cũng đọc) |
| `ARG` | Biến build-time | Metadata | Cũng lưu trong history nếu dùng sai; không cho secret |
| `USER` | Đổi user chạy | Metadata | Đặt non-root TRƯỚC ENTRYPOINT |
| `WORKDIR` | Thư mục làm việc | Metadata | |
| `EXPOSE` | Tài liệu hóa cổng | Metadata | Chỉ ghi chú, không mở cổng thật |
| `ENTRYPOINT` | Lệnh cố định khi chạy | Metadata | Dạng exec `["nginx","-g","daemon off;"]` để nhận tín hiệu đúng (PID 1) |
| `CMD` | Tham số mặc định | Metadata | Bị override bởi `docker run ... <cmd>` |
| `HEALTHCHECK` | Kiểm tra sống | Metadata | |

**Caching**: build đi tuần tự; nếu một instruction cache-hit, các instruction sau vẫn dùng cache cho tới khi gặp thay đổi. Vì vậy đặt thứ ít đổi (cài dependency) TRƯỚC, thứ hay đổi (copy source code) SAU:

```dockerfile
# Sai thứ tự: mỗi lần đổi code phải cài lại deps
COPY . .
RUN npm ci

# Đúng: tách package.json -> cache npm ci được giữ khi chỉ đổi src
COPY package*.json ./
RUN npm ci
COPY . .
```

**Multi-stage build** thật (Go) — chỉ giữ binary, bỏ toolchain:

```dockerfile
# ---- Stage build ----
FROM golang:1.22 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app ./cmd/server

# ---- Stage runtime: distroless, non-root ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app /app
USER 65532:65532          # nonroot uid của distroless
ENTRYPOINT ["/app"]
```

Vì sao distroless: không có shell, không có package manager, không có coreutils → kẻ tấn công vào container không có `sh`, `curl`, `cat` để xoay sở; bề mặt tấn công nhỏ; ít CVE từ thư viện thừa.

**BuildKit secret** (không để lại dấu vết trong layer):

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN=$(cat /run/secrets/npmtoken) npm ci
```
```bash
DOCKER_BUILDKIT=1 docker build --secret id=npmtoken,src=./.npmtoken -t app .
```
Secret được mount tạm vào RUN, không ghi vào layer.

**`.dockerignore`** — chống nuốt nhầm secret/file thừa vào context:

```
.git
node_modules
*.pem
*.key
.env
Dockerfile
```

### 14.5.6. Registry & content trust

- **Docker Registry / OCI Distribution**: API HTTP (`/v2/`). Pull = GET manifest theo tag/digest, rồi GET từng layer blob theo digest.
- **Cosign / Notary (DCT)**: ký image. `cosign sign` tạo chữ ký lưu cạnh image; `cosign verify` kiểm tra trước khi deploy.

```bash
cosign generate-key-pair
cosign sign --key cosign.key registry.example.com/app@sha256:...
cosign verify --key cosign.pub registry.example.com/app@sha256:...
```

> Lưu ý bảo mật supply chain: bật admission policy chỉ cho phép image đã ký (cosign + Kyverno/Gatekeeper), pin digest, quét trước khi push.

---

## 14.6. Quét image với Trivy

Trivy quét: lỗ hổng OS package + lib ứng dụng (đọc lockfile), misconfig (Dockerfile/K8s/Terraform), secret hardcode, license.

```bash
# Quét image, chỉ báo HIGH/CRITICAL, fail CI nếu có CRITICAL
trivy image --severity HIGH,CRITICAL --exit-code 1 \
      --ignore-unfixed nginx:1.25

# Quét filesystem / Dockerfile misconfig
trivy fs --scanners vuln,secret,misconfig .

# Xuất SARIF cho GitLab/GitHub code scanning
trivy image --format sarif -o trivy.sarif app:latest
```

Giải thích tham số:
- `--ignore-unfixed`: bỏ qua CVE chưa có bản vá (giảm nhiễu, tập trung cái fix được).
- `--exit-code 1`: trả mã lỗi để pipeline CI fail → gate bảo mật.
- `--scanners vuln,secret,misconfig`: bật đồng thời nhiều bộ quét.

Output mẫu (rút gọn):

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

Tích hợp GitLab CI (đúng môi trường DevSecOps):

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

## 14.7. Container escape — cơ chế cụ thể

Container escape = vượt khỏi cô lập namespace/cgroup để truy cập host. Ba lớp phổ biến:

### 14.7.1. `--privileged`

`docker run --privileged` tắt gần như mọi cô lập: cấp **tất cả capabilities**, vô hiệu seccomp/AppArmor mặc định, cho truy cập **mọi device** ở `/dev`. Hệ quả: container thấy đĩa host (`/dev/sda`) → mount → đọc/ghi rootfs host.

```bash
# Bên trong container privileged
fdisk -l                       # thấy /dev/sda của host
mkdir /hostroot
mount /dev/sda1 /hostroot      # mount rootfs host
echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /hostroot/etc/sudoers
# hoặc ghi /hostroot/root/.ssh/authorized_keys -> escape hoàn toàn
```

Một biến thể kinh điển dùng `release_agent` của cgroup v1 (khi privileged + cgroup v1): ghi vào file `release_agent` một script chạy với quyền host khi cgroup rỗng → thực thi lệnh trên host.

### 14.7.2. Mount `docker.sock`

`/var/run/docker.sock` là Unix socket nói chuyện với Docker daemon (chạy quyền root). Ai truy cập được socket = điều khiển daemon = tạo container privileged mới mount `/` của host → root host.

```bash
# Nếu container bị mount nhầm -v /var/run/docker.sock:/var/run/docker.sock
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
# giờ là root trên host
```

Đây là lý do KHÔNG bao giờ mount docker.sock vào container untrusted (CI runner, app). Tương đương trao root host.

### 14.7.3. `CAP_SYS_ADMIN` và capability thừa

Linux chia quyền root thành nhiều **capabilities** (bitmask trong cred của tiến trình). Docker mặc định giữ một tập nhỏ và bỏ phần nguy hiểm. `CAP_SYS_ADMIN` là "root mới" — cho phép `mount`, `pivot_root`, thao tác namespace... → con đường escape phổ biến.

```bash
# Xem capabilities hiện có trong container
grep Cap /proc/1/status
# CapEff: 00000000a80425fb   <- bitmask, giải mã:
capsh --decode=00000000a80425fb
# cap_chown,cap_dac_override,...,cap_net_raw,cap_setuid,...

# Nguyên tắc: drop tất cả, thêm lại cái cần
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx
```

**Phòng thủ tổng hợp cho container:**

| Biện pháp | Lệnh / hiệu quả |
|-----------|------------------|
| Non-root | `USER 65532` trong Dockerfile + `--user 65532` |
| Read-only rootfs | `--read-only` (chỉ ghi vào volume/tmpfs khai báo) |
| Drop caps | `--cap-drop=ALL` rồi add tối thiểu |
| No new privileges | `--security-opt=no-new-privileges` (chặn setuid leo quyền) |
| Seccomp | Mặc định Docker chặn một loạt syscall nguy hiểm; viết profile custom |
| AppArmor/SELinux | MAC giới hạn truy cập file/cap |
| User namespace | `--userns-remap` → root container = UID cao trên host |
| Không privileged | KHÔNG dùng `--privileged`; không mount docker.sock |

Ví dụ seccomp profile JSON (allowlist tối thiểu):

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
`SCMP_ACT_ERRNO` = syscall không có trong allowlist sẽ trả `EPERM` thay vì thực thi.

---

## 14.8. Kubernetes

### 14.8.1. Kiến trúc: control plane & node

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
     Pods (1..n container/pod)
```

| Thành phần | Vai trò | Chi tiết bảo mật |
|-----------|---------|-------------------|
| **kube-apiserver** | Cổng duy nhất vào cluster; mọi thao tác qua REST API; xác thực + authz + admission | Cổng 6443/TCP TLS. Là mục tiêu số 1 |
| **etcd** | Lưu TOÀN BỘ state cluster (kể cả Secret) dạng key-value | Phải mã hóa at-rest + mTLS + chỉ apiserver truy cập |
| **kube-scheduler** | Quyết định Pod chạy node nào (theo resource, taint/toleration, affinity) | |
| **kube-controller-manager** | Vòng lặp điều hòa (reconcile) đưa trạng thái thực về trạng thái mong muốn | |
| **kubelet** | Agent trên mỗi node; nói với CRI để chạy Pod; báo cáo trạng thái | API kubelet (10250) phải xác thực — nếu mở anonymous = RCE node |
| **kube-proxy** | Cài rule iptables/IPVS để hiện thực Service (cân bằng tải tới Pod) | |
| **CRI runtime** | containerd / CRI-O thực sự chạy container qua runc | |

**Luồng một request** (ví dụ `kubectl apply -f deploy.yaml`):

1. kubectl → HTTPS POST tới apiserver (cổng 6443), kèm client cert/token.
2. **Authentication**: apiserver xác định "ai" (cert CN, ServiceAccount JWT, OIDC).
3. **Authorization (RBAC)**: kiểm "user này được làm verb `create` trên resource `deployments` trong namespace này không?".
4. **Admission controllers**: mutating (sửa object, vd tiêm sidecar, set default) rồi validating (chấp nhận/từ chối, vd OPA/Gatekeeper, Pod Security).
5. apiserver ghi object vào **etcd**.
6. controller-manager thấy Deployment mới → tạo ReplicaSet → tạo Pod object.
7. scheduler gán Pod vào node (ghi `nodeName`).
8. kubelet node đó watch thấy Pod của mình → gọi CRI → containerd → runc tạo container.

### 14.8.2. Đối tượng cốt lõi (manifest thật)

**Pod** — đơn vị nhỏ nhất, một hoặc nhiều container chia sẻ NET namespace (cùng IP, cùng localhost) và volume:

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
    image: nginx@sha256:0d17b565...   # pin digest
    ports: [{ containerPort: 8080 }]
    resources:
      requests: { cpu: "100m", memory: "128Mi" }
      limits:   { cpu: "500m", memory: "256Mi" }
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
```

`100m` = 100 millicores = 0.1 CPU. `128Mi` = 128 mebibyte = 128*2^20 byte. `requests` dùng để scheduler đặt chỗ; `limits` là cgroup hard cap.

**Deployment** (quản lý ReplicaSet, rolling update):

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

Quan hệ: **Deployment** → tạo/quản lý **ReplicaSet** → giữ đúng số **Pod**. Rolling update: tạo ReplicaSet mới, tăng dần Pod mới, giảm dần Pod cũ theo `maxSurge`/`maxUnavailable`.

**Service** — IP/DNS ổn định cho tập Pod (Pod IP thay đổi liên tục):

| Loại | Cơ chế | Dùng khi |
|------|--------|----------|
| **ClusterIP** | IP ảo nội cụm, kube-proxy DNAT tới Pod | Service nội bộ (mặc định) |
| **NodePort** | Mở cùng một cổng (30000–32767) trên MỌI node | Truy cập từ ngoài đơn giản |
| **LoadBalancer** | Gọi cloud provider tạo LB ngoài trỏ vào NodePort | Cloud production |
| **ExternalName** | Trả CNAME DNS | Trỏ tới dịch vụ ngoài |

```yaml
apiVersion: v1
kind: Service
metadata: { name: web, namespace: app }
spec:
  type: ClusterIP
  selector: { app: web }     # chọn Pod theo label
  ports:
  - port: 80           # cổng của Service (ClusterIP:80)
    targetPort: 8080   # cổng container đích
```

Cơ chế kube-proxy (chế độ iptables): cho mỗi Service tạo chuỗi `KUBE-SERVICES` → `KUBE-SVC-xxx` → DNAT ngẫu nhiên (xác suất đều) tới một trong các `KUBE-SEP-xxx` (mỗi SEP = một Pod endpoint). Đây là cân bằng tải L4.

**Ingress** — định tuyến HTTP(S) L7 (host/path) vào các Service, do Ingress Controller (nginx, traefik) hiện thực:

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
  password: c3VwZXJzZWNyZXQ=   # base64("supersecret") — KHÔNG mã hóa
```

### 14.8.3. RBAC — Role / RoleBinding

RBAC trả lời: "subject (user/group/ServiceAccount) được làm `verb` gì trên `resource` nào, ở đâu". `Role`/`RoleBinding` = phạm vi 1 namespace; `ClusterRole`/`ClusterRoleBinding` = toàn cụm.

```yaml
# Role: chỉ đọc pod & log trong namespace app
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: pod-reader, namespace: app }
rules:
- apiGroups: [""]                 # "" = core group
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

Kiểm tra quyền thực tế:

```bash
kubectl auth can-i create deployments --namespace app --as system:serviceaccount:app:viewer
# no
kubectl auth can-i get pods --namespace app --as system:serviceaccount:app:viewer
# yes
```

> Lưu ý bảo mật: tránh `verbs: ["*"]`, `resources: ["*"]`. Đặc biệt nguy hiểm: quyền `create` trên `pods` (có thể tạo Pod mount host hoặc privileged để escape), quyền `get`/`create` trên `secrets`, quyền `escalate`/`bind` trên RBAC, quyền `create` trên `pods/exec`. Cấp theo least-privilege.

### 14.8.4. NetworkPolicy

Mặc định trong K8s mọi Pod nói chuyện được với mọi Pod (flat network). NetworkPolicy (cần CNI hỗ trợ: Calico, Cilium...) áp firewall L3/L4 theo label. Quy tắc: một khi có policy chọn một Pod, Pod đó chuyển sang **default-deny** cho chiều được khai báo.

```yaml
# Default deny mọi ingress trong namespace app
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-ingress, namespace: app }
spec:
  podSelector: {}            # áp cho MỌI pod
  policyTypes: ["Ingress"]
---
# Chỉ cho frontend gọi backend:8080
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

> Lưu ý: NetworkPolicy chỉ có hiệu lực nếu CNI cài đặt thực thi nó. Trên cluster dùng CNI không hỗ trợ (vd flannel thuần), manifest được chấp nhận nhưng KHÔNG chặn gì → ảo giác an toàn. Kiểm chứng bằng test thực tế (`kubectl exec` curl giữa các pod).

### 14.8.5. Secret — base64 ≠ mã hóa & mã hóa etcd

Trường `data` của Secret chỉ là **base64 encode** (để đựng nhị phân trong YAML), KHÔNG phải mã hóa:

```bash
echo 'c3VwZXJzZWNyZXQ=' | base64 -d     # supersecret  <- ai cũng giải được
```

Theo mặc định, Secret nằm trong etcd dưới dạng **plaintext** (chỉ base64). Ai đọc được etcd (backup etcd, node control plane) = đọc mọi secret. Bật **encryption at rest** bằng `EncryptionConfiguration` cho apiserver:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources: ["secrets"]
  providers:
  - aescbc:                 # hoặc aesgcm; tốt nhất là kms: (KMS ngoài)
      keys:
      - name: key1
        secret: <32-byte base64 key>
  - identity: {}            # fallback đọc dữ liệu cũ chưa mã hóa
```
Cờ apiserver: `--encryption-provider-config=/etc/kubernetes/enc.yaml`. Khuyến nghị provider `kms:` (envelope encryption với HSM/cloud KMS) thay vì để khóa trong file.

> Lưu ý bảo mật: ngoài mã hóa etcd, hạn chế ai `get secrets` qua RBAC; tránh để Secret thành ENV (lộ qua `/proc/<pid>/environ`, crash dump, logs) — ưu tiên mount dạng file (tmpfs). Cân nhắc external secret (Vault, External Secrets Operator).

### 14.8.6. Pod Security Standards (PSS) & Admission

PSS thay thế PodSecurityPolicy (đã bỏ ở v1.25). Ba mức:

| Mức | Cho phép |
|-----|----------|
| **privileged** | Không giới hạn (chỉ cho hệ thống) |
| **baseline** | Chặn các cấu hình nguy hiểm rõ ràng (privileged, hostNetwork, hostPID, capabilities thêm nguy hiểm) |
| **restricted** | Cứng nhất: bắt buộc runAsNonRoot, drop ALL caps, seccomp RuntimeDefault, không privilege escalation |

Bật bằng nhãn namespace (Pod Security Admission — built-in):

```bash
kubectl label namespace app \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted
```
Pod không đạt `restricted` sẽ bị apiserver TỪ CHỐI tạo.

**Admission controller tùy biến — OPA/Gatekeeper** (chính sách phức tạp hơn PSS):

```yaml
# ConstraintTemplate: định nghĩa policy bằng Rego
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
        msg := sprintf("image %v không từ registry tin cậy", [c.image])
      }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata: { name: only-trusted-registry }
spec:
  match: { kinds: [{ apiGroups: [""], kinds: ["Pod"] }] }
  parameters: { repos: ["registry.example.com/"] }
```
Gatekeeper là một **validating admission webhook**: apiserver gọi nó (HTTPS) trước khi lưu object; trả về allow/deny + lý do. Kyverno là lựa chọn tương đương dùng YAML thay Rego.

### 14.8.7. ServiceAccount token & API kubelet — bề mặt tấn công

Mỗi Pod (mặc định) được gắn token ServiceAccount tại `/var/run/secrets/kubernetes.io/serviceaccount/token` (JWT). Nếu attacker chiếm Pod, token này dùng để gọi apiserver với quyền của SA đó.

Cấu trúc JWT (3 phần Base64URL ngăn bởi `.`): `header.payload.signature`.

| Phần | Nội dung |
|------|----------|
| header | `{"alg":"RS256","kid":"..."}` — thuật toán ký + key id |
| payload (claims) | `iss`, `sub` (vd `system:serviceaccount:app:viewer`), `aud`, `exp`, `kubernetes.io` (namespace, pod, sa) |
| signature | RS256 ký bởi khóa riêng của apiserver — chống giả mạo |

Token hiện đại là **bound token** (projected): có `exp` ngắn, gắn với vòng đời Pod và audience cụ thể.

> Cứng hóa: đặt `automountServiceAccountToken: false` cho Pod không cần gọi API; khóa API kubelet (`--anonymous-auth=false`, `--authorization-mode=Webhook`); chặn metadata cloud (169.254.169.254) bằng NetworkPolicy để tránh đánh cắp credential IAM của node.

---

## 14.9. Falco — runtime threat detection

Falco là engine phát hiện hành vi bất thường **theo thời gian thực** bằng cách đọc **syscall** của kernel (qua eBPF probe hoặc kernel module) và đối chiếu với luật. Nó thấy: tiến trình mới, mở file, kết nối mạng, exec vào container...

Kiến trúc: kernel → (eBPF/modern_ebpf probe) → vùng ring buffer → libsinsp parse thành "event có ngữ cảnh container" → rule engine → output (stderr/JSON/gRPC/Falcosidekick → Slack, SIEM).

Một rule Falco thật:

```yaml
- rule: Shell vào container (đáng ngờ)
  desc: Phát hiện bash/sh được spawn bên trong container
  condition: >
    spawned_process and container
    and proc.name in (bash, sh, zsh)
    and not container.image.repository in (allowed_debug_images)
  output: >
    Shell mở trong container (user=%user.name container=%container.name
    image=%container.image.repository proc=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

Giải thích trường:
- `condition`: biểu thức trên các field sysdig (`proc.name`, `container.id`, `fd.name`, `evt.type`...). `spawned_process` là macro = `evt.type=execve and evt.dir=<`.
- `output`: template log, `%proc.cmdline` v.v. nội suy từ event.
- `priority`: mức nghiêm trọng.

Các rule mặc định hữu ích: "Write below /etc", "Read sensitive file (`/etc/shadow`)", "Container drift (binary mới không có trong image)", "Outbound connection to C2", "Launch privileged container".

```bash
# Chạy thử trong container, theo dõi sự kiện
docker exec -it web sh        # -> Falco bắn alert "Shell vào container"
cat /etc/shadow               # -> "Read sensitive file"
```

> Lưu ý bảo mật: Falco là **detective control** (phát hiện) bổ sung cho **preventive control** (PSS, seccomp, NetworkPolicy). eBPF probe cần kernel hỗ trợ (BTF). Gửi output sang SIEM và đặt alert; rule cần tinh chỉnh để giảm false positive (whitelist image debug hợp lệ).

---

## 14.10. Checklist cứng hóa tổng hợp

| Lớp | Kiểm soát chính |
|-----|------------------|
| Hypervisor (ESXi/Proxmox) | Vá hypervisor + microcode (L1TF/MDS); tách mạng quản lý; tắt SLP; mã hóa vMotion; LXC unprivileged |
| Image | Distroless/minimal, multi-stage, non-root USER, pin digest, ký cosign, quét Trivy gate CI, .dockerignore, BuildKit secret |
| Container runtime | `--cap-drop=ALL`, `--read-only`, `no-new-privileges`, seccomp/AppArmor, không `--privileged`, không mount docker.sock, `--pids-limit`, userns-remap |
| K8s control plane | etcd mTLS + encryption at rest (KMS), apiserver authz=RBAC, audit log bật, kubelet auth |
| K8s workload | securityContext restricted, PSS=restricted, resource limits, NetworkPolicy default-deny, RBAC least-privilege, automountServiceAccountToken=false |
| Admission | Pod Security + Gatekeeper/Kyverno (chỉ image đã ký từ registry tin cậy) |
| Runtime detect | Falco + Falcosidekick → SIEM; audit log apiserver → SIEM |
| Supply chain | SBOM (syft), ký + verify (cosign), pin digest, quét định kỳ lại image đang chạy |
