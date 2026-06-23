# Chương 1 — Mạng máy tính (TCP/IP, OSI)

## Tổng quan

Chương này trình bày cơ chế truyền dữ liệu giữa các máy tính qua mạng, từ khi một byte rời tiến trình ứng dụng cho tới khi tới đích. Đây là nền tảng cho công việc an toàn thông tin: phần lớn kỹ thuật tấn công (nghe lén, giả mạo, chặn bắt, từ chối dịch vụ) diễn ra tại một tầng cụ thể của ngăn xếp mạng. Nắm cơ chế vận hành từng tầng giúp ta xác định được bề mặt tấn công và điểm cần phòng thủ.

Đây là bản đồ nhanh các khái niệm trong chương; định nghĩa và cơ chế đầy đủ nằm ở từng mục bên dưới.

- **Mô hình phân tầng (OSI & TCP/IP)** — mạng tổ chức thành các tầng xếp chồng, mỗi tầng phục vụ tầng trên qua một interface cố định. OSI là mô hình lý thuyết 7 tầng; TCP/IP là mô hình 4 tầng chạy thực tế trên Internet.
- **Encapsulation / Decapsulation** — dữ liệu được bọc tuần tự qua các tầng, mỗi tầng thêm một header rồi truyền xuống; bên nhận bóc ngược. Mỗi header chứa thông tin mà cả công cụ phân tích lẫn kẻ tấn công đều đọc được.
- **Tầng 2 — Ethernet, MAC, VLAN, ARP, switch** — định danh phần cứng và trao đổi frame trong cùng LAN.
- **Tầng 3 — IP, ICMP, định tuyến, NAT** — định danh logic và định tuyến qua nhiều mạng tới đích.
- **Tầng 4 — TCP và UDP** — vận chuyển dữ liệu và dùng port phân hướng tới đúng ứng dụng.
- **Cổng (port) phổ biến** — một host một IP nhưng nhiều dịch vụ; port phân biệt từng dịch vụ và phản ánh bề mặt tấn công.
- **Tầng 7 — DNS, DHCP, HTTP, TLS** — các giao thức ứng dụng ta gặp hằng ngày.
- **Tường lửa, DMZ, công cụ phân tích gói** — lọc gói theo chính sách, cô lập vùng tiếp xúc Internet, và bắt/đọc gói bằng tcpdump/Wireshark.

> Sổ tay này dành cho người học và làm an toàn thông tin (Blue Team / AppSec / DevSecOps). Mỗi mục đi theo một mạch quen thuộc: khái niệm là gì, cơ chế bên trong (tới mức bit/byte/bước/tham số), một ví dụ chạy thật, rồi vài lưu ý bảo mật. Cấu trúc dữ liệu mô tả tới từng trường (field), kích thước và offset; mỗi công cụ kèm lệnh, cấu hình và output mẫu để bạn gõ lại được.

---

## 1.1. Hai mô hình tham chiếu: OSI 7 tầng và TCP/IP

### 1.1.1. Vì sao cần mô hình phân tầng

Truyền dữ liệu qua mạng là một bài toán rất nhiều việc: biểu diễn bit trên dây đồng/sợi quang, định địa chỉ máy, định tuyến qua hàng chục router, đảm bảo độ tin cậy, mã hóa, biểu diễn dữ liệu ứng dụng. Gom tất cả vào một khối nguyên (monolith) thì gần như không thể bảo trì, cũng không thể thay từng phần công nghệ (đổi cáp đồng sang quang, đổi IPv4 sang IPv6) mà không phá vỡ toàn bộ.

Giải pháp là **phân tầng (layering)**: mỗi tầng cung cấp dịch vụ cho tầng trên và sử dụng dịch vụ của tầng dưới, qua một **interface** cố định. Nguyên tắc cốt lõi:

- **Encapsulation**: dữ liệu của tầng trên được tầng dưới đối xử như payload mờ (opaque), bọc thêm header (và đôi khi trailer) của tầng dưới.
- **Tách biệt mối quan tâm (separation of concerns)**: TCP không cần biết gói tin đi qua Ethernet hay Wi-Fi; IP không cần biết payload là TCP hay UDP.
- **Khả năng thay thế (interchangeability)**: có thể thay tầng vật lý mà không đổi tầng IP.

### 1.1.2. Mô hình OSI (ISO/IEC 7498-1)

| Tầng | Tên | PDU | Chức năng cốt lõi | Ví dụ giao thức/thiết bị |
|------|-----|-----|-------------------|---------------------------|
| 7 | Application | Data | Giao diện cho ứng dụng | HTTP, DNS, SMTP, FTP |
| 6 | Presentation | Data | Mã hóa, nén, biểu diễn dữ liệu | TLS, ASCII/UTF-8, JPEG |
| 5 | Session | Data | Thiết lập/duy trì/kết thúc phiên | RPC, NetBIOS, SOCKS |
| 4 | Transport | Segment (TCP) / Datagram (UDP) | Port, độ tin cậy, kiểm soát luồng | TCP, UDP, SCTP, QUIC |
| 3 | Network | Packet | Định địa chỉ logic, định tuyến | IPv4, IPv6, ICMP, IPsec |
| 2 | Data Link | Frame | Địa chỉ vật lý (MAC), truy nhập môi trường | Ethernet, 802.11, ARP, VLAN |
| 1 | Physical | Bit/Symbol | Biểu diễn bit thành tín hiệu | Cáp đồng, quang, RF, NIC PHY |

> Lưu ý PDU — tầng 4 TCP gọi là *segment*, UDP gọi là *datagram*; tầng 3 là *packet*; tầng 2 là *frame*; tầng 1 là *bit/symbol*.

### 1.1.3. Mô hình TCP/IP (RFC 1122)

TCP/IP là mô hình thực tế (de facto) của Internet. RFC 1122 chia thành 4 tầng:

| Tầng TCP/IP | Ánh xạ OSI | Giao thức tiêu biểu |
|-------------|------------|---------------------|
| Application | 7 + 6 + 5 | HTTP, DNS, TLS (thường gộp ở đây), SMTP |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IPv4, IPv6, ICMP, ARP (ranh giới mờ với L2) |
| Link / Network Access | 2 + 1 | Ethernet, Wi-Fi, PPP |

**Vì sao có hai mô hình?** OSI là mô hình lý thuyết (đặc tả 1984) đầy đủ và dùng để giảng dạy/chuẩn hóa thuật ngữ. TCP/IP ra đời từ ARPANET, đơn giản hơn, là cái thật sự chạy trên Internet. Kỹ sư bảo mật phải thông thạo cả hai vì công cụ và tài liệu trộn lẫn cách dùng (ví dụ "L7 firewall", "L2 attack", "L3/L4 ACL").

---

## 1.2. Encapsulation / Decapsulation byte-by-byte

### 1.2.1. Quá trình bọc dữ liệu khi gửi

Giả sử trình duyệt gửi một request HTTP `GET /` tới một web server trong cùng mạng LAN qua HTTP (không TLS để đơn giản hóa).

```
Tầng 7 (HTTP)   : [ "GET / HTTP/1.1\r\nHost: x\r\n\r\n" ]               <- App data (D)
Tầng 4 (TCP)    : [ TCP header 20B | D ]                                <- Segment
Tầng 3 (IP)     : [ IPv4 header 20B | TCP header 20B | D ]              <- Packet
Tầng 2 (Eth)    : [ Eth header 14B | IPv4 20B | TCP 20B | D | FCS 4B ]  <- Frame
Tầng 1 (PHY)    : [ Preamble 7B | SFD 1B | <Frame trên dây> ]           <- Bit stream
```

Mỗi tầng **chỉ thêm header của mình** và coi tất cả những gì nhận từ tầng trên là payload mờ. Đây là lý do mỗi header phải có trường "protocol/next header" để bên nhận biết payload thuộc giao thức nào (xem `EtherType`, `Protocol` của IPv4, port của TCP).

### 1.2.2. Quá trình tháo dữ liệu khi nhận (decapsulation)

Bên nhận làm ngược lại, mỗi tầng đọc header của mình, kiểm tra (checksum/FCS), bóc ra, rồi đẩy payload lên tầng trên dựa vào trường "next protocol":

```
PHY  : nhận bit -> dò Preamble/SFD đồng bộ clock -> lấy frame
L2   : kiểm FCS (CRC32). EtherType=0x0800 -> đẩy lên IPv4
L3   : kiểm IP checksum, kiểm Dst IP là của mình, Protocol=6 -> TCP
L4   : kiểm TCP checksum, dùng Dst Port=80 -> đẩy lên process nghe cổng 80
L7   : web server parse "GET / HTTP/1.1"
```

### 1.2.3. Ví dụ thực tế: xem từng tầng bằng tcpdump

```bash
# -X in hex+ASCII, -e in cả Ethernet header, -nn không phân giải tên/cổng
sudo tcpdump -i eth0 -e -nn -X 'tcp port 80 and host 93.184.216.34' -c 1
```

Output mẫu (rút gọn, đã chú thích):

```
14:02:11.123456 aa:bb:cc:11:22:33 > de:ad:be:ef:00:01, ethertype IPv4 (0x0800), length 74:
    10.0.0.5.54321 > 93.184.216.34.80: Flags [S], seq 1001, win 64240,
    options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0
    0x0000:  dead beef 0001 aabb cc11 2233 0800 4500   <- Eth(14) + IP bắt đầu (45=Ver4,IHL5)
    0x0010:  003c 1c46 4000 4006 ...                    <- TotalLen 0x3c=60, Flags+FragOff, TTL=0x40=64, Proto=0x06=TCP
    ...
```

- `dead beef 0001` = Dst MAC; `aabb cc11 2233` = Src MAC; `0800` = EtherType IPv4.
- `45` = `0100 0101` -> Version 4, IHL 5 (5×4=20 byte).
- `40` (ở offset TTL) = TTL 64; `06` = Protocol 6 = TCP.

---

## 1.3. Tầng 2 — Ethernet, MAC, VLAN, ARP, switch

### 1.3.1. Khung Ethernet II — layout từng trường

Ethernet II (DIX) là định dạng phổ biến nhất hiện nay (khác với IEEE 802.3 dùng trường Length thay EtherType).

| Trường | Kích thước | Offset (trong frame trên dây) | Ý nghĩa | Ví dụ |
|--------|-----------|-------------------------------|---------|-------|
| Preamble | 7 byte | 0 | 7 byte `0xAA` (`10101010…`) đồng bộ clock | `AA AA AA AA AA AA AA` |
| SFD (Start Frame Delimiter) | 1 byte | 7 | `0xAB` (`10101011`), bit cuối =1 báo bắt đầu frame | `AB` |
| Destination MAC | 6 byte | 8 | MAC đích | `de:ad:be:ef:00:01` |
| Source MAC | 6 byte | 14 | MAC nguồn | `aa:bb:cc:11:22:33` |
| EtherType / Length | 2 byte | 20 | ≥0x0600 = EtherType; <0x0600 = Length (802.3) | `0x0800` (IPv4) |
| Payload | 46–1500 byte | 22 | Dữ liệu tầng trên (IP packet) | … |
| FCS (Frame Check Sequence) | 4 byte | cuối | CRC-32 trên Dst..Payload | `0x1c2d3e4f` |

> **Preamble + SFD (8 byte) không được tính vào frame** khi bắt bằng tcpdump/Wireshark (NIC bóc trước). Chúng cũng không thuộc MTU.

**EtherType phổ biến:**

| EtherType | Giao thức |
|-----------|-----------|
| 0x0800 | IPv4 |
| 0x0806 | ARP |
| 0x86DD | IPv6 |
| 0x8100 | VLAN tag 802.1Q |
| 0x8847 | MPLS unicast |

**MTU và kích thước:**
- **MTU mặc định Ethernet = 1500 byte** (payload tối đa). Frame tối đa (không tính preamble/SFD) = 14 (header) + 1500 + 4 (FCS) = **1518 byte**. Với VLAN tag thêm 4 byte → 1522.
- **Payload tối thiểu 46 byte**: nếu nhỏ hơn, phải **padding** thêm số 0 cho đủ. Vì sao? Để frame tối thiểu đạt 64 byte (đảm bảo phát hiện collision trong Ethernet half-duplex cũ — slot time).
- **Jumbo frame**: MTU 9000 (không chuẩn IEEE nhưng phổ biến trong datacenter/SAN).

**Cấu trúc địa chỉ MAC (48 bit):**
```
AA:BB:CC:DD:EE:FF
└── OUI (24 bit) ──┘└── NIC-specific (24 bit) ──┘
Byte đầu (AA): bit 0 (I/G) = 1 -> multicast; =0 -> unicast
               bit 1 (U/L) = 1 -> locally administered; =0 -> universal (OUI thật)
Broadcast = FF:FF:FF:FF:FF:FF
```

### 1.3.2. VLAN — IEEE 802.1Q tag (4 byte)

Khi cần phân tách logic nhiều mạng trên cùng hạ tầng vật lý, switch chèn **tag 802.1Q 4 byte** vào frame, ngay sau Source MAC.

```
[ Dst MAC 6B | Src MAC 6B | 802.1Q TAG 4B | EtherType 2B | Payload | FCS 4B ]
                                   │
                                   ▼
              ┌──────────────────────────────────────────┐
              │ TPID 16b | PCP 3b | DEI 1b | VID 12b       │
              └──────────────────────────────────────────┘
```

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------|---------|-------|
| TPID (Tag Protocol ID) | 16 bit | `0x8100` báo đây là 802.1Q | `0x8100` |
| PCP (Priority Code Point) | 3 bit | Ưu tiên QoS (0–7) | `5` (voice) |
| DEI (Drop Eligible Indicator) | 1 bit | Cho phép drop khi nghẽn | `0` |
| VID (VLAN ID) | 12 bit | ID VLAN (0–4095; 0 và 4095 dành riêng) | `100` |

- VID 12 bit → tối đa **4094 VLAN** dùng được. **Native VLAN**: trên trunk port, VLAN không tag.
- **Lưu ý: VLAN hopping.**
  - *Double tagging*: kẻ tấn công gắn 2 tag; switch bóc tag ngoài (native VLAN), forward sang trunk còn tag trong → frame nhảy sang VLAN khác. Phòng: đặt native VLAN là một VLAN "chết" không dùng, hoặc tag cả native VLAN (`vlan dot1q tag native`).
  - *Switch spoofing*: kẻ tấn công giả DTP để biến port access thành trunk. Phòng: tắt DTP (`switchport mode access`, `switchport nonegotiate`).

### 1.3.3. ARP — Address Resolution Protocol (RFC 826)

ARP ánh xạ địa chỉ IP (L3) sang địa chỉ MAC (L2) trong cùng broadcast domain. Trước khi gửi IP packet tới một host cùng subnet, máy phải biết MAC của host đó.

**Layout gói ARP (28 byte cho IPv4-over-Ethernet), đặt trong payload Ethernet EtherType 0x0806:**

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------|---------|-------|
| Hardware Type (HTYPE) | 2 byte | Loại L2; Ethernet = 1 | `0x0001` |
| Protocol Type (PTYPE) | 2 byte | Loại L3; IPv4 = 0x0800 | `0x0800` |
| Hardware Addr Len (HLEN) | 1 byte | Độ dài MAC = 6 | `0x06` |
| Protocol Addr Len (PLEN) | 1 byte | Độ dài IP = 4 | `0x04` |
| Operation (OPER) | 2 byte | 1=request, 2=reply | `0x0001` |
| Sender Hardware Addr (SHA) | 6 byte | MAC người gửi | `aa:bb:cc:11:22:33` |
| Sender Protocol Addr (SPA) | 4 byte | IP người gửi | `10.0.0.5` |
| Target Hardware Addr (THA) | 6 byte | MAC đích (0 trong request) | `00:00:00:00:00:00` |
| Target Protocol Addr (TPA) | 4 byte | IP cần hỏi | `10.0.0.1` |

**Quy trình request/reply:**
1. Host A (`10.0.0.5`) muốn gửi tới `10.0.0.1`, không có trong ARP cache.
2. A broadcast ARP request: Eth Dst = `ff:ff:ff:ff:ff:ff`, OPER=1, TPA=`10.0.0.1`, THA=0.
3. Mọi host trong broadcast domain nhận; chỉ `10.0.0.1` trả lời.
4. B unicast ARP reply về A: OPER=2, SHA = MAC của B, SPA=`10.0.0.1`.
5. A lưu cặp `10.0.0.1 → MAC_B` vào ARP cache (timeout vài chục giây–vài phút).

**Ví dụ thực tế:**
```bash
ip neigh show                 # Xem ARP cache (Linux hiện đại)
# 10.0.0.1 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE
arping -I eth0 10.0.0.1        # Gửi ARP request thủ công
sudo tcpdump -i eth0 -nn arp  # Bắt gói ARP
```

**ARP spoofing/poisoning.** **Lưu ý:** ARP không có xác thực. Kẻ tấn công gửi **ARP reply giả** (gratuitous ARP) liên tục: "IP gateway `10.0.0.1` có MAC = MAC_kẻ_tấn_công". Nạn nhân ghi đè cache → mọi traffic ra gateway đi qua máy attacker (Man-in-the-Middle).

```bash
# Minh họa (chỉ trong lab được phép):
sudo arpspoof -i eth0 -t 10.0.0.5 10.0.0.1   # nói với .5 rằng .1 là tôi
# Kết hợp bật ip_forward để traffic không đứt:
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
Phòng thủ: **Dynamic ARP Inspection (DAI)** trên switch (kiểm ARP với DHCP snooping binding), static ARP cho gateway quan trọng, port security, giám sát thay đổi mapping (arpwatch).

### 1.3.4. Switch CAM table (MAC address table)

Switch học MAC bằng cách xem **Source MAC** của frame đến trên mỗi port, lưu vào bảng CAM: `MAC → port`. Khi forward, tra Dst MAC:
- Có trong CAM → gửi đúng port (unicast).
- Không có (unknown unicast) hoặc broadcast/multicast → flood ra tất cả port trừ port đến.

**Bảo mật — CAM table overflow / MAC flooding:** attacker bơm hàng nghìn frame với Source MAC ngẫu nhiên (`macof`) làm đầy CAM table. Khi đầy, switch flood mọi traffic như hub → attacker sniff được. Phòng: **port security** giới hạn số MAC/port.

```
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 2
Switch(config-if)# switchport port-security violation shutdown
Switch(config-if)# switchport port-security mac-address sticky
```

---

## 1.4. Tầng 3 — IPv4, IPv6, ICMP, định tuyến, NAT

### 1.4.1. IPv4 header — layout 20 byte (không Options)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |DSCP   |ECN|         Total Length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|    Fragment Offset      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  TTL          |   Protocol    |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Options (nếu IHL>5)            |   Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Trường | Kích thước | Offset (byte) | Ý nghĩa | Ví dụ |
|--------|-----------|---------------|---------|-------|
| Version | 4 bit | 0 | Phiên bản IP = 4 | `4` |
| IHL (Internet Header Length) | 4 bit | 0 | Độ dài header theo đơn vị 4 byte; min 5 (=20B), max 15 (=60B) | `5` |
| DSCP | 6 bit | 1 | Differentiated Services (QoS) | `0` |
| ECN | 2 bit | 1 | Explicit Congestion Notification | `0` |
| Total Length | 16 bit | 2 | Tổng độ dài header+payload (byte); max 65535 | `60` |
| Identification | 16 bit | 4 | ID datagram, dùng ráp mảnh | `0x1c46` |
| Flags | 3 bit | 6 | bit0=reserved(0), bit1=DF (Don't Fragment), bit2=MF (More Fragments) | `010` (DF) |
| Fragment Offset | 13 bit | 6 | Vị trí mảnh (đơn vị 8 byte) | `0` |
| TTL (Time To Live) | 8 bit | 8 | Số hop còn lại; mỗi router −1; =0 thì drop + ICMP | `64` |
| Protocol | 8 bit | 9 | Giao thức payload: 1=ICMP,6=TCP,17=UDP | `6` |
| Header Checksum | 16 bit | 10 | Checksum chỉ của header | `0xb1e6` |
| Source IP | 32 bit | 12 | IP nguồn | `10.0.0.5` |
| Destination IP | 32 bit | 16 | IP đích | `93.184.216.34` |
| Options | 0–40 byte | 20 | Tùy chọn (record route, timestamp…) | — |

**Vì sao TTL?** Ngăn packet quay vòng vô hạn khi routing loop. `traceroute` lợi dụng TTL: gửi gói TTL=1,2,3… mỗi router làm TTL=0 sẽ trả về ICMP Time Exceeded, lộ IP của nó.

**Header Checksum** dùng one's complement sum của các half-word 16 bit của header. Vì TTL đổi mỗi hop nên router phải tính lại checksum mỗi hop (lý do IPv6 bỏ checksum này để giảm tải).

### 1.4.2. Fragmentation (phân mảnh IPv4)

Khi packet lớn hơn MTU của link kế tiếp và không có cờ DF, router chia thành nhiều mảnh.

Ví dụ: datagram payload 4000 byte qua link MTU 1500 (payload IP tối đa = 1500−20 = 1480, phải bội số 8 → dùng 1480).

| Mảnh | Bytes data | Fragment Offset (đơn vị 8B) | MF | Total Length |
|------|-----------|-----------------------------|----|--------------|
| 1 | 0–1479 | 0 | 1 | 1500 |
| 2 | 1480–2959 | 185 (=1480/8) | 1 | 1500 |
| 3 | 2960–3999 | 370 (=2960/8) | 0 | 1060 |

Tất cả mảnh dùng **cùng Identification**. Bên nhận ráp lại theo offset. **Bảo mật:** tấn công overlapping fragment (Teardrop), tiny fragment vượt firewall, fragment-based IDS evasion. Phòng: firewall ráp mảnh trước khi inspect (virtual reassembly).

### 1.4.3. IPv6 header — layout 40 byte cố định

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| Traffic Class |           Flow Label                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Payload Length        |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                  Source Address (128 bit)                     +
|                       ... (16 byte) ...                       |
+                                                               +
|                                                               |
+                Destination Address (128 bit)                  +
|                       ... (16 byte) ...                       |
+                                                               +
```

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------|---------|-------|
| Version | 4 bit | = 6 | `6` |
| Traffic Class | 8 bit | DSCP+ECN tương tự IPv4 | `0` |
| Flow Label | 20 bit | Đánh dấu luồng cho QoS | `0x12345` |
| Payload Length | 16 bit | Độ dài payload (không gồm 40B header) | `1280` |
| Next Header | 8 bit | Như Protocol IPv4; cũng trỏ extension header | `6` (TCP) |
| Hop Limit | 8 bit | Như TTL | `64` |
| Source Address | 128 bit | IPv6 nguồn | `2001:db8::1` |
| Destination Address | 128 bit | IPv6 đích | `2001:db8::2` |

**Khác biệt thiết kế quan trọng:** header cố định 40B (không IHL/Options trong header chính — dùng *extension headers* nối chuỗi qua Next Header); không checksum (giao cho L2 FCS và L4 checksum); router không phân mảnh (host tự dùng Path MTU Discovery); MTU tối thiểu 1280B. IPv6 không dùng ARP mà dùng **NDP (Neighbor Discovery Protocol)** qua ICMPv6.

### 1.4.4. ICMP (RFC 792)

Đặt trong payload IP với Protocol=1. Header chung 8 byte:

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------|---------|-------|
| Type | 1 byte | Loại thông điệp | `8` (Echo Request) |
| Code | 1 byte | Mã con | `0` |
| Checksum | 2 byte | Checksum ICMP | `0xf7ff` |
| Rest of Header | 4 byte | Tùy Type (Echo: Identifier 2B + Sequence 2B) | id=0x1234 seq=1 |

**Type/Code quan trọng:**

| Type | Code | Ý nghĩa |
|------|------|---------|
| 0 | 0 | Echo Reply (ping trả lời) |
| 3 | 0–15 | Destination Unreachable (3=port unreachable, 4=frag needed+DF) |
| 5 | 0–3 | Redirect |
| 8 | 0 | Echo Request (ping) |
| 11 | 0 | Time Exceeded (TTL=0, dùng cho traceroute) |

```bash
ping -c 3 8.8.8.8
sudo tcpdump -i eth0 -nn icmp
# ICMP type 8 = request; type 0 = reply; type 11 = traceroute hops
```
**Bảo mật:** ICMP tunneling (đẩy data trong payload Echo để bypass firewall — `ptunnel`), ICMP redirect spoofing, smurf attack (broadcast amplification). Nhiều nơi rate-limit/filter ICMP nhưng KHÔNG nên chặn `Type 3 Code 4` vì sẽ phá PMTUD.

### 1.4.5. RFC 1918, CIDR và chia subnet thủ công

**RFC 1918 — dải IP riêng (private):**

| Dải | CIDR | Số địa chỉ |
|-----|------|------------|
| 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | 16.777.216 |
| 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | 1.048.576 |
| 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | 65.536 |

Khác: `127.0.0.0/8` loopback; `169.254.0.0/16` link-local (APIPA); `100.64.0.0/10` CGNAT (RFC 6598).

**CIDR (Classless Inter-Domain Routing):** ký hiệu `/n` = n bit đầu là phần network (netmask). Ví dụ `/24` → mask `255.255.255.0`, 8 bit host → `2^8 = 256` địa chỉ, dùng được `256 − 2 = 254` host (trừ network address và broadcast).

**Chia subnet thủ công — ví dụ từng bước:** chia `192.168.1.0/24` thành 4 subnet đều nhau.

1. Cần 4 subnet → cần `log2(4) = 2` bit mượn từ phần host. Prefix mới: `/24 + 2 = /26`.
2. Mask `/26` = `255.255.255.192` (byte cuối `11000000` = 192).
3. Block size (bước nhảy) = `256 − 192 = 64`.
4. Liệt kê:

| Subnet | Network | Dải host dùng được | Broadcast |
|--------|---------|--------------------|-----------|
| 1 | 192.168.1.0/26 | .1 – .62 | 192.168.1.63 |
| 2 | 192.168.1.64/26 | .65 – .126 | 192.168.1.127 |
| 3 | 192.168.1.128/26 | .129 – .190 | 192.168.1.191 |
| 4 | 192.168.1.192/26 | .193 – .254 | 192.168.1.255 |

Mỗi subnet: `2^(32−26) = 64` địa chỉ, dùng được `64 − 2 = 62` host.

**Xác định IP có thuộc subnet không (AND bitwise):** IP `192.168.1.130` với mask `/26`:
```
IP:    11000000.10101000.00000001.10000010
Mask:  11111111.11111111.11111111.11000000
AND:   11000000.10101000.00000001.10000000  = 192.168.1.128  -> Subnet 3
```

```bash
ipcalc 192.168.1.130/26     # công cụ tính nhanh
sipcalc 192.168.1.0/24 -s 26
```

### 1.4.6. NAT / PAT / SNAT / DNAT

**NAT (Network Address Translation):** dịch IP (và port) khi packet đi qua router biên. Lý do tồn tại: IPv4 cạn kiệt; nhiều host private chia sẻ một public IP.

| Loại | Dịch gì | Dùng cho |
|------|---------|----------|
| Static NAT (1:1) | 1 private ↔ 1 public cố định | Server cần địa chỉ public ổn định |
| Dynamic NAT | private ↔ public từ pool | Nhiều host, pool public |
| **PAT / NAPT / Overload** | nhiều private → 1 public, phân biệt bằng **port** | Trường hợp phổ biến nhất ở nhà/cty |
| **SNAT** (Source NAT) | đổi Source IP (outbound) | LAN → Internet |
| **DNAT** (Destination NAT) | đổi Dst IP (inbound) | Port forwarding tới server nội bộ |

**Bảng dịch PAT (translation table):**

| Inside Local | Inside Global | Outside | Protocol |
|--------------|---------------|---------|----------|
| 10.0.0.5:54321 | 203.0.113.10:40001 | 93.184.216.34:80 | TCP |
| 10.0.0.6:51000 | 203.0.113.10:40002 | 1.1.1.1:443 | TCP |

Router thay Source `10.0.0.5:54321` → `203.0.113.10:40001` khi ra, và làm ngược khi gói trả về dựa vào port 40001.

**Ví dụ thực tế — iptables/nftables:**
```bash
# SNAT/MASQUERADE: LAN 10.0.0.0/24 ra ngoài qua eth0
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# DNAT: forward public:8080 -> server nội bộ 10.0.0.50:80
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8080 \
  -j DNAT --to-destination 10.0.0.50:80
sudo iptables -A FORWARD -p tcp -d 10.0.0.50 --dport 80 -j ACCEPT

# Xem bảng NAT đang hoạt động
sudo conntrack -L
```
**Bảo mật:** NAT không phải firewall (nhiều người nhầm). NAT slipstreaming, hairpin NAT, và việc DNAT mở cổng ra Internet là bề mặt tấn công lớn.

### 1.4.7. Định tuyến (routing) cơ bản

Router quyết định next-hop bằng **longest prefix match** trong routing table.
```bash
ip route show
# default via 10.0.0.1 dev eth0
# 10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5
ip route get 8.8.8.8     # xem packet sẽ đi route nào
```
Default route `0.0.0.0/0` là "khớp mọi đích" với prefix ngắn nhất (chỉ dùng khi không có route cụ thể hơn).

---

## 1.5. Tầng 4 — TCP và UDP

### 1.5.1. UDP header — layout 8 byte (RFC 768)

| Trường | Kích thước | Offset | Ý nghĩa | Ví dụ |
|--------|-----------|--------|---------|-------|
| Source Port | 16 bit | 0 | Cổng nguồn | `54321` |
| Destination Port | 16 bit | 2 | Cổng đích | `53` |
| Length | 16 bit | 4 | Độ dài header+data (≥8) | `40` |
| Checksum | 16 bit | 6 | Checksum (tùy chọn IPv4, bắt buộc IPv6) | `0x1a2b` |

UDP không bắt tay, không đảm bảo thứ tự/độ tin cậy, không kiểm soát luồng. Dùng cho DNS, DHCP, VoIP, QUIC. **Checksum của UDP/TCP** tính trên một **pseudo-header** gồm Src IP, Dst IP, Protocol, Length của tầng IP — để phát hiện packet bị giao nhầm địa chỉ.

### 1.5.2. TCP header — layout 20 byte (không Options), RFC 9293

```
 0                   1                   2                   3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DOff  |Rsv|N|C|E|U|A|P|R|S|F|         Window Size              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |        Urgent Pointer         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options (nếu DOff>5)         |   Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Trường | Kích thước | Offset | Ý nghĩa | Ví dụ |
|--------|-----------|--------|---------|-------|
| Source Port | 16 bit | 0 | Cổng nguồn | `54321` |
| Destination Port | 16 bit | 2 | Cổng đích | `443` |
| Sequence Number | 32 bit | 4 | Số thứ tự byte đầu của segment (hoặc ISN khi SYN) | `1001` |
| Acknowledgment Number | 32 bit | 8 | Số byte kế tiếp mong nhận (hợp lệ khi ACK=1) | `2001` |
| Data Offset (DOff) | 4 bit | 12 | Độ dài header TCP theo đơn vị 4 byte (min 5=20B) | `5` |
| Reserved | 3 bit | 12 | =0 | `0` |
| Flags (9 bit) | 9 bit | 12–13 | Xem dưới | — |
| Window Size | 16 bit | 14 | Số byte cửa sổ nhận (receive window) | `64240` |
| Checksum | 16 bit | 16 | Checksum (gồm pseudo-header) | `0x4a8c` |
| Urgent Pointer | 16 bit | 18 | Offset dữ liệu khẩn (khi URG=1) | `0` |

**9 cờ TCP (từ bit cao xuống thấp):**

| Cờ | Tên | Ý nghĩa |
|----|-----|---------|
| NS | Nonce Sum | ECN nonce (RFC 3540, hiếm dùng) |
| CWR | Congestion Window Reduced | Báo đã giảm cwnd do nghẽn |
| ECE | ECN-Echo | Báo nhận được dấu hiệu nghẽn |
| URG | Urgent | Urgent Pointer hợp lệ |
| ACK | Acknowledgment | Ack Number hợp lệ |
| PSH | Push | Đẩy data lên app ngay, không buffer |
| RST | Reset | Hủy kết nối đột ngột |
| SYN | Synchronize | Khởi tạo kết nối, đồng bộ seq |
| FIN | Finish | Kết thúc gửi dữ liệu một chiều |

**TCP Options thường gặp (trong vùng Options):**

| Option | Kind | Độ dài | Ý nghĩa |
|--------|------|--------|---------|
| End of Option List | 0 | 1B | Kết thúc options |
| No-Operation (NOP) | 1 | 1B | Padding căn 4 byte |
| MSS (Maximum Segment Size) | 2 | 4B | Kích thước segment tối đa, thường 1460 (1500−40) |
| Window Scale | 3 | 3B | Nhân hệ số window (dịch trái), tối đa ×2^14 |
| SACK Permitted | 4 | 2B | Cho phép Selective ACK |
| SACK | 5 | thay đổi | Báo các block đã nhận rời rạc |
| Timestamps | 8 | 10B | TSval/TSecr đo RTT, chống wrap (PAWS) |

### 1.5.3. Bắt tay 3 bước (3-way handshake) — giá trị seq/ack từng bước

```
Client (10.0.0.5)                                  Server (1.2.3.4:443)
        |                                                  |
        |  1. SYN  seq=x (ISN_c=1000), ack=0               |
        |------------------------------------------------->|   Flags=[S]
        |                                                  |
        |  2. SYN-ACK  seq=y (ISN_s=5000), ack=x+1=1001    |
        |<-------------------------------------------------|   Flags=[S.]
        |                                                  |
        |  3. ACK  seq=x+1=1001, ack=y+1=5001              |
        |------------------------------------------------->|   Flags=[.]
        |                                                  |
   (kết nối ESTABLISHED, data bắt đầu từ seq=1001/5001)
```

Giải thích chi tiết:
1. Client chọn **ISN (Initial Sequence Number)** ngẫu nhiên (=1000), gửi SYN với seq=1000. SYN tiêu tốn 1 số seq (dù không chở data).
2. Server chọn ISN riêng (=5000), gửi SYN-ACK: seq=5000, ack=1001 (xác nhận đã nhận seq 1000, mong byte tiếp theo là 1001).
3. Client gửi ACK: seq=1001, ack=5001. Kết nối thành ESTABLISHED.

**Vì sao ISN ngẫu nhiên?** Chống TCP sequence prediction attack (kẻ ngoài đoán seq để chèn/spoof). RFC 6528 yêu cầu ISN = hàm băm bí mật.

**Bảo mật — SYN flood:** attacker gửi loạt SYN với Source IP giả, không gửi ACK bước 3. Server giữ nhiều **half-open connection** trong backlog queue → cạn tài nguyên. Phòng: **SYN cookies** (server mã hóa state vào ISN, không lưu queue cho tới khi nhận ACK hợp lệ).
```bash
sysctl net.ipv4.tcp_syncookies=1
sysctl net.ipv4.tcp_max_syn_backlog=4096
```

### 1.5.4. Đóng kết nối 4 bước (4-way close)

```
Client                                Server
  |  FIN seq=u                          |   (Client hết data gửi)
  |------------------------------------>|
  |  ACK ack=u+1                        |
  |<------------------------------------|
  |              ... (server có thể còn gửi data) ...
  |  FIN seq=v                          |
  |<------------------------------------|
  |  ACK ack=v+1                        |
  |------------------------------------>|
  |  (Client vào TIME_WAIT ~2*MSL)      |
```

TCP là full-duplex nên mỗi chiều đóng độc lập (half-close). **TIME_WAIT** (2×MSL, MSL thường 30–120s tùy OS) đảm bảo: (1) ACK cuối tới được server, (2) các segment cũ trễ trong mạng hết hạn trước khi tái dùng cặp port. Quá nhiều TIME_WAIT trên server tải cao là vấn đề thực tế (tinh chỉnh `tcp_tw_reuse`).

### 1.5.5. State machine TCP đầy đủ (RFC 9293)

```
                              CLOSED
                                | (passive open: LISTEN) | (active open: gửi SYN)
                                v                         v
                             LISTEN                  SYN_SENT
                          recv SYN |                   | recv SYN-ACK / send ACK
                          send SYN-ACK                 v
                                v                  ESTABLISHED
                           SYN_RCVD --recv ACK------>  |
                                                       | (close: send FIN)
                        ┌──────────────────────────────┤
       recv FIN/send ACK│                              │ send FIN
                        v                              v
                   CLOSE_WAIT                       FIN_WAIT_1
                        | app close/send FIN     recv ACK | recv FIN+ACK
                        v                              v        \
                   LAST_ACK                       FIN_WAIT_2     CLOSING
                        | recv ACK                  | recv FIN       | recv ACK
                        v                           v send ACK       v
                     CLOSED                     TIME_WAIT  <----------
                                                    | (2*MSL timeout)
                                                    v
                                                 CLOSED
```

| State | Ý nghĩa |
|-------|---------|
| LISTEN | Server chờ kết nối |
| SYN_SENT | Client đã gửi SYN |
| SYN_RCVD | Đã nhận SYN, gửi SYN-ACK |
| ESTABLISHED | Kết nối hoạt động, truyền data |
| FIN_WAIT_1/2 | Phía chủ động đóng đã gửi FIN |
| CLOSE_WAIT | Phía bị động nhận FIN, app chưa đóng |
| LAST_ACK | Phía bị động đã gửi FIN, chờ ACK cuối |
| TIME_WAIT | Chờ 2×MSL trước khi đóng hẳn |

```bash
ss -tan          # xem state TCP (ESTAB, TIME-WAIT, CLOSE-WAIT...)
ss -tanp state syn-recv   # phát hiện SYN flood
```
**Bảo mật quét cổng (nmap) dựa vào state machine:**
- *SYN scan* (`-sS`): gửi SYN; nhận SYN-ACK → open (rồi gửi RST hủy); nhận RST → closed.
- *NULL/FIN/Xmas scan*: gửi cờ bất thường; theo RFC, port closed trả RST, open im lặng → suy ra trạng thái (bypass một số firewall stateless).

### 1.5.6. Sliding window, flow control, congestion control

**Flow control (kiểm soát luồng):** bên nhận quảng bá **Window Size** (kết hợp Window Scale) = lượng byte còn chỗ trong buffer. Bên gửi không gửi quá `Window`. Nếu buffer đầy → quảng bá window=0 → bên gửi dừng, định kỳ gửi *window probe*.

**Sliding window:** byte stream chia 4 vùng: (1) đã gửi & ack, (2) đã gửi chưa ack, (3) chưa gửi nhưng trong window, (4) ngoài window. Khi ack tới, "cửa sổ" trượt sang phải.

**Congestion control (kiểm soát tắc nghẽn) — thuật toán cổ điển:**
- *Slow start*: cwnd bắt đầu = 1–10 MSS, tăng gấp đôi mỗi RTT cho tới `ssthresh`.
- *Congestion avoidance*: sau ssthresh, tăng tuyến tính (+1 MSS/RTT).
- *Fast retransmit*: nhận 3 duplicate ACK → gửi lại ngay không chờ timeout.
- *Fast recovery*: giảm cwnd nửa thay vì về 1.
- Hiện đại: **CUBIC** (mặc định Linux), **BBR** (Google, đo bandwidth×RTT).
```bash
sysctl net.ipv4.tcp_congestion_control   # xem thuật toán
ss -ti                                    # xem cwnd, rtt, retrans per-socket
```

**Retransmission:** dựa **RTO (Retransmission Timeout)** tính từ RTT đo được (Jacobson/Karels: `RTO = SRTT + 4*RTTVAR`). Hết RTO mà chưa ack → gửi lại, RTO nhân đôi (exponential backoff).

---

## 1.6. Cổng (port) phổ biến

| Port | Protocol | Dịch vụ | Ghi chú bảo mật |
|------|----------|---------|-----------------|
| 20/21 | TCP | FTP data/control | Plaintext, dùng FTPS/SFTP |
| 22 | TCP | SSH | Quản trị từ xa mã hóa |
| 23 | TCP | Telnet | Plaintext — không dùng |
| 25 | TCP | SMTP | Mail, kiểm relay mở |
| 53 | TCP/UDP | DNS | UDP cho query, TCP cho zone transfer/lớn |
| 67/68 | UDP | DHCP server/client | DORA |
| 80 | TCP | HTTP | Plaintext |
| 110/143 | TCP | POP3/IMAP | Mail client |
| 123 | UDP | NTP | Amplification DDoS |
| 161/162 | UDP | SNMP | Community string mặc định nguy hiểm |
| 389/636 | TCP | LDAP/LDAPS | Directory |
| 443 | TCP/UDP | HTTPS / QUIC(UDP) | TLS |
| 445 | TCP | SMB | EternalBlue, không expose ra Internet |
| 3306 | TCP | MySQL | DB không nên public |
| 3389 | TCP | RDP | Brute-force, BlueKeep |
| 5432 | TCP | PostgreSQL | DB |
| 6379 | TCP | Redis | Không auth mặc định — nguy hiểm |

Dải port: **0–1023 well-known** (cần quyền root để bind trên Linux), **1024–49151 registered**, **49152–65535 ephemeral/dynamic** (client tự cấp).

---

## 1.7. Tầng 7 — DNS, DHCP, HTTP, TLS

### 1.7.1. DNS — Domain Name System (RFC 1035)

**Message header DNS — 12 byte:**

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------|---------|-------|
| Transaction ID | 16 bit | Khớp query/response | `0x1a2b` |
| Flags | 16 bit | QR(1b),Opcode(4b),AA,TC,RD,RA,Z,RCODE(4b) | xem dưới |
| QDCOUNT | 16 bit | Số câu hỏi | `1` |
| ANCOUNT | 16 bit | Số bản ghi answer | `2` |
| NSCOUNT | 16 bit | Số bản ghi authority | `0` |
| ARCOUNT | 16 bit | Số bản ghi additional | `0` |

**Trường Flags (16 bit) chi tiết:**

| Bit | Tên | Ý nghĩa |
|-----|-----|---------|
| QR (1) | Query/Response | 0=query, 1=response |
| Opcode (4) | | 0=standard query |
| AA (1) | Authoritative Answer | server có thẩm quyền |
| TC (1) | Truncated | response bị cắt (chuyển TCP) |
| RD (1) | Recursion Desired | client muốn đệ quy |
| RA (1) | Recursion Available | server hỗ trợ đệ quy |
| Z (3) | reserved/AD/CD | trong DNSSEC: AD=Authenticated Data, CD=Checking Disabled |
| RCODE (4) | Response code | 0=NOERROR,2=SERVFAIL,3=NXDOMAIN |

**Question section:** `QNAME` (chuỗi label dạng `[len][label]...0`, ví dụ `3www7example3com0`), `QTYPE` (2B, A=1, AAAA=28, MX=15, CNAME=5, NS=2, TXT=16, SOA=6, PTR=12), `QCLASS` (2B, IN=1).

**Resource Record (answer):** `NAME`(thường con trỏ nén 2B `0xc00c`), `TYPE`(2B), `CLASS`(2B), `TTL`(4B), `RDLENGTH`(2B), `RDATA`(thay đổi — với A là 4 byte IPv4).

**Recursive vs iterative:**
- *Recursive resolver* (8.8.8.8): client hỏi một lần, resolver tự đi hỏi hộ và trả kết quả cuối.
- *Iterative*: resolver hỏi root → TLD (`.com`) → authoritative, mỗi bước nhận referral tới server tiếp theo.

```bash
dig +trace example.com A      # xem toàn bộ chuỗi iterative từ root
dig @1.1.1.1 example.com MX
dig -x 93.184.216.34          # reverse (PTR)
sudo tcpdump -i eth0 -nn 'udp port 53'
```

Output `dig` mẫu (đã chú thích):
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6789
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
example.com.    3600   IN   A   93.184.216.34
```

**DNSSEC:** thêm bản ghi `RRSIG` (chữ ký), `DNSKEY` (khóa công khai), `DS` (delegation signer), `NSEC/NSEC3` (chứng minh không tồn tại). Bit `AD` (Authenticated Data) trong flags báo resolver đã xác thực chữ ký. Mục tiêu: chống cache poisoning/spoofing bằng chữ ký số (không mã hóa nội dung).

**Bảo mật — DNS tunneling:** mã hóa dữ liệu exfil vào QNAME (`base64data.attacker.com`) hoặc TXT records → vượt firewall vì DNS hiếm khi bị chặn. Phát hiện: QNAME bất thường dài/entropy cao, lượng query TXT lớn.

**Cache poisoning (Kaminsky):** đoán Transaction ID (16 bit) + source port để chèn answer giả trước answer thật. Phòng: random source port (entropy lớn hơn), DNSSEC, DNS-over-TLS/HTTPS.

### 1.7.2. DHCP — DORA (RFC 2131)

Bốn bước cấp IP động (UDP, server 67, client 68):

```
Client (0.0.0.0)                         DHCP Server
   | 1. DISCOVER (broadcast ff:ff..)        |   "Có server nào không?"
   |--------------------------------------->|
   | 2. OFFER (đề nghị IP, lease, gateway)   |
   |<---------------------------------------|
   | 3. REQUEST (xin chính IP được offer)    |
   |--------------------------------------->|
   | 4. ACK (xác nhận, đóng dấu lease)       |
   |<---------------------------------------|
```

| Bước | Loại | Src IP | Dst IP | Mục đích |
|------|------|--------|--------|----------|
| D | DISCOVER | 0.0.0.0 | 255.255.255.255 | Client tìm server (chưa có IP) |
| O | OFFER | server IP | broadcast/unicast | Server đề nghị IP |
| R | REQUEST | 0.0.0.0 | 255.255.255.255 | Client chấp nhận (broadcast để các server khác biết) |
| A | ACK | server IP | client | Xác nhận, cấp lease + options (DNS, gateway, mask) |

Các option quan trọng (DHCP options trong packet BOOTP): Option 53 (message type), 51 (lease time), 1 (subnet mask), 3 (router/gateway), 6 (DNS), 50 (requested IP).

```bash
sudo dhclient -v eth0
sudo tcpdump -i eth0 -nn 'udp port 67 or udp port 68'
```
**Bảo mật:** *Rogue DHCP server* cấp gateway/DNS giả → MITM. *DHCP starvation* (`yersinia`) bơm DISCOVER cạn pool. Phòng: **DHCP snooping** trên switch (chỉ trust port nối server hợp lệ).

### 1.7.3. HTTP — request/response raw

**Request (HTTP/1.1):**
```http
GET /index.html HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: curl/8.0\r\n
Accept: */*\r\n
\r\n
```
Cấu trúc: `Method SP Request-URI SP HTTP-Version CRLF`, sau đó các header `Name: Value CRLF`, một dòng trống `CRLF`, rồi body (nếu có). CRLF = `\r\n` (0x0D 0x0A).

**Response:**
```http
HTTP/1.1 200 OK\r\n
Content-Type: text/html; charset=UTF-8\r\n
Content-Length: 138\r\n
Connection: keep-alive\r\n
\r\n
<html>...</html>
```
`Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase`. Mã: 1xx info, 2xx success, 3xx redirect, 4xx client error, 5xx server error.

```bash
# Gửi raw request không che giấu chi tiết:
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
  | ncat example.com 80
curl -v http://example.com/      # -v in cả request/response headers
```
**Bảo mật:** header an toàn — `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`. Tấn công: request smuggling (mâu thuẫn `Content-Length` vs `Transfer-Encoding`), host header injection.

### 1.7.4. TLS — 1.2 và 1.3

Phần nền tảng mật mã đứng sau TLS/PKI (trao đổi khóa, AEAD, chứng chỉ X.509) được trình bày tại [Chương 4 — Mật mã & Nền tảng bảo mật](#sec-04).

**TLS Record layer — header 5 byte (bọc mọi message TLS):**

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------|---------|-------|
| Content Type | 1 byte | 20=ChangeCipherSpec,21=Alert,22=Handshake,23=Application Data | `22` |
| Version | 2 byte | `0x0303`=TLS1.2 (1.3 giả là 1.2 ở record để tương thích) | `0x0303` |
| Length | 2 byte | Độ dài payload (≤16384) | `0x0200` |

**TLS 1.2 handshake — từng message:**
```
Client                                       Server
  | 1. ClientHello (random_c, cipher list, SNI, sessionID)
  |------------------------------------------------->|
  | 2. ServerHello (random_s, cipher chosen)         |
  |    Certificate (chuỗi X.509)                     |
  |    ServerKeyExchange (params ECDHE)              |
  |    ServerHelloDone                               |
  |<-------------------------------------------------|
  | 3. ClientKeyExchange (ECDHE public)              |
  |    ChangeCipherSpec                              |
  |    Finished (mã hóa)                             |
  |------------------------------------------------->|
  | 4. ChangeCipherSpec                              |
  |    Finished (mã hóa)                             |
  |<-------------------------------------------------|
  (2 RTT trước khi gửi application data)
```

**TLS 1.3 handshake — rút gọn còn 1 RTT (RFC 8446):**
```
Client                                       Server
  | ClientHello (+ key_share, supported_versions, SNI)
  |------------------------------------------------->|
  |          ServerHello (+ key_share)               |
  |          {EncryptedExtensions}                   |
  |          {Certificate}{CertificateVerify}        |
  |          {Finished}                              |
  |<-------------------------------------------------|
  | {Finished}                                       |
  |------------------------------------------------->|
  (1 RTT; 0-RTT nếu dùng PSK/resumption)
```

Khác biệt TLS 1.3: bỏ ciphersuite yếu (RSA key exchange tĩnh, RC4, CBC, SHA-1), bắt buộc **forward secrecy** (ECDHE), mã hóa cả phần lớn handshake (Certificate được mã hóa), chỉ còn các ciphersuite AEAD (vd `TLS_AES_128_GCM_SHA256`).

**X.509 certificate — các trường chính:**

| Trường | Ý nghĩa | Ví dụ |
|--------|---------|-------|
| Version | v3 | `2` (=v3) |
| Serial Number | định danh duy nhất từ CA | `0x0a1b...` |
| Signature Algorithm | thuật toán ký | `sha256WithRSAEncryption` |
| Issuer | DN của CA cấp | `CN=R3, O=Let's Encrypt` |
| Validity | notBefore / notAfter | `2026-01-01 .. 2026-04-01` |
| Subject | DN chủ thể | `CN=example.com` |
| Subject Public Key Info | thuật toán + khóa công khai | `RSA 2048` / `EC P-256` |
| Extensions | SAN, Key Usage, EKU, Basic Constraints, AIA, CRL/OCSP | SAN: `example.com, www.example.com` |
| Signature | chữ ký của CA trên TBS | … |

```bash
# Xem handshake và cert thật:
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null
echo | openssl s_client -connect example.com:443 2>/dev/null \
  | openssl x509 -noout -text -dates -subject -issuer -ext subjectAltName

# Wireshark filter cho handshake:
#   tls.handshake.type == 1   (ClientHello)
#   tls.handshake.type == 2   (ServerHello)
#   tls.handshake.extensions_server_name == "example.com"
```
**Bảo mật:** SNI (Server Name Indication) lộ tên miền dù mã hóa → ECH (Encrypted Client Hello) khắc phục. Kiểm chain trust, revocation (OCSP stapling), cipher downgrade, Heartbleed (CVE-2014-0160 — đọc bộ nhớ qua heartbeat).

---

## 1.8. Firewall, DMZ, công cụ phân tích gói

### 1.8.1. Firewall stateless vs stateful

| Tiêu chí | Stateless (packet filter) | Stateful |
|----------|---------------------------|----------|
| Quyết định dựa trên | Từng packet riêng lẻ (IP/port/flags) | Trạng thái kết nối (conntrack) |
| Cho phép gói trả về | Phải mở rule cả hai chiều thủ công | Tự động (RELATED,ESTABLISHED) |
| Chống spoof flags | Yếu | Tốt (chỉ chấp nhận packet hợp state) |
| Tải bộ nhớ | Thấp | Cao (giữ bảng kết nối) |

**Ví dụ stateful với iptables:**
```bash
# Mặc định DROP, chỉ cho SSH inbound và mọi outbound đã thiết lập
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -P OUTPUT ACCEPT
```
`-m conntrack --ctstate ESTABLISHED,RELATED` chính là điểm "stateful": kernel theo dõi kết nối nên gói trả về (vd response của SSH) tự được chấp nhận mà không cần rule riêng.

### 1.8.2. DMZ (Demilitarized Zone)

DMZ là vùng mạng đệm giữa Internet và LAN nội bộ, chứa server cần truy cập từ ngoài (web, mail). Kiến trúc hai firewall:
```
Internet --[FW ngoài]-- DMZ (web, mail) --[FW trong]-- LAN nội bộ
```
Nguyên tắc: Internet → DMZ được phép (cổng cụ thể); DMZ → LAN bị hạn chế tối đa; nếu server DMZ bị chiếm, attacker vẫn khó pivot vào LAN.

### 1.8.3. tcpdump / Wireshark — bộ lọc thực tế

**tcpdump (BPF filter — capture filter):**
```bash
# Bắt SYN-only (phát hiện scan): cờ SYN bật, ACK tắt
sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn'

# Bắt HTTP GET (byte đầu payload = 'G','E','T',' ')
sudo tcpdump -i eth0 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# DNS query tới một domain, ghi ra file pcap để mở bằng Wireshark
sudo tcpdump -i eth0 -nn -w /tmp/dns.pcap 'udp port 53'

# Một host, không phân giải tên, in payload hex/ascii, 100 gói
sudo tcpdump -i eth0 -nn -X host 10.0.0.50 -c 100
```
Tham số: `-i` interface, `-nn` không phân giải tên/cổng, `-e` in L2 header, `-X` hex+ascii, `-w` ghi pcap, `-c` số gói, `-s 0` capture full packet.

**Wireshark (display filter — khác cú pháp BPF):**
```
ip.addr == 10.0.0.50
tcp.flags.syn == 1 && tcp.flags.ack == 0      # SYN scan
tcp.analysis.retransmission                   # phát hiện mất gói
http.request.method == "POST"
dns.qry.name contains "example"
tls.handshake.type == 1                       # ClientHello
tcp.port == 443 && tls.record.content_type == 23   # app data đã mã hóa
ip.ttl < 5                                    # traceroute / hop thấp bất thường
```
Quy trình điều tra điển hình: bắt bằng tcpdump trên server không có GUI (`-w file.pcap`), chuyển về máy phân tích, mở Wireshark, dùng "Follow TCP Stream" để ráp lại phiên, "Statistics → Conversations" để thấy top talker.

---

## 1.9. Tổng kết các con số cần thuộc

| Hạng mục | Giá trị |
|----------|---------|
| Ethernet header / FCS / MTU / frame max | 14B / 4B / 1500B / 1518B (1522 với VLAN) |
| Payload Ethernet min/max | 46B / 1500B |
| 802.1Q tag | 4B (TPID 16b + PCP 3b + DEI 1b + VID 12b) |
| ARP packet (IPv4) | 28B |
| IPv4 header min/max | 20B / 60B |
| IPv6 header | 40B cố định, MTU min 1280B |
| TCP header min / UDP header | 20B / 8B |
| ICMP header | 8B |
| DNS header | 12B |
| TLS record header | 5B |
| IPv4 Total Length max | 65535B |
| Port ranges | 0–1023 / 1024–49151 / 49152–65535 |

> Các con số RFC trên là chuẩn ổn định. Với các chi tiết phụ thuộc cài đặt (MSL, kích thước backlog, thuật toán congestion mặc định) hãy kiểm chứng trên hệ thống cụ thể bằng `sysctl`/`ss` vì giá trị thay đổi theo OS và phiên bản kernel.


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*
