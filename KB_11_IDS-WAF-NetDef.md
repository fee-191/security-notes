# Chương 11 — IDS/IPS, WAF & Phòng thủ mạng (Snort, ModSecurity, pfSense, VPN)

## Nhập môn — hiểu nôm na trước khi đi sâu

Chương này nói về cách chúng ta **bảo vệ một mạng máy tính** khỏi kẻ tấn công: làm sao phát hiện được có người đang dò quét hay tấn công, làm sao chặn lại, và làm sao tạo ra những "đường đi an toàn" trên Internet. Nó quan trọng vì ngày nay mọi thứ đều nối mạng — một website, một hệ thống nội bộ, một sàn giao dịch — và kẻ xấu thì luôn rình mò ngoài cửa. Hãy tưởng tượng mạng của bạn như một **toà nhà**: chương này dạy bạn cách lắp **camera an ninh**, **bảo vệ ở cửa**, **nhân viên kiểm tra giấy tờ khách**, và **hành lang bí mật có khoá** để đi lại an toàn. Dưới đây là từng "món đồ" trong bộ công cụ phòng thủ đó, giải thích thật đơn giản.

### Phòng thủ theo chiều sâu (defense-in-depth) — nói đơn giản

- **Phòng thủ theo chiều sâu là gì?** Là ý tưởng "đừng đặt hết trứng vào một giỏ". Thay vì tin tưởng một lớp bảo vệ duy nhất, ta dựng **nhiều lớp** xếp chồng nhau: tường rào, rồi cửa khoá, rồi két sắt. Kẻ tấn công vượt được lớp này vẫn còn vướng lớp sau.
- **Vì sao cần?** Vì không lớp nào hoàn hảo cả. Một lớp sơ hở thì lớp khác vẫn đỡ được. Trong mạng, mỗi thiết bị "nhìn thấy" được những phần dữ liệu khác nhau (có cái chỉ thấy địa chỉ, có cái đọc được nội dung), nên ta cần phối hợp nhiều thiết bị để bao quát đủ.

### IDS và IPS — nói đơn giản

- **IDS (hệ thống phát hiện xâm nhập) là gì?** Giống một **camera an ninh có còi báo động**: nó quan sát mọi thứ đi qua mạng, thấy điều khả nghi thì **hú còi báo** cho bạn biết — nhưng bản thân nó không lao ra chặn kẻ trộm.
- **IPS (hệ thống ngăn chặn xâm nhập) là gì?** Giống một **bảo vệ đứng chắn ngay lối đi**: không chỉ phát hiện mà còn **chặn đứng** kẻ khả nghi tại chỗ. Vì nó đứng giữa đường, nếu nó "bắt nhầm" người tốt thì dịch vụ có thể bị gián đoạn.
- **Vì sao cần cả hai khái niệm?** Vì chúng đánh đổi khác nhau: IDS an toàn cho hệ thống (không làm tắc đường) nhưng chỉ cảnh báo; IPS mạnh tay hơn nhưng rủi ro chặn nhầm. Thực tế người ta thường bật chế độ "chỉ báo động" (IDS) một thời gian để tinh chỉnh cho ít báo nhầm, rồi mới chuyển sang "chặn thật" (IPS).

### NIDS và HIDS — nói đơn giản

- **NIDS là gì?** Camera đặt ở **hành lang chung** của toà nhà — nó nhìn được mọi người đi qua đi lại giữa các phòng (tức là toàn bộ lưu lượng mạng).
- **HIDS là gì?** Camera đặt **bên trong từng phòng** (từng máy chủ) — nó thấy chi tiết những gì xảy ra ngay trong phòng đó, nhưng không thấy phòng khác.
- **Vì sao cần?** Hai góc nhìn bổ sung cho nhau: camera hành lang bắt được kẻ lẻn từ phòng này sang phòng kia, camera trong phòng bắt được kẻ đang lục lọi đồ đạc. Gộp cả hai mới thấy được toàn cảnh.

### Snort và Suricata — nói đơn giản

- **Snort/Suricata là gì?** Là những **phần mềm IDS/IPS phổ biến** dựa trên "chữ ký". Hãy hình dung nó như một anh bảo vệ cầm **cuốn sổ mô tả nhận dạng tội phạm**: ai đi qua mà khớp với mô tả trong sổ thì bị tóm. "Chữ ký" ở đây là các mẫu dữ liệu đặc trưng của một kiểu tấn công đã biết.
- **Vì sao cần?** Vì nhiều cuộc tấn công có dấu hiệu lặp lại, đã được cộng đồng ghi nhận. Có sẵn "cuốn sổ nhận dạng" giúp phát hiện nhanh và chính xác những đòn quen thuộc. (Điểm yếu: kẻ tấn công kiểu mới chưa có trong sổ thì khó bắt — nên cần thêm công cụ khác.)

### WAF, ModSecurity và OWASP CRS — nói đơn giản

- **WAF (tường lửa ứng dụng web) là gì?** Giống **nhân viên kiểm tra nội dung** đứng trước cửa website: tường lửa thường chỉ xem "ai đến từ đâu", còn WAF mở từng "lá đơn" khách gửi vào để đọc xem **có chứa thứ độc hại** không (ví dụ một câu lệnh lén lút để moi dữ liệu).
- **ModSecurity là gì?** Là một **WAF cụ thể** rất nổi tiếng — phần "động cơ" làm công việc kiểm tra đó.
- **OWASP CRS là gì?** Là **bộ quy tắc kiểm tra soạn sẵn** (Core Rule Set) để nạp vào động cơ ModSecurity, giống như "cẩm nang dấu hiệu hàng cấm" do các chuyên gia bảo mật biên soạn để bạn khỏi phải tự viết từ đầu.
- **Vì sao cần?** Vì tường lửa thường (xem mục dưới) không hiểu nội dung website, nên không phân biệt được một yêu cầu bình thường với một yêu cầu tấn công ẩn bên trong. WAF lấp đúng chỗ trống đó: nó đọc được nội dung web và chặn các đòn nhắm vào ứng dụng.

### pfSense và firewall (tường lửa) — nói đơn giản

- **Firewall là gì?** Là **anh gác cổng** của mạng: nó quyết định gói dữ liệu nào được vào/ra dựa trên các quy tắc đơn giản như "địa chỉ này, cánh cửa (cổng) kia thì cho qua, còn lại chặn".
- **pfSense là gì?** Là một **phần mềm firewall/router miễn phí** mạnh mẽ, biến một máy tính thường thành thiết bị gác cổng cho cả mạng. "Stateful" nghĩa là nó **ghi nhớ** các cuộc trò chuyện đang diễn ra, nên khi câu trả lời quay về nó biết đó là phản hồi hợp lệ và cho qua.
- **Vì sao cần?** Vì đây là **lớp chặn rẻ và nhanh nhất**, đặt ngay ngoài cùng. Chặn được những thứ rõ ràng không nên vào (ví dụ truy cập từ Internet vào cổng quản trị) ngay từ cổng, đỡ tốn công cho các lớp sâu hơn. pfSense cũng làm thêm việc chia mạng thành các khu (VLAN) và làm điểm kết nối VPN.

### VPN — IPsec, OpenVPN, WireGuard — nói đơn giản

- **VPN là gì?** Là một **đường hầm bí mật** chạy xuyên qua Internet công cộng. Dữ liệu của bạn được **bọc kín và khoá lại** trước khi gửi đi, nên người ngoài có chặn được cũng không đọc hay sửa được. Giống như gửi thư trong một chiếc xe bọc thép thay vì bưu thiếp ai cũng đọc được.
- **IPsec / OpenVPN / WireGuard là gì?** Là **ba cách làm đường hầm** đó. Cứ hiểu nôm na: IPsec là chuẩn lâu đời, nhiều tuỳ chọn nhưng phức tạp; OpenVPN linh hoạt, dễ chui qua tường lửa; WireGuard là loại mới, gọn nhẹ, nhanh và dễ kiểm tra độ an toàn. Cả ba đều đạt mục tiêu giống nhau, chỉ khác về cách trao "chìa khoá" và độ phức tạp.
- **Vì sao cần?** Vì nhân viên làm việc từ xa, hay hai văn phòng ở hai thành phố, cần nối với nhau **một cách an toàn** qua Internet. VPN cho phép họ "ở chung một mạng riêng" dù thực tế đang cách xa và đi qua đường truyền công cộng.

### Proxy và reverse proxy — nói đơn giản

- **Forward proxy là gì?** Là **người đại diện đi mua hàng hộ bạn**: bạn nhờ nó ra ngoài lấy thông tin, nên bên ngoài chỉ thấy mặt nó chứ không thấy bạn. Dùng để ẩn danh, lọc nội dung, kiểm soát truy cập ra Internet.
- **Reverse proxy là gì?** Ngược lại: là **lễ tân đứng trước văn phòng**, tiếp tất cả khách rồi mới chuyển vào đúng người bên trong. Khách không bao giờ thấy "phòng làm việc thật" (máy chủ thật) nằm ở đâu.
- **Vì sao cần?** Reverse proxy là **chỗ lý tưởng để gắn WAF**, để cân bằng tải, và để giấu máy chủ thật khỏi con mắt kẻ tấn công — giảm bớt thứ mà chúng có thể nhắm vào.

### Zeek — nói đơn giản

- **Zeek là gì?** Là một **người ghi nhật ký mạng cực kỳ tỉ mỉ**. Khác với Snort/Suricata chỉ hô "có khớp dấu hiệu xấu không", Zeek lặng lẽ ghi lại **"chuyện gì đã xảy ra trên mạng"**: ai nói chuyện với ai, lúc nào, bằng giao thức gì, kéo dài bao lâu.
- **Vì sao cần?** Vì khi điều tra một sự cố, bạn cần **cuốn nhật ký chi tiết** để lần lại dấu vết, kể cả với những kiểu tấn công mới chưa có "chữ ký". Snort/Suricata báo động nhanh, còn Zeek cho bạn câu chuyện đầy đủ để truy vết.

Nắm được mấy ý trên rồi thì phần dưới đây sẽ đi sâu vào chi tiết kỹ thuật.

> Chương này là tài liệu tham chiếu kỹ thuật cho kỹ sư Blue Team / AppSec / DevSecOps. Mục tiêu: đào tới mức field/byte/bước, kèm ví dụ thực tế chạy được cho từng công cụ. Các số liệu cấu trúc giao thức bám theo RFC tương ứng (IPv4 RFC 791, TCP RFC 9293, IPsec/ESP RFC 4303, IKEv2 RFC 7296, WireGuard whitepaper, OpenVPN protocol). Khi một con số phụ thuộc phiên bản/triển khai cụ thể, chương sẽ ghi rõ "cần kiểm chứng theo phiên bản".

---

## 11.1. Mô hình phòng thủ mạng và vị trí của IDS/IPS/WAF

### 11.1.1. Phòng thủ theo chiều sâu (defense-in-depth) và bản đồ tầng OSI

Mọi thiết bị phòng thủ đều hành động ở một (hoặc nhiều) tầng OSI. Hiểu chính xác thiết bị "đọc" được tới byte nào của gói tin là gốc rễ để biết nó chặn được gì và mù với cái gì.

| Tầng OSI | Đơn vị dữ liệu (PDU) | Thiết bị đọc tới | Quyết định dựa trên |
|---|---|---|---|
| L2 Data Link | Frame (Ethernet) | Switch, MACsec | MAC src/dst, VLAN tag 802.1Q |
| L3 Network | Packet (IP) | Router, firewall L3 (packet filter) | IP src/dst, protocol number |
| L4 Transport | Segment (TCP) / Datagram (UDP) | Stateful firewall (pfSense/pf), L4 LB | Port, TCP flags, trạng thái kết nối |
| L5-L7 App | Message (HTTP, DNS, TLS) | WAF (ModSecurity), L7 proxy, NGFW DPI | URI, header, body, chữ ký ứng dụng |

Điểm mấu chốt thiết kế (VÌ SAO): một firewall L3/L4 chỉ thấy `IP/port/flags` nên có thể cho phép `tcp dst port 443` nhưng hoàn toàn không biết trong luồng HTTPS đó có `UNION SELECT`. Đó là lý do WAF tồn tại — nó phải kết thúc TLS (TLS termination) để đọc plaintext HTTP. Ngược lại WAF không hiệu quả để chặn SYN flood vì việc đó nên dừng ở L3/L4 trước khi tốn tài nguyên giải mã TLS.

### 11.1.2. IDS vs IPS

| Tiêu chí | IDS (Detection) | IPS (Prevention) |
|---|---|---|
| Vai trò | Phát hiện + cảnh báo | Phát hiện + chặn |
| Vị trí mạng | Out-of-band (SPAN/TAP) | Inline (gói đi xuyên qua) |
| Tác động lên gói | Không (chỉ copy) | Có (drop/reset/modify) |
| Rủi ro khi sai | False negative = bỏ lọt | False positive = chặn nhầm traffic hợp lệ |
| Rủi ro khả dụng | Không ảnh hưởng đường truyền nếu IDS chết | Single point of failure; cần fail-open/fail-close |
| Độ trễ | 0 (song song) | Thêm latency xử lý mỗi gói |

VÌ SAO phân biệt quan trọng: IPS nằm trên đường dữ liệu, nên một rule kém (regex thảm hoạ, hay drop dựa trên anomaly) có thể gây mất dịch vụ. IDS an toàn hơn về khả dụng nhưng chỉ hữu ích khi có quy trình phản ứng (SOAR/SOC). Trong thực tế thường triển khai IDS trước (tuning rules ở chế độ alert), sau khi giảm false positive mới chuyển sang IPS (inline-block).

### 11.1.3. NIDS vs HIDS

- NIDS (Network IDS): đặt ở biên/lõi mạng, phân tích gói tin trên dây (Snort, Suricata, Zeek). Thấy toàn bộ traffic nhưng mù với traffic mã hoá nếu không có khoá.
- HIDS (Host IDS): chạy trên host, thấy syscall, file integrity, log, process (OSSEC/Wazuh, auditd, Sysmon, Falco). Thấy được hành vi sau giải mã (vd: lệnh shell), nhưng chỉ thấy host đó.

NIDS và HIDS bù trừ nhau: NIDS bắt lateral movement/scan; HIDS bắt persistence/privilege escalation. SIEM tổng hợp cả hai.

### 11.1.4. Lấy gói: inline vs SPAN vs TAP

```
SPAN (port mirroring):  Switch copy traffic của các port → 1 monitor port → NIDS
   Ưu: rẻ, cấu hình mềm.  Nhược: switch quá tải sẽ DROP bản copy trước (mất gói), không thấy lỗi tầng vật lý, copy có thể bỏ frame lỗi CRC.

TAP (Test Access Point): thiết bị phần cứng cắt vào dây, copy 100% bit (kể cả lỗi).
   Ưu: full-fidelity, fail-safe.  Nhược: tốn cổng (TX/RX tách 2 chiều cần aggregation), phải cắt dây.

INLINE (IPS): traffic đi XUYÊN qua thiết bị.  Drop được. Nhưng là điểm chết tiềm năng.
```

Lưu ý bảo mật: với traffic full-duplex 10G, một TAP tách RX/TX thành 2 luồng 10G; NIDS cần NIC nhận tổng 20G hoặc cần packet broker để aggregate. SPAN trên cùng switch có thể mất gói âm thầm khi tải cao → bỏ lọt tấn công mà không ai biết.

---

## 11.2. Snort & Suricata — NIDS/IPS dựa trên chữ ký

### 11.2.1. Kiến trúc xử lý gói

Cả Snort (2.x/3.x) và Suricata chia pipeline thành các giai đoạn:

```
[ Capture ] → [ Decode L2/L3/L4 ] → [ Preprocessors / App-layer parsers ]
   → [ Detection engine: so khớp rule ] → [ Output: alert/log/drop ]
```

- Decode: parse Ethernet → IP → TCP/UDP, dựng struct mô tả gói.
- Preprocessors (Snort) / app-layer (Suricata): tái lắp luồng TCP (stream reassembly), chống evasion bằng phân mảnh IP (frag3), chuẩn hoá HTTP (http_inspect), giải mã, theo dõi trạng thái flow.
- Detection engine: dùng thuật toán đa mẫu (Aho-Corasick) để so `content` của hàng nghìn rule song song, rồi mới chạy `pcre` đắt đỏ trên các rule đã lọt qua bước content nhanh.

VÌ SAO đặt `content` trước `pcre`: regex tốn CPU; engine dùng `content` (so chuỗi cố định bằng Aho-Corasick O(n)) làm "fast pattern" để loại nhanh đa số gói, chỉ những gói chứa chuỗi đó mới chịu chi phí regex. Đây là lý do mọi rule tốt nên có ít nhất một `content` để có fast pattern.

Khác biệt then chốt: Suricata đa luồng (multi-thread) bản thiết kế, hỗ trợ tương thích phần lớn cú pháp rule Snort, có thêm `app-layer` keywords (http.uri, tls.sni, dns.query) và xuất EVE JSON. Snort 3 cũng đã viết lại đa luồng. Cú pháp rule dưới đây tương thích cả hai trừ khi ghi chú.

### 11.2.2. Cấu trúc một rule — phân rã từng phần

Một rule gồm RULE HEADER + RULE OPTIONS (trong ngoặc đơn).

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 ( msg:"..."; content:"..."; sid:1000001; rev:1; )
└─┬─┘ └┬┘ └─────┬──────┘└┬┘ └┬┘ └──┬───┘ └┬┘  └────────────── OPTIONS ──────────────┘
action proto   src_ip  sp dir dst_ip dp
```

#### Rule Header — từng trường

| Trường | Giá trị hợp lệ | Ý nghĩa | Ví dụ |
|---|---|---|---|
| action | alert, log, pass, drop, reject, sdrop | Hành động khi khớp | `alert` (log+cảnh báo), `drop` (chặn, chỉ IPS inline) |
| protocol | tcp, udp, icmp, ip (Suricata thêm: http, tls, dns, ssh...) | Giao thức | `tcp` |
| src_ip | IP/CIDR, biến `$HOME_NET`, list `[a,b]`, phủ định `!` | Nguồn | `$EXTERNAL_NET`, `![10.0.0.0/8]` |
| src_port | số, dải `1:1024`, `any`, `!80`, `[80,443]` | Cổng nguồn | `any` |
| direction | `->` một chiều, `<>` hai chiều | Hướng | `->` |
| dst_ip | như src_ip | Đích | `$HOME_NET` |
| dst_port | như src_port | Cổng đích | `80` |

Ý nghĩa action chi tiết:
- `alert`: tạo cảnh báo và log gói.
- `log`: chỉ log, không cảnh báo.
- `pass`: bỏ qua gói (whitelist), dừng đánh giá thêm.
- `drop` (inline): chặn gói + log. Không gửi gì cho client.
- `reject`: chặn + gửi TCP RST (hoặc ICMP unreachable cho UDP) để đóng kết nối ngay.
- `sdrop`: silent drop, chặn mà không log.

Biến `$HOME_NET`, `$EXTERNAL_NET` định nghĩa trong `snort.conf`/`suricata.yaml`:
```
ipvar HOME_NET [10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]
ipvar EXTERNAL_NET !$HOME_NET
portvar HTTP_PORTS [80,81,8080,8000]
```

#### Rule Options — bảng tham chiếu đầy đủ

| Option | Loại | Ý nghĩa | Ví dụ |
|---|---|---|---|
| `msg` | metadata | Chuỗi mô tả ghi vào alert | `msg:"SQLi UNION SELECT";` |
| `content` | payload | So khớp chuỗi byte (text hoặc hex `\|41 42\|`) | `content:"UNION";` |
| `nocase` | modifier | content không phân biệt hoa thường | `content:"union"; nocase;` |
| `offset` | modifier | Bắt đầu tìm content từ byte thứ N (0-based) | `offset:4;` |
| `depth` | modifier | Chỉ tìm trong N byte đầu (kể từ offset) | `depth:20;` |
| `distance` | modifier | Khoảng cách tối thiểu sau content trước đó | `distance:0;` |
| `within` | modifier | content kế tiếp phải nằm trong N byte sau content trước | `within:10;` |
| `pcre` | payload | Perl-compatible regex | `pcre:"/union\s+select/i";` |
| `flow` | state | Chiều/trạng thái luồng | `flow:established,to_server;` |
| `flowbits` | state | Đặt/kiểm cờ trên luồng (correlate đa gói) | `flowbits:set,logged_in;` |
| `threshold`/`detection_filter` | rate | Giới hạn tần suất alert | `detection_filter:track by_src, count 5, seconds 60;` |
| `sid` | metadata | Signature ID (duy nhất; >1.000.000 cho local) | `sid:1000001;` |
| `rev` | metadata | Số revision của rule | `rev:1;` |
| `classtype` | metadata | Phân loại (ánh xạ priority) | `classtype:web-application-attack;` |
| `reference` | metadata | Liên kết CVE/URL | `reference:cve,2021-44228;` |
| `priority` | metadata | Ưu tiên thủ công (1 cao nhất) | `priority:1;` |
| `http_uri`/`http.uri` | sticky buffer | Giới hạn content vào URI đã chuẩn hoá | `http.uri; content:"/admin";` |
| `dsize` | payload | Kích thước payload | `dsize:>100;` |
| `byte_test`/`byte_jump` | payload | So sánh/nhảy theo giá trị byte | `byte_test:2,>,1000,0;` |

Giải thích `offset`/`depth` và `distance`/`within` (rất hay nhầm):
- `offset`/`depth` đo TUYỆT ĐỐI từ đầu payload. `offset:4; depth:20;` = tìm trong byte 4..23.
- `distance`/`within` đo TƯƠNG ĐỐI so với cuối match của content liền trước. Dùng để khớp nhiều mẩu gần nhau mà không cần biết vị trí tuyệt đối.

VÌ SAO có cả hai: payload thực tế có phần header độ dài cố định (dùng offset/depth) và phần biến thiên cần khớp tương đối (dùng distance/within). Giới hạn vùng tìm cũng giảm false positive và tăng tốc.

### 11.2.3. Ví dụ rule thật — giải thích từng tham số

Phát hiện SQLi `UNION SELECT` trong HTTP request:
```
alert http $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"WEB SQLi UNION SELECT in URI";
    flow:established,to_server;
    http.uri;
    content:"union"; nocase;
    content:"select"; nocase; distance:0; within:100;
    pcre:"/union\s+(all\s+)?select/i";
    classtype:web-application-attack;
    reference:url,owasp.org/sqli;
    sid:1000001; rev:2;
)
```
- `flow:established,to_server`: chỉ xét gói trong kết nối TCP đã bắt tay xong, hướng client→server. Tránh khớp trên gói đơn lẻ giả mạo và giảm tải.
- `http.uri` (sticky buffer): giới hạn các `content`/`pcre` sau nó vào URI ĐÃ CHUẨN HOÁ (decode `%55` → `U`). Đây là chống evasion: kẻ tấn công gửi `%75nion` để né content thô, nhưng buffer chuẩn hoá đã decode.
- `content:"union"; nocase`: fast pattern. `content:"select"; distance:0; within:100`: "select" phải xuất hiện sau "union", trong vòng 100 byte.
- `pcre`: tinh lọc để giảm false positive (yêu cầu khoảng trắng giữa, cho phép `union all select`).

Phát hiện nmap SYN scan (nhiều SYN tới nhiều cổng trong thời gian ngắn):
```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"SCAN nmap SYN scan";
    flags:S;
    detection_filter:track by_src, count 20, seconds 5;
    classtype:attempted-recon;
    sid:1000010; rev:1;
)
```
- `flags:S`: chỉ gói có CỜ SYN bật (xem mục TCP flags 11.2.5).
- `detection_filter:track by_src, count 20, seconds 5`: chỉ alert khi cùng một src tạo ≥20 lần khớp trong 5 giây — đặc trưng scan, không alert cho 1 SYN bình thường.

Phát hiện C2 beacon qua User-Agent đáng ngờ:
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE Suspicious User-Agent C2 beacon";
    flow:established,to_server;
    http.user_agent; content:"Mozilla/5.0 (compatible; MSIE 9.0";
    http.uri; content:"/submit.php"; nocase;
    detection_filter:track by_src, count 3, seconds 30;
    classtype:trojan-activity;
    reference:url,attack.mitre.org/techniques/T1071/001;
    sid:1000020; rev:1;
)
```
Lưu ý: rule dựa vào artefact mặc định; threat actor đổi profile dễ dàng → đây là minh hoạ cơ chế, không phải chữ ký bền vững.

Dùng `flowbits` để tương quan đa gói (chỉ alert exfil sau khi đã thấy đăng nhập):
```
alert http any any -> any any ( msg:"login seen"; http.uri; content:"/login"; flowbits:set,auth; flowbits:noalert; sid:1000030; )
alert http any any -> any any ( msg:"download after login"; http.uri; content:"/export?all=1"; flowbits:isset,auth; sid:1000031; )
```
- `flowbits:set,auth` gắn cờ lên flow; `flowbits:noalert` để rule đầu không tự cảnh báo. Rule sau chỉ khớp khi `auth` đã set.

### 11.2.4. Signature vs Anomaly detection

| | Signature-based | Anomaly-based |
|---|---|---|
| Nguyên lý | So với mẫu đã biết (rule/IOC) | Xây baseline "bình thường", báo lệch chuẩn |
| Bắt 0-day | Kém (chưa có chữ ký) | Tốt hơn (nếu hành vi lệch) |
| False positive | Thấp (nếu rule chuẩn) | Cao (baseline khó đúng) |
| Ví dụ công cụ | Snort/Suricata rule | thống kê, ML, một số preprocessor |

Snort/Suricata chủ yếu signature-based, nhưng preprocessors có yếu tố anomaly (vd: cảnh báo gói TCP có flag bất hợp lệ, header dị thường).

### 11.2.5. TCP flags — cần cho rule `flags:`

TCP flags nằm trong 1 byte (offset 13 của TCP header), 6 bit thấp (+2 bit ECN/NS):

| Bit | Cờ | Ý nghĩa |
|---|---|---|
| 0x01 | FIN | Kết thúc |
| 0x02 | SYN | Mở kết nối |
| 0x04 | RST | Reset |
| 0x08 | PSH | Push buffer |
| 0x10 | ACK | Xác nhận |
| 0x20 | URG | Khẩn |

Cú pháp `flags`: `flags:S` (chỉ SYN), `flags:SA` (SYN+ACK), `flags:S,12` (SYN bật, bỏ qua bit 1&2 = CWR/ECE khi so), `flags:!R` (không RST). NULL scan = `flags:0`; XMAS = `flags:FPU`.

### 11.2.6. Cài đặt, chạy, và TEST trigger rule

```bash
# Suricata: kiểm tra cấu hình và rule
suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules

# Chạy IDS đọc từ interface eth0
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Phân tích offline một file pcap (rất hợp để test rule)
suricata -r capture.pcap -S local.rules -l ./out/
cat ./out/fast.log         # alert dạng text
jq . ./out/eve.json | less # alert JSON đầy đủ

# Snort 3 test rule trên pcap
snort -c /etc/snort/snort.lua -R local.rules -r capture.pcap -A alert_fast
```

TEST trigger rule SQLi ở trên bằng curl (chỉ trong lab):
```bash
curl "http://victim.lab/search?q=1%20union%20select%20password%20from%20users"
# → fast.log:
# 06/19/2026-10:00:00.123456  [**] [1:1000001:2] WEB SQLi UNION SELECT in URI [**]
#   [Classification: Web Application Attack] [Priority: 1] {TCP} 203.0.113.5:51234 -> 10.0.0.10:80
```
Test scan rule:
```bash
nmap -sS -p1-1000 10.0.0.10    # tạo nhiều SYN → trigger sid:1000010
```

Lưu ý bảo mật/vận hành: luôn test rule trên pcap trước khi đẩy lên IPS inline. Một `pcre` không neo (không có `content` fast pattern) chạy trên mọi gói có thể gây CPU 100% → DoS chính hệ thống phòng thủ (ReDoS). Đặt `sid` local ≥ 1.000.000 để không đụng rule cộng đồng (ET/Talos).

---

## 11.3. ModSecurity + OWASP CRS — WAF tầng 7

### 11.3.1. WAF là gì và VÌ SAO khác firewall L3/L4

WAF (Web Application Firewall) hoạt động ở L7: nó parse HTTP request (method, URI, headers, body, cookies, params) sau khi TLS đã được kết thúc, rồi áp luật lên NỘI DUNG ứng dụng.

| | Firewall L3/L4 (pf, iptables) | WAF L7 (ModSecurity) |
|---|---|---|
| Đọc tới | IP/port/flags | URI, header, body, JSON, multipart |
| Chặn được | Port 22 từ internet | `' OR 1=1--` trong tham số `id` |
| TLS | Không cần | Phải termination để đọc plaintext |
| Hiểu ngữ cảnh ứng dụng | Không | Có (per-param, per-route) |

ModSecurity là một engine rule chạy như module embedded (Apache `mod_security2`, NGINX `ModSecurity-nginx` connector) hoặc reverse proxy. OWASP CRS (Core Rule Set) là bộ rule chuẩn chạy trên engine đó.

### 11.3.2. Năm phase xử lý của ModSecurity

ModSecurity gắn rule vào 5 phase theo vòng đời transaction HTTP:

| Phase | Tên | Khi nào | Dữ liệu sẵn có | Dùng để |
|---|---|---|---|---|
| 1 | Request Headers | Sau khi nhận headers | method, URI, headers, cookies | chặn sớm dựa header/URI |
| 2 | Request Body | Sau khi nhận body | ARGS (POST), JSON, multipart | chặn SQLi/XSS trong body |
| 3 | Response Headers | Trước khi gửi resp headers | status, resp headers | che server banner, kiểm leak |
| 4 | Response Body | Trước khi gửi resp body | nội dung response | data leak, ẩn lỗi SQL |
| 5 | Logging | Khi ghi log | toàn bộ | quyết định ghi audit log |

VÌ SAO tách phase: body có thể rất lớn; chặn ở phase 1 (chỉ header) rẻ hơn nhiều. Phase 4 cho phép phát hiện dữ liệu nhạy cảm rò ra (vd thông báo lỗi MySQL lộ schema).

### 11.3.3. Directive SecRule — phân rã cú pháp

```
SecRule VARIABLES "OPERATOR" "ACTIONS"
```
Ví dụ:
```
SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,log,msg:'SQLi detected',t:none,t:urlDecodeUni,t:lowercase"
```

Thành phần:

| Phần | Vai trò | Ví dụ giá trị |
|---|---|---|
| VARIABLES | Nguồn dữ liệu để kiểm | `ARGS`, `ARGS:id`, `REQUEST_URI`, `REQUEST_HEADERS:User-Agent`, `REQUEST_BODY`, `XML`, `FILES` |
| OPERATOR | Phép kiểm | `@rx <regex>`, `@detectSQLi`, `@detectXSS`, `@contains`, `@eq`, `@ipMatch`, `@pmFromFile` |
| ACTIONS | Hành động + metadata | `id`, `phase`, `deny/pass/block/drop`, `status`, `log/nolog`, `msg`, `t:` (transform), `setvar`, `ctl`, `chain` |

Các biến hay dùng:
- `ARGS` = tất cả tham số (GET+POST). `ARGS:id` = chỉ tham số `id`. `ARGS_NAMES` = tên tham số.
- `REQUEST_URI` = đường dẫn + query (raw). `REQUEST_FILENAME` = chỉ path.
- `REQUEST_HEADERS`, `REQUEST_HEADERS:Host`.
- `REQUEST_BODY`, `XML:/*`, `FILES`, `FILES_TMPNAMES`.

Operators chính:
- `@rx`: regex (PCRE). `@detectSQLi`: dùng libinjection (tokenize SQL, ít false positive hơn regex thuần). `@detectXSS`: libinjection XSS. `@pmFromFile`: so khớp nhiều chuỗi từ file (Aho-Corasick, nhanh).

Transformations (`t:`) chuẩn hoá trước khi so — chống evasion:
- `t:none` (xoá transform kế thừa), `t:urlDecodeUni` (decode `%XX` và `%uXXXX`), `t:htmlEntityDecode`, `t:lowercase`, `t:removeNulls`, `t:compressWhitespace`, `t:cmdLine`.

VÌ SAO transform: kẻ tấn công gửi `%27` thay `'`, hay `SeLeCt`. Không chuẩn hoá thì regex né dễ. Thứ tự transform quan trọng (áp tuần tự).

Actions disruptive (chỉ MỘT trên mỗi rule chain): `deny`, `drop`, `block`, `pass`, `allow`, `redirect`. `block` ủy quyền quyết định cho `SecDefaultAction`.

`chain` nối nhiều SecRule thành điều kiện AND:
```
SecRule REQUEST_METHOD "@streq POST" "id:1002,phase:2,deny,status:403,chain"
    SecRule REQUEST_HEADERS:Content-Type "!@rx ^application/json" "t:lowercase"
```
→ chặn POST mà Content-Type không phải JSON.

### 11.3.4. DetectionOnly vs On, và file cấu hình thật

`modsecurity.conf` (trích, có giải thích):
```apache
# DetectionOnly = chỉ log, KHÔNG chặn (giai đoạn tuning).  On = thực thi chặn.
SecRuleEngine DetectionOnly

# Bật đọc request body để phase 2 có ARGS POST
SecRequestBodyAccess On
SecRequestBodyLimit 13107200          # 12.5MB; vượt → SecRequestBodyLimitAction
SecRequestBodyLimitAction Reject

# Đọc response body (phase 4) chỉ với vài content-type để khỏi tốn RAM
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json

# Hành động mặc định khi rule dùng "block"
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# Audit log: ghi chi tiết transaction bị đánh dấu
SecAuditEngine RelevantOnly           # chỉ ghi khi có rule khớp / lỗi
SecAuditLogParts ABIJDEFHZ            # A=audit header, B=req headers, C=req body, F=resp headers...
SecAuditLog /var/log/modsec_audit.log
```

Quy trình triển khai an toàn (VÌ SAO): bật `DetectionOnly` vài ngày, đọc `modsec_audit.log` để tìm rule chặn nhầm traffic hợp lệ → tạo exclusion → mới chuyển `SecRuleEngine On`. Chuyển thẳng sang On dễ gây outage do CRS false positive.

### 11.3.5. OWASP CRS — anomaly scoring & paranoia level

CRS không chặn ngay khi một rule khớp. Nó CỘNG ĐIỂM (anomaly scoring):

```
Mỗi rule khớp → cộng điểm theo severity:
   CRITICAL = 5, ERROR = 4, WARNING = 3, NOTICE = 2 (cần kiểm chứng theo version CRS)
Cuối cùng: nếu tx.anomaly_score >= tx.inbound_anomaly_score_threshold (mặc định 5) → deny
```

VÌ SAO scoring thay vì block-on-first-match: giảm false positive. Một tín hiệu yếu (vd có ký tự `'`) không đủ chặn; nhiều tín hiệu cộng dồn mới vượt ngưỡng. Quản trị viên hạ ngưỡng để chặt hơn, nâng để nới.

Paranoia Level (PL1–PL4): mức "đa nghi".
- PL1 (mặc định): rule chắc chắn, ít false positive.
- PL2–PL4: thêm rule ngày càng nhạy (bắt nhiều biến thể hơn) nhưng false positive tăng mạnh.

`crs-setup.conf`:
```apache
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=1"
SecAction "id:900110,phase:1,nolog,pass,t:none,\
   setvar:tx.inbound_anomaly_score_threshold=5,\
   setvar:tx.outbound_anomaly_score_threshold=4"
```

Ví dụ rule CRS chặn SQLi (minh hoạ cơ chế scoring):
```apache
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES "@detectSQLi" \
    "id:942100,phase:2,block,capture,t:none,t:urlDecodeUni,\
     msg:'SQL Injection Attack Detected via libinjection',\
     logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\
     severity:'CRITICAL',\
     setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
     setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```
- `block`: tuân theo SecDefaultAction (cộng điểm hoặc chặn).
- `capture` + `%{TX.0}`: lưu phần khớp để log (forensics).
- `setvar:tx.anomaly_score_pl1=+...`: cộng điểm; rule "blocking evaluation" cuối cùng so tổng với ngưỡng.

Tạo exclusion (gỡ false positive cho một route):
```apache
SecRule REQUEST_URI "@beginsWith /api/free-text-comment" \
    "id:1000100,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:comment"
```
→ với route đó, không áp rule 942100 lên `ARGS:comment`.

### 11.3.6. Ví dụ chặn SQLi end-to-end và output

```bash
# Request tấn công
curl "http://app.lab/product?id=1' OR '1'='1"
# Phản hồi khi SecRuleEngine On và vượt ngưỡng:
# HTTP/1.1 403 Forbidden
```
Trích `modsec_audit.log`:
```
--a1b2c3-H--
Message: Access denied with code 403 (phase 2). detected SQLi via libinjection.
   [id "942100"] [msg "SQL Injection Attack Detected via libinjection"]
   [data "Matched Data: 1' OR '1'='1 found within ARGS:id"] [severity "CRITICAL"]
Action: Intercepted (phase 2)
Apache-Error: ModSecurity: Access denied with code 403
```

Lưu ý bảo mật: WAF là lớp bù (compensating control), KHÔNG thay thế sửa code (prepared statements, output encoding). WAF bypass khả thi (encoding lạ, HTTP parameter pollution, smuggling). Luôn dùng anomaly scoring + tuning theo ứng dụng cụ thể; bật response-body inspection để chống data leak nhưng cân nhắc chi phí RAM/latency.

---

## 11.4. pfSense — firewall/router (pf, NAT, state, VPN)

pfSense dựa trên FreeBSD + `pf` (Packet Filter). Hiểu pf là hiểu pfSense.

### 11.4.1. Stateful firewall và state table — cơ chế

pf là STATEFUL: khi một gói khớp rule có `keep state` (mặc định trên pfSense), pf tạo một entry trong STATE TABLE. Gói trả về (reply) được khớp với state table trước cả ruleset → không cần rule ngược.

```
Client 192.168.1.10:51000 ──SYN──► Server 203.0.113.9:443
   pf: rule "pass out" khớp → tạo state:
   proto tcp, 192.168.1.10:51000 ↔ 203.0.113.9:443, state SYN_SENT
Server ──SYN/ACK──► Client
   pf: tra state table → MATCH → cho qua, state → ESTABLISHED
```

State table entry (khái niệm các trường):

| Trường | Ý nghĩa |
|---|---|
| proto | tcp/udp/icmp |
| src host:port | địa chỉ/cổng nguồn (sau NAT lưu cả original) |
| dst host:port | đích |
| direction | chiều tạo state |
| state | TCP: SYN_SENT, ESTABLISHED, FIN_WAIT...; UDP: SINGLE/MULTIPLE |
| expire | timeout còn lại |
| packets/bytes | đếm cho mỗi chiều |

VÌ SAO stateful tốt hơn stateless: stateless cần rule cho cả hai chiều và dễ bị giả mạo gói ACK lọt qua. Stateful theo dõi cả chuỗi handshake; chỉ gói khớp với một kết nối hợp lệ mới qua. Xem state: `pfctl -ss`. Đếm: `pfctl -si`.

### 11.4.2. Rule firewall trên pfSense — các trường

Mỗi rule trên một interface có:

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| Action | Pass / Block (im lặng drop) / Reject (gửi RST/ICMP) | Pass |
| Interface | NIC áp rule (WAN, LAN, OPT1/VLAN) | LAN |
| Direction | in / out (mặc định in trên pfSense GUI) | in |
| Address Family | IPv4 / IPv6 | IPv4 |
| Protocol | TCP/UDP/ICMP/... | TCP |
| Source | host/net/alias/`any`, có thể `!` | LAN net |
| Source port | thường `any` cho client | any |
| Destination | host/net/alias | any |
| Dest port | cổng dịch vụ | 443 |
| Gateway | định tuyến policy-based | default |
| State type | keep state / sloppy / none | keep state |

Thứ tự đánh giá pf: pf gốc dùng "LAST MATCH WINS" trừ khi có `quick`. pfSense GUI thêm `quick` nên rule khớp ĐẦU TIÊN (từ trên xuống) quyết định. Block mặc định: pfSense có default-deny inbound trên WAN.

Block vs Reject (VÌ SAO chọn): Block = drop âm thầm → kẻ scan phải chờ timeout (làm chậm họ). Reject = trả RST → đóng nhanh (tốt cho UX nội bộ) nhưng giúp attacker map cổng nhanh hơn. Quy tắc: Reject trong LAN, Block ngoài WAN.

### 11.4.3. Alias

Alias = nhóm có tên (hosts/networks/ports/URLs) để tái sử dụng và gom rule.
```
Alias  WebServers     = 10.0.0.10, 10.0.0.11
Alias  AdminPorts     = 22, 3389, 8443
Rule:  Pass LAN → WebServers proto TCP dst AdminPorts  (source: AdminPCs)
```
VÌ SAO: 1 rule thay vì N×M rule; cập nhật một alias áp dụng mọi rule. Alias URL (pfBlockerNG) có thể nạp danh sách IP độc hại tự động.

### 11.4.4. NAT — port forward và outbound

Port Forward (DNAT — inbound):
```
WAN  TCP  any:any  →  203.0.113.9:443   (NAT: redirect tới 10.0.0.10:443)
   + Firewall rule kèm theo: Pass WAN proto TCP dst 10.0.0.10:443
```
- pf viết lại địa chỉ ĐÍCH gói đến từ IP công khai sang IP nội bộ. pfSense tự sinh rule firewall đi kèm (tùy chọn "Associated filter rule").

Outbound NAT (SNAT/masquerade): pfSense mặc định "Automatic outbound NAT" — viết lại IP NGUỒN của traffic LAN→WAN thành IP WAN.
```
192.168.1.10:51000  ──►  (SNAT)  203.0.113.1:51000  ──►  internet
   pf lưu mapping trong state để dịch ngược reply.
```
1:1 NAT: ánh xạ trọn một IP công khai ↔ một IP nội bộ (cả in và out).

VÌ SAO NAT + state gắn nhau: để dịch ngược gói trả về, pf phải nhớ mapping (port gốc ↔ port dịch) trong state table. Đây cũng là lý do PAT (port address translation) cần theo dõi cổng nguồn.

### 11.4.5. VLAN

VLAN 802.1Q chèn tag 4 byte vào Ethernet frame (cấu trúc):

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|---|---|---|---|
| TPID | 16 bit | Tag Protocol ID = 0x8100 | 0x8100 |
| PCP | 3 bit | Priority (QoS 802.1p) | 0 |
| DEI | 1 bit | Drop Eligible Indicator | 0 |
| VID | 12 bit | VLAN ID (1–4094) | 20 |

pfSense tạo interface VLAN trên một NIC vật lý (router-on-a-stick): mỗi VLAN = một subnet/interface với ruleset riêng → phân đoạn mạng (segmentation) chống lateral movement. VÌ SAO 12 bit VID → tối đa 4094 VLAN khả dụng (0 và 4095 dành riêng).

---

## 11.5. VPN — IPsec, OpenVPN, WireGuard (cực sâu)

VPN tạo "đường hầm" mã hoá: gói gốc được bọc trong gói mới có xác thực + mã hoá. Khác biệt cốt lõi giữa ba công nghệ nằm ở: cách trao khoá, cấu trúc gói bọc, và độ phức tạp.

### 11.5.1. IPsec — kiến trúc

IPsec gồm: giao thức bảo vệ dữ liệu (AH hoặc ESP) + giao thức trao khoá (IKE). Mọi liên kết bảo vệ định nghĩa bằng SA (Security Association).

#### SA (Security Association)
Một SA là quan hệ một chiều mô tả: thuật toán, khoá, SPI, lifetime. Hai chiều = 2 SA. Mỗi SA định danh bởi tuple:
```
SA = ( SPI, IP đích, giao thức[AH/ESP] )
```
- SPI (Security Parameters Index): 32 bit, chỉ mục để bên nhận tra đúng SA/khoá giải mã.

#### AH vs ESP

| | AH (Protocol 51) | ESP (Protocol 50) |
|---|---|---|
| Bảo mật (mã hoá) | KHÔNG | CÓ |
| Toàn vẹn + xác thực | CÓ (kể cả phần IP header bất biến) | CÓ (chỉ payload ESP, không gồm IP header ngoài) |
| Tương thích NAT | KÉM (hash gồm IP header → NAT làm hỏng) | TỐT (với NAT-T, đóng gói UDP 4500) |
| Dùng thực tế | Hiếm | Phổ biến (gần như luôn dùng ESP) |

VÌ SAO ESP thắng: AH xác thực cả IP header ngoài → NAT đổi IP làm sai ICV → gãy. ESP chỉ bảo vệ payload, và NAT-T bọc thêm UDP/4500 nên xuyên NAT được. Hầu hết VPN dùng ESP với mã hoá + xác thực (AES-GCM gộp cả hai).

#### Tunnel vs Transport mode

```
Gói gốc:           [ IP_orig | TCP | Data ]

TRANSPORT mode (ESP):  [ IP_orig | ESP_hdr | TCP | Data | ESP_trailer | ESP_ICV ]
   → bảo vệ payload, GIỮ IP header gốc. Dùng host-to-host.

TUNNEL mode (ESP):     [ IP_new | ESP_hdr | IP_orig | TCP | Data | ESP_trailer | ESP_ICV ]
   → bọc TOÀN BỘ gói gốc trong gói IP mới. Dùng gateway-to-gateway (site-to-site).
```
VÌ SAO tunnel cho site-to-site: hai gateway có IP công khai; IP nội bộ gốc được giấu trong payload mã hoá → ẩn topology nội bộ và định tuyến qua internet bằng IP gateway.

#### Cấu trúc ESP header/trailer — từng trường (RFC 4303)

| Trường | Kích thước | Ý nghĩa | Vị trí |
|---|---|---|---|
| SPI | 32 bit (4 byte) | Chỉ SA để giải mã | Đầu ESP |
| Sequence Number | 32 bit (4 byte) | Chống replay (tăng dần) | Sau SPI |
| Payload Data | thay đổi | Dữ liệu mã hoá (gói gốc trong tunnel mode) | Giữa |
| Padding | 0–255 byte | Căn block cipher + ẩn độ dài | Trong trailer |
| Pad Length | 8 bit (1 byte) | Số byte padding | Trailer |
| Next Header | 8 bit (1 byte) | Loại payload (4=IP, 6=TCP) | Trailer |
| ICV | thay đổi (vd 16 byte với AES-GCM) | Integrity Check Value (xác thực) | Cuối cùng |

Sequence Number + cửa sổ chống replay (anti-replay window, mặc định 64 gói): bên nhận từ chối gói có seq đã thấy hoặc quá cũ → chống phát lại.

#### IKEv2 — trao khoá (RFC 7296)

IKEv2 chạy trên UDP/500 (hoặc UDP/4500 khi NAT-T). Thiết lập gồm 2 cặp message ban đầu:

```
Phase 1 (IKE_SA_INIT):  thoả thuận crypto + Diffie-Hellman
   Init → Resp:  HDR, SAi1 (đề xuất thuật toán), KEi (DH public), Ni (nonce)
   Resp → Init:  HDR, SAr1 (chọn thuật toán), KEr (DH public), Nr (nonce)
   → cả hai tính SKEYSEED từ DH shared secret + nonce → dẫn xuất khoá.

Phase 2 (IKE_AUTH):  xác thực danh tính + tạo CHILD_SA (cho ESP)
   Init → Resp:  HDR, [IDi], [AUTH], SAi2, TSi, TSr   (mã hoá bằng khoá IKE)
   Resp → Init:  HDR, [IDr], [AUTH], SAr2, TSi, TSr
   → AUTH = chữ ký/PSK chứng minh danh tính; TS = traffic selector (subnet được bảo vệ).
```

So với IKEv1: IKEv1 có Phase 1 (Main mode 6 message / Aggressive 3 message) rồi Phase 2 (Quick mode 3 message). IKEv2 gọn hơn (4 message thiết lập), hỗ trợ MOBIKE, NAT-T tích hợp, EAP. Thuật ngữ "phase 1/phase 2" vẫn dùng: phase 1 = IKE SA (bảo vệ kênh điều khiển), phase 2 = CHILD SA = ESP SA (bảo vệ dữ liệu).

Header IKE (các trường chính):

| Trường | Kích thước | Ý nghĩa |
|---|---|---|
| Initiator SPI | 64 bit | Định danh phía khởi tạo |
| Responder SPI | 64 bit | Định danh phía đáp |
| Next Payload | 8 bit | Loại payload kế |
| Version | 8 bit | Major/Minor (2.0) |
| Exchange Type | 8 bit | IKE_SA_INIT(34), IKE_AUTH(35)... |
| Flags | 8 bit | Initiator/Response/Version |
| Message ID | 32 bit | Chống replay, sắp thứ tự |
| Length | 32 bit | Độ dài tổng |

Ví dụ cấu hình IPsec site-to-site bằng strongSwan (`/etc/swanctl/swanctl.conf`):
```
connections {
   site-a-to-b {
      version = 2                       # IKEv2
      local_addrs  = 203.0.113.1
      remote_addrs = 198.51.100.1
      proposals = aes256gcm16-prfsha384-ecp384   # phase1 crypto
      local  { auth = psk; id = 203.0.113.1 }
      remote { auth = psk; id = 198.51.100.1 }
      children {
         net-net {
            local_ts  = 10.10.0.0/16    # subnet nội bộ A (TS)
            remote_ts = 10.20.0.0/16    # subnet nội bộ B
            esp_proposals = aes256gcm16  # phase2/ESP crypto, AEAD gộp mã hoá+xác thực
            mode = tunnel
            start_action = trap          # tự lập SA khi có traffic khớp TS
         }
      }
   }
}
secrets { ike-psk { id = 203.0.113.1; secret = "S3cretPSK!" } }
```
```bash
swanctl --load-all
swanctl --initiate --child net-net
swanctl --list-sas         # xem SA đã thiết lập, SPI, thuật toán, byte count
```
Lưu ý bảo mật: PSK yếu là điểm gãy (IKEv1 Aggressive mode lộ hash PSK cho offline crack). Ưu tiên chứng thư số hoặc EAP, AEAD (AES-GCM), nhóm DH ≥ ecp256/Group 19. Bật PFS (Perfect Forward Secrecy) để mỗi CHILD_SA có DH riêng → lộ một khoá không lộ phiên cũ.

### 11.5.2. OpenVPN — VPN dựa TLS

OpenVPN chạy trong user-space, dùng TLS để trao khoá và một kênh dữ liệu riêng. Chạy trên UDP/1194 (mặc định) hoặc TCP/443 (xuyên firewall/proxy).

Kiến trúc kênh đôi:
- Control channel: TLS handshake (X.509 cert) → thoả thuận khoá phiên.
- Data channel: gói tin được mã hoá bằng khoá phiên (AES-GCM/CBC + HMAC), bọc trong UDP.

```
[ IP_outer | UDP(1194) | OpenVPN hdr | (opcode/key-id) | encrypted{ IP_inner | TCP | Data } ]
```
OpenVPN tạo interface ảo `tun` (L3, định tuyến IP) hoặc `tap` (L2, bridge Ethernet).

Cấu hình server (`server.conf`):
```
port 1194
proto udp
dev tun                         # L3 tunnel
ca   ca.crt
cert server.crt
key  server.key                 # giữ bí mật
dh   dh2048.pem
tls-auth ta.key 0               # HMAC trên control channel chống DoS/quét
cipher AES-256-GCM              # data channel AEAD
auth  SHA256
server 10.8.0.0 255.255.255.0   # cấp IP cho client trong subnet này
push "route 10.0.0.0 255.255.0.0"   # đẩy route mạng nội bộ
push "dhcp-option DNS 10.0.0.53"
keepalive 10 120                # ping mỗi 10s, restart sau 120s im lặng
persist-key
persist-tun
verb 3
```
Client (`client.ovpn`):
```
client
dev tun
proto udp
remote vpn.example.com 1194
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
cipher AES-256-GCM
remote-cert-tls server          # bắt buộc server cert có EKU server → chống MITM
verb 3
```
```bash
openvpn --config server.conf      # khởi động server
openvpn --config client.ovpn      # client kết nối
# Kiểm tra: ip addr show tun0 ; ping 10.8.0.1
```
VÌ SAO `tls-auth`/`tls-crypt`: thêm một lớp HMAC (hoặc mã hoá toàn bộ với tls-crypt) lên control channel → gói không có HMAC đúng bị drop trước cả khi xử lý TLS → chống port-scan, DoS, và làm khó nhận dạng dịch vụ. `remote-cert-tls server` chống client bị lừa nối tới server giả.

### 11.5.3. WireGuard — VPN hiện đại, Noise protocol

WireGuard tối giản (~4000 dòng kernel code), chạy trong kernel, dùng bộ crypto cố định (không thương lượng):
- Mã hoá AEAD: ChaCha20-Poly1305
- Trao khoá: Curve25519 ECDH
- Hash: BLAKE2s
- Khung handshake: Noise Protocol Framework (Noise_IK)

VÌ SAO không thương lượng thuật toán: loại bỏ "downgrade attack" và độ phức tạp của IKE. Muốn đổi thuật toán → nâng phiên bản giao thức, không thương lượng runtime.

#### Mô hình khoá
Mỗi peer có cặp khoá Curve25519 (private 32 byte, public 32 byte). "Cryptokey routing": mỗi peer khai báo `AllowedIPs` — danh sách IP mà peer đó được phép gửi/nhận. Public key ↔ AllowedIPs là toàn bộ "định tuyến + xác thực".

#### Handshake (Noise IK) — 2 message, 1-RTT
```
Initiator → Responder:  Handshake Initiation
   - chứa: ephemeral public, static public (đã mã hoá), timestamp (TAI64N, chống replay), MAC
Responder → Initiator:  Handshake Response
   - chứa: ephemeral public, empty (đã mã hoá), MAC
→ sau 2 message: cả hai có khoá phiên đối xứng. Khoá xoay sau ~2 phút (rekey).
```
Cấu trúc message handshake initiation (theo whitepaper — đối chiếu spec khi triển khai):

| Trường | Kích thước | Ý nghĩa |
|---|---|---|
| message type | 1 byte | =1 (initiation) |
| reserved | 3 byte | 0 |
| sender index | 4 byte | chỉ số phiên phía gửi |
| unencrypted ephemeral | 32 byte | ephemeral public key |
| encrypted static | 32+16 byte | static public + tag Poly1305 |
| encrypted timestamp | 12+16 byte | TAI64N + tag |
| mac1 | 16 byte | MAC dùng public key đích (chống gói rác) |
| mac2 | 16 byte | MAC dùng cookie (chống DoS khi quá tải) |

VÌ SAO mac1/mac2 + cookie: WireGuard "im lặng" — không phản hồi gói không hợp lệ (stealth, chống quét). mac1 chứng minh người gửi biết public key của đích (chống flood ngẫu nhiên). Khi bị tải, responder phát cookie; initiator phải tính mac2 đúng → chống DoS amplification.

#### Cấu hình thực tế
Server (`/etc/wireguard/wg0.conf`):
```ini
[Interface]
Address = 10.9.0.1/24
ListenPort = 51820
PrivateKey = <server_private_key>      # sinh: wg genkey
# (không khai PublicKey ở Interface; nó dẫn xuất từ private)

[Peer]                                  # client 1
PublicKey = <client1_public_key>
AllowedIPs = 10.9.0.2/32                # chỉ IP này được nhận từ peer
```
Client (`wg0.conf`):
```ini
[Interface]
Address = 10.9.0.2/24
PrivateKey = <client1_private_key>
DNS = 10.0.0.53

[Peer]
PublicKey = <server_public_key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0                  # full tunnel: route mọi traffic qua VPN
PersistentKeepalive = 25               # giữ NAT mapping (gửi keepalive 25s)
```
```bash
wg genkey | tee privatekey | wg pubkey > publickey   # sinh cặp khoá
wg-quick up wg0          # bật interface + route theo AllowedIPs
wg show                  # xem peer, last handshake, transfer bytes
wg-quick down wg0
```
VÌ SAO `PersistentKeepalive`: WireGuard không gửi gì khi rảnh → NAT/firewall ở giữa hết hạn mapping, server không gọi ngược client được. Keepalive 25s giữ "lỗ" NAT mở.

So sánh ba VPN:

| Tiêu chí | IPsec/IKEv2 | OpenVPN | WireGuard |
|---|---|---|---|
| Tầng/triển khai | Kernel (L3) | User-space (tun/tap) | Kernel (L3) |
| Trao khoá | IKEv2 (thương lượng) | TLS (X.509) | Noise IK (cố định) |
| Crypto agility | Cao (thương lượng) | Cao | Không (cố định, nâng version) |
| Cổng mặc định | UDP 500/4500 | UDP 1194 / TCP 443 | UDP 51820 |
| Xuyên firewall hạn chế | NAT-T | tốt (TCP/443 giả HTTPS) | UDP, có thể bị chặn |
| Codebase | lớn, phức tạp | trung bình | rất nhỏ (audit dễ) |
| Hiệu năng | cao (kernel) | thấp hơn (user-space) | cao nhất |
| Roaming (đổi IP) | MOBIKE | tái kết nối | liền mạch (theo public key) |

Lưu ý bảo mật chung: bảo vệ private key (quyền file 600), bật PFS/rekey, ghim danh tính peer (cert/public key), giám sát handshake bất thường. WireGuard lưu allowed-IPs là biên giới tin cậy — sai AllowedIPs = lỗ định tuyến/spoofing.

---

## 11.6. Proxy và Reverse proxy

| | Forward proxy | Reverse proxy |
|---|---|---|
| Đại diện cho | Client (ẩn client với server) | Server (ẩn server với client) |
| Vị trí | Cạnh client (egress) | Cạnh server (ingress) |
| Dùng để | Lọc nội dung, cache egress, ẩn danh, kiểm soát truy cập ra | TLS termination, load balancing, WAF, cache, ẩn backend |
| Ví dụ | Squid | NGINX, HAProxy, Envoy |

Reverse proxy là điểm gắn WAF lý tưởng: nó kết thúc TLS (đọc plaintext), rồi áp ModSecurity, rồi forward tới backend.

Ví dụ NGINX reverse proxy + ModSecurity:
```nginx
server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate     /etc/nginx/ssl/app.crt;
    ssl_certificate_key /etc/nginx/ssl/app.key;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;   # nạp CRS

    location / {
        proxy_pass http://10.0.0.10:8080;                 # backend nội bộ
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
VÌ SAO `X-Forwarded-For`: sau reverse proxy, backend thấy IP của proxy. Header này chuyển IP client thật để logging/rate-limit. Lưu ý bảo mật: backend chỉ được tin XFF khi đến từ proxy đáng tin (nếu không client tự đặt XFF giả → bypass IP allowlist/rate-limit). Reverse proxy cũng giúp giấu phiên bản backend (giảm bề mặt tấn công) và là nơi chống HTTP request smuggling khi chuẩn hoá nghiêm ngặt header `Content-Length`/`Transfer-Encoding`.

---

## 11.7. Zeek — phân tích lưu lượng dựa hành vi (network security monitor)

Zeek (trước là Bro) KHÁC Snort/Suricata: không chủ yếu khớp chữ ký, mà sinh LOG GIÀU NGỮ CẢNH cho mọi kết nối và sự kiện giao thức, dùng cho threat hunting và phát hiện bất thường. Nó chạy script trên các event (connection_established, dns_request, http_request).

Các log chính (TSV, một dòng/sự kiện):
- `conn.log`: mọi kết nối L3/L4.
- `dns.log`: truy vấn/đáp DNS.
- `http.log`: từng request/response HTTP.
- `ssl.log`/`x509.log`: handshake TLS, cert.
- `files.log`, `notice.log`, `weird.log`.

Trường tiêu biểu `conn.log`:

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| ts | timestamp | 1718780400.123 |
| uid | ID kết nối duy nhất (liên kết log) | CwjjYf3 |
| id.orig_h / id.orig_p | IP/port nguồn | 10.0.0.5 / 51234 |
| id.resp_h / id.resp_p | IP/port đích | 8.8.8.8 / 53 |
| proto | tcp/udp/icmp | udp |
| service | giao thức L7 nhận dạng | dns |
| duration | thời lượng | 0.034 |
| orig_bytes/resp_bytes | byte mỗi chiều | 31 / 75 |
| conn_state | trạng thái (S0, SF, REJ, RSTO...) | SF |

`uid` là chìa khoá: cùng `uid` xuất hiện trong `conn.log`, `dns.log`, `http.log` → pivot toàn bộ hoạt động của một kết nối.

Chạy Zeek offline trên pcap và truy vấn:
```bash
zeek -r capture.pcap                  # sinh conn.log, dns.log, http.log...
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | sort | uniq -c | sort -rn
# Tìm DNS exfil: truy vấn rất dài / nhiều subdomain ngẫu nhiên
zeek-cut query < dns.log | awk '{ if (length($1) > 50) print }'
```
Script Zeek phát hiện kết nối tới cổng lạ (ví dụ minh hoạ):
```zeek
event connection_established(c: connection) {
    if (c$id$resp_p == 4444/tcp)
        NOTICE([$note=Weird::Activity,
                $msg=fmt("Possible reverse shell to %s:%s", c$id$resp_h, c$id$resp_p),
                $conn=c]);
}
```
VÌ SAO Zeek bổ sung Suricata: Suricata trả lời "có khớp chữ ký không"; Zeek trả lời "chuyện gì đã xảy ra trên mạng" — cho phép săn mối đe doạ chưa có chữ ký (beaconing đều đặn, DNS tunneling, JA3 fingerprint TLS bất thường). Kết hợp: Suricata cho alert nhanh, Zeek cho ngữ cảnh điều tra, đẩy cả hai vào SIEM.

---

## 11.8. Tổng hợp kiến trúc phòng thủ và lưu ý vận hành

Bố trí điển hình một tổ chức:
```
Internet
  │
[ pfSense / NGFW ]  ── L3/L4 stateful filter, NAT, anti-DDoS, VPN termination (IPsec/WG/OVPN)
  │  (SPAN/TAP) ───────────────► [ Suricata IDS ]  +  [ Zeek ]  ──► SIEM
  │
[ Reverse proxy + ModSecurity/CRS ]  ── L7 WAF, TLS termination
  │
[ App servers ]  ── HIDS (Wazuh/auditd), prepared statements (gốc vẫn là code an toàn)
```

Nguyên tắc vận hành cốt lõi:
1. Tuning trước, enforce sau: IDS alert-only và WAF DetectionOnly trong giai đoạn baseline; đo false positive rồi mới inline/On.
2. Lớp đúng việc: chặn L3/L4 ở firewall (rẻ), L7 ở WAF; đừng dùng WAF chống flood hay firewall chống SQLi.
3. Defense-in-depth: WAF/IDS là compensating control; không thay thế code an toàn, patch, least-privilege.
4. Khả dụng của thiết bị phòng thủ: IPS/WAF inline là điểm chết tiềm năng — thiết kế fail-open/fail-close có chủ đích, HA, và giới hạn regex/ReDoS.
5. Mã hoá làm NIDS mù: cân nhắc TLS inspection ở reverse proxy (nơi đã có khoá) thay vì giải mã giữa đường.
6. Bảo vệ khoá VPN và danh tính peer: private key quyền 600, PFS/rekey, ghim cert/public key, giám sát handshake.
7. Tương quan đa nguồn: NIDS (Suricata) + NSM (Zeek) + HIDS (Wazuh) + WAF audit log → SIEM để thấy chuỗi tấn công đầy đủ thay vì cảnh báo rời rạc.
