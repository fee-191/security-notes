# Chương 11 — Phòng thủ mạng: IDS/IPS, WAF, Firewall & VPN

## Tổng quan

Thứ khiến mình để tâm tới mảng này là một chuyện rất tầm thường: đám scanner ngoài Internet không cần biết bạn là ai, cứ có cổng mở là chúng gõ cửa suốt ngày. Bảo vệ một mạng vì thế không phải là dựng một bức tường thật dày, mà là xếp nhiều lớp kiểm soát mà mỗi lớp "nhìn" được một phạm vi dữ liệu khác nhau — đó là **phòng thủ theo chiều sâu**: có thiết bị chỉ thấy địa chỉ và cổng ở L3/L4, có thiết bị đọc được cả nội dung HTTP ở L7, và không lớp nào bao phủ hết phần còn lại.

Chương đi theo đúng thứ tự các lớp đó. Ngoài cùng là **firewall** với **pfSense** (dựa trên `pf` của FreeBSD, stateful nên nhớ được kết nối đang mở, kiêm luôn phân đoạn VLAN và làm điểm cuối VPN) — lớp chặn rẻ nhất, loại bỏ thứ rõ ràng không hợp lệ trước khi nó đi sâu hơn. Sâu vào trong là **IDS/IPS**: cùng một engine nhưng khác cách đặt — IDS đứng out-of-band chỉ cảnh báo, IPS nằm inline và chặn thật, đổi lại chặn nhầm là gián đoạn dịch vụ (nên thực tế luôn chạy IDS để tinh chỉnh trước rồi mới dám chuyển sang chặn). Hai góc nhìn bổ khuyết nhau: **NIDS** thấy traffic giữa các host nên bắt được lateral movement và quét mạng, **HIDS** thấy syscall và file trên một host nên bắt được persistence và leo thang đặc quyền. Phần engine đi sâu vào **Snort** và **Suricata** — khớp theo chữ ký, mạnh với đòn đã biết, mù với đòn chưa có chữ ký.

Lên tới tầng ứng dụng là **WAF** — thứ mà firewall L3/L4 không làm được, vì nó phải parse method, URI, header, body mới phân biệt nổi request hợp lệ với request mang payload — với **ModSecurity** và bộ luật soạn sẵn **OWASP CRS**. Song song đó là **VPN** (IPsec, OpenVPN, WireGuard — cùng mục tiêu, khác nhau ở cách trao khoá và độ phức tạp) cho nhu cầu nối hai đầu qua Internet như thể chung một mạng. Cuối chương là hai thứ mình dùng nhiều nhất trong thực tế: **hardening nginx làm reverse proxy** (11.6 — rate limit, chặn tên tệp nhạy cảm, `default_server`, và cả giới hạn của chính nginx), và **Zeek** — công cụ không khớp chữ ký mà ghi lại hành vi mạng thành log có cấu trúc để phân tích sau.

> Các mục có nhãn [DEMO] là cấu hình rút gọn để minh hoạ cú pháp, đừng bê thẳng lên production — bản dùng thật luôn nằm ở phần kế bên.
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

**Vì sao:** một firewall L3/L4 chỉ thấy `IP/port/flags` nên có thể cho phép `tcp dst port 443` nhưng hoàn toàn không biết trong luồng HTTPS đó có `UNION SELECT`. Đó là lý do WAF tồn tại — nó phải kết thúc TLS (TLS termination) để đọc plaintext HTTP. Ngược lại WAF không hiệu quả để chặn SYN flood vì việc đó nên dừng ở L3/L4 trước khi tốn tài nguyên giải mã TLS.

### 11.1.2. IDS vs IPS

| Tiêu chí | IDS (Detection) | IPS (Prevention) |
|---|---|---|
| Vai trò | Phát hiện + cảnh báo | Phát hiện + chặn |
| Vị trí mạng | Out-of-band (SPAN/TAP) | Inline (gói đi xuyên qua) |
| Tác động lên gói | Không (chỉ copy) | Có (drop/reset/modify) |
| Rủi ro khi sai | False negative = bỏ lọt | False positive = chặn nhầm traffic hợp lệ |
| Rủi ro khả dụng | Không ảnh hưởng đường truyền nếu IDS chết | Single point of failure; cần fail-open/fail-close |
| Độ trễ | 0 (song song) | Thêm latency xử lý mỗi gói |

**Vì sao:** phân biệt này quan trọng vì IPS nằm trên đường dữ liệu, nên một rule kém (regex thảm hoạ, hay drop dựa trên anomaly) có thể gây mất dịch vụ. IDS an toàn hơn về khả dụng nhưng chỉ hữu ích khi có quy trình phản ứng (SOAR/SOC). Trong thực tế thường triển khai IDS trước (tuning rules ở chế độ alert), sau khi giảm false positive mới chuyển sang IPS (inline-block).

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

INLINE (IPS): traffic đi XUYÊN qua thiết bị.  Drop được. Nhưng là một điểm nghẽn/điểm có thể gây gián đoạn (chokepoint - điểm thắt cổ chai).
```

**Lưu ý:**
- Với traffic full-duplex 10G, một TAP tách RX/TX thành 2 luồng 10G; NIDS cần NIC nhận tổng 20G, hoặc cần packet broker để aggregate.
- SPAN trên cùng switch có thể mất gói âm thầm khi tải cao, dẫn tới bỏ lọt tấn công mà không ai biết.

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

**Vì sao** đặt `content` trước `pcre`: regex tốn CPU; engine dùng `content` (so chuỗi cố định bằng Aho-Corasick O(n)) làm "fast pattern" để loại nhanh đa số gói, chỉ những gói chứa chuỗi đó mới chịu chi phí regex. Đây là lý do mọi rule tốt nên có ít nhất một `content` để có fast pattern.

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

**Vì sao** có cả hai: payload thực tế có phần header độ dài cố định (dùng offset/depth) và phần biến thiên cần khớp tương đối (dùng distance/within). Giới hạn vùng tìm cũng giảm false positive và tăng tốc.

### 11.2.3. Ví dụ rule thật — giải thích từng tham số

Phát hiện SQLi `UNION SELECT` trong HTTP request:
```
# [PROD] rule có fast pattern + sticky buffer chuẩn hoá + pcre tinh lọc; vẫn cần tuning theo lưu lượng thực tế
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
# [PROD] ngưỡng count/seconds cần hiệu chỉnh theo baseline mạng để tránh false positive
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
# [DEMO] chỉ minh hoạ cơ chế: dựa vào artefact mặc định, attacker đổi profile là né được — KHÔNG dùng thẳng production
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
**Lưu ý:** rule dựa vào artefact mặc định; threat actor đổi profile dễ dàng, nên đây chỉ là minh hoạ cơ chế, không phải chữ ký bền vững.

Dùng `flowbits` để tương quan đa gói (chỉ alert exfil sau khi đã thấy đăng nhập):
```
# [DEMO] URI mẫu /login, /export?all=1 chỉ minh hoạ cơ chế flowbits — thay bằng route thật trước khi dùng
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

TCP định nghĩa 9 cờ điều khiển. 8 cờ nằm gọn trong 1 byte tại offset 13 của TCP header (gồm 6 cờ cổ điển FIN..URG cộng 2 cờ ECN là ECE/CWR theo RFC 3168); cờ thứ 9 là NS (Nonce Sum, RFC 3540) nằm ở bit thấp nhất của byte offset 12 (dùng chung byte với trường Data Offset), nên không cùng byte với 8 cờ còn lại:

| Bit (byte offset 13) | Cờ | Ý nghĩa |
|---|---|---|
| 0x01 | FIN | Kết thúc kết nối |
| 0x02 | SYN | Mở kết nối |
| 0x04 | RST | Reset kết nối |
| 0x08 | PSH | Đẩy buffer lên ứng dụng ngay |
| 0x10 | ACK | Xác nhận (trường Acknowledgment hợp lệ) |
| 0x20 | URG | Khẩn (trường Urgent Pointer hợp lệ) |
| 0x40 | ECE | ECN-Echo — báo hiệu tắc nghẽn (RFC 3168) |
| 0x80 | CWR | Congestion Window Reduced (RFC 3168) |
| — (bit thấp byte offset 12) | NS | Nonce Sum — ECN nonce (RFC 3540; ít triển khai, được RFC 8311 chuyển sang thử nghiệm) |

Cú pháp `flags`: `flags:S` (chỉ SYN), `flags:SA` (SYN+ACK), `flags:S,CE` (SYN bật, bỏ qua hai bit CWR/ECE khi so — tương đương ký pháp số `flags:S,12`), `flags:!R` (không RST). NULL scan = `flags:0`; XMAS = `flags:FPU`. Ký hiệu cờ trong rule Snort/Suricata: `C`=CWR, `E`=ECE, `U`=URG, `A`=ACK, `P`=PSH, `R`=RST, `S`=SYN, `F`=FIN.

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

**Lưu ý:**
- Luôn test rule trên pcap trước khi đẩy lên IPS inline.
- Một `pcre` không neo (không có `content` fast pattern) chạy trên mọi gói có thể đẩy CPU lên 100%, tự gây DoS cho chính hệ thống phòng thủ (ReDoS).
- Đặt `sid` local ≥ 1.000.000 để không đụng rule cộng đồng (ET/Talos).

---

## 11.3. ModSecurity + OWASP CRS — WAF tầng 7

### 11.3.1. WAF là gì và vì sao khác firewall L3/L4

WAF (Web Application Firewall) hoạt động ở L7: nó parse HTTP request (method, URI, headers, body, cookies, params) sau khi TLS đã được kết thúc, rồi áp luật lên NỘI DUNG ứng dụng.

| | Firewall L3/L4 (pf, iptables) | WAF L7 (ModSecurity) |
|---|---|---|
| Đọc tới | IP/port/flags | URI, header, body, JSON, multipart |
| Chặn được | Port 22 từ internet | `' OR 1=1--` trong tham số `id` |
| TLS | Không cần | Phải termination để đọc plaintext |
| Hiểu ngữ cảnh ứng dụng | Không | Có (per-param, per-route) |

ModSecurity là một engine rule chạy như module embedded (Apache `mod_security2`, NGINX `ModSecurity-nginx` connector) hoặc reverse proxy. OWASP CRS (Core Rule Set) là bộ rule chuẩn chạy trên engine đó. (Các lớp lỗ hổng web mà WAF nhắm chặn — SQLi, XSS, OWASP Top 10 — xem [Chương 5](#sec-05).)

Lưu ý về vòng đời dự án: Trustwave đã kết thúc hỗ trợ thương mại ModSecurity và chuyển giao dự án về OWASP từ 2024; hiện ModSecurity (v2/v3) do cộng đồng OWASP duy trì (cần kiểm chứng). Bản thân CRS từ dòng 4.x cũng đổi tên từ "OWASP ModSecurity Core Rule Set" thành **OWASP CRS** — vì bộ rule không còn gắn riêng với engine ModSecurity: cùng cú pháp SecLang chạy được trên engine tương thích như **Coraza** (viết bằng Go, hay dùng với Caddy/Envoy, hỗ trợ CRS đầy đủ). Bắt đầu dự án mới thì nên cân nhắc cả Coraza (cần kiểm chứng theo thời điểm đọc).

### 11.3.2. Năm phase xử lý của ModSecurity

ModSecurity gắn rule vào 5 phase theo vòng đời transaction HTTP:

| Phase | Tên | Khi nào | Dữ liệu sẵn có | Dùng để |
|---|---|---|---|---|
| 1 | Request Headers | Sau khi nhận headers | method, URI, headers, cookies | chặn sớm dựa header/URI |
| 2 | Request Body | Sau khi nhận body | ARGS (POST), JSON, multipart | chặn SQLi/XSS trong body |
| 3 | Response Headers | Trước khi gửi resp headers | status, resp headers | che server banner, kiểm leak |
| 4 | Response Body | Trước khi gửi resp body | nội dung response | data leak, ẩn lỗi SQL |
| 5 | Logging | Khi ghi log | toàn bộ | quyết định ghi audit log |

**Vì sao** tách phase: body có thể rất lớn; chặn ở phase 1 (chỉ header) rẻ hơn nhiều. Phase 4 cho phép phát hiện dữ liệu nhạy cảm rò ra (vd thông báo lỗi MySQL lộ schema).

### 11.3.3. Directive SecRule — phân rã cú pháp

```
SecRule VARIABLES "OPERATOR" "ACTIONS"
```
Ví dụ:
```
# [DEMO] minh hoạ cú pháp SecRule; production nên dùng OWASP CRS với anomaly scoring thay vì deny ngay khi một rule khớp
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

**Vì sao** cần transform: kẻ tấn công gửi `%27` thay `'`, hay `SeLeCt`. Không chuẩn hoá thì regex né dễ. Thứ tự transform quan trọng (áp tuần tự).

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

Quy trình triển khai an toàn. **Vì sao:** bật `DetectionOnly` vài ngày, đọc `modsec_audit.log` để tìm rule chặn nhầm traffic hợp lệ → tạo exclusion → mới chuyển `SecRuleEngine On`. Chuyển thẳng sang On dễ gây outage do CRS false positive.

### 11.3.5. OWASP CRS — anomaly scoring & paranoia level

CRS không chặn ngay khi một rule khớp. Nó CỘNG ĐIỂM (anomaly scoring):

```
Mỗi rule khớp → cộng điểm theo severity:
   CRITICAL = 5, ERROR = 4, WARNING = 3, NOTICE = 2 (cần kiểm chứng theo version CRS)
Cuối cùng: nếu tx.anomaly_score >= tx.inbound_anomaly_score_threshold (mặc định 5) → deny
```

**Vì sao** dùng scoring thay vì block-on-first-match: để giảm false positive. Một tín hiệu yếu (vd có ký tự `'`) không đủ chặn; nhiều tín hiệu cộng dồn mới vượt ngưỡng. Quản trị viên hạ ngưỡng để chặt hơn, nâng để nới.

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
# [PROD] đây là rule CRS chính thức (942100): dùng libinjection + cộng điểm anomaly, chạy được trong production sau khi tuning exclusion
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
# [DEMO] route /api/free-text-comment và rule id 942100 chỉ là ví dụ — thay bằng route và rule id thực tế
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

**Lưu ý:**
- WAF là lớp bù (compensating control), không thay thế việc sửa code (prepared statements, output encoding).
- WAF bypass vẫn khả thi (encoding lạ, HTTP parameter pollution, request smuggling).
- Luôn dùng anomaly scoring và tuning theo ứng dụng cụ thể.
- Bật response-body inspection để chống data leak, nhưng cân nhắc chi phí RAM/latency.
- WAF không nên là lớp chặn ĐẦU TIÊN: những pattern rẻ tiền (tên tệp nhạy cảm, rate-limit theo IP, Host lạ) nên bị loại ngay ở reverse proxy phía trước (xem 11.6) — để WAF dành tài nguyên cho phần khó: mọi biến thể encoding, injection trong body/tham số.

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

**Vì sao** stateful tốt hơn stateless: stateless cần rule cho cả hai chiều và dễ bị giả mạo gói ACK lọt qua. Stateful theo dõi cả chuỗi handshake; chỉ gói khớp với một kết nối hợp lệ mới qua. Xem state: `pfctl -ss`. Đếm: `pfctl -si`.

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

Block vs Reject. **Vì sao** chọn cái nào: Block = drop âm thầm → kẻ scan phải chờ timeout (làm chậm họ). Reject = trả RST → đóng nhanh (tốt cho UX nội bộ) nhưng giúp attacker map cổng nhanh hơn. Quy tắc: Reject trong LAN, Block ngoài WAN.

### 11.4.3. Alias

Alias = nhóm có tên (hosts/networks/ports/URLs) để tái sử dụng và gom rule.
```
Alias  WebServers     = 10.0.0.10, 10.0.0.11
Alias  AdminPorts     = 22, 3389, 8443
Rule:  Pass LAN → WebServers proto TCP dst AdminPorts  (source: AdminPCs)
```
**Vì sao:** 1 rule thay vì N×M rule; cập nhật một alias áp dụng mọi rule. Alias URL (pfBlockerNG) có thể nạp danh sách IP độc hại tự động.

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

**Vì sao** NAT và state gắn nhau: để dịch ngược gói trả về, pf phải nhớ mapping (port gốc ↔ port dịch) trong state table. Đây cũng là lý do PAT (port address translation) cần theo dõi cổng nguồn.

### 11.4.5. VLAN

VLAN 802.1Q chèn tag 4 byte vào Ethernet frame (cấu trúc):

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|---|---|---|---|
| TPID | 16 bit | Tag Protocol ID = 0x8100 | 0x8100 |
| PCP | 3 bit | Priority (QoS 802.1p) | 0 |
| DEI | 1 bit | Drop Eligible Indicator | 0 |
| VID | 12 bit | VLAN ID (1–4094) | 20 |

pfSense tạo interface VLAN trên một NIC vật lý (router-on-a-stick): mỗi VLAN = một subnet/interface với ruleset riêng → phân đoạn mạng (segmentation) chống lateral movement. **Vì sao** tối đa 4094 VLAN: VID dài 12 bit (0 và 4095 dành riêng nên không dùng được).

---

## 11.5. VPN — IPsec, OpenVPN, WireGuard (cực sâu)

VPN tạo "đường hầm" mã hoá: gói gốc được bọc trong gói mới có xác thực + mã hoá. Khác biệt cốt lõi giữa ba công nghệ nằm ở: cách trao khoá, cấu trúc gói bọc, và độ phức tạp. (Nền tảng mật mã — trao khoá Diffie-Hellman, AEAD, PFS — xem [Chương 4](#sec-04).)

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
| Confidentiality (bí mật) | KHÔNG | CÓ |
| Toàn vẹn + xác thực | CÓ (kể cả phần IP header bất biến) | CÓ (chỉ payload ESP, không gồm IP header ngoài) |
| Tương thích NAT | KÉM (hash gồm IP header → NAT làm hỏng) | TỐT (với NAT-T, đóng gói UDP 4500) |
| Dùng thực tế | Hiếm | Phổ biến (gần như luôn dùng ESP) |

**Vì sao** ESP thắng: AH xác thực cả IP header ngoài → NAT đổi IP làm sai ICV → gãy. ESP chỉ bảo vệ payload, và NAT-T bọc thêm UDP/4500 nên xuyên NAT được. Hầu hết VPN dùng ESP với mã hoá + xác thực (AES-GCM gộp cả hai).

#### Tunnel vs Transport mode

```
Gói gốc:           [ IP_orig | TCP | Data ]

TRANSPORT mode (ESP):  [ IP_orig | ESP_hdr | TCP | Data | ESP_trailer | ESP_ICV ]
   → bảo vệ payload, GIỮ IP header gốc. Dùng host-to-host.

TUNNEL mode (ESP):     [ IP_new | ESP_hdr | IP_orig | TCP | Data | ESP_trailer | ESP_ICV ]
   → bọc TOÀN BỘ gói gốc trong gói IP mới. Dùng gateway-to-gateway (site-to-site).
```
**Vì sao** dùng tunnel cho site-to-site: hai gateway có IP công khai; IP nội bộ gốc được giấu trong payload mã hoá → ẩn topology nội bộ và định tuyến qua internet bằng IP gateway.

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
**Lưu ý:**
- PSK yếu là điểm gãy (IKEv1 Aggressive mode lộ hash PSK cho offline crack).
- Ưu tiên chứng thư số hoặc EAP, AEAD (AES-GCM), nhóm DH ≥ ecp256/Group 19.
- Bật PFS (Perfect Forward Secrecy) để mỗi CHILD_SA có DH riêng, nhờ vậy lộ một khoá không kéo theo lộ phiên cũ.

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
**Vì sao** cần `tls-auth`/`tls-crypt`: thêm một lớp HMAC (hoặc mã hoá toàn bộ với tls-crypt) lên control channel → gói không có HMAC đúng bị drop trước cả khi xử lý TLS → chống port-scan, DoS, và làm khó nhận dạng dịch vụ. `remote-cert-tls server` chống client bị lừa nối tới server giả.

### 11.5.3. WireGuard — VPN hiện đại, Noise protocol

WireGuard tối giản (~4000 dòng kernel code), chạy trong kernel, dùng bộ crypto cố định (không thương lượng):
- Mã hoá AEAD: ChaCha20-Poly1305
- Trao khoá: Curve25519 ECDH
- Hash: BLAKE2s
- Khung handshake: Noise Protocol Framework (Noise_IK)

**Vì sao** không thương lượng thuật toán: loại bỏ "downgrade attack" và độ phức tạp của IKE. Muốn đổi thuật toán → nâng phiên bản giao thức, không thương lượng runtime.

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

**Vì sao** có mac1/mac2 + cookie: WireGuard "im lặng" — không phản hồi gói không hợp lệ (stealth, chống quét). mac1 chứng minh người gửi biết public key của đích (chống flood ngẫu nhiên). Khi bị tải, responder phát cookie; initiator phải tính mac2 đúng → chống DoS amplification.

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
**Vì sao** cần `PersistentKeepalive`: WireGuard không gửi gì khi rảnh → NAT/firewall ở giữa hết hạn mapping, server không gọi ngược client được. Keepalive 25s giữ "lỗ" NAT mở.

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

**Lưu ý** (chung cho cả ba VPN):
- Bảo vệ private key (quyền file 600), bật PFS/rekey.
- Ghim danh tính peer (cert/public key) và giám sát handshake bất thường.
- WireGuard coi allowed-IPs là biên giới tin cậy — sai AllowedIPs là một lỗ định tuyến/spoofing.

---

## 11.6. Proxy, Reverse proxy và hardening NGINX làm reverse proxy

### 11.6.1. Forward proxy vs reverse proxy

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
**Vì sao** cần `X-Forwarded-For`: sau reverse proxy, backend thấy IP của proxy. Header này chuyển IP client thật để logging/rate-limit.

**Lưu ý:**
- Backend chỉ được tin XFF khi đến từ proxy đáng tin; nếu không, client tự đặt XFF giả sẽ bypass được IP allowlist/rate-limit.
- Reverse proxy cũng giúp giấu phiên bản backend (giảm bề mặt tấn công).
- Đây cũng là nơi chống HTTP request smuggling, bằng cách chuẩn hoá nghiêm ngặt header `Content-Length`/`Transfer-Encoding`.

### 11.6.2. Vấn đề của cấu hình mặc định: `location /` proxy tất cả

Reverse proxy không chỉ để "chuyển tiếp cho chạy được" — nó là chỗ đứng lý tưởng cho **lớp chặn sớm** trong defense-in-depth. Nhưng template phổ biến nhất khi dựng nginx làm reverse proxy lại bỏ trống hoàn toàn vai trò đó:

```nginx
# [ANTI-PATTERN] server block "chạy được" nhưng không có một lớp phòng vệ nào
server {
    listen 443 ssl;
    server_name api-dev.example.com;
    client_max_body_size 4G;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Đây gần như nguyên văn một server block mình gặp khi audit một máy dev chạy web API ở hệ thống mình vận hành (đã ẩn danh hoá). Nó phục vụ người dùng bình thường tốt, nhưng đứng trước một đợt quét tự động thì:

| Thiếu | Hệ quả |
|---|---|
| Không `limit_req`/`limit_conn` | Không có phanh — scanner gửi bao nhiêu, nginx nhận bấy nhiêu |
| `location /` proxy MỌI path xuống app | Request quét (`/.ssh/id_rsa`, `/.env`...) cũng được đẩy xuống app rồi mới bị app từ chối |
| `client_max_body_size 4G` | Bất kỳ IP nào cũng được phép đẩy body 4GB → nguy cơ DoS cạn RAM/disk (11.6.6) |
| Không có `default_server` riêng | Request bằng IP trần / Host lạ vẫn được server block "thật" tiếp đón (11.6.5) |

Vấn đề nằm ở chỗ **"trả lỗi nhưng vẫn tốn tài nguyên"**. Mỗi request rác vẫn đi đủ chuỗi: TLS handshake (phần đắt nhất — mật mã bất đối xứng), nginx parse request, mở socket/kết nối tới backend, app nhận request, chạy router, sinh 404/500. App "từ chối" không có nghĩa là miễn phí — và nguy hiểm hơn, nó nghĩa là toàn bộ phòng thủ đang dựa vào việc app tự bảo vệ, không có lớp nào phía trước. 536 request quét trong hơn 2 giờ (case thật ở 11.6.8) là 536 lần TLS + parse + một phần chạm app. Nguyên tắc: cái gì chắc chắn là rác thì phải bị loại càng sớm càng tốt — ngay tại proxy, trước khi chạm app. Các mục 11.6.3–11.6.7 là các lớp chặn sớm đó, xếp từ "hành vi" đến "diệt gốc".

### 11.6.3. Rate limiting — `limit_req` (leaky bucket) và `limit_conn`

**Sinh ra để giải quyết:** người thật không gửi đều đặn một request mỗi vài giây suốt hai tiếng; scanner thì có. Giới hạn tốc độ theo IP nguồn chặn được *hành vi* đó mà không cần biết trước IP nào là xấu — quan trọng khi nguồn quét xoay IP liên tục (11.6.8).

```nginx
# Trong http {} — khai báo vùng nhớ đếm trạng thái
limit_req_zone  $binary_remote_addr zone=perip:10m  rate=10r/s;
limit_conn_zone $binary_remote_addr zone=connperip:10m;

# Trong server {} hoặc location {}
limit_req        zone=perip burst=20 nodelay;
limit_req_status 429;      # mặc định 503; 429 Too Many Requests đúng ngữ nghĩa hơn
limit_conn       connperip 20;
```

Từng tham số:
- `$binary_remote_addr`: IP client ở dạng nhị phân (IPv4 = 4 byte) thay vì chuỗi văn bản — mỗi entry trong zone nhỏ hơn, chứa được nhiều IP hơn.
- `zone=perip:10m`: 10MB shared memory lưu bộ đếm cho từng IP; cỡ 160.000 trạng thái (mỗi state ~64 byte — cần kiểm chứng theo phiên bản). Hết chỗ thì nginx xoá entry cũ nhất.
- `rate=10r/s`: cơ chế **leaky bucket** — mỗi IP có một "xô rò" thoát nước với tốc độ cố định 10 request/giây (nginx đo mịn theo mili giây: 1 request/100ms). Request đến khi xô đầy sẽ bị từ chối.
- `burst=20`: cho xô chứa thêm tối đa 20 request vượt nhịp. Truy cập thật thường "bùng" theo cụm (mở một trang kéo theo hàng chục request tài nguyên gần như đồng thời) — không có burst sẽ chặn nhầm ngay.
- `nodelay`: xử lý ngay các request trong hạn mức burst thay vì xếp hàng nhả dần theo nhịp `rate`; chỉ khi vượt cả burst mới bị trả lỗi. Thiếu `nodelay` thì client hợp lệ bị cộng trễ nhân tạo.
- `limit_conn connperip 20`: tối đa 20 kết nối đồng thời mở từ một IP — chặn kiểu tấn công mở thật nhiều kết nối rồi giữ treo (slow attack), thứ `limit_req` (đếm request) không nhìn thấy.

**Chọn ngưỡng thế nào:** đừng đoán — đo tải thật. Đếm request/giây theo từng IP từ access log giờ cao điểm (`awk` cột IP + timestamp, hoặc panel sẵn có trên hệ giám sát), lấy đỉnh của client hợp lệ *bận nhất* rồi nhân hệ số an toàn 2–3 lần. Ngưỡng đúng là ngưỡng mà client thật không bao giờ chạm còn scanner thì chạm ngay.

**Đánh đổi:** nhiều client sau một NAT (văn phòng, CGNAT di động) dùng chung một IP nguồn — ngưỡng quá thấp chặn nhầm cả toà nhà; API client hợp lệ gọi dày cần zone riêng (key theo API key/token thay vì IP) hoặc dùng module `geo` ánh xạ dải IP tin cậy sang biến để miễn limit.

### 11.6.4. Chặn tên tệp/đường dẫn nhạy cảm — và giới hạn của nginx

**Sinh ra để giải quyết:** scanner dò tệp bí mật theo danh sách quen thuộc — `.env`, `.git/config`, `.ssh/id_rsa`, dump `.sql`, backup `.bak`, `.mysql_history`. Không có lý do gì để những path đó đi xuống app; chặn ngay ở nginx bằng một location regex:

```nginx
location ~* (?:\.env|\.git|/\.ssh/|id_rsa|id_ed25519|\.mysql_history|\.sql|\.bak)(?:$|/) {
    return 403;
}
```

(Lưu ý: `location` chỉ so khớp phần *path* của URI — query string không nằm trong đó, nên đừng cố khớp `?` ở đây.)

`return 403` tại nginx gần như miễn phí: không proxy, không chạm app, không sinh lỗi 500 phía backend.

**Điểm kỹ thuật quan trọng — vì sao chặn theo TÊN TỆP chứ không chặn pattern `../`:** trước khi so khớp `location`, nginx **chuẩn hoá URI**: decode percent-encoding (`%2e` → `.`), gộp slash thừa (`merge_slashes`), phân giải các thành phần `./` và `../`. Hệ quả là chặn theo cú pháp traversal ở tầng location **không đáng tin**: pattern `../` viết trong regex thì URI đã bị nginx phân giải mất trước khi match; pattern `%2e%2e` thì đã bị decode thành `..`; còn biến thể double-encoding `%252e%252e` chỉ bị decode một lần thành `%2e%2e` — không khớp cả hai cách viết. Nhưng dù kẻ quét mã hoá đường đi kiểu gì, **đích cuối vẫn là một tên tệp cụ thể** (`id_rsa`, `.env`, `.mysql_history`) — và tên tệp đó sau chuẩn hoá luôn hiện nguyên hình trong URI. Chặn theo tên tệp bắt được đa số scan với chi phí gần bằng 0. Còn chặn traversal *triệt để* (mọi biến thể encoding, kể cả trong body/tham số POST) là việc của WAF — ModSecurity + OWASP CRS với chuỗi transform `t:urlDecodeUni` và các rule traversal/LFI chuyên dụng (xem 11.3.3 về transform, 11.3.5 về CRS).

### 11.6.5. `default_server` — ngắt request Host lạ / IP trần bằng `return 444`

**Sinh ra để giải quyết:** đa số scanner quét theo dải IP, gửi request bằng IP trần hoặc Host ngẫu nhiên chứ không biết domain của bạn. Nếu không khai báo `default_server` tường minh, nginx lấy server block **đầu tiên** trên mỗi cặp địa chỉ:port làm mặc định — nghĩa là vhost "thật" của bạn đứng ra tiếp đón toàn bộ request rác đó.

```nginx
server {
    listen 80  default_server;
    listen 443 ssl default_server;
    server_name _;                                   # bắt mọi Host không khớp block nào khác
    ssl_certificate     /etc/nginx/ssl/dummy.crt;    # cert self-signed "vứt đi"
    ssl_certificate_key /etc/nginx/ssl/dummy.key;
    return 444;                                      # đóng kết nối, không trả một byte
}
```

**Vì sao `444`:** đây là mã riêng của nginx (không phải HTTP status chuẩn) — nginx **đóng kết nối ngay, không gửi response**. So với `403`: một response 403 vẫn là HTTP hoàn chỉnh (status line, header, body), tự xác nhận "ở đây có web server sống" cho scanner ghi nhận; `444` khiến phía quét chỉ thấy kết nối bị ngắt — ít thông tin nhất có thể.

**Vì sao cần cert dummy cho block 443:** với HTTPS, TLS handshake diễn ra *trước khi* nginx đọc được request. Client vào bằng IP trần không gửi SNI → nginx chọn cert của `default_server`; block `listen 443 ssl` không có cert thì cấu hình không hợp lệ. Cert self-signed là đủ — ta không cần scanner tin cert, chỉ cần handshake không đổ lỗi sang vhost thật.

### 11.6.6. `client_max_body_size` — đừng bao giờ nới 4G mặc định

Kịch bản quen thuộc: upload bị lỗi `413 Request Entity Too Large` (mặc định nginx chỉ cho 1m) → ai đó sửa thành `client_max_body_size 4G;` ở tầng server cho "hết lỗi". Hệ quả: **bất kỳ IP nào** cũng được phép đẩy body 4GB vào **mọi endpoint**. Body lớn được nginx buffer vào RAM (`client_body_buffer_size`) rồi tràn sang file tạm trên disk — vài kết nối song song đủ cạn disk/RAM. Đây là DoS rẻ tiền, không cần lỗ hổng nào trong app.

Cách đúng: mặc định nhỏ, override đúng chỗ cần:
```nginx
# http {} hoặc server {}
client_max_body_size 20m;

# chỉ location thật sự nhận upload lớn
location /api/upload {
    client_max_body_size 200m;
    proxy_pass http://localhost:5000;
}
```
**Đánh đổi:** phải rà xem endpoint nào thật sự cần upload lớn để override — làm ngược (nới toàn cục, quên siết) là anti-pattern ở 11.6.2.

### 11.6.7. Môi trường dev/staging: allow/deny theo IP — diệt gốc

Mọi biện pháp phía trên là *giảm thiểu*; với môi trường dev/staging còn có biện pháp *diệt gốc*: các domain này không có lý do phơi ra toàn Internet. Bot chỉ quét được thứ nó chạm tới được — giới hạn nguồn truy cập về dải IP office/VPN thì toàn bộ chiến dịch scan bên ngoài dừng ở tầng này:

```nginx
# trong server {} của môi trường dev/staging
allow 203.0.113.0/24;   # dải IP office (placeholder — thay bằng dải thật)
allow 10.8.0.0/24;      # subnet VPN nội bộ
deny  all;              # còn lại: 403
```

Cần lọc thô theo quốc gia (dịch vụ chỉ phục vụ một thị trường) thì có module `geoip2` ánh xạ IP → mã quốc gia làm biến điều kiện. **Đánh đổi:** phải duy trì danh sách IP hợp lệ; dev/QA làm việc từ xa buộc phải qua VPN — nhưng đó là cái giá đúng cho môi trường không dành cho công chúng.

### 11.6.8. Bài học từ một chiến dịch scan thực tế

Chuỗi biện pháp 11.6.2–11.6.7 không phải lý thuyết — nó là kết quả một cuộc điều tra ở hệ thống mình vận hành (7/2026), kể lại đã ẩn danh hoá.

Từ dashboard giám sát, một IP nổi bật áp đảo bảng top nguồn cảnh báo: `45.148.10.80` (VPS ở Amsterdam) — **536 request trong ~2 giờ 15 phút** nhắm một máy dev chạy web API, toàn path traversal dò tệp bí mật. Một dòng access log gốc điển hình:

```
45.148.10.80 - - [20/Jul/2026:16:50:30 +0000] "GET /....//....//....//....//home/admin/.ssh/id_rsa?_=mknzjth2 HTTP/1.1" 301 178 "https://www.bing.com/search?q=3x4et6" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) ... Safari/605.1.15"
```

Đặc điểm đọc ra từ log: biến thể `....//` và double-encoding `%252e%252e` để né bộ lọc `../` thông thường (đúng cái bẫy ở 11.6.4); nhắm `.ssh/id_rsa`, `.ssh/id_ed25519`, `.env`, `.mysql_history` lần lượt cho mọi user phổ biến (root/admin/ubuntu/deploy/www-data...); referer giả Bing + user-agent xoay liên tục để né phát hiện; nhịp đều ~1 request/5 giây suốt 2 giờ — chắc chắn là máy, không phải người. Kết quả: toàn 301/400/404, không request nào trả 200 — **chưa thủng**, nhưng toàn bộ 536 request đều được nhận và một phần chạm app (cấu hình đúng như anti-pattern 11.6.2).

Mở rộng truy vấn ra cả fleet thì bức tranh đổi hẳn: **hàng chục IP thuộc nhiều subnet** (`185.177.72.x`, `45.148.10.x`, `195.178.110.x`...) quét tất cả các máy web-facing, IP xoay liên tục. Bài học rút ra:

1. **Chặn IP đơn lẻ là "đập chuột chũi"**: chặn xong `.80` thì `.62`, `.42` và subnet khác tới ngay. Chặn IP/subnet chỉ là biện pháp tình thế khi đang bị dồn dập.
2. **Ưu tiên biện pháp theo hành vi, áp cho cả fleet**: rate-limit (11.6.3), chặn tên tệp (11.6.4), `default_server` 444 (11.6.5), siết body size (11.6.6) — không phụ thuộc IP nguồn nên không phải chạy theo scanner. Với dev/staging, allow/deny theo IP (11.6.7) diệt gốc luôn.
3. **Hướng tự động hoá (đang nghiên cứu)**: nối fail2ban hoặc cơ chế active response của SIEM để tự chặn IP khi vượt ngưỡng cảnh báo (SIEM đếm alert theo `srcip` → đẩy lệnh chặn xuống firewall). Cần đặt ngưỡng và thời hạn chặn cẩn thận để không tự chặn nhầm đối tác NAT chung IP.

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
**Vì sao** Zeek bổ sung Suricata: Suricata trả lời "có khớp chữ ký không"; Zeek trả lời "chuyện gì đã xảy ra trên mạng" — cho phép săn mối đe doạ chưa có chữ ký (beaconing đều đặn, DNS tunneling, JA3 fingerprint TLS bất thường). Kết hợp: Suricata cho alert nhanh, Zeek cho ngữ cảnh điều tra, đẩy cả hai vào SIEM.

---

## 11.8. Tổng hợp kiến trúc phòng thủ và lưu ý vận hành

Bố trí điển hình một tổ chức:
```
Internet
  │
[ pfSense / NGFW ]  ── L3/L4 stateful filter, NAT, anti-DDoS, VPN termination (IPsec/WG/OVPN)
  │  (SPAN/TAP) ───────────────► [ Suricata IDS ]  +  [ Zeek ]  ──► SIEM
  │
[ Reverse proxy + ModSecurity/CRS ]  ── L7 WAF, TLS termination, rate-limit + chặn sớm (11.6)
  │
[ App servers ]  ── HIDS (Wazuh/auditd), prepared statements (gốc vẫn là code an toàn)
```

Nguyên tắc vận hành cốt lõi:
1. Tuning trước, enforce sau: IDS alert-only và WAF DetectionOnly trong giai đoạn baseline; đo false positive rồi mới inline/On.
2. Lớp đúng việc: chặn L3/L4 ở firewall (rẻ), L7 ở WAF; đừng dùng WAF chống flood hay firewall chống SQLi. Request rác nhận diện được bằng pattern rẻ (tên tệp nhạy cảm, tần suất, Host lạ) thì ngắt ngay ở reverse proxy (11.6) trước khi chạm WAF/app.
3. Defense-in-depth: WAF/IDS là compensating control; không thay thế code an toàn, patch, least-privilege.
4. Khả dụng của thiết bị phòng thủ: IPS/WAF inline là điểm có thể gây gián đoạn / điểm thắt cổ chai (chokepoint) — thiết kế fail-open/fail-close có chủ đích, HA, và giới hạn regex/ReDoS.
5. Mã hoá làm NIDS mù: cân nhắc TLS inspection ở reverse proxy (nơi đã có khoá) thay vì giải mã giữa đường.
6. Bảo vệ khoá VPN và danh tính peer: private key quyền 600, PFS/rekey, ghim cert/public key, giám sát handshake.
7. Tương quan đa nguồn: NIDS (Suricata) + NSM (Zeek) + HIDS (Wazuh) + WAF audit log → SIEM để thấy chuỗi tấn công đầy đủ thay vì cảnh báo rời rạc.


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*

- Phần 11.6 mình viết lại sau một đợt audit cấu hình nginx trên cả fleet máy web ở hệ thống mình vận hành. Mẹo audit nhanh mà mình thấy đáng giá: chạy trên từng máy `sudo nginx -T 2>/dev/null | grep -cE "limit_req|limit_conn|default_server"` — một con số duy nhất cho biết máy đó có bao nhiêu dòng cấu hình phòng vệ. Kết quả của mình: 5/6 máy trả về **0**. Con số 0 đó thuyết phục hơn mọi bài thuyết trình về defense-in-depth.
- Máy duy nhất có sẵn một phần cấu hình tốt được mình lấy làm **mẫu chuẩn hoá** cho các máy còn lại — đỡ viết từ đầu, và "máy X đang chạy ổn định với config này" là lập luận dễ được DevOps chấp nhận hơn một config mới tinh mình tự nghĩ ra.
- Từng hiểu sai: thấy scanner ăn toàn 301/400/404 thì yên tâm "app chặn được rồi". Sai ở hai chỗ — trả lỗi vẫn tốn đủ TLS + parse + một phần chạm app; và quan trọng hơn, nó nghĩa là cả hệ thống đang dựa vào đúng một lớp là app tự bảo vệ, không có gì phía trước.
- Cũng từng tin chặn regex `../` ở nginx là chống được traversal — sai nốt, vì nginx chuẩn hoá URI trước khi match location (11.6.4). May mà hiểu ra trước khi kịp tuyên bố "đã chặn traversal" ở đâu đó.
- Kinh nghiệm triển khai: đề xuất theo thứ tự ưu tiên (diệt gốc bằng allow/deny cho dev trước, rồi rate-limit, chặn tên tệp, default_server, body size), và **thử trên MỘT máy dev trước** — theo dõi vài ngày xem `limit_req` có chặn nhầm client hợp lệ không (đếm 429/503 trong log) rồi mới nhân bản ra cả fleet.
- Đang tìm hiểu tiếp: tự chặn IP theo ngưỡng qua fail2ban hoặc active response của SIEM, và đưa WAF (ModSecurity/CRS hoặc Coraza) lên reverse proxy — hiện các máy của mình mới dừng ở lớp chặn rẻ tiền bằng nginx thuần.
