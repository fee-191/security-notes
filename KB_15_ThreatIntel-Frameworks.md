# Chương 15 — Threat Intelligence & Frameworks tấn công (MITRE ATT&CK)

## Nhập môn — hiểu nôm na trước khi đi sâu

Chương này nói về cách những người làm bảo mật **mô tả, phát hiện và đo lường** hành vi của kẻ tấn công bằng một "ngôn ngữ chung". Hãy tưởng tượng cảnh sát điều tra: muốn phá án hiệu quả thì cả lực lượng phải gọi tên thủ đoạn của tội phạm giống nhau ("phá khóa", "giả danh nhân viên"), chứ mỗi đồn một kiểu thì không ai phối hợp được. Trong an toàn thông tin cũng vậy — nếu mỗi đội mô tả tấn công theo cách riêng thì không thể trao đổi, không thể biết mình đang phòng thủ tốt đến đâu. Các "framework" và công cụ trong chương chính là bộ từ điển và sổ tay chung đó. Dưới đây ta đi nhanh qua từng món lớn, bằng lời lẽ thật đời thường.

### Threat Intelligence (CTI) — nói đơn giản

- **Threat Intelligence là gì?** Là thông tin về kẻ xấu đã được **xử lý và thêm bối cảnh** để giúp ta ra quyết định, chứ không phải dữ liệu thô. Ví dụ: "có một địa chỉ IP lạ trong log" mới chỉ là dữ liệu; còn "IP này là máy chủ điều khiển của một nhóm tội phạm đang nhắm vào ngân hàng, nên chặn ngay" mới là intelligence. Giống như khác biệt giữa "trời có mây" và "bản tin dự báo bão khuyên bạn nên ở nhà".
- **Vì sao cần?** Vì mỗi ngày có hàng triệu cảnh báo. Nếu không biến chúng thành thông tin **hành động được**, đội bảo mật sẽ chết chìm trong nhiễu. CTI giúp lọc ra "cái gì đáng lo, vì sao, và làm gì tiếp theo".

### Cyber Kill Chain — nói đơn giản

- **Là gì?** Là cách chia một cuộc tấn công có chủ đích thành **7 bước nối tiếp**, từ lúc kẻ địch dò la cho đến lúc chúng đánh cắp được dữ liệu. Hãy hình dung như các bước của một vụ trộm nhà: rình rập trước cửa → chuẩn bị đồ nghề → lẻn vào → mở két → ôm tài sản chạy.
- **Vì sao cần?** Vì nó cho ta một câu chuyện dễ kể và một bài học quý: chỉ cần **chặn được một mắt xích** bất kỳ là cả chuỗi tấn công đứt gãy. Nó giúp lãnh đạo hình dung bức tranh tổng thể.

### Diamond Model — nói đơn giản

- **Là gì?** Là cách nhìn mỗi sự cố qua **4 góc của một viên kim cương**: kẻ tấn công, năng lực (công cụ/mã độc), hạ tầng (máy chủ, tên miền chúng dùng) và nạn nhân. Như bảng điều tra với 4 tấm ảnh được nối bằng dây.
- **Vì sao cần?** Vì khi nắm được **một góc**, ta có thể lần ra các góc còn lại (gọi là "pivoting" — bắc cầu điều tra). Biết một tên miền độc hại có thể lần ra địa chỉ IP, rồi ra các tên miền khác của cùng băng nhóm.

### IOC và IOA — nói đơn giản

- **IOC (dấu hiệu đã bị xâm nhập) là gì?** Là **bằng chứng tĩnh** cho biết "đã có chuyện xảy ra" — ví dụ mã băm (hash) của một file độc, một địa chỉ IP xấu. Giống dấu vân tay để lại tại hiện trường.
- **IOA (dấu hiệu đang bị tấn công) là gì?** Là **một chuỗi hành vi đáng ngờ đang diễn ra** — ví dụ "Word tự mở PowerShell rồi tải file từ Internet". Giống việc thấy ai đó đang cạy cửa sổ ngay lúc này.
- **Vì sao cần phân biệt?** Vì IOC dễ bị kẻ địch thay đổi (đổi 1 byte là có hash mới), còn hành vi (IOA) thì khó đổi hơn nhiều. Tập trung vào IOA giúp bắt được cả những biến thể chưa từng thấy.

### Pyramid of Pain — nói đơn giản

- **Là gì?** Là một cái tháp xếp hạng: chặn loại dấu hiệu nào thì **gây "đau" (tốn kém) nhất** cho kẻ tấn công. Đáy tháp (mã băm, IP) thì chúng đổi trong vài phút; đỉnh tháp (cách hành động — TTP) thì chúng phải thay đổi cả lối đánh, rất khó.
- **Vì sao cần?** Để ta đầu tư công sức cho đúng chỗ: chặn IP thì rẻ nhưng mau lỗi thời; phát hiện theo hành vi thì khó làm hơn nhưng bền hơn nhiều.

### MITRE ATT&CK — nói đơn giản

- **Là gì?** Là một **cuốn bách khoa toàn thư** liệt kê những việc kẻ tấn công **thực sự làm** trong đời thực, sắp thành ma trận. Nó dùng cây phân cấp: *Tactic* (mục tiêu — "vì sao"), *Technique* (cách làm — "làm gì"), *Sub-technique* (biến thể — "làm như thế nào"), *Procedure* (ai cụ thể làm ra sao). Mỗi mục có một mã định danh như `T1059.001`. Hãy coi nó như danh mục chiêu thức võ thuật, mỗi chiêu có tên riêng.
- **Vì sao cần?** Vì nhờ ai cũng gọi cùng một chiêu bằng cùng một mã, ta có thể **đo được** mình phát hiện được bao nhiêu chiêu, còn sót chiêu nào, và viết quy tắc phát hiện theo từng chiêu.

### ATT&CK Navigator — nói đơn giản

- **Là gì?** Là một công cụ web **tô màu** lên ma trận ATT&CK để nhìn bằng mắt: ô xanh là chiêu ta đã phát hiện được, ô đỏ là "lỗ hổng" chưa phát hiện được. Dữ liệu lưu trong một file JSON gọi là "layer".
- **Vì sao cần?** Vì một bảng màu trực quan giúp sếp và cả đội thấy ngay "ta đang yếu ở đâu" thay vì phải đọc danh sách dài.

### Detection Engineering: Sigma, YARA, Suricata — nói đơn giản

- **Sigma là gì?** Là cách viết **một quy tắc phát hiện trên log** theo định dạng trung lập, rồi dịch tự động sang nhiều hệ thống SIEM khác nhau (Splunk, Elastic...). Giống viết công thức một lần rồi dịch ra nhiều thứ tiếng.
- **YARA là gì?** Là cách viết quy tắc để **tìm chuỗi/byte đặc trưng trong file hay bộ nhớ**, dùng để nhận diện mã độc. Như mô tả đặc điểm nhận dạng của một tên tội phạm để máy quét tìm ra.
- **Suricata là gì?** Là "lính gác mạng" (IDS/IPS) soi **lưu lượng đi qua dây mạng** để bắt kênh điều khiển của mã độc hay dữ liệu bị tuồn ra.
- **Vì sao cần cả ba?** Vì kẻ tấn công để lại dấu vết ở ba nơi khác nhau — trong log, trong file, và trên đường mạng — nên cần ba loại "kính lúp" tương ứng. Cả ba đều gắn được mã ATT&CK để biết mình đang phủ chiêu nào.

### Chia sẻ tình báo: STIX, TAXII, MISP — nói đơn giản

- **STIX là gì?** Là một **định dạng chuẩn (JSON)** để viết thông tin về mối đe dọa sao cho máy nào cũng đọc hiểu. Như một mẫu biểu thống nhất để khai báo.
- **TAXII là gì?** Là **giao thức để gửi/nhận** các tờ khai STIX đó qua mạng một cách tự động. Như dịch vụ bưu điện chuyên chuyển những tờ khai ấy.
- **MISP là gì?** Là một **nền tảng phần mềm thực dụng** để các tổ chức cùng nhau lưu trữ và chia sẻ IOC, có gắn cả nhãn TLP (đèn giao thông quy định ai được xem) và ATT&CK.
- **Vì sao cần?** Vì kẻ tấn công thường dùng lại thủ đoạn cho nhiều nạn nhân; nếu các tổ chức chia sẻ kịp thời thì người sau được cảnh báo trước.

### Phân loại và phân tích Malware — nói đơn giản

- **Là gì?** Phần cuối chương phân biệt các loại mã độc (virus, worm, trojan, ransomware...) theo cách chúng lây lan và tự nhân bản, rồi giới thiệu cách **mổ xẻ một mẫu mã độc** (phân tích tĩnh: nhìn file mà không chạy; phân tích động: cho chạy trong môi trường cách ly để quan sát).
- **Vì sao cần?** Vì gọi đúng tên loại mã độc và hiểu cách nó hoạt động giúp ta chọn đúng cách phòng chống và phản ứng.

Nắm được mấy ý trên rồi thì phần dưới đây sẽ đi sâu vào chi tiết kỹ thuật.

> Mục tiêu chương: trang bị cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps) một mô hình tư duy thống nhất để **mô tả**, **phát hiện**, **đo lường** và **phản ứng** với hành vi của kẻ tấn công. Chương đi từ lý thuyết tình báo (CTI) xuống tới cấu trúc dữ liệu cụ thể (STIX object, MISP attribute, định dạng IOC, header PE), tới lệnh và file cấu hình chạy được (Sigma, YARA, Suricata, ATT&CK Navigator JSON, MISP REST API).

---

## 15.1. Vì sao cần Framework: từ "alert rời rạc" tới "ngôn ngữ chung"

Trước khi có các framework chuẩn hóa, mỗi đội bảo mật mô tả tấn công theo cách riêng: "có người login sai nhiều lần", "có file lạ chạy PowerShell". Vấn đề không phải thiếu dữ liệu mà là **thiếu ngôn ngữ chung** để:

1. **Trao đổi** giữa các đội/tổ chức (SOC nội bộ ↔ ISAC ↔ vendor).
2. **Đo lường độ phủ phát hiện** (detection coverage): ta phát hiện được bao nhiêu phần trăm hành vi mà đối thủ có thể làm?
3. **Ưu tiên đầu tư**: nên viết rule phát hiện gì trước?
4. **Tái lập (reproducibility)**: cùng một hành vi luôn được gọi bằng cùng một định danh.

Các framework trong chương này giải các bài toán khác nhau nhưng bổ trợ nhau:

| Framework | Câu hỏi nó trả lời | Mức trừu tượng |
|---|---|---|
| Cyber Kill Chain | Tấn công đi qua những **giai đoạn tuyến tính** nào? | Cao (chiến lược) |
| Diamond Model | Một sự kiện liên hệ **adversary / capability / infrastructure / victim** ra sao? | Trung (phân tích sự kiện) |
| MITRE ATT&CK | Đối thủ **thực sự làm gì** ở mỗi giai đoạn (hành vi quan sát được)? | Thấp (kỹ thuật, đo được) |
| Pyramid of Pain | Chặn IOC nào thì **gây đau** nhất cho đối thủ? | Thước đo giá trị IOC |

**Vì sao cần nhiều framework?** Kill Chain quá thô để viết detection; ATT&CK quá chi tiết để báo cáo cho lãnh đạo; Diamond Model giúp phân tích quan hệ nhưng không liệt kê kỹ thuật. Một SOC trưởng thành dùng cả ba: Kill Chain để kể chuyện, Diamond để pivot điều tra, ATT&CK để đo coverage và viết rule.

---

## 15.2. Cyber Threat Intelligence (CTI): định nghĩa, phân loại, vòng đời

### 15.2.1. CTI là gì và không là gì

**Threat Intelligence** = dữ liệu về mối đe dọa đã qua **xử lý + phân tích + bối cảnh hóa** để hỗ trợ **ra quyết định**. Điểm mấu chốt phân biệt với "data" thuần:

```
Data      → "IP 185.220.101.45 xuất hiện trong log"
Information→ "IP này là Tor exit node, kết nối lúc 03:00"
Intelligence→ "IP này được nhóm FIN7 dùng làm C2 trong chiến dịch
              nhắm ngành tài chính tháng 5; khuyến nghị chặn + hunt
              các host đã beacon tới nó"
```

Intelligence phải **actionable** (hành động được) và gắn **bối cảnh** (ai, mục tiêu gì, vì sao).

### 15.2.2. Bốn loại CTI

| Loại | Người tiêu thụ | Chân trời thời gian | Ví dụ cụ thể | Định dạng điển hình |
|---|---|---|---|---|
| **Strategic** | Ban lãnh đạo, CISO | Dài hạn (tháng/năm) | "Ngành crypto-exchange bị nhắm bởi Lazarus với động cơ tài chính" | Báo cáo văn xuôi, không kỹ thuật |
| **Operational** | SOC manager, IR lead | Trung hạn (tuần) | "Chiến dịch đang dùng macro Office → Cobalt Strike; TTP gồm T1566.001, T1059.001" | Campaign report, TTP list |
| **Tactical** | Threat hunter, detection engineer | Ngắn–trung | "TTP cụ thể: PowerShell `-enc` base64 spawn từ winword.exe" | Sigma rule, ATT&CK technique |
| **Technical** | SOC analyst L1/L2, hệ thống tự động | Rất ngắn (giờ/ngày) | "Hash `a1b2c3...`, IP `185.x`, domain `evil.com`" | IOC feed (STIX/MISP), CSV |

**Vì sao chia tầng?** Vì IOC kỹ thuật **mau hỏng** (đối thủ đổi IP/hash dễ dàng) còn TTP/strategic **bền** hơn. Đầu tư phát hiện nên dịch chuyển lên các tầng cao (xem Pyramid of Pain ở 15.6).

### 15.2.3. Vòng đời tình báo (Intelligence Lifecycle) — 6 pha

Mô hình kinh điển (gốc từ cộng đồng tình báo quân sự/CIA, áp dụng cho CTI):

```
        ┌──────────────────────────────────────────┐
        ▼                                            │
 1.Direction → 2.Collection → 3.Processing →         │
                                   4.Analysis →       │
                                   5.Dissemination →  │
                                   6.Feedback ────────┘
```

| Pha | Việc làm | Đầu ra | Lưu ý kỹ thuật |
|---|---|---|---|
| **1. Direction (Planning)** | Xác định yêu cầu tình báo (PIR – Priority Intelligence Requirements) | "Ai nhắm vào ta? Bằng TTP nào?" | Không có PIR → thu thập vô định, ngập IOC vô dụng |
| **2. Collection** | Thu thập từ OSINT, feed thương mại, telemetry nội bộ, dark web, ISAC | Raw data | Ghi nguồn + thời điểm để đánh giá độ tin cậy |
| **3. Processing** | Chuẩn hóa: parse log, decode, dedupe, normalize sang STIX | Structured data | Bước hay bị bỏ qua → "garbage in" |
| **4. Analysis** | Tương quan, gán TTP, đánh giá độ tin cậy (Admiralty Code) | Intelligence product | Tránh confirmation bias; dùng ACH (Analysis of Competing Hypotheses) |
| **5. Dissemination** | Phát hành đúng định dạng cho đúng đối tượng | Báo cáo, feed, rule | Strategic ≠ technical về format |
| **6. Feedback** | Người dùng đánh giá: có actionable không? | Điều chỉnh PIR | Đóng vòng lặp, nếu không CTI sẽ lệch nhu cầu |

**Admiralty Code (NATO)** dùng để gán độ tin cậy hai chiều: **độ tin nguồn (A–F)** và **độ tin thông tin (1–6)**. Ví dụ "B2" = nguồn thường đáng tin, thông tin có thể đúng.

| Source reliability | Information credibility |
|---|---|
| A = Completely reliable | 1 = Confirmed |
| B = Usually reliable | 2 = Probably true |
| C = Fairly reliable | 3 = Possibly true |
| D = Not usually reliable | 4 = Doubtful |
| E = Unreliable | 5 = Improbable |
| F = Cannot be judged | 6 = Cannot be judged |

---

## 15.3. Cyber Kill Chain (Lockheed Martin) — 7 bước

Mô hình do Lockheed Martin công bố (2011), mô tả tấn công có chủ đích (APT) như chuỗi tuyến tính. Triết lý phòng thủ: **phá vỡ bất kỳ một mắt xích nào** thì toàn chuỗi gãy → "intrusion kill chain".

| # | Giai đoạn | Hành động của attacker | Dấu hiệu / Phòng thủ Blue Team |
|---|---|---|---|
| 1 | **Reconnaissance** | Thu thập email, công nghệ, nhân sự (LinkedIn, whois, scan) | Log WAF/IDS phát hiện scan; honeytoken; theo dõi đăng ký domain giống thương hiệu |
| 2 | **Weaponization** | Ghép exploit + payload (vd: PDF có macro) | Khó phát hiện (xảy ra ở phía attacker); phân tích mẫu thu được |
| 3 | **Delivery** | Gửi qua email/USB/web | Email gateway, sandbox đính kèm, proxy log |
| 4 | **Exploitation** | Khai thác lỗ hổng để chạy code | EDR phát hiện exploit, EMET/CFG, patch |
| 5 | **Installation** | Cài backdoor/persistence | Giám sát autorun, dịch vụ mới, registry Run key |
| 6 | **Command & Control (C2)** | Thiết lập kênh điều khiển | Phân tích beacon, DNS tunneling, JA3 fingerprint |
| 7 | **Actions on Objectives** | Đánh cắp dữ liệu, phá hoại, lan ngang | DLP, monitor exfil, phát hiện encryption hàng loạt (ransomware) |

**Hạn chế:** Kill Chain giả định tuyến tính và lấy "phần mềm độc hại bên ngoài" làm trung tâm; yếu khi mô tả tấn công từ bên trong (insider), lateral movement lặp lại, hoặc tấn công cloud không có "malware delivery". ATT&CK ra đời để bù chỗ này (vòng lặp, phi tuyến, hành vi quan sát được).

**Unified Kill Chain (Paul Pols, 2017)** hợp nhất Kill Chain + ATT&CK thành 18 giai đoạn theo 3 cụm (In → Through → Out), khắc phục tính tuyến tính. Cần kiểm chứng số giai đoạn theo bản gốc nếu trích dẫn chính xác.

---

## 15.4. Diamond Model of Intrusion Analysis

Công bố 2013 (Caltagirone, Pendergast, Betz). Mỗi **sự kiện xâm nhập (event)** được mô hình hóa bằng 4 đỉnh kim cương, liên kết với nhau:

```
                 Adversary
                    /\
                   /  \
                  /    \
   Infrastructure ------ Capability
                  \    /
                   \  /
                    \/
                  Victim
```

| Đỉnh | Ý nghĩa | Ví dụ cụ thể |
|---|---|---|
| **Adversary** | Kẻ tấn công (operator/customer) | Nhóm APT29 |
| **Capability** | Năng lực: malware, exploit, kỹ năng (TTP) | Backdoor "WellMess", exploit CVE-XXXX |
| **Infrastructure** | Hạ tầng: C2 domain, IP, email gửi đi | `185.220.101.45`, `update-msft[.]com` |
| **Victim** | Nạn nhân: tổ chức, người, tài sản | Hãng dược X, mail server |

**Sức mạnh — Pivoting:** khi nắm một đỉnh, ta lần ra đỉnh khác. Ví dụ: từ một **domain C2** (infrastructure) → tra passive DNS ra **IP** dùng chung → tìm **các domain khác** trỏ cùng IP → suy ra **capability/adversary** khác của cùng nhóm.

```
Domain evil.com ─(passive DNS)→ 1.2.3.4 ─(reverse)→ bad2.com, bad3.com
       │                                                    │
   (whois)                                              (sandbox)
       ▼                                                    ▼
 email reg X ──────(pivot adversary)─────► cùng campaign
```

**Các meta-feature** mở rộng: timestamp, phase (gắn Kill Chain), result, direction, methodology, resources. **Social-Political** (động cơ adversary↔victim) và **Technology** (capability↔infrastructure) là hai trục bổ sung.

Diamond bổ trợ ATT&CK: ATT&CK điền vào **Capability** (TTP cụ thể), còn Diamond đặt nó trong quan hệ điều tra.

---

## 15.5. IOC vs IOA

| Tiêu chí | **IOC (Indicator of Compromise)** | **IOA (Indicator of Attack)** |
|---|---|---|
| Bản chất | Bằng chứng tĩnh đã xảy ra | Hành vi/ý đồ đang diễn ra |
| Ví dụ | Hash `e3b0c44...`, IP, domain, mutex, registry key | "winword.exe spawn powershell.exe rồi tải file từ Internet" |
| Độ bền | Thấp (đổi dễ) | Cao (logic tấn công khó đổi) |
| Phát hiện | So khớp danh sách | Phân tích chuỗi hành vi (EDR) |

**Ví dụ IOA (chuỗi nhân–quả) mà EDR phát hiện:**

```
1. outlook.exe  → tạo tiến trình winword.exe (mở đính kèm)
2. winword.exe  → spawn cmd.exe /c powershell -enc <base64>
3. powershell   → kết nối ra 185.x (download)
4. powershell   → ghi file vào %APPDATA%\svchost.exe
5. file mới     → tạo registry Run key (persistence)
```

Không indicator đơn lẻ nào ở trên là "xấu tuyệt đối" — chính **chuỗi** mới là dấu hiệu tấn công. Đây là khác biệt cốt lõi: IOC = "cái gì đã thấy"; IOA = "đang định làm gì". ATT&CK technique về bản chất là cách chuẩn hóa **IOA**.

---

## 15.6. Pyramid of Pain (David Bianco, 2013)

Đo **mức đau** mà việc ta chặn một loại indicator gây ra cho đối thủ — tức chi phí họ phải bỏ ra để né tránh.

```
                /\
               /  \   TTPs            ←  TOUGH!   (khó nhất cho attacker đổi)
              /----\
             / Tools \                ←  Challenging
            /--------\
           / Network/ \  Host Artifacts ← Annoying
          /------------\
         /  Domain Names \            ←  Simple
        /----------------\
       /   IP Addresses    \          ←  Easy
      /--------------------\
     /     Hash Values       \        ←  Trivial (đổi 1 byte → hash mới)
    /------------------------\
```

| Mức | Indicator | Chi phí đối thủ để né | Hành động Blue Team |
|---|---|---|---|
| Trivial | Hash (MD5/SHA256) | Đổi 1 byte → hash khác hoàn toàn | Vẫn block, nhưng đừng kỳ vọng |
| Easy | IP address | Thuê IP mới (vài phút) | Block + theo dõi pattern hạ tầng |
| Simple | Domain | Đăng ký domain mới (DGA tự động) | DNS sinkhole, phát hiện DGA |
| Annoying | Host/Network artifacts (mutex, User-Agent lạ, registry) | Phải sửa malware | Viết detection theo artifact |
| Challenging | Tools (Mimikatz, Cobalt Strike) | Phải đổi công cụ | YARA theo công cụ, JA3 |
| Tough | **TTPs** (hành vi: dump LSASS, pass-the-hash) | Phải đổi **cách hành động** | ATT&CK detection — đầu tư ở đây |

**Bài học vận hành:** đầu tư detection ở đỉnh tháp (TTP) cho lợi nhuận lâu dài; IOC ở đáy tháp rẻ nhưng chỉ chặn được đúng chiến dịch đã biết. Đây là lý do MITRE ATT&CK (catalog TTP) là trung tâm của detection engineering hiện đại.

---

## 15.7. MITRE ATT&CK — kiến trúc và mô hình dữ liệu

**ATT&CK** = *Adversarial Tactics, Techniques, and Common Knowledge*. Là **knowledge base** các hành vi đối thủ **quan sát được trong thực tế** (curated từ báo cáo công khai). Không phải framework tuyến tính như Kill Chain — nó là **ma trận** các hành vi.

### 15.7.1. Phân cấp khái niệm

```
Tactic  = MỤC TIÊU chiến thuật ("VÌ SAO" — attacker muốn đạt gì)
   └─ Technique = CÁCH chung để đạt mục tiêu ("LÀM GÌ")   → ID  Txxxx
        └─ Sub-technique = biến thể cụ thể ("LÀM NHƯ THẾ NÀO") → ID Txxxx.xxx
              └─ Procedure = hiện thực CỤ THỂ của một nhóm/malware
```

| Cấp | Trả lời | Định danh | Ví dụ |
|---|---|---|---|
| **Tactic** | Why (mục tiêu) | `TAxxxx` | TA0006 Credential Access |
| **Technique** | What (phương pháp) | `Txxxx` | T1003 OS Credential Dumping |
| **Sub-technique** | How (biến thể) | `Txxxx.xxx` | T1003.001 LSASS Memory |
| **Procedure** | Cụ thể ai làm sao | (mô tả) | "Mimikatz `sekurlsa::logonpasswords` đọc LSASS" |

**Cấu trúc ID — phân tích từng phần:**

| Thành phần | Định dạng | Ý nghĩa | Ví dụ |
|---|---|---|---|
| Prefix | 1 ký tự | Loại đối tượng | `T`=Technique, `TA`=Tactic, `S`=Software, `G`=Group, `M`=Mitigation, `C`=Campaign, `DS`=Data Source |
| Số technique | 4 chữ số | Định danh technique | `1003` |
| Dấu chấm + 3 chữ số | `.xxx` | Sub-technique | `.001` |

Ví dụ đầy đủ: `T1059.001` = Technique 1059 (Command and Scripting Interpreter), sub-technique 001 (PowerShell).

### 15.7.2. Mô hình quan hệ (ATT&CK STIX data model)

ATT&CK được phát hành dưới dạng **STIX 2.1 bundle** (JSON) trên GitHub `mitre/cti`. Các object type chính và ánh xạ:

| Khái niệm ATT&CK | STIX 2.1 type | Quan hệ |
|---|---|---|
| Technique | `attack-pattern` | — |
| Tactic | `x-mitre-tactic` | technique `kill_chain_phases` trỏ tới tactic |
| Group | `intrusion-set` | `uses` → attack-pattern / malware |
| Software (malware/tool) | `malware` / `tool` | `uses` → attack-pattern |
| Mitigation | `course-of-action` | `mitigates` → attack-pattern |
| Data Source/Component | `x-mitre-data-source` / `x-mitre-data-component` | `detects` → attack-pattern |
| Relationship | `relationship` | nối các object |

**Trích một `attack-pattern` (rút gọn, đúng cấu trúc STIX):**

```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
  "spec_version": "2.1",
  "name": "PowerShell",
  "x_mitre_is_subtechnique": true,
  "kill_chain_phases": [
    { "kill_chain_name": "mitre-attack", "phase_name": "execution" }
  ],
  "external_references": [
    { "source_name": "mitre-attack",
      "external_id": "T1059.001",
      "url": "https://attack.mitre.org/techniques/T1059/001" }
  ],
  "x_mitre_platforms": ["Windows"],
  "x_mitre_data_sources": ["Command: Command Execution",
                           "Process: Process Creation",
                           "Module: Module Load"],
  "x_mitre_detection": "Monitor for execution of powershell.exe with..."
}
```

Lưu ý quan trọng: **technique ID đặt trong `external_references`** (nơi `source_name == "mitre-attack"`), KHÔNG phải trường `id` (đó là STIX UUID). Đây là điểm hay nhầm khi viết script parse ATT&CK.

### 15.7.3. Lấy và truy vấn dữ liệu ATT&CK — ví dụ chạy được

Tải bundle Enterprise và đếm số technique bằng `jq`:

```bash
# Tải STIX bundle Enterprise ATT&CK
curl -sSL -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# Đếm số attack-pattern chưa bị deprecated/revoked
jq '[.objects[]
      | select(.type=="attack-pattern")
      | select((.revoked // false)|not)
      | select((.x_mitre_deprecated // false)|not)] | length' \
   enterprise-attack.json

# Liệt kê technique ID + tên cho tactic "credential-access"
jq -r '.objects[]
        | select(.type=="attack-pattern")
        | select(.kill_chain_phases[]?.phase_name=="credential-access")
        | (.external_references[]
            | select(.source_name=="mitre-attack").external_id)
          + "  " + .name' \
   enterprise-attack.json | sort | head
```

Giải thích tham số: `select(.type=="attack-pattern")` lọc đúng technique; `.kill_chain_phases[]?.phase_name` truy cập tactic (dấu `?` tránh lỗi khi mảng vắng); `.external_references[] | select(.source_name=="mitre-attack").external_id` rút technique ID.

Truy vấn ở tầng Python với thư viện chính thức `mitreattack-python`:

```python
from mitreattack.stix20 import MitreAttackData

mad = MitreAttackData("enterprise-attack.json")

# Lấy technique theo ATT&CK ID
t = mad.get_object_by_attack_id("T1003.001", "attack-pattern")
print(t.name)                       # LSASS Memory

# Nhóm nào dùng technique này?
groups = mad.get_groups_using_technique(t.id)
for g in groups:
    print(g["object"].name)         # vd: APT28, ...
```

### 15.7.4. 14 Tactic Enterprise (Reconnaissance → Impact)

Thứ tự cột trong ma trận Enterprise (đây là **thứ tự logic**, không bắt buộc tuyến tính khi tấn công thật):

| # | Tactic | ID | Mục tiêu của attacker | Technique ví dụ |
|---|---|---|---|---|
| 1 | **Reconnaissance** | TA0043 | Thu thập thông tin trước tấn công | T1595 Active Scanning, T1589 Gather Victim Identity Info |
| 2 | **Resource Development** | TA0042 | Chuẩn bị hạ tầng/công cụ | T1583 Acquire Infrastructure, T1587 Develop Capabilities |
| 3 | **Initial Access** | TA0001 | Đặt chân vào mạng | T1566 Phishing, T1190 Exploit Public-Facing App |
| 4 | **Execution** | TA0002 | Chạy code độc hại | **T1059** Command and Scripting Interpreter |
| 5 | **Persistence** | TA0003 | Duy trì chỗ đứng qua reboot | T1547 Boot/Logon Autostart, T1053 Scheduled Task |
| 6 | **Privilege Escalation** | TA0004 | Nâng quyền | T1548 Abuse Elevation Control, T1068 Exploit for PrivEsc |
| 7 | **Defense Evasion** | TA0005 | Né phát hiện | T1070 Indicator Removal, T1027 Obfuscated Files |
| 8 | **Credential Access** | TA0006 | Lấy tài khoản/mật khẩu | **T1110** Brute Force, **T1003** OS Credential Dumping |
| 9 | **Discovery** | TA0007 | Dò xét môi trường | T1083 File/Directory Discovery, T1018 Remote System Discovery |
| 10 | **Lateral Movement** | TA0008 | Di chuyển sang host khác | **T1021** Remote Services, T1550 Use Alternate Auth Material |
| 11 | **Collection** | TA0009 | Gom dữ liệu mục tiêu | T1005 Data from Local System, T1113 Screen Capture |
| 12 | **Command and Control** | TA0011 | Điều khiển từ xa | T1071 App Layer Protocol, T1572 Protocol Tunneling |
| 13 | **Exfiltration** | TA0010 | Tuồn dữ liệu ra | **T1041** Exfil Over C2 Channel, T1048 Exfil Over Alt Protocol |
| 14 | **Impact** | TA0040 | Phá hoại/tống tiền | T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery |

**Vì sao 2 tactic "Reconnaissance" và "Resource Development" được thêm sau (PRE-ATT&CK gộp vào):** ban đầu ATT&CK Enterprise bắt đầu từ Initial Access. Các hoạt động trước xâm nhập (recon, mua hạ tầng) xảy ra ngoài mạng nạn nhân nên khó telemetry, được tách thành PRE-ATT&CK rồi (2020) tích hợp lại làm 2 cột đầu.

---

## 15.8. Đào sâu các Technique trọng yếu (cơ chế + dấu hiệu phát hiện)

### 15.8.1. T1110 — Brute Force (Credential Access)

**Là gì:** thử nhiều cặp credential cho tới khi đúng. Sub-techniques:

| ID | Tên | Cơ chế |
|---|---|---|
| T1110.001 | Password Guessing | Thử nhiều mật khẩu cho **một** tài khoản |
| T1110.002 | Password Cracking | Bẻ hash **offline** (sau khi đã dump) |
| T1110.003 | Password Spraying | Thử **một** mật khẩu phổ biến trên **nhiều** tài khoản (né lockout) |
| T1110.004 | Credential Stuffing | Dùng cặp user/pass rò rỉ từ nơi khác |

**Vì sao password spraying nguy hiểm:** chính sách lockout thường khóa sau N lần sai *trên một tài khoản*. Spray thử `Summer2024!` lần lượt cho 5000 user → mỗi user chỉ 1 lần sai → không kích hoạt lockout.

**Ví dụ thực tế — spray SMB/RDP bằng `crackmapexec` (dùng trong lab có phép):**

```bash
# Một mật khẩu, nhiều user, có --continue-on-success để gom hết hit
crackmapexec smb 10.0.0.0/24 -u users.txt -p 'Summer2024!' \
    --continue-on-success
```

**Dấu hiệu Blue Team (Windows Security log):**

| Trường | Giá trị cần để ý |
|---|---|
| Event ID | `4625` (logon failed) — nhiều, rải nhiều `TargetUserName` |
| Event ID | `4771` (Kerberos pre-auth failed), `4768` |
| Failure Reason / Status | `0xC000006A` (sai mật khẩu), `0xC0000234` (account locked) |
| Pattern | **Nhiều username khác nhau, cùng một password attempt window** → spray |

```
Detection logic (pseudo-SIEM):
  COUNT(distinct TargetUserName) WHERE EventID=4625
  GROUP BY SourceIP, time_bucket(5m) > 20  → cảnh báo password spraying
```

### 15.8.2. T1059 — Command and Scripting Interpreter (Execution)

| Sub | Interpreter |
|---|---|
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell (cmd) |
| T1059.004 | Unix Shell (bash) |
| T1059.005 | Visual Basic |
| T1059.006 | Python |
| T1059.007 | JavaScript |

**Ví dụ payload PowerShell mã hóa — giải thích từng phần:**

```powershell
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...
```

| Tham số | Ý nghĩa | Vì sao attacker dùng |
|---|---|---|
| `-nop` | `-NoProfile` | Bỏ qua profile (tránh logging/khởi tạo) |
| `-w hidden` | `-WindowStyle Hidden` | Ẩn cửa sổ |
| `-enc` | `-EncodedCommand` (Base64 **UTF-16LE**) | Né phát hiện chuỗi, né dấu nháy escape |

**Lưu ý mã hóa:** chuỗi sau `-enc` là Base64 của text **UTF-16 Little Endian**, không phải UTF-8. Giải mã đúng:

```bash
# Lệnh thực: giải mã encoded command
echo 'SQBFAFgAIAAoAE4AZQB3AC0ATwBi' | base64 -d | iconv -f UTF-16LE -t UTF-8
# → "IEX (New-Ob..."   (Invoke-Expression — tải & chạy từ bộ nhớ)
```

**Dấu hiệu Blue Team:**
- **Script Block Logging** (Event ID `4104`) ghi lại nội dung script đã giải mã — bật qua GPO `Administrative Templates → Windows PowerShell → Turn on PowerShell Script Block Logging`.
- Process creation (`4688` / Sysmon `1`) với `CommandLine` chứa `-enc`, `-e`, `FromBase64String`, `IEX`, `DownloadString`.
- Parent–child bất thường: `winword.exe → powershell.exe` (IOA).

### 15.8.3. T1003 — OS Credential Dumping (Credential Access)

| Sub | Nguồn credential | Cơ chế |
|---|---|---|
| T1003.001 | **LSASS Memory** | Đọc bộ nhớ tiến trình `lsass.exe` (chứa hash/vé Kerberos/đôi khi plaintext) |
| T1003.002 | Security Account Manager (SAM) | Đọc registry hive `SAM` → NTLM hash local |
| T1003.003 | NTDS (`ntds.dit`) | Database AD trên Domain Controller → toàn bộ hash domain |
| T1003.004 | LSA Secrets | `HKLM\SECURITY\Policy\Secrets` |
| T1003.006 | DCSync | Giả làm DC, yêu cầu replication (`DRSGetNCChanges`) để lấy hash |

**Vì sao LSASS là mục tiêu:** Local Security Authority Subsystem Service giữ credential material để hỗ trợ SSO. Mimikatz `sekurlsa::logonpasswords` mở handle tới `lsass.exe`, đọc các cấu trúc bộ nhớ và giải mã.

**Ví dụ thực tế (lab):**

```
mimikatz # privilege::debug          # bật SeDebugPrivilege
mimikatz # sekurlsa::logonpasswords  # dump credential từ LSASS
```

Dump bằng công cụ "sống nhờ đất" (LOLBIN) khó bị AV chú ý hơn:

```cmd
:: Tạo minidump LSASS bằng comsvcs.dll (LOLBIN)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_lsass> C:\temp\l.dmp full
```

**Dấu hiệu Blue Team:**
- Sysmon **Event ID 10** (ProcessAccess) với `TargetImage` = `lsass.exe` và `GrantedAccess` = `0x1010`/`0x1410`/`0x143A` (quyền đọc bộ nhớ) từ tiến trình không phải hệ thống.
- **Credential Guard** (VBS) cô lập LSASS secrets → vô hiệu mimikatz `logonpasswords`.
- **PPL (Protected Process Light)** cho LSASS: `RunAsPPL=1` ở `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

Sysmon config phát hiện đọc LSASS:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="lsass-access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 15.8.4. T1021 — Remote Services (Lateral Movement)

| Sub | Dịch vụ | Port | Dấu hiệu |
|---|---|---|---|
| T1021.001 | RDP | TCP **3389** | Event `4624` Logon Type **10** (RemoteInteractive) |
| T1021.002 | SMB/Windows Admin Shares (C$, ADMIN$) | TCP **445** | Logon Type **3**; truy cập `\\host\ADMIN$` |
| T1021.004 | SSH | TCP 22 | auth log |
| T1021.006 | WinRM | TCP 5985/5986 | Logon Type 3; `wsmprovhost.exe` |

**Logon Type — bảng tra (Windows Event 4624):**

| Type | Ý nghĩa | Liên quan lateral movement |
|---|---|---|
| 2 | Interactive (tại máy) | — |
| 3 | Network (SMB, share, WinRM) | **Có** — pass-the-hash, psexec |
| 10 | RemoteInteractive (RDP) | **Có** |
| 5 | Service | persistence |

**Ví dụ thực tế — pass-the-hash qua SMB (`impacket`):**

```bash
# Dùng NTLM hash thay vì mật khẩu để thực thi từ xa (T1021.002 + T1550.002)
impacket-psexec -hashes :32ed87bdb5fdc5e9cba88547376818d4 \
    Administrator@10.0.0.5
```

**Dấu hiệu:** chuỗi `4624 (Type 3) → tạo service "PSEXESVC" (Event 7045) → tiến trình con cmd.exe` trên host đích.

### 15.8.5. T1041 — Exfiltration Over C2 Channel (Exfiltration)

**Là gì:** tuồn dữ liệu ra **qua chính kênh C2 đang dùng** (HTTP/HTTPS/DNS) thay vì mở kênh riêng — để hòa lẫn lưu lượng.

**Dấu hiệu Blue Team — phát hiện C2/beacon ở mức gói tin:**
- **Beaconing**: kết nối định kỳ đều đặn (vd mỗi 60s ± jitter) tới cùng host. Phát hiện qua phân tích **periodicity** của NetFlow.
- **Tỷ lệ upload/download bất thường** (bytes_out >> bytes_in cho exfil).
- **JA3/JA3S** fingerprint của TLS client hello khớp Cobalt Strike/Metasploit.
- **DNS exfil**: subdomain dài, entropy cao, nhiều query TXT/NULL.

```
Beacon pattern (NetFlow nhìn theo thời gian):
  10:00:00  client → C2  220 bytes
  10:01:00  client → C2  240 bytes   ← chu kỳ ~60s
  10:02:01  client → C2  225 bytes
  ...  (độ lệch nhỏ = jitter)  → cảnh báo regular beaconing
```

---

## 15.9. Các Matrix: Enterprise, Mobile, ICS

ATT&CK có nhiều "domain" với tactic/technique riêng phù hợp môi trường:

| Matrix | Phạm vi | Platform con | Tactic đặc thù |
|---|---|---|---|
| **Enterprise** | IT doanh nghiệp | Windows, Linux, macOS, **Cloud** (IaaS, SaaS, Office/Google Workspace, Azure AD/Entra ID), Network, Containers | 14 tactic (đã liệt kê) |
| **Mobile** | Android, iOS | — | Có thêm các tactic liên quan thiết bị; vd Network Effects |
| **ICS** | Hệ thống điều khiển công nghiệp/OT | PLC, SCADA, HMI | 12 tactic gồm **Impair Process Control**, **Inhibit Response Function** |

**Cloud (nằm trong Enterprise):** ví dụ technique đặc thù cloud:
- T1078.004 Valid Accounts: **Cloud Accounts**
- T1098 Account Manipulation (thêm credential/role IAM)
- T1530 Data from Cloud Storage (đọc S3 bucket public)
- T1526 Cloud Service Discovery

**ICS — vì sao tách riêng:** trong OT, "Impact" có thể là **gây thiệt hại vật lý** (đóng/mở van, làm hỏng tua-bin — như Stuxnet/Triton). Tactic `Inhibit Response Function` mô tả việc vô hiệu hệ thống an toàn (Safety Instrumented System) — không có khái niệm tương đương trong IT. Technique ví dụ: T0816 Device Restart/Shutdown, T0831 Manipulation of Control.

---

## 15.10. ATT&CK Navigator: map detection & đo coverage

**Navigator** là ứng dụng web (chạy được offline) tô màu các ô technique trên ma trận để trực quan hóa: coverage phát hiện, hoạt động của một nhóm APT, gap analysis. Dữ liệu lưu dưới **layer file (JSON)**.

### 15.10.1. Cấu trúc layer JSON — từng trường

```json
{
  "name": "SOC Detection Coverage Q2",
  "versions": { "attack": "15", "navigator": "5.0.0", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Độ phủ rule SIEM hiện tại",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "tactic": "execution",
      "score": 100,
      "color": "",
      "comment": "Phủ bởi Sigma rule win_susp_powershell_enc",
      "enabled": true,
      "metadata": [
        { "name": "rule_id", "value": "SIGMA-0421" }
      ]
    },
    {
      "techniqueID": "T1003.001",
      "tactic": "credential-access",
      "score": 50,
      "comment": "Chỉ có rule Sysmon EID10, chưa cover comsvcs"
    }
  ],
  "gradient": {
    "colors": ["#ff6666", "#ffe766", "#8ec843"],
    "minValue": 0, "maxValue": 100
  },
  "legendItems": [],
  "showTacticRowBackground": true,
  "tacticRowBackground": "#dddddd",
  "selectTechniquesAcrossTactics": true
}
```

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `domain` | string | `enterprise-attack` / `mobile-attack` / `ics-attack` |
| `versions.attack` | string | Phiên bản ATT&CK (vd "15") — phải khớp để ID hợp lệ |
| `techniques[].techniqueID` | string | ID technique/sub-technique |
| `techniques[].tactic` | string | tactic shortname (vì 1 technique có thể thuộc nhiều tactic → cần chỉ rõ ô nào) |
| `techniques[].score` | number | Điểm để tô gradient (vd % coverage) |
| `gradient` | object | Ánh xạ score→màu (min→max) |

**Vì sao cần `tactic` trên từng technique:** một technique như T1078 Valid Accounts xuất hiện ở **nhiều cột** (Initial Access, Persistence, Privilege Escalation, Defense Evasion). Trường `tactic` chỉ định tô ô nào.

### 15.10.2. Quy trình đo coverage thực tế

1. Liệt kê toàn bộ detection rule (Sigma/SIEM) hiện có.
2. Gán mỗi rule → một/nhiều technique ID (qua trường `tags: attack.txxxx` trong Sigma — xem 15.11).
3. Sinh layer JSON (script), `score=100` cho technique có rule, `0` cho chưa.
4. Mở Navigator → import layer → nhìn vùng đỏ = **detection gap**.
5. So với layer của các APT nhắm vào ngành mình (MITRE cung cấp sẵn layer theo group) → **kết hợp 2 layer** bằng phép toán để ưu tiên.

**Script sinh layer từ kho Sigma (rút gọn):**

```python
import glob, yaml, json, re

techs = {}
for f in glob.glob("rules/**/*.yml", recursive=True):
    doc = yaml.safe_load(open(f, encoding="utf-8"))
    for tag in (doc.get("tags") or []):
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.I)
        if m:
            techs[m.group(1).upper()] = techs.get(m.group(1).upper(), 0) + 1

layer = {
  "name": "Sigma coverage", "domain": "enterprise-attack",
  "versions": {"attack": "15", "navigator": "5.0.0", "layer": "4.5"},
  "techniques": [
     {"techniqueID": t, "score": min(100, c*25),
      "comment": f"{c} rule(s)"} for t, c in techs.items()
  ],
  "gradient": {"colors": ["#ff6666","#8ec843"], "minValue":0, "maxValue":100}
}
json.dump(layer, open("coverage.json","w"), indent=2)
```

Navigator hỗ trợ **layer arithmetic**: ví dụ tạo layer mới = `a - b` để tìm technique APT dùng (a) mà ta chưa cover (b).

---

## 15.11. Detection Engineering: Sigma, YARA, Suricata gắn ATT&CK

### 15.11.1. Sigma — rule SIEM-agnostic

**Là gì:** định dạng YAML mô tả detection trên **log** một cách trung lập, rồi `sigma-cli` chuyển sang truy vấn Splunk/Elastic/Sentinel...

**Cấu trúc rule — từng trường:**

```yaml
title: PowerShell EncodedCommand Suspicious
id: f7d4c3b2-1a2b-4c3d-9e8f-0a1b2c3d4e5f
status: experimental
description: Phát hiện powershell.exe chạy với tham số -EncodedCommand
references:
  - https://attack.mitre.org/techniques/T1059/001
author: Blue Team
date: 2026/06/19
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e '
  condition: selection
falsepositives:
  - Một số script quản trị hợp lệ dùng -enc
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

| Trường | Bắt buộc | Ý nghĩa |
|---|---|---|
| `id` | Có | UUID duy nhất (dedupe, tham chiếu) |
| `logsource.category` | Có | Loại log (`process_creation`, `firewall`, `dns_query`...) |
| `detection.selection` | Có | Điều kiện khớp (map key→field log) |
| `detection.condition` | Có | Logic boolean kết hợp các selection |
| `tags` | Khuyến nghị | `attack.txxxx` → liên kết ATT&CK (dùng đo coverage) |

**Modifier** (`|`): `endswith`, `contains`, `startswith`, `re` (regex), `all`. Vì sao có modifier: log thực tế đường dẫn đầy đủ → cần `endswith` thay vì so khớp tuyệt đối.

**Biên dịch sang backend (lệnh thật):**

```bash
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -p splunk_windows powershell_enc.yml
# Output (SPL):
# Image="*\\powershell.exe" (CommandLine="* -enc *" OR CommandLine="* -e *" ...)
```

### 15.11.2. YARA — pattern matching trên file/bộ nhớ

**Là gì:** ngôn ngữ rule khớp **chuỗi/byte/regex** trong file hoặc process memory → phân loại malware (mức "Tools" trên Pyramid of Pain).

**Cấu trúc rule:**

```yara
import "pe"

rule Mimikatz_Strings
{
    meta:
        author      = "BlueTeam"
        description = "Phát hiện chuỗi đặc trưng Mimikatz"
        attack      = "T1003.001"
        reference   = "https://attack.mitre.org/software/S0002/"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide
        $s2 = "privilege::debug"          ascii wide
        $s3 = { 6D 69 6D 69 6B 61 74 7A }      // "mimikatz" hex
        $re = /gentilkiwi|benjamin delpy/ nocase

    condition:
        uint16(0) == 0x5A4D and          // MZ header (PE file)
        pe.number_of_sections > 1 and
        2 of ($s*) and $re
}
```

| Phần | Ý nghĩa |
|---|---|
| `strings` | Khai báo pattern: `ascii`/`wide` (UTF-16), `nocase`, hex `{ .. }`, regex `/../` |
| `condition` | Logic; `uint16(0)==0x5A4D` kiểm tra 2 byte đầu = `MZ` (PE); `2 of ($s*)` = ít nhất 2 string khớp |
| `import "pe"` | Module phân tích PE (số section, import, entry point) |

**Vì sao `uint16(0)==0x5A4D`:** file PE bắt đầu bằng signature **"MZ"** (0x4D 0x5A) — little-endian đọc 2 byte đầu thành `0x5A4D`. Điều kiện này loại sớm file không phải PE → rule nhanh hơn.

**Lệnh quét thật:**

```bash
yara -r -w mimikatz.yar /path/to/scan        # -r đệ quy, -w tắt warning
yara mimikatz.yar --scan-list pids.txt        # quét theo PID (memory)
```

### 15.11.3. Suricata — IDS/IPS phát hiện network (C2/exfil)

**Là gì:** IDS/IPS chữ ký + phân tích giao thức. Rule khớp gói/flow, gắn `metadata` ATT&CK.

**Cấu trúc rule — từng phần:**

```
alert http $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"ATT&CK T1071.001 Suspicious User-Agent CobaltStrike default"; \
    flow:established,to_server; \
    http.user_agent; content:"Mozilla/5.0 (compatible; MSIE 9.0"; \
    http.uri; content:"/__utm.gif"; \
    classtype:trojan-activity; \
    metadata: attack_target Client_Endpoint, mitre_technique_id T1071; \
    sid:9000001; rev:1; )
```

| Thành phần | Ý nghĩa |
|---|---|
| `alert http` | Action (`alert`/`drop`/`reject`) + protocol app-layer |
| `$HOME_NET any -> $EXTERNAL_NET any` | Hướng: nguồn IP/port → đích IP/port |
| `flow:established,to_server` | Chỉ khớp gói client→server trong kết nối đã thiết lập |
| `http.user_agent` + `content` | Sticky buffer: chỉ tìm trong header User-Agent |
| `sid` | Signature ID (duy nhất); `rev` revision |
| `metadata: mitre_technique_id` | Gắn ATT&CK ID |

**Vì sao dùng sticky buffer (`http.user_agent`):** giới hạn việc tìm `content` đúng vào trường cần, tránh false positive và tăng tốc (không scan toàn payload).

**Chạy thật trên file pcap:**

```bash
suricata -r capture.pcap -S local.rules -l ./out/
# Kết quả alert ở ./out/fast.log và eve.json (JSON, đầy đủ field)
cat ./out/fast.log
# 06/19/2026-10:00:01  [**] [1:9000001:1] ATT&CK T1071.001 ... [**] ...
```

---

## 15.12. Chia sẻ tình báo: STIX, TAXII, MISP

### 15.12.1. STIX 2.1 — ngôn ngữ mô tả CTI

**STIX (Structured Threat Information eXpression)** dùng **JSON**; mọi thứ là **SDO** (STIX Domain Object), **SRO** (Relationship Object), hoặc **SCO** (Cyber-observable Object).

**STIX Indicator (SDO) — từng trường:**

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2026-06-19T08:00:00.000Z",
  "modified": "2026-06-19T08:00:00.000Z",
  "name": "Malicious C2 domain",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'update-msft.com']",
  "pattern_type": "stix",
  "valid_from": "2026-06-19T00:00:00Z"
}
```

| Trường | Kích thước/Định dạng | Ý nghĩa |
|---|---|---|
| `type` | string | Loại object (`indicator`, `malware`, `threat-actor`...) |
| `id` | `type--UUIDv4` | Định danh toàn cục duy nhất |
| `created`/`modified` | ISO 8601 UTC (timestamp) | Versioning |
| `pattern` | STIX Patterning language | Biểu thức khớp observable |
| `pattern_type` | enum | `stix`, `snort`, `yara`, `sigma`... |

**STIX Pattern** là một mini-ngôn ngữ: `[file:hashes.'SHA-256' = 'abc...' AND file:size > 1024]`. Toán tử: `AND OR FOLLOWEDBY`, qualifier `WITHIN`, `REPEATS`. Vì sao tách `pattern` riêng: cho phép biểu diễn điều kiện phức hợp, không chỉ một IOC đơn.

### 15.12.2. TAXII 2.1 — giao thức vận chuyển STIX

**TAXII (Trusted Automated eXchange of Indicator Information)** là API **HTTPS REST** để trao đổi STIX. Mô hình: **Server → API Roots → Collections → Objects**.

| Endpoint | Method | Trả về |
|---|---|---|
| `/taxii2/` | GET | Discovery: liệt kê API roots |
| `/{api-root}/collections/` | GET | Danh sách collection |
| `/{api-root}/collections/{id}/objects/` | GET | Lấy STIX objects (hỗ trợ filter `?added_after=`) |
| `/{api-root}/collections/{id}/objects/` | POST | Đẩy object lên |

```bash
# Phải set Accept đúng media type TAXII 2.1
curl -s -H "Accept: application/taxii+json;version=2.1" \
     -u user:pass \
     "https://taxii.example.org/api1/collections/<id>/objects/?added_after=2026-06-18T00:00:00Z"
```

Header `Accept: application/taxii+json;version=2.1` là **bắt buộc** — server dùng nó để negotiate phiên bản; thiếu thì trả 406.

### 15.12.3. MISP — nền tảng chia sẻ thực dụng

**MISP** dùng mô hình **Event → Attribute → Object → Tag/Galaxy**.

| Khái niệm | Ý nghĩa |
|---|---|
| **Event** | Một sự kiện/chiến dịch (chứa nhiều attribute) |
| **Attribute** | Một IOC: `type` (ip-dst, domain, sha256, url...), `value`, `category`, `to_ids` (có đẩy ra IDS không) |
| **Object** | Nhóm attribute có cấu trúc (vd "file" gồm filename+md5+sha256) |
| **Galaxy / Cluster** | Tri thức ngữ cảnh; **MITRE ATT&CK được nhúng làm Galaxy** → gắn technique vào event |
| **Tag** | Nhãn (TLP, ATT&CK, threat-actor) |

**Trường `to_ids` quan trọng:** `true` = IOC đủ tin cậy để đẩy thành rule IDS/SIEM; `false` = chỉ ngữ cảnh, không tự động chặn (tránh false positive).

**TLP (Traffic Light Protocol)** điều khiển chia sẻ:

| Tag | Chia sẻ tới |
|---|---|
| `tlp:red` | Chỉ người nhận trực tiếp |
| `tlp:amber` | Tổ chức + đối tác cần biết |
| `tlp:amber+strict` | Chỉ trong tổ chức |
| `tlp:green` | Cộng đồng, không công khai |
| `tlp:clear` (trước là white) | Công khai |

**Ví dụ thật — tạo event + thêm attribute qua REST API (PyMISP):**

```python
from pymisp import PyMISP, MISPEvent, MISPAttribute

misp = PyMISP("https://misp.local", "<AUTH_KEY>", ssl=False)

ev = MISPEvent()
ev.info = "FIN7 phishing campaign June 2026"
ev.distribution = 1          # 1 = This community only
ev.threat_level_id = 2       # 1=High,2=Medium,3=Low,4=Undefined
ev.analysis = 1              # 0=Initial,1=Ongoing,2=Completed
ev.add_tag("tlp:amber")
ev.add_tag('misp-galaxy:mitre-attack-pattern="OS Credential Dumping - T1003"')

ev.add_attribute("domain", "update-msft.com", to_ids=True,
                 category="Network activity")
ev.add_attribute("sha256",
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                 to_ids=True, category="Payload delivery")

created = misp.add_event(ev, pythonify=True)
print(created.id)
```

Hoặc thuần HTTP:

```bash
curl -s https://misp.local/events/add \
  -H "Authorization: <AUTH_KEY>" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  -d '{"Event":{"info":"Test","distribution":"0","threat_level_id":"2",
        "analysis":"0",
        "Attribute":[{"type":"ip-dst","value":"185.220.101.45","to_ids":true}]}}'
```

---

## 15.13. Phân loại Malware

| Loại | Cơ chế lan/định nghĩa | Cần host? | Tự nhân? | ATT&CK liên quan |
|---|---|---|---|---|
| **Virus** | Chèn code vào file/chương trình khác; chạy khi host chạy | Có | Có (qua host) | T1204 User Execution |
| **Worm** | Tự lan qua mạng/lỗ hổng, không cần người dùng | Không | Có (tự động) | T1210 Exploit Remote Services |
| **Trojan** | Giả phần mềm hợp lệ, mở cửa hậu | — | Không | T1036 Masquerading |
| **Ransomware** | Mã hóa dữ liệu, đòi tiền chuộc | — | Có thể | **T1486** Data Encrypted for Impact |
| **Rootkit** | Ẩn sự hiện diện (kernel/bootkit), hook API | — | Không | T1014 Rootkit |
| **RAT** | Remote Access Trojan: điều khiển từ xa toàn diện | — | Không | T1219 Remote Access Software |
| **Botnet** | Mạng máy bị nhiễm điều khiển tập trung (DDoS/spam) | — | Có | T1583.005 Botnet |
| **Fileless** | Sống trong bộ nhớ/registry/WMI, ít/không chạm đĩa | Không | — | T1059, T1047 WMI, T1620 Reflective Loading |

**Vì sao fileless khó phát hiện:** không có file để AV quét hash/signature → phải phát hiện ở mức **hành vi** (IOA): PowerShell tải code vào RAM, WMI event subscription làm persistence, registry chứa payload base64. Đây minh họa trực tiếp Pyramid of Pain — buộc Blue Team lên tầng TTP.

---

## 15.14. Phân tích Malware cơ bản

### 15.14.1. Static Analysis (không chạy mẫu)

**Strings** — trích chuỗi ASCII/Unicode để tìm dấu vết (URL, IP, lệnh, mutex):

```bash
strings -n 8 sample.exe | grep -Ei 'http|\.exe|powershell|HKEY|cmd'
strings -e l sample.exe          # -e l = little-endian 16-bit (Unicode/UTF-16)
```

`-n 8` chỉ lấy chuỗi ≥ 8 ký tự (giảm nhiễu); `-e l` cần thiết vì Windows hay dùng chuỗi UTF-16LE mà mặc định `strings` bỏ qua.

**PE Header — cấu trúc file thực thi Windows (đào tới byte):**

Một file PE bố cục như sau (offset từ đầu file):

```
Offset 0x00  ┌────────────────────────┐
             │ DOS Header (IMAGE_DOS_HEADER, 64 bytes) │
             │   e_magic  = "MZ" (0x4D5A)              │  ← 2 bytes, offset 0x00
             │   e_lfanew = offset tới PE header       │  ← 4 bytes, offset 0x3C
0x3C ───────►│                                          │
             ├────────────────────────┤
e_lfanew ──► │ PE Signature "PE\0\0" (0x50450000)       │  ← 4 bytes
             ├────────────────────────┤
             │ COFF File Header (IMAGE_FILE_HEADER, 20B)│
             │   Machine          (2B)  0x8664=x64      │
             │   NumberOfSections (2B)                  │
             │   TimeDateStamp    (4B)  epoch compile   │
             │   ... SizeOfOptionalHeader (2B)          │
             │   Characteristics  (2B)                  │
             ├────────────────────────┤
             │ Optional Header (PE32: 224B / PE32+:240B)│
             │   Magic (2B) 0x10B=PE32, 0x20B=PE32+     │
             │   AddressOfEntryPoint (4B) RVA           │
             │   ImageBase, SectionAlignment, ...       │
             │   Subsystem (2B) 2=GUI,3=CUI             │
             │   DataDirectory[16] (Import, Export...)  │
             ├────────────────────────┤
             │ Section Table (mỗi entry 40 bytes)       │
             │   .text  .data  .rdata  .rsrc            │
             └────────────────────────┘
```

| Trường | Offset | Kích thước | Ý nghĩa | Giá trị ví dụ |
|---|---|---|---|---|
| `e_magic` | 0x00 | 2 B | Chữ ký DOS | `4D 5A` ("MZ") |
| `e_lfanew` | 0x3C | 4 B | Offset tới PE header | `0x000000E8` |
| PE signature | e_lfanew | 4 B | `50 45 00 00` ("PE\0\0") | — |
| `Machine` | +0x04 | 2 B | Kiến trúc | `0x8664` (x64), `0x014C` (x86) |
| `NumberOfSections` | +0x06 | 2 B | Số section | `5` |
| `TimeDateStamp` | +0x08 | 4 B | Thời điểm compile (epoch) | `0x5F2A...` |
| `Magic` (Opt.) | +0x18 | 2 B | PE32 vs PE32+ | `0x010B` / `0x020B` |
| `AddressOfEntryPoint` | Opt+0x10 | 4 B | RVA điểm vào code | `0x1500` |
| `Subsystem` | Opt | 2 B | GUI/Console | `2`=GUI, `3`=Console |

**Vì sao đọc PE header có giá trị forensic:**
- `TimeDateStamp` lệch vô lý (tương lai/quá khứ xa) → có thể bị giả mạo (anti-forensics).
- Section có **RawSize ≈ 0 nhưng VirtualSize lớn** + entropy cao → dấu hiệu **packed** (UPX, themida).
- **Imports nghèo nàn** (chỉ `LoadLibrary`+`GetProcAddress`) → import resolution động → packed/obfuscated.

```bash
# Phân tích PE bằng pefile (Python)
python3 - <<'PY'
import pefile, math
pe = pefile.PE("sample.exe")
print("Machine:", hex(pe.FILE_HEADER.Machine))
print("Compile time:", pe.FILE_HEADER.TimeDateStamp)
print("EntryPoint RVA:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
for s in pe.sections:
    data = s.get_data()
    ent = 0
    if data:
        from collections import Counter
        for c in Counter(data).values():
            p = c/len(data); ent -= p*math.log2(p)
    print(s.Name.decode(errors='replace').strip('\x00'),
          "vsize=%#x rawsize=%#x entropy=%.2f" %
          (s.Misc_VirtualSize, s.SizeOfRawData, ent))
PY
```

Entropy > ~7.0 trên một section thực thi gợi ý dữ liệu nén/mã hóa (packed). Đây là heuristic quan trọng trong triage.

**Hashing & lookup:**

```bash
sha256sum sample.exe                # hash để tra VirusTotal/MISP
# Import hash (imphash) – đặc trưng theo bảng import, gom biến thể cùng builder
python3 -c "import pefile;print(pefile.PE('sample.exe').get_imphash())"
```

`imphash` (import hash) bền hơn file hash vì các mẫu cùng "builder" thường có cùng thứ tự import → gom được biến thể (mức Tools trên Pyramid of Pain).

### 15.14.2. Dynamic Analysis (chạy trong sandbox)

**Là gì:** chạy mẫu trong môi trường cô lập (VM snapshot, không có route ra Internet thật hoặc dùng INetSim giả lập), thu hành vi: tiến trình tạo, file ghi, registry, kết nối mạng, API call.

**Setup an toàn — vì sao:**
- VM **không nối mạng sản xuất**; snapshot để revert.
- **INetSim/FakeNet** giả lập DNS/HTTP để mẫu "tin" là online → lộ C2 mà không thật sự kết nối ra ngoài.
- Tránh sandbox-aware malware: nhiều mẫu kiểm tra `VMware`, số CPU, `sbiedll.dll`, sleep dài để né.

**Công cụ & lệnh thật:**

```bash
# 1. Giả lập dịch vụ mạng (Linux phân tích)
inetsim                          # log DNS query, HTTP request mẫu gửi đi

# 2. Theo dõi hệ thống call (Linux ELF)
strace -f -e trace=network,file ./sample 2>strace.log

# 3. Procmon (Windows) — lọc:
#    Operation = Process Create / RegSetValue / WriteFile
#    → xuất CSV để map sang ATT&CK
```

**Đầu ra mẫu (Procmon) → map ATT&CK:**

```
winword.exe → Process Create powershell.exe -enc ...   → T1059.001
powershell  → WriteFile %APPDATA%\Microsoft\svchost.exe → T1105 Ingress Tool Transfer
powershell  → RegSetValue HKCU\...\Run\Updater          → T1547.001 Registry Run Key
svchost.exe → TCP Connect 185.220.101.45:443            → T1071.001 / T1041
```

**Báo cáo Cuckoo/CAPE Sandbox** tự động hóa: chạy mẫu, hook API, trả JSON gồm danh sách hành vi + **đã tự map sang ATT&CK technique** (`ttps` trong report). CAPE còn dump payload đã giải nén (unpacked) từ bộ nhớ — hữu ích vì static analysis trên mẫu packed vô dụng.

---

## 15.15. Tổng hợp: vòng đời tấn công ↔ dấu hiệu phát hiện

Bảng tra cứu nhanh nối **giai đoạn → technique → telemetry → detection**:

| Giai đoạn | Technique tiêu biểu | Nguồn telemetry | Dấu hiệu / Rule |
|---|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment | Email gateway, EDR | Office spawn script (IOA) |
| Execution | T1059.001 PowerShell | EID 4104, Sysmon 1 | `-enc`, `IEX`, `DownloadString` |
| Persistence | T1547.001 Run Key | Sysmon 13 (RegSet) | Ghi `...\CurrentVersion\Run` |
| Priv Esc | T1068 Exploit for PrivEsc | EDR, kernel log | Token manipulation, crash dump |
| Defense Evasion | T1070.001 Clear Windows Event Logs | EID 1102 | Audit log bị xóa |
| Credential Access | T1003.001 LSASS | Sysmon 10 | GrantedAccess `0x1010` tới lsass |
| Discovery | T1018 Remote System Discovery | Sysmon 1 | `net view`, `nltest /dclist` |
| Lateral Movement | T1021.002 SMB/Admin Shares | EID 4624 Type 3, 7045 | PSEXESVC service tạo |
| Collection | T1560 Archive Collected Data | Sysmon 11 | `rar.exe a -hp`, 7zip |
| C2 | T1071.001 Web Protocols | Proxy, NetFlow, Zeek | Beaconing, JA3 khớp |
| Exfiltration | T1041 Exfil over C2 | NetFlow | bytes_out >> bytes_in |
| Impact | T1486 Data Encrypted | Sysmon 11, EDR | Đổi tên đuôi hàng loạt, xóa shadow copy (T1490 `vssadmin delete shadows`) |

**Nguyên tắc detection engineering:**
1. Map mọi rule → ATT&CK ID (cho đo coverage trong Navigator).
2. Ưu tiên TTP (đỉnh Pyramid) hơn IOC (đáy).
3. Một technique nên có **nhiều rule ở nhiều data source** (defense in depth detection) — vd LSASS dump phát hiện cả qua Sysmon 10 lẫn EDR memory scan.
4. Theo dõi **false positive** qua trường `falsepositives` của Sigma; rule không tinh chỉnh sẽ bị bỏ qua (alert fatigue).
5. Đóng vòng lặp: dùng feedback từ IR thực tế (Diamond Model pivot) để tạo PIR mới → cập nhật collection (CTI lifecycle).

---

## 15.16. Lưu ý bảo mật & vận hành tổng kết

- **IOC mau hỏng**: tự động hết hạn IOC technical (qua `valid_from`/TTL trong STIX, hoặc decay model của MISP) để tránh phình danh sách block và FP.
- **`to_ids` phải có người duyệt**: đừng auto-block mọi IOC nhận từ feed — một domain hợp lệ bị gắn nhầm có thể gây outage.
- **TLP nghiêm ngặt**: rò rỉ tình báo `tlp:red` có thể tiết lộ nguồn/nạn nhân; thực thi TLP ở cả con người và hệ thống chia sẻ.
- **ATT&CK không phải checklist tuân thủ**: "100% coverage" là ảo tưởng — technique luôn mở rộng và procedure vô hạn; coverage chỉ là công cụ ưu tiên, không phải đích.
- **Phân tích malware = hoạt động rủi ro**: luôn cô lập mạng, dùng VM throwaway, không phân tích mẫu live trên máy nối mạng sản xuất.
- **Threat-informed defense**: chọn các nhóm APT thực sự nhắm ngành mình (qua report/ISAC), lấy layer ATT&CK của họ, ưu tiên detection theo đó thay vì cố phủ toàn ma trận.

---

### Tài liệu nên kiểm chứng khi trích dẫn chính xác
- Số tactic/technique và ID cụ thể thay đổi theo từng phiên bản ATT&CK — luôn đối chiếu `attack.mitre.org` và `versions.attack` trong layer.
- Số giai đoạn Unified Kill Chain (18) và chi tiết STIX media types nên kiểm lại theo bản đặc tả gốc (OASIS STIX/TAXII 2.1) trước khi dùng trong tài liệu chính thức.
