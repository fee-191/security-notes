# Chương 16 — Tuân thủ & Quản trị (GRC)

## Tổng quan

**GRC (Governance, Risk, Compliance)** là khuôn khổ để một tổ chức tự quản lý hoạt động an toàn thông tin. Nó trả lời ba câu hỏi: ai chịu trách nhiệm, rủi ro nào cần ưu tiên, và bằng chứng nào chứng minh tổ chức tuân thủ với cơ quan quản lý, khách hàng và đối tác.

Bảo mật không chỉ là vấn đề kỹ thuật (firewall, mã hóa) mà còn là vấn đề **trách nhiệm và bằng chứng**. Khi xảy ra sự cố mà thiếu hồ sơ chứng minh đã thực hiện đúng quy trình, tổ chức có thể bị xử phạt, mất chứng chỉ hoặc chịu trách nhiệm pháp lý. Kỹ thuật xây dựng hệ thống vững chắc; GRC bảo đảm hệ thống đó có cơ sở pháp lý, hồ sơ vận hành và phân định trách nhiệm rõ ràng.

Chương này bao gồm các khối kiến thức sau:

- **GRC** — ba lớp lồng nhau. **Governance (quản trị)** là lớp ngoài: lãnh đạo đặt luật chơi, xác định khẩu vị rủi ro (risk appetite) và thẩm quyền quyết định. **Risk (rủi ro)** là lớp giữa: đánh giá điều gì có thể hỏng và mức thiệt hại. **Compliance (tuân thủ)** là lớp trong: chứng minh tuân thủ các tiêu chuẩn và luật. Thiếu quản trị tập trung, mỗi đội làm theo cách riêng, rủi ro tồn dư không được theo dõi, và không có hồ sơ khi bị kiểm toán.
- **Quản lý rủi ro (Risk Management)** — rủi ro hình thành từ chuỗi **tài sản → mối đe dọa → điểm yếu → tác động × khả năng xảy ra**. Đo lường theo hai cách: **định lượng** (gán giá trị tiền: SLE, ARO, ALE) để so sánh chi phí kiểm soát, và **định tính** (chấm thang 1–5 likelihood × impact) khi thiếu số liệu tài chính. Xử lý rủi ro có 4 lựa chọn: **giảm thiểu (mitigate), chuyển giao (transfer), né tránh (avoid), chấp nhận (accept)** — phần rủi ro còn lại sau khi xử lý gọi là **residual risk (rủi ro tồn dư)**, và mọi rủi ro tồn dư phải có risk owner ký chấp nhận chính thức. **Risk Register** là kho trung tâm theo dõi mọi rủi ro kèm chủ sở hữu và hạn xử lý.
- **NIST Cybersecurity Framework (CSF)** — khung tự nguyện cung cấp ngôn ngữ chung để mô tả tình trạng an ninh, chia thành 6 Function (CSF 2.0): **Govern, Identify, Protect, Detect, Respond, Recover**. CSF xác định *cần làm gì* chứ không quy định *công nghệ cụ thể*.
- **NIST Special Publications** — **SP 800-53** là catalog control chi tiết (trả lời câu hỏi cụ thể mà CSF để ngỏ). **SP 800-61** là quy trình ứng phó sự cố: chuẩn bị → phát hiện và phân tích → khoanh vùng/diệt/phục hồi → rút kinh nghiệm. **SP 800-207 (Zero Trust)** loại bỏ tin tưởng mặc định theo vị trí mạng; mỗi truy cập đều phải xác thực và đánh giá rủi ro lại.
- **ISO/IEC 27001 & 27002** — **27001** là tiêu chuẩn quốc tế cho Hệ thống quản lý an toàn thông tin (ISMS), **có chứng nhận** bởi bên thứ ba. **27002** là code of practice hướng dẫn triển khai từng control. Tài liệu trung tâm là **SoA (Statement of Applicability)** — liệt kê mọi control kèm lý do áp dụng hay loại trừ, là điểm xuất phát của auditor.
- **PCI DSS** — tiêu chuẩn bắt buộc theo hợp đồng (không phải luật) cho mọi tổ chức lưu, xử lý hoặc truyền dữ liệu thẻ thanh toán; gồm 12 yêu cầu. Quy tắc cốt lõi: Sensitive Authentication Data (CVV, dữ liệu dải từ, PIN) **tuyệt đối không được lưu** sau khi authorize. **Tokenization** thay số thẻ thật bằng token vô nghĩa để giảm phạm vi tuân thủ.
- **Pháp lý Việt Nam** — bốn văn bản chính: **Luật An toàn thông tin mạng 2015** (khung kỹ thuật nền), **Luật An ninh mạng 2018** (an ninh quốc gia, yêu cầu lưu dữ liệu trong nước), **Nghị định 85/2016** (phân loại hệ thống thành 5 cấp độ), **Nghị định 13/2023** (bảo vệ dữ liệu cá nhân, tương tự GDPR). Đây là quy định pháp luật bắt buộc; việc xác định cấp độ hệ thống và xin sự đồng ý (consent) khi thu thập dữ liệu cá nhân quyết định thiết kế hệ thống và nơi lưu trữ dữ liệu.
- **Vận hành tuân thủ (Operational Compliance)** — biến framework thành thao tác hằng ngày: phân loại dữ liệu (data classification) để biết áp control nào, audit trail dạng hash chain chống chối bỏ, log retention và data residency, và crosswalk ánh xạ một control sang nhiều framework để khỏi làm trùng.
- **GRC ngân hàng/tài chính** — đặc thù ngành: **Three Lines Model** tách trách nhiệm vận hành / giám sát / kiểm toán độc lập, khung giám sát của Ngân hàng Nhà nước và Luật Phòng chống rửa tiền, và continuous compliance (policy-as-code chạy trong CI/CD, fail-closed).

Các mục dưới đây trình bày chi tiết kỹ thuật cho từng khối.

> Chương này dành cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps) cần tra cứu và vận hành thực tế. Mỗi khái niệm đi theo trình tự: **là gì → cơ chế bên trong (tới mức trường/bước/tham số) → ví dụ thực tế chạy được → lưu ý bảo mật**. Các điều khoản pháp lý Việt Nam được trình bày ở mức **ý nghĩa vận hành**; chỗ nào số hiệu/điều khoản cần kiểm chứng sẽ được ghi rõ `[CẦN KIỂM CHỨNG]` thay vì bịa.

---

## 16.0. Bản đồ chương và mô hình GRC tổng thể

GRC = **Governance, Risk, Compliance**. Đây không phải ba thứ rời rạc mà là ba lớp lồng nhau:

```
+------------------------------------------------------------------+
|  GOVERNANCE (Quản trị)                                            |
|  - Ai chịu trách nhiệm? Khẩu vị rủi ro (risk appetite)?           |
|  - Chính sách (policy), tiêu chuẩn (standard), quy trình (proc)   |
|   +-----------------------------------------------------------+   |
|   |  RISK MANAGEMENT (Quản lý rủi ro)                          |  |
|   |  asset -> threat -> vuln -> likelihood x impact -> risk    |  |
|   |  -> treat (accept/mitigate/transfer/avoid) -> register     |  |
|   |   +----------------------------------------------------+   |  |
|   |   |  COMPLIANCE (Tuân thủ)                              |  |  |
|   |   |  Ánh xạ control -> framework -> chứng cứ -> audit   |  |  |
|   |   |  NIST CSF/800-53/800-61/800-207, ISO 27001/27002,  |  |  |
|   |   |  PCI DSS, Luật ATTT/ANM, NĐ 85/2016, NĐ 13/2023    |  |  |
|   |   +----------------------------------------------------+   |  |
|   +-----------------------------------------------------------+   |
+------------------------------------------------------------------+
```

**Phân biệt 4 tầng tài liệu quản trị** (rất hay bị nhầm lẫn — bảng dưới là chuẩn dùng trong ISMS):

| Tầng | Tên tiếng Anh | Tính chất | Ví dụ |
|------|---------------|-----------|-------|
| 1 | Policy (chính sách) | "Phải làm gì" — bắt buộc, do lãnh đạo phê duyệt | "Mọi dữ liệu cá nhân phải được mã hóa khi lưu trữ" |
| 2 | Standard (tiêu chuẩn) | "Bằng công nghệ/thông số nào" — bắt buộc | "Mã hóa at-rest dùng AES-256-GCM" |
| 3 | Procedure (quy trình) | "Làm theo các bước nào" — bắt buộc | "Quy trình xoay khóa KMS mỗi 90 ngày: bước 1..n" |
| 4 | Guideline (hướng dẫn) | "Nên làm" — khuyến nghị | "Nên dùng envelope encryption" |

**Vì sao tách 4 tầng?** Để policy ổn định lâu dài (ít thay đổi → ít phải tái phê duyệt cấp lãnh đạo), trong khi standard/procedure thay đổi theo công nghệ. Nếu nhét "AES-256" vào policy thì mỗi lần đổi thuật toán phải đưa cả Board ký lại — không khả thi.

---

## 16.1. Quản lý rủi ro (Risk Management)

Quản lý rủi ro là một chu trình lặp, không phải hoạt động một lần. Sơ đồ dưới đây tóm tắt quy trình từ thiết lập bối cảnh đến giám sát liên tục (ánh xạ với ISO 31000 và NIST RMF):

```
   ┌──────────────────────────────────────────────────────────┐
   │  ① THIẾT LẬP BỐI CẢNH (scope, risk appetite)             │
   └───────────────────────────────┬──────────────────────────┘
                                   ▼
   ┌──────────────────────────────────────────────────────────┐
   │  ② NHẬN DIỆN RỦI RO                                       │
   │     asset → threat → vulnerability                       │
   └───────────────────────────────┬──────────────────────────┘
                                   ▼
   ┌──────────────────────────────────────────────────────────┐
   │  ③ PHÂN TÍCH & ĐÁNH GIÁ                                   │
   │     Inherent risk = Likelihood × Impact                  │
   │     (định lượng SLE/ALE  hoặc  định tính 5×5)            │
   └───────────────────────────────┬──────────────────────────┘
                                   ▼
   ┌──────────────────────────────────────────────────────────┐
   │  ④ XỬ LÝ RỦI RO (4 lựa chọn)                              │
   │     mitigate | transfer | avoid | accept                 │
   │     → còn lại residual risk (rủi ro tồn dư)              │
   └───────────────────────────────┬──────────────────────────┘
                                   ▼
   ┌──────────────────────────────────────────────────────────┐
   │  ⑤ GHI NHẬN vào RISK REGISTER + risk owner ký            │
   └───────────────────────────────┬──────────────────────────┘
                                   ▼
   ┌──────────────────────────────────────────────────────────┐
   │  ⑥ GIÁM SÁT & SOÁT XÉT ĐỊNH KỲ                            │
   └───────────────────────────────┬──────────────────────────┘
                                   │
   └───────────────────────────────┘  (vòng lặp: quay lại ② —
        residual risk được tái đánh giá định kỳ)
```

Chú thích: rủi ro được giảm dần qua từng vòng (inherent → residual), nhưng không bao giờ về 0 — phần tồn dư phải được một người có thẩm quyền chấp nhận chính thức. Vòng giám sát đóng lại chu trình: register lỗi thời tạo cảm giác an toàn giả nên phải soát xét định kỳ.

### 16.1.1. Chuỗi nhân quả: asset → threat → vulnerability → risk

**Là gì.** Rủi ro không tự sinh ra. Nó là kết quả của một chuỗi: có **tài sản** (asset) giá trị → tồn tại **mối đe dọa** (threat) muốn/có thể gây hại → tài sản có **điểm yếu** (vulnerability) để mối đe dọa khai thác → khi khai thác thành công gây **tác động** (impact) với một **khả năng xảy ra** (likelihood). Risk = hàm của likelihood và impact.

**Cơ chế — định nghĩa chính xác từng thành phần:**

| Thành phần | Định nghĩa vận hành | Ví dụ trên hệ thống sàn giao dịch (CEX) |
|------------|---------------------|------------------------------------------|
| Asset | Thứ có giá trị cần bảo vệ (data, hệ thống, danh tiếng) | DB chứa private key ví nóng (hot wallet) |
| Threat | Tác nhân + hành động có thể gây hại | Nhóm APT nhắm ví nóng để rút tiền |
| Threat actor | Chủ thể (con người/automation) | APT38 (Lazarus) |
| Vulnerability | Điểm yếu cho phép threat thành công | RPC node lộ ra Internet, không filter `eth_sendRawTransaction` |
| Exploit | Cách hiện thực hóa việc khai thác vuln | Gửi tx ký sẵn qua RPC bị lộ |
| Impact | Hậu quả nếu xảy ra (tiền/uy tín/pháp lý) | Mất 50 triệu USD coin |
| Likelihood | Xác suất/tần suất xảy ra | "Trung bình–cao" hoặc ARO=0.3/năm |
| Control | Biện pháp giảm likelihood hoặc impact | HSM ký giao dịch, allowlist RPC, MPC |

**Công thức khái niệm:**

```
Inherent Risk  = Likelihood(chưa control) x Impact(chưa control)
Residual Risk  = Likelihood(sau control)  x Impact(sau control)
Risk Treatment làm việc trên khoảng cách: Inherent - Residual
```

**Lưu ý bảo mật.** Sai lầm phổ biến: đánh giá rủi ro chỉ trên *vulnerability* (kết quả scan) mà bỏ asset value. Một CVE 9.8 trên máy in nội bộ không có dữ liệu nhạy cảm có residual risk thấp hơn một CVE 6.5 trên gateway thanh toán. Luôn nhân với *impact lên asset*, không xếp hạng thuần theo CVSS.

### 16.1.2. Định lượng (Quantitative): SLE, ARO, ALE

**Là gì.** Phương pháp gán **giá trị tiền** cho rủi ro để so sánh khách quan và biện minh chi phí kiểm soát (cost-benefit). Bộ ba thuật ngữ chuẩn (NIST/(ISC)² CISSP):

| Ký hiệu | Tên đầy đủ | Đơn vị | Công thức |
|---------|-----------|--------|-----------|
| AV | Asset Value | tiền | nhập trực tiếp |
| EF | Exposure Factor | % (0–1) | tỷ lệ asset bị mất trong 1 sự kiện |
| SLE | Single Loss Expectancy | tiền | `SLE = AV × EF` |
| ARO | Annualized Rate of Occurrence | lần/năm | tần suất sự kiện/năm |
| ALE | Annualized Loss Expectancy | tiền/năm | `ALE = SLE × ARO` |

**Ví dụ thực tế tính tay.** Asset = cụm web e-commerce, AV = 2.000.000 USD. Sự cố ransomware làm gián đoạn 30% doanh thu/sự kiện → EF = 0.30.

```
SLE = AV × EF = 2.000.000 × 0.30 = 600.000 USD / sự kiện
Giả định ARO = 0.5  (cứ 2 năm 1 lần)
ALE = SLE × ARO = 600.000 × 0.5 = 300.000 USD / năm
```

**Quyết định đầu tư control (cost-benefit):** Nếu mua giải pháp EDR + backup tốn 80.000 USD/năm và làm ARO giảm còn 0.1:

```
ALE_mới  = 600.000 × 0.1 = 60.000 USD/năm
ALE_giảm = 300.000 - 60.000 = 240.000 USD/năm  (tiết kiệm rủi ro)
ROSI (Return On Security Investment) = (240.000 - 80.000) / 80.000 = 200%
```

**Script tính nhanh (chạy được, Python 3):**

```python
#!/usr/bin/env python3
# ale_calc.py — tính SLE/ALE và ROSI cho cost-benefit control
def ale(av, ef, aro):
    sle = av * ef
    return sle, sle * aro

def rosi(ale_before, ale_after, control_cost):
    benefit = ale_before - ale_after
    return (benefit - control_cost) / control_cost

av, ef, aro = 2_000_000, 0.30, 0.5
sle, ale_b = ale(av, ef, aro)
_, ale_a   = ale(av, ef, 0.1)
print(f"SLE      = {sle:,.0f} USD/event")
print(f"ALE base = {ale_b:,.0f} USD/yr")
print(f"ALE post = {ale_a:,.0f} USD/yr")
print(f"ROSI     = {rosi(ale_b, ale_a, 80_000):.0%}")
```

Output mẫu:

```
SLE      = 600,000 USD/event
ALE base = 300,000 USD/yr
ALE post = 60,000 USD/yr
ROSI     = 200%
```

**Lưu ý bảo mật.** Định lượng nghe khoa học nhưng **EF và ARO thường là phỏng đoán**. Dùng nó để *so sánh tương đối* các phương án, không để báo cáo "rủi ro chính xác 300.000 USD" — đó là giả khoa học. Với rủi ro đuôi dài (tail risk) như mất toàn bộ khóa ví lạnh, ALE đánh giá thấp vì ARO cực nhỏ × impact cực lớn → nên dùng phân tích kịch bản riêng.

### 16.1.3. Định tính (Qualitative): ma trận likelihood × impact

**Là gì.** Khi không có dữ liệu tiền cậy, dùng thang định tính (thường 5×5). Mỗi trục 1–5, risk score = tích, ánh xạ sang vùng màu.

```
IMPACT →        1-Insig  2-Minor  3-Mod   4-Major  5-Severe
LIKELIHOOD ↓
5-Almost Certain   5       10       15      20       25
4-Likely           4        8       12      16       20
3-Possible         3        6        9      12       15
2-Unlikely         2        4        6       8       10
1-Rare             1        2        3       4        5

Vùng:  1-4 = Low (xanh)  |  5-9 = Medium (vàng)
       10-15 = High (cam) | 16-25 = Critical (đỏ)
```

**Bảng định nghĩa thang (phải viết ra cụ thể, nếu không mỗi người chấm khác nhau):**

| Mức | Likelihood (định nghĩa) | Impact (định nghĩa tài chính/vận hành) |
|-----|--------------------------|-----------------------------------------|
| 5 | Xảy ra >1 lần/năm | Mất >1% doanh thu năm HOẶC vi phạm pháp luật bị phạt |
| 4 | 1 lần/1–2 năm | Gián đoạn dịch vụ chính >4h |
| 3 | 1 lần/2–5 năm | Gián đoạn nội bộ, phục hồi trong ngày |
| 2 | 1 lần/5–10 năm | Ảnh hưởng nhỏ, 1 đội |
| 1 | Hầu như không | Không đáng kể |

### 16.1.4. Xử lý rủi ro (Risk Treatment): 4 lựa chọn

| Chiến lược | Ý nghĩa | Khi nào dùng | Ví dụ |
|-----------|---------|--------------|-------|
| **Mitigate** (giảm thiểu) | Thêm control để giảm L hoặc I | Rủi ro trên ngưỡng, có control khả thi | WAF, MFA, mã hóa |
| **Transfer** (chuyển giao) | Chuyển hậu quả tài chính cho bên khác | Impact lớn, khó tự giảm | Mua bảo hiểm cyber; thuê SaaS có SLA |
| **Avoid** (né tránh) | Bỏ hoạt động sinh rủi ro | Rủi ro vượt khẩu vị, không bù được lợi ích | Ngừng lưu số thẻ tín dụng |
| **Accept** (chấp nhận) | Giữ nguyên, ghi nhận chính thức | Residual ≤ risk appetite | Chấp nhận rủi ro thấp có chữ ký risk owner |

**Vì sao phải có "Accept" chính thức?** Mọi rủi ro tồn dư bắt buộc có **risk owner** ký chấp nhận. Đây là điểm pháp lý/quản trị then chốt: nếu sự cố xảy ra, tài liệu chứng minh rủi ro đã được nhận biết và một người có thẩm quyền đã quyết định chấp nhận — chứ không phải "không ai biết".

### 16.1.5. Risk Register — cấu trúc bản ghi tới từng trường

**Là gì.** Sổ đăng ký rủi ro — kho trung tâm theo dõi mọi rủi ro. Mỗi dòng = một rủi ro. Dưới đây là schema chuẩn (CSV) tới từng trường:

| Trường | Kiểu/Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------------|---------|-------|
| `risk_id` | string, vd RISK-0001 | Định danh duy nhất | RISK-0042 |
| `asset` | text | Tài sản liên quan | Hot wallet signing service |
| `threat` | text | Mối đe dọa | Key exfiltration bởi attacker |
| `vulnerability` | text | Điểm yếu | RPC không allowlist |
| `likelihood_inherent` | int 1–5 | L trước control | 4 |
| `impact_inherent` | int 1–5 | I trước control | 5 |
| `inherent_score` | int (L×I) | Điểm rủi ro gốc | 20 |
| `existing_controls` | text | Control hiện có | HSM, network ACL |
| `likelihood_residual` | int 1–5 | L sau control | 2 |
| `impact_residual` | int 1–5 | I sau control | 5 |
| `residual_score` | int | Điểm tồn dư | 10 |
| `treatment` | enum | mitigate/transfer/avoid/accept | mitigate |
| `risk_owner` | string | Người chịu trách nhiệm | CISO |
| `target_date` | date ISO-8601 | Hạn xử lý | 2026-09-30 |
| `status` | enum | open/in_progress/closed/accepted | in_progress |
| `last_review` | date | Lần soát gần nhất | 2026-06-01 |

**Ví dụ thực tế — file `risk_register.csv`:**

```csv
risk_id,asset,threat,vulnerability,L_inh,I_inh,inh_score,controls,L_res,I_res,res_score,treatment,owner,target_date,status
RISK-0042,Hot wallet signer,Key exfiltration,RPC no allowlist,4,5,20,"HSM; net ACL",2,5,10,mitigate,CISO,2026-09-30,in_progress
RISK-0043,KYC PII DB,Data breach,Unencrypted backup,3,5,15,"TDE; KMS",1,5,5,mitigate,DPO,2026-08-15,open
RISK-0044,Old TLS endpoint,MITM,TLS 1.0 enabled,3,3,9,"none",3,3,9,avoid,Infra Lead,2026-07-01,open
```

**Truy vấn vận hành (chạy được, dùng `q`/`csvkit` hoặc awk):**

```bash
# Liệt kê các rủi ro residual >= 10 (High/Critical) còn open, dùng awk
awk -F',' 'NR>1 && $11>=10 && $15!="closed" {print $1": "$2" (res="$11", owner="$13")"}' risk_register.csv
```

Output:

```
RISK-0042: Hot wallet signer (res=10, owner=CISO)
```

**Lưu ý bảo mật.** Risk register là tài liệu nhạy cảm — nó vẽ bản đồ điểm yếu cho attacker. Phải kiểm soát truy cập (need-to-know), không để trong wiki mở. Đồng thời phải *sống*: review định kỳ (vd hàng quý) — register lỗi thời còn nguy hiểm hơn không có vì tạo cảm giác an toàn giả.

---

## 16.2. NIST Cybersecurity Framework (CSF)

### 16.2.1. Cấu trúc & 6 Functions (CSF 2.0)

**Là gì.** NIST CSF là khung tự nguyện, không phải checklist control mà là **ngôn ngữ chung** để mô tả tình trạng an ninh. CSF 1.1 có 5 Functions; **CSF 2.0 (phát hành 2024) thêm GOVERN** thành 6:

```
            +-------------------+
            |   GV - GOVERN     |  (mới ở 2.0, bao trùm các function khác)
            +---------+---------+
                      |
 +----------+ +-------+------+ +---------+ +----------+ +----------+
 | ID       | | PR           | | DE      | | RS       | | RC       |
 | IDENTIFY | | PROTECT      | | DETECT  | | RESPOND  | | RECOVER  |
 +----------+ +--------------+ +---------+ +----------+ +----------+
```

**Cấu trúc phân cấp 3 mức (rất quan trọng để map control):**

```
Function  (vd: PR - Protect)
  └─ Category   (vd: PR.AC - Identity Management & Access Control)
       └─ Subcategory  (vd: PR.AC-01 - Identities & credentials managed)
            └─ Informative References (ánh xạ sang 800-53, ISO 27001, CIS...)
```

| Mã | Function | Mục tiêu | Category tiêu biểu |
|----|----------|----------|---------------------|
| GV | Govern | Thiết lập & giám sát chiến lược an ninh, vai trò, chính sách, quản lý rủi ro chuỗi cung ứng | GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, GV.SC |
| ID | Identify | Hiểu tài sản, rủi ro, môi trường | ID.AM (Asset Mgmt), ID.RA (Risk Assessment) |
| PR | Protect | Biện pháp bảo vệ | PR.AC/PR.AA, PR.DS (Data Security), PR.PT |
| DE | Detect | Phát hiện sự kiện | DE.CM (Continuous Monitoring), DE.AE |
| RS | Respond | Ứng phó | RS.RP, RS.CO, RS.AN, RS.MI |
| RC | Recover | Phục hồi | RC.RP, RC.IM, RC.CO |

> `[CẦN KIỂM CHỨNG]` Mã category cụ thể giữa CSF 1.1 và 2.0 có thay đổi (vd PR.AC → PR.AA ở 2.0). Khi viết tài liệu chính thức nên đối chiếu bản CSF 2.0 mới nhất từ nist.gov.

### 16.2.2. Implementation Tiers & Profiles

**Tiers (1–4)** mô tả mức độ trưởng thành của quy trình quản lý rủi ro (KHÔNG phải mức điểm bảo mật):

| Tier | Tên | Đặc điểm |
|------|-----|----------|
| 1 | Partial | Phản ứng bị động, ad-hoc, không có quy trình |
| 2 | Risk Informed | Có nhận thức rủi ro nhưng chưa toàn tổ chức |
| 3 | Repeatable | Chính sách hóa, quy trình lặp lại, cập nhật định kỳ |
| 4 | Adaptive | Cải tiến liên tục, dùng lessons learned & predictive |

**Profile** = ánh xạ Functions/Categories phù hợp business cụ thể. So sánh **Current Profile** vs **Target Profile** để ra gap list.

**Ví dụ thực tế — file profile dạng JSON dùng để theo dõi gap:**

```json
{
  "organization": "CEX-Example",
  "csf_version": "2.0",
  "assessment_date": "2026-06-19",
  "subcategories": [
    { "id": "GV.SC-04", "desc": "Suppliers prioritized by criticality",
      "current_tier": 2, "target_tier": 4, "gap": 2, "owner": "Procurement" },
    { "id": "PR.DS-01", "desc": "Data-at-rest protected",
      "current_tier": 3, "target_tier": 4, "gap": 1, "owner": "Platform" },
    { "id": "DE.CM-01", "desc": "Networks monitored",
      "current_tier": 2, "target_tier": 3, "gap": 1, "owner": "SOC" }
  ]
}
```

```bash
# Liệt kê gap > 0, sắp xếp giảm dần — chạy được với jq
jq -r '.subcategories | sort_by(-.gap)[] | select(.gap>0)
       | "\(.id)\tgap=\(.gap)\towner=\(.owner)"' csf_profile.json
```

Output:

```
GV.SC-04	gap=2	owner=Procurement
PR.DS-01	gap=1	owner=Platform
DE.CM-01	gap=1	owner=SOC
```

**Lưu ý bảo mật.** CSF chỉ định khung; nó *không* nói "phải cấu hình AES-256". Để hành động cụ thể phải nhảy xuống Informative References → NIST SP 800-53 hoặc CIS Controls. Đừng dừng ở mức CSF rồi tưởng đã có control.

---

## 16.3. NIST Special Publications

### 16.3.1. SP 800-53 — Catalog of Security and Privacy Controls

**Là gì.** Bộ catalog control chi tiết nhất của NIST (Rev. 5). Bắt buộc cho hệ thống liên bang Mỹ (qua FISMA), được dùng rộng làm thư viện control. Tổ chức theo **control family** (20 họ ở Rev.5).

**Cấu trúc định danh control:**

```
   AC - 2 ( 3 )
   │    │   │
   │    │   └── Control Enhancement (tùy chọn, số trong ngoặc)
   │    └────── Control number trong family
   └─────────── Family identifier (2 chữ cái)

Ví dụ: AC-2(3) = Account Management, enhancement 3 (Disable Inactive Accounts)
```

**Bảng các họ control (selection):**

| Mã | Family | Lĩnh vực |
|----|--------|----------|
| AC | Access Control | Phân quyền, tài khoản, least privilege |
| AU | Audit and Accountability | Log, audit trail, time stamp |
| AT | Awareness and Training | Đào tạo |
| CM | Configuration Management | Baseline, hardening |
| CP | Contingency Planning | DR/BCP |
| IA | Identification and Authentication | Định danh, MFA |
| IR | Incident Response | Ứng phó sự cố |
| RA | Risk Assessment | Đánh giá rủi ro, scan |
| SC | System and Communications Protection | Crypto, network, boundary |
| SI | System and Information Integrity | Patch, AV, flaw remediation |
| SA | System and Services Acquisition | SDLC, supply chain |
| PM | Program Management | Quản lý chương trình |

> Rev.5 có **20 họ** (thêm các họ như PT - PII Processing, SR - Supply Chain Risk Management). `[CẦN KIỂM CHỨNG]` danh sách đầy đủ 20 họ nếu cần trích dẫn chính thức.

**Cấu trúc một control (anatomy) — ví dụ AU-2 Audit Events:**

```
Control:        AU-2 EVENT LOGGING
Statement (a):  Identify the types of events the system is capable of logging
Statement (b):  Coordinate the event logging function with other org entities...
Discussion:     [giải thích lý do]
Related:        AC-6, AU-3, AU-12, SI-4 ...
Enhancements:   AU-2(...) [Rev.5 đã withdraw một số]
Baseline:       LOW / MODERATE / HIGH allocation
```

**Baseline theo phân loại tác động (từ FIPS 199):** mỗi hệ thống được phân loại Low/Moderate/High cho mỗi mục tiêu CIA, control được chọn theo baseline tương ứng (SP 800-53B).

**Ví dụ thực tế — OSCAL.** NIST phát hành catalog 800-53 ở định dạng máy đọc **OSCAL** (JSON/XML/YAML). Đây là cách dùng thật trong DevSecOps để tự động hóa compliance:

```bash
# Tải catalog 800-53 Rev5 ở OSCAL JSON (repo công khai usnistgov/oscal-content)
# rồi trích control AU-2 bằng jq
jq -r '.catalog.groups[]?.controls[]?
        | select(.id=="au-2")
        | "\(.id | ascii_upcase): \(.title)"' \
   NIST_SP-800-53_rev5_catalog.json
```

Output mẫu:

```
AU-2: Event Logging
```

**Mapping control → cấu hình thật (ví dụ AU-2/AU-3 trên Linux auditd):** control nói "log sự kiện", còn cấu hình thật là file `/etc/audit/rules.d/audit.rules`:

```bash
# /etc/audit/rules.d/00-compliance.rules  (auditd)
# AU-2/AU-3: log mọi thay đổi cấu hình quyền & ghi nhận who/what/when
-w /etc/passwd  -p wa -k identity         # theo dõi sửa user
-w /etc/sudoers -p wa -k privilege        # thay đổi quyền sudo
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_cmd   # lệnh chạy với root
# AU-9: bảo vệ log khỏi sửa đổi
-e 2                                       # khóa cấu hình audit (immutable đến reboot)
```

Áp dụng và kiểm tra:

```bash
sudo augenrules --load            # nạp rule
sudo auditctl -l                  # liệt kê rule đang chạy
# tìm bản ghi liên quan key 'privilege'
sudo ausearch -k privilege --start today
```

**Lưu ý bảo mật.** Control `AU-9 Protection of Audit Information` đòi log không bị attacker sửa. Trên auditd, `-e 2` đặt cấu hình immutable; ngoài ra phải đẩy log ra **xa** (remote syslog/SIEM) ngay lập tức vì attacker giành root sẽ xóa log cục bộ. Audit trail mất tính chống chối bỏ (non-repudiation) nếu attacker sửa được.

### 16.3.2. SP 800-61 — Computer Security Incident Handling Guide

**Là gì.** Hướng dẫn quy trình ứng phó sự cố (IR). Định nghĩa **vòng đời 4 giai đoạn** (lưu ý: khác với mô hình 6 bước SANS PICERL):

```
   ┌──────────────────────┐
   │ 1. Preparation       │  Chuẩn bị: công cụ, playbook, đào tạo, IR team
   └──────────┬───────────┘
              ▼
   ┌──────────────────────┐
   │ 2. Detection &       │  Phát hiện & phân tích: triage, scope, mức nghiêm trọng
   │    Analysis          │
   └──────────┬───────────┘
              ▼   ◄──────────────┐   (vòng lặp: chứa nhiều đợt)
   ┌──────────────────────┐      │
   │ 3. Containment,      │──────┘
   │    Eradication &     │
   │    Recovery          │
   └──────────┬───────────┘
              ▼
   ┌──────────────────────┐
   │ 4. Post-Incident     │  Bài học, cập nhật control & playbook
   │    Activity          │
   └──────────────────────┘
```

> So sánh: **SANS PICERL** = Preparation, Identification, Containment, Eradication, Recovery, Lessons learned (6 bước). NIST gộp Containment/Eradication/Recovery thành 1 pha lớn (4 pha). `[Bản 800-61 Rev.3, 2025, đã tích hợp ngôn ngữ CSF 2.0 — CẦN KIỂM CHỨNG chi tiết thay đổi]`.

**Containment chia 2 loại (quyết định kỹ thuật quan trọng):**

| Loại | Mục tiêu | Ví dụ kỹ thuật |
|------|----------|-----------------|
| Short-term | Cô lập ngay, ngăn lan rộng | Cô lập VLAN, ngắt NIC, chặn IP ở firewall |
| Long-term | Vá tạm để hệ thống chạy trong khi điều tra | Patch tạm, tăng giám sát, host thay thế sạch |

**Ví dụ thực tế — chứng cứ & chain of custody.** Khi containment, phải thu thập chứng cứ *trước khi* phá trạng thái. Thứ tự thu thập theo độ "bay hơi" (order of volatility, RFC 3227):

```
Bay hơi cao  ->  thấp
1. CPU registers, cache
2. RAM (memory), routing table, ARP cache, process list
3. Temp files, swap
4. Disk
5. Remote logging / monitoring data
6. Physical config, network topology
7. Archival media
```

Lệnh thu thập RAM và băm để bảo toàn tính toàn vẹn (chain of custody):

```bash
# Dump RAM trên Linux điều tra (LiME hoặc avml), rồi hash ngay
sudo ./avml /evidence/mem-$(hostname)-$(date +%Y%m%dT%H%M%SZ).lime
sha256sum /evidence/mem-*.lime | tee /evidence/HASHES.txt
# Ghi nhận chain of custody (ai, khi nào, gì)
printf '%s\tcollector=%s\thost=%s\tsha256=%s\n' \
  "$(date -u +%FT%TZ)" "$USER" "$(hostname)" "$(sha256sum /evidence/mem-*.lime|cut -d' ' -f1)" \
  >> /evidence/custody.log
```

**Lưu ý bảo mật.** Băm SHA-256 *ngay lúc thu thập* là bằng chứng pháp lý rằng chứng cứ không bị sửa sau này. Nếu hash thay đổi → chứng cứ mất giá trị tại tòa. Không bao giờ phân tích trên bản gốc — làm việc trên bản sao đã verify hash.

### 16.3.3. SP 800-207 — Zero Trust Architecture

**Là gì.** Mô hình bỏ "tin tưởng theo vị trí mạng" (không còn "trong mạng = an toàn"). Mọi yêu cầu truy cập đều phải xác thực + ủy quyền + đánh giá rủi ro liên tục, dựa trên 7 nguyên lý (tenets).

**Kiến trúc logic — PEP/PDP:**

```
   Subject (user/device) ── request ──►  ┌──────── PEP ────────┐
                                          │  Policy Enforcement │  (gateway/proxy)
                                          │     Point           │
                                          └─────────┬───────────┘
                                                    │ allow/deny?
                                                    ▼
                              ┌──────────── Control Plane ──────────────┐
                              │  PDP = Policy Decision Point             │
                              │   ├─ Policy Engine (PE): tính trust score│
                              │   └─ Policy Administrator (PA): cấp/thu  │
                              │      token, cấu hình kênh                │
                              └────────────┬─────────────────────────────┘
        Tín hiệu vào PE:                   │
        CDM, threat intel, SIEM, ID mgmt, data access policy, PKI
```

**Luồng (state machine) một request Zero Trust:**

```
1. Subject gửi request tới resource -> chặn ở PEP
2. PEP hỏi PDP: "subject X, device Y, xin truy cập resource Z"
3. PE thu thập tín hiệu: danh tính (đã MFA?), tư thế thiết bị (patch? EDR?),
   ngữ cảnh (giờ, vị trí), threat intel -> tính trust score
4. So với policy -> ALLOW / DENY / STEP-UP (yêu cầu thêm MFA)
5. Nếu ALLOW: PA cấp session/token ngắn hạn, PEP mở kênh
6. Liên tục đánh giá lại (continuous): nếu posture xấu đi -> thu hồi session
```

**Ví dụ thực tế — chính sách OPA/Rego (PDP thật trong môi trường K8s/microservice):**

```rego
package zerotrust.authz

import future.keywords.if

default allow := false

# Cho phép nếu: đã MFA, thiết bị compliant, trong giờ làm, ko bị threat-intel gắn cờ
allow if {
    input.subject.mfa == true
    input.device.compliant == true
    input.device.patch_age_days <= 30
    input.context.threat_score < 50
    valid_business_hours
}

valid_business_hours if {
    h := time.clock([time.now_ns(), "Asia/Ho_Chi_Minh"])[0]
    h >= 7
    h < 20
}

# Yêu cầu step-up MFA cho hành động nhạy cảm
step_up if {
    input.resource.sensitivity == "high"
    input.subject.mfa_age_minutes > 15
}
```

Truy vấn quyết định (chạy được với binary `opa`):

```bash
echo '{
  "subject": {"mfa": true, "mfa_age_minutes": 5},
  "device":  {"compliant": true, "patch_age_days": 12},
  "context": {"threat_score": 10},
  "resource":{"sensitivity": "high"}
}' | opa eval -I -d zerotrust.rego 'data.zerotrust.authz.allow' --format=pretty
```

Output:

```
true
```

**Lưu ý bảo mật.** PDP/PEP trở thành điểm tập trung quyền lực — nếu attacker chiếm Policy Administrator, họ kiểm soát toàn bộ ủy quyền. Phải bảo vệ control plane ở mức cao nhất (HSM-backed signing token, log mọi quyết định vào SIEM, không cho PEP fail-open). Token cấp phải ngắn hạn (vài phút) để continuous evaluation có ý nghĩa.

---

## 16.4. ISO/IEC 27001 & 27002

### 16.4.1. ISO/IEC 27001 — ISMS

**Là gì.** Tiêu chuẩn quốc tế cho **Hệ thống quản lý an toàn thông tin (ISMS)**. Khác NIST CSF (tự nguyện), 27001 là tiêu chuẩn **có chứng nhận** (certifiable) — tổ chức được audit bởi bên thứ ba và cấp chứng chỉ. Phiên bản hiện hành: **ISO/IEC 27001:2022**.

**Cấu trúc 27001 = Phần điều khoản (clauses 4–10, BẮT BUỘC) + Annex A (control tham chiếu).**

**PDCA (Plan-Do-Check-Act)** là động cơ cải tiến liên tục, ánh xạ vào clauses:

```
       PLAN ───────────────► DO
   (4 Context,            (8 Operation)
    5 Leadership,             │
    6 Planning,               ▼
    7 Support)            CHECK (9 Performance
        ▲                      evaluation:
        │                      monitoring, audit,
        │                      mgmt review)
        │                         │
       ACT ◄──────────────────────┘
   (10 Improvement:
    nonconformity,
    corrective action)
```

**Bảng điều khoản 4–10 (mandatory clauses) — đào từng clause:**

| Clause | Tên | Yêu cầu vận hành cốt lõi |
|--------|-----|---------------------------|
| 4 | Context of the organization | Xác định bối cảnh, bên liên quan, **scope của ISMS** |
| 4.3 | Scope | Phạm vi áp dụng (quan trọng: scope hẹp = audit dễ nhưng bảo vệ ít) |
| 5 | Leadership | Cam kết lãnh đạo, chính sách ISMS, vai trò & trách nhiệm |
| 6 | Planning | **Risk assessment + risk treatment**, mục tiêu an ninh, **SoA** |
| 6.1.2 | Risk assessment | Quy trình đánh giá rủi ro lặp lại được |
| 6.1.3 | Risk treatment | Chọn control + lập **Statement of Applicability** |
| 7 | Support | Nguồn lực, năng lực, nhận thức, truyền thông, **documented information** |
| 8 | Operation | Triển khai kế hoạch xử lý rủi ro, kiểm soát thay đổi |
| 9 | Performance evaluation | Đo lường, **internal audit**, **management review** |
| 10 | Improvement | Xử lý sự không phù hợp (nonconformity), hành động khắc phục, cải tiến liên tục |

**Statement of Applicability (SoA)** — tài liệu trung tâm của 27001. Liệt kê **mọi** control của Annex A, ghi: áp dụng hay không, lý do, đã triển khai chưa.

**Ví dụ thực tế — SoA dạng bảng (CSV):**

```csv
control_id,control_name,applicable,justification,status,evidence
A.5.1,Policies for information security,YES,Required by ISMS scope,Implemented,POL-001 v3
A.5.7,Threat intelligence,YES,CEX faces APT,In progress,TI feed contract
A.8.1,User endpoint devices,YES,BYOD allowed,Implemented,MDM Intune
A.8.24,Use of cryptography,YES,PII + funds,Implemented,KMS+AES-256-GCM
A.7.4,Physical security monitoring,NO,No own datacenter (cloud only),N/A,AWS SOC2 report
```

```bash
# Kiểm: control nào applicable=YES mà chưa Implemented (gap kiểm toán)
awk -F',' 'NR>1 && $3=="YES" && $5!="Implemented" {print $1" ("$2") -> "$5}' soa.csv
```

Output:

```
A.5.7 (Threat intelligence) -> In progress
```

**Vì sao SoA quan trọng?** Auditor dùng SoA làm điểm xuất phát: với mỗi control "Applicable + Implemented", họ đòi **bằng chứng** (evidence). Với "Not applicable", họ đòi **lý do hợp lý**. SoA là khế ước giữa tổ chức và auditor.

**Annex A 27001:2022 — 93 control, 4 theme** (đã tái cấu trúc từ 114 control/14 domain của bản 2013):

| Theme | Mã | Số control | Nội dung |
|-------|-----|-----------|----------|
| Organizational | A.5 | 37 | Chính sách, vai trò, supplier, IR, compliance |
| People | A.6 | 8 | Tuyển dụng, đào tạo, kỷ luật, remote work |
| Physical | A.7 | 14 | Vùng an ninh, thiết bị, hủy dữ liệu |
| Technological | A.8 | 34 | Access control, crypto, logging, network, secure dev |

### 16.4.2. ISO/IEC 27002 — Code of practice

**Là gì.** Trong khi 27001 *nói control nào* (Annex A liệt kê tên), **27002 giải thích control đó nghĩa là gì và triển khai ra sao** (implementation guidance). Cùng đánh số (A.5–A.8).

**5 thuộc tính (attributes) mới ở 27002:2022** — gắn nhãn mỗi control để lọc/ánh xạ:

| Thuộc tính | Giá trị có thể |
|------------|----------------|
| Control type | Preventive / Detective / Corrective |
| Information security properties | Confidentiality / Integrity / Availability |
| Cybersecurity concepts | Identify / Protect / Detect / Respond / Recover (map CSF) |
| Operational capabilities | Governance, Asset_mgmt, Identity_and_access_mgmt... |
| Security domains | Governance_and_Ecosystem, Protection, Defence, Resilience |

**Vì sao có attributes?** Cho phép cắt lát danh mục control theo nhiều chiều — ví dụ lọc tất cả control "Detective + Detect" để xây năng lực giám sát. Đây là cầu nối kỹ thuật giữa ISO và NIST CSF.

### 16.4.3. Audit & chứng nhận

**Quy trình chứng nhận 27001 (2 giai đoạn):**

```
Stage 1 audit  (Documentation review)
  - Kiểm tra ISMS có đầy đủ tài liệu: scope, policy, SoA, risk assessment,
    risk treatment plan, internal audit, management review.
  - Kết quả: sẵn sàng cho Stage 2 hay chưa.
        │
        ▼
Stage 2 audit  (Implementation / effectiveness)
  - Auditor lấy mẫu control, đòi bằng chứng thực thi (log, vé, screenshot,
    cấu hình). Phỏng vấn nhân sự.
  - Phát hiện: Major NC / Minor NC / Observation.
        │
        ▼
Certification (chứng chỉ giá trị 3 năm)
        │
        ▼
Surveillance audit (năm 1, năm 2) -> Recertification (năm 3)
```

**Phân loại phát hiện (findings):**

| Loại | Nghĩa | Hệ quả |
|------|-------|--------|
| Major nonconformity | Vi phạm hệ thống/thiếu control bắt buộc | Chặn chứng nhận đến khi khắc phục |
| Minor nonconformity | Sai lệch cục bộ, không hệ thống | Phải có corrective action plan |
| Observation/OFI | Cơ hội cải tiến | Không bắt buộc, nên xử lý |

**Lưu ý bảo mật.** Chứng chỉ 27001 chứng nhận *hệ thống quản lý* tồn tại và vận hành, KHÔNG đảm bảo hệ thống "không thể bị hack". Scope hẹp (vd chỉ 1 phòng ban) vẫn được cấp chứng chỉ hợp lệ — luôn đọc **scope statement** trên chứng chỉ của nhà cung cấp trước khi tin tưởng. Đây là điểm due diligence quan trọng khi đánh giá vendor.

---

## 16.5. PCI DSS (sơ lược — ngành tài chính/thẻ)

**Là gì.** Payment Card Industry Data Security Standard — tiêu chuẩn bắt buộc theo *hợp đồng* (không phải luật) với mọi tổ chức lưu/xử lý/truyền **dữ liệu chủ thẻ (CHD)**. Phiên bản hiện hành **PCI DSS v4.0 / v4.0.1**. 6 mục tiêu, **12 yêu cầu**.

**Dữ liệu chủ thẻ — phân loại tới từng trường (CỰC KỲ quan trọng, quyết định cái gì được lưu):**

| Nhóm | Trường | Được lưu sau authorization? | Ghi chú |
|------|--------|------------------------------|---------|
| Cardholder Data (CHD) | PAN (Primary Account Number, 13–19 chữ số) | CÓ — nhưng phải mã hóa/truncate | Tối đa hiển thị 6 đầu + 4 cuối |
| CHD | Cardholder name | CÓ | |
| CHD | Expiration date | CÓ | |
| CHD | Service code | CÓ | |
| Sensitive Auth Data (SAD) | Full track data (magnetic stripe) | **KHÔNG BAO GIỜ** | Cấm lưu sau auth |
| SAD | CAV2/CVC2/CVV2/CID (mã 3–4 số) | **KHÔNG BAO GIỜ** | Cấm lưu sau auth |
| SAD | PIN / PIN block | **KHÔNG BAO GIỜ** | Cấm lưu sau auth |

**12 yêu cầu PCI DSS (6 mục tiêu):**

```
Build & Maintain Secure Network
  1. Cài đặt & bảo trì network security controls (firewall)
  2. Áp dụng cấu hình an toàn (no vendor defaults)
Protect Account Data
  3. Bảo vệ stored account data (mã hóa PAN)
  4. Mã hóa truyền CHD qua mạng công cộng (TLS)
Maintain Vulnerability Mgmt
  5. Bảo vệ chống malware
  6. Phát triển & bảo trì hệ thống/phần mềm an toàn
Strong Access Control
  7. Hạn chế truy cập theo need-to-know
  8. Định danh & xác thực truy cập (MFA)
  9. Hạn chế truy cập vật lý
Monitor & Test
  10. Log & giám sát mọi truy cập tới CHD
  11. Test bảo mật thường xuyên (scan, pentest)
Maintain Policy
  12. Chính sách an ninh thông tin
```

**Ví dụ thực tế — masking PAN (Requirement 3.4) trong log.** Tuyệt đối không log PAN đầy đủ. Hàm masking giữ 6 đầu + 4 cuối:

```python
def mask_pan(pan: str) -> str:
    pan = pan.replace(" ", "")
    if len(pan) < 13:
        raise ValueError("PAN không hợp lệ")
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]

print(mask_pan("4111111111111111"))   # -> 411111******1111
```

**Kiểm tra Luhn (mod-10) — PAN hợp lệ về cấu trúc:**

```python
def luhn_ok(pan: str) -> bool:
    digits = [int(d) for d in pan if d.isdigit()][::-1]
    total = sum(d if i % 2 == 0 else (d*2 - 9 if d*2 > 9 else d*2)
                for i, d in enumerate(digits))
    return total % 10 == 0

print(luhn_ok("4111111111111111"))   # -> True
```

**Lưu ý bảo mật.** Cách giảm scope PCI hiệu quả nhất là **tokenization** — thay PAN bằng token vô nghĩa, để PAN thật trong vault hoặc đẩy toàn bộ cho payment processor (PAN không bao giờ chạm hệ thống mình). Mỗi hệ thống "chạm" CHD đều rơi vào scope audit, nên kiến trúc tốt là cô lập **Cardholder Data Environment (CDE)** bằng segmentation chặt (Requirement 1) để thu hẹp phạm vi.

---

## 16.6. Pháp lý Việt Nam (mức ý nghĩa vận hành)

> Phần này diễn giải **nghĩa vận hành** cho kỹ sư. Số hiệu văn bản/điều khoản cụ thể được đánh dấu `[CẦN KIỂM CHỨNG]` ở chỗ không chắc chắn — KHÔNG dùng làm tư vấn pháp lý chính thức; với quyết định pháp lý phải đối chiếu văn bản gốc và hỏi bộ phận pháp chế.

### 16.6.1. Luật An toàn thông tin mạng 2015

**Là gì.** Luật ATTT mạng số **86/2015/QH13**, hiệu lực **01/07/2016**. Khung pháp lý nền cho an toàn thông tin: bảo vệ thông tin trên mạng, phân loại thông tin, bảo vệ thông tin cá nhân (ở mức nguyên tắc), an toàn hệ thống thông tin, kinh doanh sản phẩm/dịch vụ ATTT (giấy phép), mật mã dân sự.

**Ý nghĩa vận hành cho kỹ sư:**

| Chủ đề trong luật | Hệ quả vận hành thực tế |
|-------------------|--------------------------|
| Bảo vệ thông tin cá nhân (nguyên tắc) | Phải có sự đồng ý khi thu thập; được sửa/xóa theo yêu cầu (chi tiết hơn ở NĐ 13/2023) |
| Phân loại hệ thống theo cấp độ | Đặt nền cho phân cấp độ 1–5 (chi tiết ở NĐ 85/2016) |
| Kinh doanh sản phẩm/dịch vụ ATTT | Cung cấp dịch vụ pentest/giám sát ATTT cần giấy phép |
| Mật mã dân sự | Kinh doanh sản phẩm mật mã dân sự cần giấy phép (Ban Cơ yếu CP) |

### 16.6.2. Luật An ninh mạng 2018

**Là gì.** Luật An ninh mạng số **24/2018/QH14**, hiệu lực **01/01/2019**. Tập trung **an ninh quốc gia, trật tự an toàn xã hội** trên không gian mạng — khác trọng tâm với Luật ATTT (thiên kỹ thuật).

**Hai điểm vận hành nổi bật (gây tranh luận và ảnh hưởng kiến trúc hệ thống):**

| Chủ đề | Ý nghĩa vận hành |
|--------|-------------------|
| **Lưu trữ dữ liệu trong nước (data localization)** | Một số doanh nghiệp (đặc biệt cung cấp dịch vụ trên mạng viễn thông/Internet có thu thập dữ liệu người dùng VN) có thể bị yêu cầu **lưu trữ dữ liệu tại VN** và đặt chi nhánh/văn phòng đại diện. Đây là yếu tố **data residency** then chốt khi thiết kế kiến trúc cloud. |
| **Bảo vệ hệ thống thông tin quan trọng về an ninh quốc gia** | Hệ thống thuộc danh mục này chịu yêu cầu kiểm tra/giám sát an ninh mạng của cơ quan chức năng |
| Phối hợp điều tra | Nghĩa vụ cung cấp thông tin/hỗ trợ cơ quan chức năng theo quy định |

> `[CẦN KIỂM CHỨNG]` Phạm vi đối tượng và điều kiện cụ thể của yêu cầu localization được quy định chi tiết trong nghị định hướng dẫn (vd NĐ 53/2022/NĐ-CP hướng dẫn Luật An ninh mạng). Đối tượng và "trigger" áp dụng cần đọc kỹ nghị định.

### 16.6.3. Phân loại hệ thống theo cấp độ — Nghị định 85/2016/NĐ-CP

**Là gì.** Nghị định **85/2016/NĐ-CP** về **bảo đảm an toàn hệ thống thông tin theo cấp độ** (hướng dẫn Luật ATTT 2015). Phân hệ thống thông tin thành **5 cấp độ** theo mức độ hậu quả nếu bị xâm phạm. Cấp càng cao → yêu cầu kỹ thuật & quản lý càng nghiêm.

**Tương tự về tinh thần với FIPS 199 (Low/Mod/High) của Mỹ nhưng có 5 mức:**

| Cấp độ | Mô tả hậu quả (diễn giải vận hành) | Ví dụ minh họa |
|--------|-------------------------------------|----------------|
| Cấp 1 | Hậu quả nhẹ tới quyền/lợi ích hợp pháp của tổ chức, cá nhân | Website giới thiệu nội bộ |
| Cấp 2 | Hậu quả nghiêm trọng tới quyền/lợi ích | Hệ thống dịch vụ nội bộ doanh nghiệp |
| Cấp 3 | Hậu quả nghiêm trọng tới sản xuất, lợi ích công cộng, trật tự xã hội | Hệ thống có nhiều dữ liệu cá nhân; dịch vụ trực tuyến quy mô |
| Cấp 4 | Hậu quả rất nghiêm trọng tới quốc phòng, an ninh quốc gia HOẶC đặc biệt nghiêm trọng tới trật tự, lợi ích công cộng | Hệ thống tài chính/ngân hàng lớn, hạ tầng trọng yếu |
| Cấp 5 | Hậu quả đặc biệt nghiêm trọng tới quốc phòng, an ninh quốc gia | Hệ thống quốc gia tối quan trọng |

**Hệ quả vận hành (quy trình hồ sơ cấp độ):**

```
1. Phân loại sơ bộ hệ thống -> xác định cấp độ đề xuất
2. Lập HỒ SƠ đề xuất cấp độ (mô tả hệ thống, phương án bảo đảm an toàn)
3. Thẩm định & phê duyệt cấp độ (cấp có thẩm quyền)
4. Triển khai phương án bảo đảm an toàn theo yêu cầu của CẤP ĐỘ
   (yêu cầu kỹ thuật tham chiếu TCVN 11930:2017 - yêu cầu cơ bản về
    bảo đảm an toàn HTTT theo cấp độ)
5. Kiểm tra, đánh giá định kỳ
```

> **Cấp 4 trở lên** có yêu cầu kỹ thuật & quản lý chặt (giám sát, phương án ứng cứu, kiểm soát truy cập mạnh...). `[CẦN KIỂM CHỨNG]` Yêu cầu kỹ thuật chi tiết từng cấp nằm ở **TCVN 11930:2017** và các thông tư hướng dẫn của Bộ TT&TT — cần tra cứu bản gốc để liệt kê chính xác từng yêu cầu kỹ thuật cho cấp 4.

**Lưu ý bảo mật.** Với hệ thống sàn giao dịch/tài chính ở VN, việc xác định cấp độ (thường rơi vào cấp 3 hoặc 4) quyết định toàn bộ baseline control bắt buộc về pháp lý — tương tự cách FIPS 199 quyết định baseline 800-53. Phải làm hồ sơ cấp độ trước khi thiết kế control, không làm ngược lại.

### 16.6.4. Bảo vệ dữ liệu cá nhân — Nghị định 13/2023/NĐ-CP

**Là gì.** Nghị định **13/2023/NĐ-CP** về **bảo vệ dữ liệu cá nhân (PDPD)**, hiệu lực **01/07/2023**. Đây là văn bản gần với GDPR nhất ở VN tính tới thời điểm hiện tại. Định nghĩa dữ liệu cá nhân, dữ liệu cá nhân nhạy cảm, vai trò các bên, quyền của chủ thể, và nghĩa vụ.

**Phân loại dữ liệu cá nhân (quyết định mức bảo vệ kỹ thuật):**

| Loại | Định nghĩa vận hành | Ví dụ |
|------|---------------------|-------|
| Dữ liệu cá nhân cơ bản | Thông tin định danh thông thường | Họ tên, ngày sinh, số điện thoại, email, CCCD |
| Dữ liệu cá nhân nhạy cảm | Cần bảo vệ tăng cường | Sức khỏe, sinh trắc học, tài chính, quan điểm chính trị/tôn giáo, vị trí, đời sống tình dục... |

**Vai trò các bên (ánh xạ với GDPR controller/processor):**

| Vai trò NĐ 13/2023 | Tương đương GDPR | Nghĩa |
|---------------------|-------------------|-------|
| Bên Kiểm soát dữ liệu | Controller | Quyết định mục đích & phương tiện xử lý |
| Bên Xử lý dữ liệu | Processor | Xử lý theo ủy quyền của bên kiểm soát |
| Bên Kiểm soát và xử lý | Controller+Processor | Vừa quyết định vừa xử lý |
| Bên thứ ba | Third party | |

**Nghĩa vụ vận hành then chốt:**

| Nghĩa vụ | Hệ quả kỹ thuật |
|----------|------------------|
| **Sự đồng ý (consent)** trước khi xử lý | Phải có cơ chế thu thập + lưu vết consent (timestamp, mục đích, phiên bản chính sách) |
| Quyền chủ thể: truy cập, sửa, xóa, rút đồng ý, phản đối | Phải có API/quy trình DSAR (Data Subject Access Request) |
| **Hồ sơ đánh giá tác động (DPIA)** — `[CẦN KIỂM CHỨNG tên gọi/biểu mẫu chính xác]` | Lập hồ sơ đánh giá tác động xử lý dữ liệu cá nhân, lưu và sẵn sàng cung cấp cho cơ quan (Bộ Công an - A05) |
| Thông báo xử lý dữ liệu nhạy cảm / chuyển dữ liệu ra nước ngoài | Hồ sơ chuyển dữ liệu cá nhân ra nước ngoài (TIA) |
| Thông báo vi phạm | Quy trình breach notification trong thời hạn quy định |

> `[CẦN KIỂM CHỨNG]` Thời hạn thông báo vi phạm (72h?) và biểu mẫu hồ sơ DPIA/TIA cụ thể theo NĐ 13/2023 — tra cứu văn bản gốc.

**Ví dụ thực tế — schema lưu vết consent (audit được, đáp ứng nghĩa vụ chứng minh):**

```sql
CREATE TABLE consent_records (
    consent_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_subject  VARCHAR(64)  NOT NULL,         -- pseudonym, KHÔNG để PII trần
    purpose       VARCHAR(128) NOT NULL,         -- mục đích cụ thể
    policy_version VARCHAR(16) NOT NULL,         -- phiên bản chính sách đã hiển thị
    consent_given BOOLEAN      NOT NULL,
    granted_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    withdrawn_at  TIMESTAMPTZ,                   -- null nếu chưa rút
    source_ip_hash CHAR(64),                     -- sha256(ip) — chứng cứ, ko lưu IP trần
    evidence_hash CHAR(64)                       -- hash của bản consent đầy đủ
);
-- Quyền rút đồng ý: cập nhật withdrawn_at, KHÔNG xóa bản ghi (giữ audit trail)
UPDATE consent_records SET withdrawn_at = now()
 WHERE data_subject = 'subj_8f2a' AND purpose = 'marketing';
```

**Lưu ý bảo mật.** Bảng consent là **chứng cứ pháp lý** — phải bất biến (append-only/audit log), không cho phép UPDATE/DELETE tùy tiện trên `granted_at`. Khi xử lý "quyền được xóa" (right to erasure), phải cân bằng với nghĩa vụ lưu giữ khác (vd luật phòng chống rửa tiền yêu cầu giữ KYC nhiều năm) — không phải dữ liệu nào cũng xóa được ngay; đây là xung đột retention rất thực tế.

### 16.6.5. Nghị định 356/2025 (cần kiểm chứng)

> `[CẦN KIỂM CHỨNG — KHÔNG ĐỦ DỮ LIỆU TIN CẬY]` Tại thời điểm biên soạn, tôi **không có thông tin đã được xác minh** về nội dung chi tiết của "Nghị định 356/2025". Không bịa nội dung. Khi cần viện dẫn, bắt buộc:
> 1. Tra cứu văn bản gốc trên Cổng thông tin pháp luật (vbpl.vn / thuvienphapluat.vn / công báo).
> 2. Xác nhận số hiệu, ngày ban hành, phạm vi điều chỉnh, và mối quan hệ với các nghị định đã có (vd có thay thế NĐ nào không).
> 3. Cập nhật phần này với điều khoản cụ thể sau khi đối chiếu.
>
> Việc trích dẫn sai số hiệu/điều khoản nghị định trong tài liệu tuân thủ có thể dẫn tới sai sót pháp lý nghiêm trọng — do đó tài liệu này chủ động để trống thay vì điền thông tin chưa xác minh.

---

## 16.7. Vận hành tuân thủ (Operational Compliance)

### 16.7.1. Phân loại dữ liệu (Data Classification)

**Là gì.** Gán nhãn dữ liệu theo độ nhạy cảm để áp control tương ứng. Đây là *điều kiện tiên quyết* cho mọi control khác (mã hóa, retention, access) — không phân loại thì không biết áp gì.

**Mô hình 4 mức điển hình + ánh xạ control:**

| Nhãn | Mô tả | Control mã hóa | Retention | Ai truy cập |
|------|-------|----------------|-----------|--------------|
| Public | Công khai được | Không bắt buộc | Tùy | Mọi người |
| Internal | Nội bộ | TLS truyền | 1–3 năm | Nhân viên |
| Confidential | Bí mật KD | At-rest + transit | Theo nghiệp vụ | Need-to-know |
| Restricted/Secret | PII nhạy, khóa ví, CHD | AES-256 + KMS + tách khóa | Theo luật (KYC nhiều năm) | Tối thiểu, MFA, log mọi truy cập |

**Ví dụ thực tế — gắn nhãn ở tầng hạ tầng (AWS S3 tag + bucket policy ép mã hóa):**

```json
// bucket policy: từ chối upload nếu không mã hóa SSE-KMS (ép control với Restricted data)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnEncryptedUploads",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::cex-kyc-restricted/*",
    "Condition": {
      "StringNotEquals": { "s3:x-amz-server-side-encryption": "aws:kms" }
    }
  }]
}
```

```bash
# Gắn nhãn phân loại lên tài nguyên (tag-based policy)
aws s3api put-bucket-tagging --bucket cex-kyc-restricted \
  --tagging 'TagSet=[{Key=DataClass,Value=Restricted},{Key=Regulation,Value=ND13-2023}]'
```

### 16.7.2. Kiểm soát truy cập & audit trail

**Audit trail — bản ghi log "ai làm gì, khi nào, kết quả" — cấu trúc tới từng trường:**

| Trường | Kích thước/Kiểu | Ý nghĩa | Ví dụ |
|--------|------------------|---------|-------|
| `timestamp` | ISO-8601, UTC | Thời điểm (đồng bộ NTP) | 2026-06-19T03:22:11.482Z |
| `actor` | string | Chủ thể thực hiện | uid=svc_payment / user=alice |
| `actor_ip` | IPv4/IPv6 | Nguồn | 10.4.2.17 |
| `action` | enum | Hành động | READ / WRITE / DELETE / LOGIN |
| `resource` | URI/ID | Đối tượng | kyc-db/customer/8842 |
| `result` | enum | Kết quả | SUCCESS / DENIED / ERROR |
| `session_id` | uuid | Phiên | b1f2... |
| `correlation_id` | uuid | Lần truy vết liên hệ thống | trace-... |
| `prev_hash` | hex(32B) | Hash bản ghi trước (chống sửa) | 9f3c... |

**Tại sao có `prev_hash`?** Để biến log thành **chuỗi băm (hash chain)** — sửa 1 bản ghi cũ làm vỡ toàn bộ hash về sau, phát hiện được tampering. Đây là cốt lõi của audit trail chống chối bỏ:

```
record[n].hash = SHA256( record[n].fields || record[n-1].hash )

Nếu attacker sửa record[k], thì record[k].hash thay đổi
-> record[k+1].prev_hash không khớp -> phát hiện đứt chuỗi
```

**Ví dụ thực tế — sinh hash chain log (Python):**

```python
import hashlib, json
def chain_append(prev_hash: str, event: dict) -> str:
    payload = json.dumps(event, sort_keys=True).encode() + bytes.fromhex(prev_hash or "00"*32)
    return hashlib.sha256(payload).hexdigest()

prev = "00"*32
for ev in [{"ts":"2026-06-19T03:22:11Z","actor":"alice","action":"READ","res":"kyc/8842","result":"SUCCESS"}]:
    prev = chain_append(prev, ev)
    print(ev["action"], "->", prev[:16], "...")
```

### 16.7.3. Log retention & data residency

**Log retention** — thời gian giữ log, chịu chi phối bởi: (1) yêu cầu pháp lý, (2) năng lực điều tra, (3) chi phí lưu trữ.

| Loại log | Retention khuyến nghị (tham khảo) | Lý do |
|----------|-----------------------------------|-------|
| Security/audit log (truy cập PII, đặc quyền) | thường ≥ 1 năm (PCI DSS Req.10: tối thiểu 1 năm, 3 tháng online) | Điều tra sự cố, audit |
| KYC/AML records | nhiều năm theo luật phòng chống rửa tiền | Nghĩa vụ pháp lý |
| Application/debug log | 30–90 ngày | Vận hành |

> `[CẦN KIỂM CHỨNG]` Thời hạn retention pháp lý cụ thể tại VN (vd theo Luật Phòng chống rửa tiền 2022, NĐ về cấp độ) — đối chiếu văn bản. PCI DSS Req.10 quy định **giữ ≥12 tháng, ≥3 tháng truy xuất ngay** là con số đã xác minh trong chuẩn PCI.

**Data residency** — dữ liệu phải nằm ở vùng địa lý nào. Liên quan trực tiếp Luật An ninh mạng (localization). Áp dụng kỹ thuật bằng region pinning:

```hcl
# Terraform: ép tài nguyên ở region VN/gần VN & cấm replicate ra ngoài
provider "aws" {
  region = "ap-southeast-1"   # Singapore (gần VN); nếu cần đặt tại VN dùng
                              # nhà cung cấp trong nước (VNG, Viettel, FPT...)
}
resource "aws_s3_bucket" "kyc" {
  bucket = "cex-kyc-restricted"
}
# Chặn cross-region replication: KHÔNG khai báo replication_configuration
# + dùng SCP (Service Control Policy) cấm tạo bucket ngoài region cho phép
```

**SCP ép data residency ở tổ chức (AWS Organizations):**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyOutsideAllowedRegions",
    "Effect": "Deny",
    "NotAction": [ "iam:*", "organizations:*", "route53:*" ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": { "aws:RequestedRegion": [ "ap-southeast-1" ] }
    }
  }]
}
```

**Lưu ý bảo mật.** Data residency không chỉ là region của bucket — coi chừng: backup tự động sang region khác, CDN edge cache, log forwarding sang SaaS US (Datadog/Splunk Cloud), email/SMS provider quốc tế. Phải vẽ **data flow map** đầy đủ để biết PII *thực sự* đi đâu, không tin mỗi cấu hình region của DB chính.

### 16.7.4. Ánh xạ control xuyên framework (crosswalk)

**Vì sao.** Một tổ chức thường chịu nhiều framework cùng lúc (27001 + CSF + NĐ 85 + PCI). Triển khai một control vật lý → thỏa nhiều yêu cầu. **Crosswalk** tránh làm việc trùng lặp.

**Ví dụ ánh xạ control "MFA cho truy cập đặc quyền":**

| Framework | Định danh control |
|-----------|--------------------|
| NIST CSF 2.0 | PR.AA-03 (authenticate) |
| NIST 800-53 | IA-2(1), IA-2(2) |
| ISO 27001:2022 Annex A | A.8.5 (Secure authentication) |
| PCI DSS v4.0 | Req. 8.4 / 8.5 (MFA) |
| NĐ 85/2016 (TCVN 11930) | Yêu cầu xác thực theo cấp độ `[CẦN KIỂM CHỨNG mã mục]` |

**Ví dụ thực tế — file crosswalk YAML dùng trong DevSecOps (1 control → nhiều framework, gắn evidence):**

```yaml
controls:
  - id: ORG-MFA-PRIV
    name: "MFA bắt buộc cho truy cập đặc quyền"
    implementation: "Okta + FIDO2 cho admin; điều kiện trong OPA"
    evidence:
      - "okta_policy_export_2026Q2.json"
      - "opa_test_results.txt"
    satisfies:
      nist_csf: ["PR.AA-03"]
      nist_800_53: ["IA-2(1)", "IA-2(2)"]
      iso_27001: ["A.8.5"]
      pci_dss: ["8.4.2", "8.5.1"]
```

```bash
# Đếm 1 control thỏa bao nhiêu yêu cầu (đo "đòn bẩy" của control)
yq '.controls[] | .id + ": " + ([.satisfies[][]] | length | tostring) + " requirements"' crosswalk.yaml
```

Output:

```
ORG-MFA-PRIV: 7 requirements
```

---

## 16.8. GRC trong ngân hàng / tài chính

### 16.8.1. Three Lines Model (mô hình 3 tuyến phòng thủ)

**Là gì.** Mô hình quản trị rủi ro chuẩn ngành tài chính (IIA — Institute of Internal Auditors). Tách bạch trách nhiệm để tránh xung đột lợi ích.

```
┌──────────────────────────────────────────────────────────────────┐
│  HỘI ĐỒNG QUẢN TRỊ / ỦY BAN KIỂM TOÁN  (giám sát tổng thể)        │
└──────────────────────────────────────────────────────────────────┘
        1st Line               2nd Line               3rd Line
┌────────────────────┐ ┌────────────────────┐ ┌────────────────────┐
│ Sở hữu & quản lý   │ │ Giám sát rủi ro    │ │ Đảm bảo độc lập    │
│ rủi ro hằng ngày   │ │ & tuân thủ         │ │ (Internal Audit)   │
│                    │ │ (Risk, Compliance, │ │                    │
│ (Dev, SecOps,      │ │  CISO office)      │ │ - audit độc lập    │
│  IT, business)     │ │                    │ │   1st & 2nd line   │
│ - vận hành         │ │ - đặt policy       │ │ - báo cáo thẳng    │
│   control          │ │ - giám sát control │ │   HĐQT, không qua  │
│                    │ │                    │ │   CISO             │
└────────────────────┘ └────────────────────┘ └─────────┬──────────┘
                                                         │
                  External Audit + Regulator ◄───────────┘
                  (bên ngoài, độc lập)
```

**Vì sao tách tuyến?** Người *vận hành* control (1st) không được tự *đánh giá* control của mình (3rd) — nếu không sẽ "vừa đá bóng vừa thổi còi". Internal Audit (3rd line) báo cáo thẳng HĐQT, không qua CISO, để giữ độc lập.

### 16.8.2. Khung pháp lý/giám sát ngành tài chính VN (mức vận hành)

| Cơ quan/Văn bản | Vai trò vận hành |
|------------------|-------------------|
| Ngân hàng Nhà nước (NHNN) | Cơ quan giám sát; ban hành thông tư về an toàn CNTT ngân hàng |
| Thông tư về an toàn hệ thống thông tin ngân hàng | `[CẦN KIỂM CHỨNG số hiệu]` — thường quy định phân cấp hệ thống, sao lưu, DR, kiểm soát truy cập, log cho TCTD |
| Luật Phòng chống rửa tiền (2022) | Nghĩa vụ KYC/CDD, báo cáo giao dịch đáng ngờ (STR), lưu hồ sơ |
| Basel / chuẩn quốc tế | Tham chiếu quản trị rủi ro hoạt động (operational risk) |

> `[CẦN KIỂM CHỨNG]` Số hiệu thông tư NHNN về an toàn CNTT (vd các thông tư quy định bảo đảm an toàn hệ thống thông tin trong hoạt động ngân hàng) — tra cứu bản gốc trước khi trích dẫn.

### 16.8.3. Vận hành GRC liên tục (Continuous Compliance) trong DevSecOps

**Là gì.** Thay vì audit thủ công 1 lần/năm, **kiểm soát tuân thủ liên tục** bằng policy-as-code chạy trong CI/CD. Đây là điểm giao giữa GRC và DevSecOps.

**Ví dụ thực tế — kiểm tra control trong pipeline (OPA Conftest kiểm IaC trước deploy):**

```rego
# policy/encryption.rego — fail build nếu tài nguyên Restricted không mã hóa
package main
deny[msg] {
    input.resource.aws_s3_bucket[name]
    not input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    msg := sprintf("S3 bucket '%s' thiếu mã hóa at-rest (vi phạm A.8.24 / NĐ13)", [name])
}
```

```bash
# Chạy trong CI: chặn merge nếu vi phạm control mã hóa
conftest test --policy policy/ terraform-plan.json
```

Output mẫu khi vi phạm:

```
FAIL - terraform-plan.json - main - S3 bucket 'cex-kyc-restricted' thiếu mã hóa at-rest (vi phạm A.8.24 / NĐ13)
1 test, 0 passed, 1 failure
```

**Ví dụ — thu thập evidence tự động cho audit (script gom log + cấu hình thành gói chứng cứ có hash):**

```bash
#!/usr/bin/env bash
# collect_evidence.sh — đóng gói evidence cho audit kỳ Q2
set -euo pipefail
OUT="evidence_$(date +%Y%m%d).tar.gz"
mkdir -p evidence/{access,config,scan}
aws iam get-account-password-policy            > evidence/config/pw_policy.json
aws s3api get-bucket-encryption --bucket cex-kyc-restricted > evidence/config/s3_enc.json
auditctl -l                                    > evidence/access/auditd_rules.txt
tar czf "$OUT" evidence/
sha256sum "$OUT" | tee "${OUT}.sha256"
echo "Evidence package: $OUT"
```

**Lưu ý bảo mật.** Policy-as-code có thể bị **fail-open** nếu pipeline bỏ qua bước test khi lỗi (vd `|| true`). Trong môi trường tài chính, control compliance phải **fail-closed** — pipeline phải dừng (exit non-zero) khi policy vi phạm hoặc khi bản thân policy engine lỗi. Đồng thời evidence tự động phải bất biến (write-once, đẩy sang object lock / WORM storage) để auditor tin cậy.

---

## 16.9. Tổng kết & checklist tra cứu nhanh

**Khi nào dùng framework nào:**

| Nhu cầu | Dùng |
|---------|------|
| Ngôn ngữ chung mô tả tình trạng an ninh, báo cáo lãnh đạo | NIST CSF 2.0 |
| Thư viện control kỹ thuật chi tiết để chọn & triển khai | NIST SP 800-53 |
| Quy trình ứng phó sự cố | NIST SP 800-61 |
| Bỏ tin theo vị trí mạng, microsegmentation | NIST SP 800-207 (ZT) |
| Chứng nhận quốc tế hệ thống quản lý | ISO/IEC 27001 + 27002 |
| Xử lý dữ liệu thẻ thanh toán | PCI DSS v4.0 |
| Pháp lý VN — an toàn theo cấp độ | Luật ATTT 2015 + NĐ 85/2016 + TCVN 11930 |
| Pháp lý VN — an ninh quốc gia, localization | Luật ANM 2018 (+ NĐ hướng dẫn) |
| Pháp lý VN — dữ liệu cá nhân | NĐ 13/2023 |

**Quy tắc tự bảo vệ khi viết tài liệu tuân thủ:** mọi số hiệu văn bản, điều khoản, thời hạn retention pháp lý phải đối chiếu văn bản gốc trước khi dùng chính thức. Tài liệu này đánh dấu `[CẦN KIỂM CHỨNG]` ở mọi chỗ chưa xác minh được — đặc biệt **Nghị định 356/2025** (chưa có thông tin tin cậy), các số hiệu thông tư NHNN, mã mục TCVN 11930, và thời hạn breach notification của NĐ 13/2023.


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*
