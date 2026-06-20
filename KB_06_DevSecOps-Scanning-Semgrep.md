# Chương 6 — DevSecOps: Quét bảo mật & Semgrep

## Nhập môn — hiểu nôm na trước khi đi sâu

Chương này nói về cách "gắn việc kiểm tra bảo mật" vào ngay trong quy trình làm phần mềm, thay vì để tới cuối mới đi tìm lỗ hổng. Nói cách khác: thay vì xây xong cả ngôi nhà rồi mới thuê người đi soi xem có chỗ nào dột, chúng ta đặt sẵn người soi ở từng công đoạn — đổ móng, dựng tường, lợp mái — để bắt lỗi ngay khi nó vừa xuất hiện. Điều này quan trọng vì lỗ hổng càng phát hiện muộn thì sửa càng đắt và càng nguy hiểm (có khi đã bị hacker khai thác rồi mới biết). Dưới đây là các "nhân vật chính" của chương, mình giải thích thật đời thường trước khi phần kỹ thuật đi vào chi tiết.

### DevSecOps & shift-left — nói đơn giản

**DevSecOps** là cách làm việc trong đó bảo mật (Sec) được trộn thẳng vào quy trình lập trình (Dev) và vận hành (Ops), thay vì là một khâu tách rời ở cuối. Hãy hình dung một dây chuyền làm bánh: ngày xưa người ta nướng xong cả mẻ bánh mới kiểm tra vệ sinh; bây giờ ta đặt người kiểm tra ở mọi khâu. **"Shift-left"** chỉ có nghĩa là "dịch việc kiểm tra về phía trái" — tức là về sớm hơn trên dòng thời gian. Cần nó vì sửa một lỗi lúc lập trình viên còn đang gõ code thì rẻ và nhanh, còn sửa lúc đã lên production thì tốn kém gấp hàng chục lần và rủi ro lớn.

### CI/CD & pipeline — nói đơn giản

**CI/CD** là cụm từ chỉ việc tự động hóa quá trình từ "viết code xong" tới "chạy được trên máy chủ". CI (Continuous Integration) là mỗi khi ai đó nộp code, hệ thống tự động gom lại, build và chạy kiểm thử. CD (Continuous Deployment/Delivery) là tự động đưa code đã qua kiểm thử ra môi trường thật. **Pipeline** là "dây chuyền" gồm các bước nối tiếp đó. Cần nó vì làm tay thì chậm, dễ quên, dễ sai; còn dây chuyền tự động thì mỗi lần nộp code đều được kiểm tra y hệt nhau. Trong chương này, pipeline chính là nơi ta nhét các công cụ quét bảo mật vào để chúng tự chạy.

### Các loại quét: SAST, DAST, SCA, secret scanning... — nói đơn giản

Mỗi loại công cụ nhìn phần mềm từ một góc khác nhau, giống như nhiều bác sĩ khám một bệnh nhân bằng các thiết bị khác nhau:
- **SAST** (quét tĩnh) đọc *mã nguồn* mà không cần chạy chương trình — như đọc bản vẽ thiết kế để tìm chỗ vẽ sai. Bắt tốt các lỗi kiểu "lấy dữ liệu người dùng nhét thẳng vào câu lệnh nguy hiểm".
- **DAST** (quét động) thì *chạy thật* ứng dụng rồi thử tấn công nó qua trình duyệt/HTTP — như thử mở từng cánh cửa xem có khóa chắc không, mà không cần biết bên trong xây thế nào.
- **SCA** kiểm tra các *thư viện bên thứ ba* mà dự án dùng lại — như kiểm tra xem nguyên liệu mua ngoài có bị thu hồi (CVE) hay không. Quan trọng vì phần lớn code hiện đại là vay mượn từ người khác.
- **Secret scanning** đi tìm *mật khẩu, khóa API, token* bị lỡ tay viết thẳng vào code — như rà soát xem có ai dán chìa khóa nhà lên cửa không.
- **IaC scanning** kiểm tra *file cấu hình hạ tầng* (máy chủ, mạng) xem có chỗ nào để hớ hênh, ví dụ mở toang cho cả thế giới truy cập.

Cần nhiều loại vì mỗi loại có "vùng mù" riêng; chồng chúng lên nhau để bù cho nhau.

### Semgrep — nói đơn giản

**Semgrep** (đọc là "sem-grép", nghĩa là "grep ngữ nghĩa") là một công cụ SAST mã nguồn mở. Bạn cứ hình dung lệnh tìm kiếm văn bản quen thuộc, nhưng thông minh hơn: thay vì tìm theo từng chữ cái, nó *hiểu cấu trúc của code*. Ta viết một "khuôn mẫu" trông gần giống đoạn code muốn bắt, rồi Semgrep tự tìm mọi chỗ khớp với khuôn đó — kể cả khi cách viết có xê dịch khoảng trắng, xuống dòng, đặt tên khác. Cần nó vì tìm lỗi bằng tìm-chữ-thuần (regex) hay báo nhầm và bỏ sót, còn Semgrep cân bằng được giữa nhanh và chính xác. Trong chương, đây là công cụ trung tâm: ta sẽ học cách viết **rule** (luật) bằng file YAML, dùng **metavariable** (biến đại diện như `$X`), và **taint mode** — chế độ theo dõi "dữ liệu bẩn" chảy từ nơi nhận vào (source) tới nơi nguy hiểm (sink).

### Gitleaks — nói đơn giản

**Gitleaks** là công cụ chuyên đi soi *bí mật bị lộ* trong code và trong cả lịch sử git (mọi lần commit trước đây). Nó bắt theo hai cách: tìm theo mẫu nhận dạng (ví dụ khóa AWS luôn bắt đầu bằng `AKIA`) và đo "độ ngẫu nhiên" của chuỗi (mật khẩu thật thường lộn xộn hơn chữ tiếng Anh bình thường). Cần nó vì một khi mật khẩu đã bị đẩy lên kho code chung thì coi như đã lộ, phải đổi ngay.

### Trivy — nói đơn giản

**Trivy** là một scanner đa năng: nó soi *container image* (gói phần mềm đóng sẵn để chạy ở mọi nơi), soi thư mục mã nguồn, soi cấu hình hạ tầng, và lập danh sách thành phần. Hãy coi nó như máy soi hành lý ở sân bay — đưa cái gì vào nó cũng quét được và chỉ ra món nào có "CVE" (lỗ hổng đã được công bố). Cần nó vì image bạn dùng thường chứa cả một hệ điều hành thu nhỏ với hàng trăm gói phần mềm, mỗi gói đều có thể dính lỗ hổng.

### Cổng pipeline (gate) & exit code — nói đơn giản

**Gate** (cổng) là điểm trong dây chuyền tự động quyết định "cho đi tiếp hay chặn lại". Cách máy móc giao tiếp với nhau là qua **exit code**: một con số mà chương trình trả về khi chạy xong — quy ước `0` nghĩa là "ổn, qua", khác `0` nghĩa là "có vấn đề, dừng". Cần thiết kế cổng thành **nhiều tầng**: lỗi nghiêm trọng thì chặn hẳn, lỗi nhẹ thì chỉ cảnh báo. Nếu chặn mọi thứ, lập trình viên bị làm phiền quá mức rồi tìm cách lách; nếu không chặn gì, lỗ hổng nặng lọt ra ngoài.

### An ninh chuỗi cung ứng, SBOM, ký artifact — nói đơn giản

**Chuỗi cung ứng phần mềm** là toàn bộ "đường đi của nguyên liệu" để làm ra sản phẩm: thư viện vay mượn, công cụ build, máy chủ đóng gói. Kẻ xấu có thể đầu độc một mắt xích trong đó. **SBOM** (Software Bill of Materials) giống như "bảng thành phần in trên vỏ hộp thực phẩm" — liệt kê mọi thứ có trong phần mềm, để khi nghe tin một thành phần dính lỗ hổng (như vụ Log4Shell) thì tra ngay được "sản phẩm nào của mình có dùng nó". **Ký artifact** (với cosign/sigstore) là dán một con dấu chống giả lên gói phần mềm, để bên nhận kiểm tra được "đúng là của ta làm ra và chưa bị sửa đổi".

### Quản lý secret & Vault — nói đơn giản

Thay vì viết mật khẩu thẳng vào code (rất dễ lộ), ta dùng một "két sắt tập trung" như **HashiCorp Vault**. Hay hơn nữa là **dynamic secret**: mỗi khi ứng dụng cần truy cập cơ sở dữ liệu, Vault cấp một tài khoản tạm sống vài giờ rồi tự thu hồi — giống chìa khóa khách sạn chỉ dùng được trong thời gian bạn thuê phòng. **OIDC/workload identity** giải bài toán "con gà và quả trứng": làm sao xác thực với két sắt mà không cần một mật khẩu ban đầu? Câu trả lời là dùng danh tính có sẵn và đã được ký của chính môi trường chạy (ví dụ GitHub Actions).

### pre-commit hook — nói đơn giản

**pre-commit hook** là một đoạn script tự động chạy *ngay trước khi* bạn lưu (commit) code vào kho. Nếu nó phát hiện vấn đề, nó chặn luôn không cho commit. Đây là điểm "shift-left" xa nhất — bắt lỗi ngay trên máy lập trình viên, trước cả khi code rời khỏi máy. Cần nó để bí mật và lỗi rõ ràng không bao giờ kịp lọt vào lịch sử git. Lưu ý: vì lập trình viên có thể cố tình bỏ qua, nên các kiểm tra này phải được lặp lại ở phía máy chủ (CI).

Nắm được mấy ý trên rồi thì phần dưới đây sẽ đi sâu vào chi tiết kỹ thuật.

> Chương này là tài liệu tham chiếu để học và tra cứu. Mỗi công cụ đều có ví dụ chạy được, mỗi định dạng dữ liệu đều mô tả tới mức trường/byte, và mỗi cơ chế đều giải thích "vì sao thiết kế như vậy".

---

## 6.1. Triết lý shift-left & mô hình DevSecOps

### 6.1.1. Vấn đề kinh tế đằng sau shift-left

DevSecOps không phải là một công cụ mà là một **mô hình vận hành** trong đó kiểm soát bảo mật được nhúng (embed) vào từng giai đoạn của vòng đời phát triển phần mềm (SDLC) thay vì làm một lần ở cuối.

Lý do nền tảng là chi phí sửa lỗi tăng theo cấp số nhân theo giai đoạn phát hiện. Mô hình chi phí kinh điển (thường gán cho NIST/IBM Systems Sciences Institute — con số chính xác cần kiểm chứng theo nguồn vì các trích dẫn dao động mạnh) định tính như sau:

| Giai đoạn phát hiện lỗi | Chi phí tương đối (định tính) | Vì sao |
|---|---|---|
| Coding / IDE | 1x | Lập trình viên đang nắm context, sửa ngay |
| Build / CI | ~5x | Phải quay lại, mất context, chạy lại pipeline |
| QA / Test | ~10x | Cần điều tra, viết test tái hiện |
| Production | ~30x–100x+ | Hotfix khẩn, downtime, có thể đã bị khai thác, nghĩa vụ pháp lý |

"Shift-left" nghĩa là dịch hoạt động bảo mật về **phía trái** trên trục thời gian SDLC (trái = sớm). Mục tiêu không phải bỏ kiểm thử cuối, mà là **giảm số lỗi sống sót** tới các giai đoạn đắt đỏ.

```
TRADITIONAL (security ở cuối):
[Plan]→[Code]→[Build]→[Test]→[Release]→[Deploy]→[Operate]
                                                    └── Pentest 1 lần/năm

DEVSECOPS (security ở mọi điểm):
[Plan]    [Code]      [Build]      [Test]     [Release]   [Deploy]    [Operate]
  │         │           │            │           │           │           │
threat    SAST        SCA          DAST       sign        admission   runtime
model   pre-commit   secret      IAST        SBOM       controller   detection
        IDE plugin   container   ZAP        provenance   policy      WAF/EDR
                     scan
```

### 6.1.2. Nguyên tắc thiết kế cốt lõi

- **Tự động hóa (automation)**: con người không scale; cổng (gate) phải chạy tự động trong pipeline.
- **Feedback nhanh**: cảnh báo phải tới lập trình viên trong vài phút (tại PR/MR), không phải vài tuần (báo cáo PDF).
- **Policy as Code**: chính sách bảo mật được mã hóa (rule YAML, OPA Rego, manifest) để versioned, review được, tái lập được.
- **Fail tiered (phân tầng)**: không phải mọi phát hiện đều chặn build — phân biệt blocking vs warning (xem 6.9).
- **Guardrails, không phải gatekeepers**: cung cấp lan can để đi nhanh an toàn, thay vì cổng chặn làm dev tìm cách đi vòng (shadow IT).

---

## 6.2. Phân loại kỹ thuật quét bảo mật

Đây là phần nền tảng: mỗi họ công cụ nhìn phần mềm từ một góc khác nhau, có vùng mù (blind spot) riêng. Hiểu cơ chế giúp chọn đúng công cụ và biết tại sao cần kết hợp nhiều loại (defense in depth cho chính quy trình kiểm thử).

### 6.2.1. Bảng tổng quan

| Loại | Tên đầy đủ | Đầu vào | Cần chạy app? | Phát hiện tốt | Vùng mù |
|---|---|---|---|---|---|
| SAST | Static Application Security Testing | Source/bytecode | Không | SQLi, XSS, path traversal, hardcoded crypto | Lỗi runtime/config, auth logic |
| DAST | Dynamic Application Security Testing | App đang chạy (HTTP) | Có | Lỗi runtime, server misconfig, auth | Không thấy code, coverage phụ thuộc crawler |
| IAST | Interactive AST | Agent trong runtime + traffic | Có | Kết hợp data-flow runtime + vị trí code | Cần instrument, ngôn ngữ hạn chế |
| SCA | Software Composition Analysis | Manifest/lockfile deps | Không | CVE thư viện bên thứ ba, license | Lỗi code tự viết |
| Secret scanning | — | Source + git history | Không | API key, token, private key bị commit | Secret đã mã hóa, ngoài repo |
| IaC scanning | Infrastructure as Code | Terraform/K8s/CFN | Không | S3 public, SG mở 0.0.0.0/0 | Drift runtime so với code |
| Container scanning | — | Image layers / filesystem | Không | CVE OS packages, app deps trong image | Lỗi logic ứng dụng |

### 6.2.2. SAST — phân tích tĩnh

**Là gì**: phân tích mã nguồn (hoặc bytecode) mà không thực thi. 

**Cơ chế bên trong**: pipeline điển hình:

1. **Lexing (tokenize)**: chuỗi ký tự → token. Ví dụ `user_id = req.params.id` → `[IDENT(user_id), OP(=), IDENT(req), DOT, IDENT(params), DOT, IDENT(id)]`.
2. **Parsing**: token → **AST** (Abstract Syntax Tree) theo grammar của ngôn ngữ.
3. **Phân tích ngữ nghĩa**: xây control-flow graph (CFG), data-flow graph (DFG), call graph.
4. **Taint analysis**: theo dõi dữ liệu từ **source** (input không tin cậy) tới **sink** (hàm nguy hiểm) mà không qua **sanitizer**.

**Vì sao dùng AST chứ không regex**: regex không hiểu cấu trúc cú pháp. Ví dụ regex tìm `query(...)` sẽ báo nhầm trên comment, string literal, hoặc bỏ sót khi code xuống dòng. AST hiểu `query` là một hàm gọi với đối số là biểu thức nối chuỗi chứa biến nhiễm độc.

### 6.2.3. DAST — phân tích động

**Cơ chế**: công cụ đóng vai HTTP client/proxy, **crawl** ứng dụng để lập bản đồ endpoint, rồi **fuzz** từng tham số bằng payload tấn công (`' OR 1=1--`, `<script>`, `../../etc/passwd`), quan sát **phản hồi** (status code, độ trễ, nội dung, error message) để suy ra lỗ hổng. Black-box: không thấy code.

### 6.2.4. IAST

**Cơ chế**: gắn **agent** (instrumentation) vào runtime (ví dụ Java agent qua `-javaagent`, bytecode instrumentation). Khi DAST/test gửi request, agent quan sát data-flow **thật** bên trong process — biết payload đi từ HTTP parameter tới câu SQL thực thi. Kết hợp độ chính xác data-flow (như SAST) với context runtime (như DAST), nên ít false positive hơn.

### 6.2.5. SCA

**Cơ chế**: đọc manifest/lockfile (`package-lock.json`, `pom.xml`, `go.sum`, `requirements.txt`), dựng cây phụ thuộc (kể cả transitive), so khớp với CSDL lỗ hổng (NVD, GitHub Advisory, OSV). Then map version → CVE qua dải version bị ảnh hưởng. Quan trọng vì >80% codebase hiện đại là code bên thứ ba.

---

## 6.3. Semgrep — kiến trúc và cơ chế parse → AST → matching

Semgrep ("semantic grep") là công cụ SAST mã nguồn mở, định vị giữa "grep" (nhanh, đơn giản) và SAST nặng (chính xác, chậm). Triết lý: rule **trông giống code cần tìm**.

### 6.3.1. Pipeline xử lý nội bộ

```
                Source file (vd app.py)
                        │
                        ▼
         ┌──────────────────────────────┐
         │  Tree-sitter / parser riêng  │  Parse tới CST/AST cụ thể ngôn ngữ
         └──────────────────────────────┘
                        │
                        ▼
         ┌──────────────────────────────┐
         │   Generic AST (semgrep core) │  Chuẩn hóa về AST chung đa ngôn ngữ
         └──────────────────────────────┘
                        │
   Rule pattern ──────► │  Pattern cũng được parse thành AST cùng kiểu
                        ▼
         ┌──────────────────────────────┐
         │   Structural matching        │  So khớp cây-với-cây + ràng buộc
         │   + metavariable binding     │  metavariable, taint propagation
         └──────────────────────────────┘
                        │
                        ▼
                  Findings (JSON/SARIF)
```

Điểm cốt lõi: **pattern trong rule cũng được parse thành AST** giống như code đích, rồi Semgrep so khớp **cấu trúc cây với cây** (structural match), không so khớp văn bản. Vì vậy:

- `foo(1, 2)` khớp dù code viết `foo(1,2)`, `foo( 1, 2 )`, hay xuống dòng.
- Comment, khoảng trắng, dấu ngoặc thừa được bỏ qua một cách tự nhiên.
- Hiểu ngữ nghĩa cơ bản (ví dụ `$X == $X` hiểu hai vế là cùng biến).

### 6.3.2. Equivalences (tương đương ngữ nghĩa)

Semgrep tự áp dụng một số phép tương đương để giảm số rule phải viết. Ví dụ: import có alias (`import subprocess as sp` → pattern `subprocess.call(...)` vẫn khớp `sp.call(...)`), constant propagation đơn giản, các kiểu gọi tương đương. Đây là lý do một pattern ngắn bắt được nhiều biến thể.

### 6.3.3. Cài đặt và lệnh CLI cơ bản

```bash
# Cài qua pip (Python 3.8+)
python3 -m pip install semgrep
semgrep --version        # vd: 1.x.x

# Hoặc Docker (không cần cài local)
docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep --config auto /src
```

Lệnh quét cốt lõi:

```bash
# Quét bằng ruleset cộng đồng có sẵn (registry)
semgrep --config "p/owasp-top-ten" .

# 'auto' = Semgrep tự chọn ruleset theo ngôn ngữ phát hiện được
semgrep --config auto .

# Dùng 1 file rule cục bộ
semgrep --config ./rules/sqli.yaml ./src

# Nhiều config cùng lúc
semgrep --config p/security-audit --config ./rules/ .
```

Giải thích tham số quan trọng:

| Tham số | Ý nghĩa |
|---|---|
| `--config <X>` | Nguồn rule: `p/<pack>` (registry), đường dẫn file/thư mục, URL, hoặc `auto` |
| `--json` / `--sarif` | Định dạng xuất (tích hợp CI / GitHub code scanning) |
| `--output <file>` | Ghi kết quả ra file |
| `--severity <LVL>` | Lọc theo ERROR/WARNING/INFO |
| `--error` | Trả exit code != 0 khi có finding (dùng cho gate — xem 6.9) |
| `--baseline-commit <sha>` | Chỉ báo finding **mới** so với commit gốc (diff-aware) |
| `--exclude <glob>` | Bỏ qua path (vd `--exclude 'tests/*'`) |
| `--max-target-bytes` | Bỏ file lớn hơn ngưỡng (mặc định ~1MB) |
| `--metrics off` | Tắt gửi metrics ẩn danh |

---

## 6.4. Cú pháp viết rule YAML — cấu trúc trường

### 6.4.1. Bộ khung một rule

Một file rule Semgrep là YAML với khóa gốc `rules` (mảng). Mỗi phần tử mô tả một rule. Các trường:

| Trường | Bắt buộc | Kiểu | Ý nghĩa | Ví dụ |
|---|---|---|---|---|
| `id` | Có | string | Định danh duy nhất (xuất hiện trong báo cáo) | `python.sqli.format-string` |
| `languages` | Có | list | Ngôn ngữ áp dụng | `[python]`, `[javascript, typescript]` |
| `severity` | Có | enum | `ERROR` / `WARNING` / `INFO` | `ERROR` |
| `message` | Có | string | Mô tả gửi tới dev (nên kèm cách sửa) | `Phát hiện SQL injection...` |
| `pattern` | (1 trong các) | string | Pattern đơn cần khớp | `eval(...)` |
| `patterns` | — | list | AND logic: tất cả con phải đúng | (xem dưới) |
| `pattern-either` | — | list | OR logic: bất kỳ con đúng là khớp | |
| `pattern-not` | — | string | Loại trừ (giảm false positive) | |
| `pattern-inside` | — | string | Chỉ khớp khi nằm trong ngữ cảnh này | |
| `pattern-not-inside` | — | string | Loại nếu nằm trong ngữ cảnh này | |
| `metavariable-regex` | — | map | Ràng buộc metavariable theo regex | |
| `mode` | — | enum | `search` (mặc định) hoặc `taint` | `taint` |
| `metadata` | — | map | CWE, OWASP, references, confidence | |
| `fix` | — | string | Tự động sửa (autofix) | |

### 6.4.2. Metavariable `$X`

Metavariable là **biến trong pattern**, viết hoa, bắt đầu bằng `$`: `$X`, `$FUNC`, `$ARG`. Nó khớp một node AST bất kỳ (biểu thức, định danh, lời gọi...) và **ghi nhớ** (bind) giá trị đó. Cùng tên metavariable trong cùng pattern phải khớp cùng nội dung.

```yaml
# Bắt so sánh một biến với chính nó (luôn true/false — bug logic)
rules:
  - id: self-comparison
    languages: [python]
    severity: WARNING
    message: "So sánh $X với chính nó luôn cho kết quả cố định."
    pattern: $X == $X
```

Pattern trên khớp `a == a`, `user.id == user.id` (vì hai vế bind cùng `$X`), nhưng KHÔNG khớp `a == b`.

Các dạng metavariable đặc biệt:

| Cú pháp | Khớp |
|---|---|
| `$X` | Một node đơn |
| `...` (ellipsis) | Chuỗi 0+ đối số/câu lệnh/phần tử bất kỳ |
| `$...ARGS` | Chuỗi đối số nhưng có bind tên |
| `"..."` | Bất kỳ chuỗi literal |
| `$X.$METHOD(...)` | Gọi method bất kỳ trên `$X` |

Ellipsis `...` rất quan trọng: `foo(...)` khớp `foo()`, `foo(1)`, `foo(a, b, c)`. Còn `foo(..., $SENSITIVE, ...)` khớp `$SENSITIVE` xuất hiện ở vị trí đối số bất kỳ.

### 6.4.3. `patterns` (AND), `pattern-either` (OR), `pattern-not`, `pattern-inside`

```yaml
rules:
  - id: dangerous-subprocess-with-shell
    languages: [python]
    severity: ERROR
    message: "subprocess gọi với shell=True và input động → command injection."
    patterns:
      # AND: phải khớp cả lời gọi VÀ có shell=True VÀ KHÔNG phải literal
      - pattern-either:
          - pattern: subprocess.call(...)
          - pattern: subprocess.run(...)
          - pattern: subprocess.Popen(...)
      - pattern: $FN(..., shell=True, ...)
      - pattern-not: $FN("...", ..., shell=True, ...)   # bỏ qua command hằng số
```

Ngữ nghĩa logic:

- `patterns:` = **AND** — mọi mục con phải đúng trên cùng vùng code.
- `pattern-either:` = **OR** — chỉ cần một mục con đúng.
- `pattern-not:` = phủ định — loại finding nếu pattern này khớp (giảm FP).
- `pattern-inside:` = ràng buộc ngữ cảnh — chỉ khớp khi đoạn code **nằm bên trong** một cấu trúc bao ngoài (ví dụ trong một hàm, một vòng lặp).

Ví dụ `pattern-inside` để chỉ bắt lỗi trong route handler:

```yaml
rules:
  - id: raw-sql-in-flask-route
    languages: [python]
    severity: ERROR
    message: "Câu SQL ghép chuỗi bên trong Flask route."
    patterns:
      - pattern-inside: |
          @app.route(...)
          def $HANDLER(...):
              ...
      - pattern: $CUR.execute("..." % ...)
```

### 6.4.4. `metavariable-regex` và `metavariable-pattern`

```yaml
rules:
  - id: weak-hash-algo
    languages: [python]
    severity: WARNING
    message: "Thuật toán băm yếu: $ALGO"
    patterns:
      - pattern: hashlib.new($ALGO, ...)
      - metavariable-regex:
          metavariable: $ALGO
          regex: ^["'](md5|sha1)["']$
```

`metavariable-regex` áp regex lên **giá trị văn bản** mà metavariable đã bind. Ở đây chỉ báo khi thuật toán là `md5` hoặc `sha1`.

---

## 6.5. Taint mode — source / sink / sanitizer

### 6.5.1. Cơ chế

`search` mode khớp theo cấu trúc tại một điểm. Nhưng SQLi/command injection là vấn đề **luồng dữ liệu** (data flow): dữ liệu bẩn đi từ A tới B qua nhiều bước. `mode: taint` mô hình hóa điều này bằng three-set:

- **source**: nơi dữ liệu không tin cậy xuất hiện (HTTP param, đọc file, env).
- **sink**: nơi nguy hiểm nếu nhận dữ liệu bẩn (`execute`, `eval`, `os.system`).
- **sanitizer**: nơi "rửa sạch" dữ liệu (escape, parametrize, allowlist). Nếu dữ liệu đi qua sanitizer trước khi tới sink → không báo.

Semgrep theo dõi sự lan truyền (propagation) của taint qua phép gán, nối chuỗi, lời gọi hàm. Finding chỉ phát sinh khi tồn tại đường đi **source → ... → sink** mà KHÔNG cắt ngang sanitizer.

```
[source]──taint──►[var a]──taint──►[a + "x"]──taint──►[sink]   ❌ BÁO LỖI
[source]──taint──►[sanitize(a)]──clean──►[sink]                ✅ AN TOÀN
```

### 6.5.2. Ví dụ taint bắt SQL injection

```yaml
rules:
  - id: python-sqli-taint
    languages: [python]
    severity: ERROR
    message: >
      Dữ liệu từ HTTP request đi vào câu SQL mà không tham số hóa
      → SQL injection (CWE-89).
    mode: taint
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
      confidence: HIGH
    pattern-sources:
      - pattern: flask.request.$ANYTHING
      - pattern: flask.request.args.get(...)
      - pattern: flask.request.form[...]
    pattern-sanitizers:
      - pattern: int(...)                       # ép kiểu int = an toàn cho SQLi
      - pattern: $DB.execute($Q, $PARAMS)       # truy vấn tham số hóa
    pattern-sinks:
      - patterns:
          - pattern: $CURSOR.execute($QUERY, ...)
          - focus-metavariable: $QUERY
```

Code bị bắt:

```python
from flask import request
name = request.args.get("name")          # SOURCE
q = "SELECT * FROM users WHERE name='%s'" % name   # taint lan truyền
cursor.execute(q)                        # SINK  → BÁO LỖI
```

Code KHÔNG bị bắt (đã sanitize):

```python
uid = int(request.args.get("id"))        # int() = sanitizer
cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))  # tham số hóa
```

`focus-metavariable` thu hẹp finding vào đúng phần biểu thức (`$QUERY`) thay vì cả lời gọi, giúp báo cáo chính xác vị trí.

---

## 6.6. Nhiều ví dụ rule thật

### 6.6.1. Bắt `eval()` trên input động (RCE)

```yaml
rules:
  - id: js-eval-user-input
    languages: [javascript, typescript]
    severity: ERROR
    message: "eval() với dữ liệu động → remote code execution (CWE-95)."
    metadata: { cwe: "CWE-95", owasp: "A03:2021" }
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")     # cho phép eval chuỗi hằng (vẫn nên tránh)
```

```javascript
eval(req.query.code);   // ❌ khớp
eval("1 + 1");          // ✅ bỏ qua nhờ pattern-not
```

### 6.6.2. Bắt hardcoded secret

```yaml
rules:
  - id: hardcoded-aws-key
    languages: [python, javascript, go]
    severity: ERROR
    message: "AWS Access Key ID hardcode trong source."
    patterns:
      - pattern-regex: AKIA[0-9A-Z]{16}
  - id: hardcoded-generic-password
    languages: [python]
    severity: WARNING
    message: "Mật khẩu gán cứng cho biến."
    patterns:
      - pattern-either:
          - pattern: $PWD = "..."
      - metavariable-regex:
          metavariable: $PWD
          regex: (?i)(password|passwd|pwd|secret|token|api_?key)
      - pattern-not: $PWD = ""
```

`AKIA[0-9A-Z]{16}` là cấu trúc của AWS Access Key ID: tiền tố `AKIA` + 16 ký tự (tổng 20 ký tự). Semgrep `pattern-regex` áp regex trên văn bản nguồn (kết hợp được với AST qua `patterns`).

### 6.6.3. Bắt command injection (Go)

```yaml
rules:
  - id: go-command-injection
    languages: [go]
    severity: ERROR
    message: "exec.Command với input từ HTTP → command injection."
    mode: taint
    pattern-sources:
      - pattern: $R.URL.Query().Get(...)
      - pattern: $R.FormValue(...)
    pattern-sinks:
      - pattern: exec.Command($CMD, ...)
      - pattern: exec.Command("sh", "-c", $ARG)
```

### 6.6.4. Autofix

```yaml
rules:
  - id: insecure-yaml-load
    languages: [python]
    severity: ERROR
    message: "yaml.load không an toàn → dùng safe_load."
    pattern: yaml.load($X)
    fix: yaml.safe_load($X)
```

Chạy `semgrep --config rule.yaml --autofix .` sẽ thay `yaml.load(data)` thành `yaml.safe_load(data)` ngay trong file.

### 6.6.5. Output mẫu

```
$ semgrep --config rules/ src/app.py

┌─────────────┐
│ 2 Findings  │
└─────────────┘

  src/app.py
    python-sqli-taint
        Dữ liệu từ HTTP request đi vào câu SQL... (CWE-89)
        12┆ cursor.execute(q)

    hardcoded-aws-key
        AWS Access Key ID hardcode trong source.
        20┆ KEY = "AKIAIOSFODNN7EXAMPLE"

Ran 5 rules on 1 file: 2 findings.
```

### 6.6.6. Xử lý false positive & severity

Chiến lược giảm false positive theo thứ tự ưu tiên:

1. **Thêm `pattern-not` / `pattern-not-inside`** để loại trường hợp an toàn đã biết.
2. **Thêm sanitizer** (taint mode) cho hàm rửa dữ liệu nội bộ.
3. **Nolint inline**: thêm comment `# nosemgrep: <rule-id>` ngay dòng để bỏ qua có chủ đích (nên kèm lý do).
4. **`.semgrepignore`** (cú pháp giống `.gitignore`) để loại path (vendored code, tests, generated).

```python
result = eval(trusted_expr)   # nosemgrep: js-eval-user-input — chuỗi đã whitelist
```

Quy ước severity → hành động (liên kết với cổng pipeline 6.9):

| Severity | Ý nghĩa | Hành động pipeline đề xuất |
|---|---|---|
| ERROR | Lỗ hổng khai thác được, độ tin cậy cao | Chặn build (blocking) |
| WARNING | Có thể là vấn đề / cần review | Cảnh báo, không chặn |
| INFO | Khuyến nghị, best practice | Ghi chú |

---

## 6.7. Gitleaks — secret scanning (regex + entropy)

### 6.7.1. Cơ chế hai tầng

Gitleaks quét **nội dung file VÀ lịch sử git** (mọi commit/blob qua `git log -p`), tìm secret bằng hai phương pháp bổ sung nhau:

1. **Regex rule**: bắt secret có **cấu trúc nhận dạng được** (AWS key `AKIA...`, GitHub PAT `ghp_...`, JWT `eyJ...`). Chính xác cao, ít FP.
2. **Shannon entropy**: bắt secret **không có cấu trúc** (chuỗi ngẫu nhiên cao như base64 token). Entropy đo "độ ngẫu nhiên" của chuỗi:

```
H = -Σ p(x) · log2 p(x)        (bit/ký tự)
```

Chuỗi tiếng Anh thường ~3.5–4.5 bit/ký tự; secret ngẫu nhiên base64 thường >4.5. Đặt ngưỡng entropy giúp bắt secret lạ nhưng dễ FP nếu để thấp.

### 6.7.2. Lệnh

```bash
# Quét toàn bộ lịch sử git của repo hiện tại
gitleaks detect --source . --verbose

# Quét chỉ thư mục làm việc (không lịch sử) — nhanh, dùng cho pre-commit
gitleaks detect --no-git --source .

# Quét các thay đổi đang staged (pre-commit hook)
gitleaks protect --staged --source .

# Xuất báo cáo + exit code != 0 nếu có leak
gitleaks detect --source . --report-format sarif --report-path leaks.sarif
```

### 6.7.3. `.gitleaks.toml` ví dụ

```toml
title = "Cấu hình Gitleaks công ty"

[extend]
useDefault = true        # kế thừa bộ rule mặc định, rồi bổ sung bên dưới

[[rules]]
id = "company-internal-token"
description = "Internal service token (prefix INT_)"
regex = '''INT_[A-Za-z0-9]{32}'''
keywords = ["INT_"]      # tối ưu tốc độ: chỉ chạy regex nếu file chứa keyword
entropy = 3.5            # yêu cầu entropy tối thiểu để giảm FP

[[rules]]
id = "generic-api-key"
description = "Generic API key gán cho biến"
regex = '''(?i)(api[_-]?key|apikey)['"\s:=]{1,5}['"]([0-9a-zA-Z]{32,45})['"]'''
secretGroup = 2          # nhóm capture chứa giá trị secret thật

[allowlist]
description = "Bỏ qua mẫu test và example"
regexes = [
  '''AKIAIOSFODNN7EXAMPLE''',     # khóa ví dụ chính thức của AWS
]
paths = [
  '''(.*?)(test|spec|fixtures)(.*?)''',
]
```

Mô tả các trường rule chính:

| Trường | Ý nghĩa |
|---|---|
| `id` | Định danh rule |
| `regex` | Mẫu nhận diện secret |
| `keywords` | Lọc nhanh: chỉ chạy regex nếu file chứa từ khóa (tối ưu hiệu năng) |
| `entropy` | Ngưỡng entropy tối thiểu của capture group |
| `secretGroup` | Nhóm regex chứa giá trị secret (cho entropy/redaction) |
| `[allowlist]` | Loại trừ theo regex/path/commit (giảm FP) |

---

## 6.8. Trivy — quét image / filesystem / IaC

Trivy là scanner đa năng: container image, filesystem, repo git, IaC, và tạo SBOM.

### 6.8.1. Quét container image

```bash
trivy image --severity HIGH,CRITICAL nginx:1.21.0
```

Cơ chế: Trivy **giải nén các layer** của image, đọc cơ sở dữ liệu package của distro (APK/`/lib/apk/db`, DPKG/`/var/lib/dpkg/status`, RPM), liệt kê (package, version), so với CSDL lỗ hổng (`trivy-db` đồng bộ từ NVD, GHSA, distro advisories). Cũng phát hiện dependency ứng dụng (lockfile nhúng trong image).

Output mẫu (rút gọn):

```
nginx:1.21.0 (debian 10.9)
Total: 142 (HIGH: 130, CRITICAL: 12)

┌──────────────┬────────────────┬──────────┬───────────────┬───────────────┐
│   Library    │ Vulnerability  │ Severity │ Installed Ver │ Fixed Version │
├──────────────┼────────────────┼──────────┼───────────────┼───────────────┤
│ openssl      │ CVE-2021-3711  │ CRITICAL │ 1.1.1d-0+deb10│ 1.1.1d-0+deb10u7│
│ libc6        │ CVE-2021-33574 │ CRITICAL │ 2.28-10       │ (won't fix)   │
└──────────────┴────────────────┴──────────┴───────────────┴───────────────┘
```

Tham số quan trọng:

| Tham số | Ý nghĩa |
|---|---|
| `--severity` | Lọc mức (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL) |
| `--ignore-unfixed` | Bỏ CVE chưa có bản vá (giảm noise không hành động được) |
| `--exit-code 1` | Trả exit != 0 khi tìm thấy (gate) |
| `--scanners vuln,secret,misconfig` | Chọn loại quét |
| `--format sarif --output x.sarif` | Tích hợp CI |

### 6.8.2. Quét filesystem & IaC

```bash
# Quét deps trong source (lockfile) + secret + misconfig
trivy fs --scanners vuln,secret,misconfig .

# Quét cấu hình hạ tầng (Terraform / K8s / Dockerfile)
trivy config ./infra/
```

`trivy config` phát hiện sai cấu hình kiểu: S3 bucket public, security group mở `0.0.0.0/0`, container chạy `privileged: true`, thiếu `readOnlyRootFilesystem`.

### 6.8.3. Gate trong CI

```bash
trivy image --exit-code 0 --severity MEDIUM,HIGH --format table myapp:ci   # cảnh báo
trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed myapp:ci    # chặn
```

Hai lệnh tách biệt thể hiện nguyên tắc gate phân tầng (6.9): CRITICAL chặn, HIGH chỉ cảnh báo.

---

## 6.9. Thiết kế cổng pipeline — exit code và phân tầng

### 6.9.1. Exit code là hợp đồng giữa scanner và CI

CI/CD coi **exit code** của tiến trình là tín hiệu pass/fail: `0` = pass, `!= 0` = fail (build dừng). Mọi scanner đều cho phép điều khiển exit code:

- Semgrep: `--error` → exit 1 nếu có finding; có thể lọc `--severity ERROR` trước.
- Trivy: `--exit-code 1`.
- Gitleaks: mặc định exit 1 khi tìm thấy leak.

### 6.9.2. Vì sao tách hai tầng (blocking vs warning)

Nếu chặn build trên **mọi** finding (kể cả HIGH/MEDIUM), dev bị "alert fatigue", bắt đầu vô hiệu hóa scan hoặc commit `--no-verify`. Nếu **không** chặn gì, lỗ hổng nghiêm trọng lọt production. Giải pháp: **hai tầng**.

| Tầng | Severity | Exit | Hiệu ứng | Mục tiêu |
|---|---|---|---|---|
| Blocking gate | CRITICAL (và ERROR có confidence HIGH) | 1 | Build đỏ, không merge | Chặn lỗ hổng khai thác được |
| Warning gate | HIGH / WARNING | 0 | Build xanh + annotation/comment PR | Tạo nhận thức, đưa vào backlog |

### 6.9.3. Ví dụ GitLab CI (.gitlab-ci.yml)

```yaml
stages: [security]

semgrep_block:
  stage: security
  image: semgrep/semgrep
  script:
    # Chỉ ERROR mới chặn; --error đặt exit code theo finding còn lại
    - semgrep --config p/security-audit --severity ERROR --error --json --output sg.json .
  artifacts:
    when: always
    reports:
      sast: sg.json

semgrep_warn:
  stage: security
  image: semgrep/semgrep
  allow_failure: true          # KHÔNG chặn pipeline dù có finding
  script:
    - semgrep --config p/security-audit --severity WARNING .

trivy_block:
  stage: security
  image: aquasec/trivy
  script:
    - trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

gitleaks:
  stage: security
  image: zricethezav/gitleaks
  script:
    - gitleaks detect --source . --no-banner
```

`allow_failure: true` là cơ chế GitLab cho phép job thất bại mà không làm đỏ pipeline — đúng nghĩa "warning gate". Job `semgrep_block` không có nó nên thất bại của nó chặn merge.

Để giảm noise trên PR/MR, dùng diff-aware (chỉ báo finding **mới**):

```bash
semgrep ci   # tự dùng baseline = nhánh đích trong môi trường CI
# hoặc thủ công:
semgrep --config auto --baseline-commit "$CI_MERGE_REQUEST_DIFF_BASE_SHA" .
```

---

## 6.10. An ninh chuỗi cung ứng phần mềm

### 6.10.1. Dependency confusion

**Cơ chế tấn công**: nếu công ty dùng package nội bộ tên `internal-utils` chỉ tồn tại trên registry riêng, kẻ tấn công đẩy một package công khai **cùng tên** lên registry public (npm/PyPI) với **version cao hơn**. Trình quản lý gói cấu hình sai có thể ưu tiên registry public (vì version cao hơn) → tải mã độc của kẻ tấn công.

```
Resolver thấy: internal-utils
  ├─ private registry: 1.2.0   ← mong muốn
  └─ public registry:  99.0.0  ← của attacker (version cao hơn)
Nếu cả hai được hỏi → có thể chọn 99.0.0  → RCE khi cài đặt (postinstall)
```

**Phòng thủ**: scoped packages (`@company/utils`), pin registry theo scope, dùng lockfile + hash, bật namespace/scope reservation, mirror nội bộ chỉ-đọc.

### 6.10.2. SLSA levels

SLSA (Supply-chain Levels for Software Artifacts) là khung đánh giá độ toàn vẹn của quy trình build. Mô tả tổng quát các cấp (số hiệu cụ thể nên kiểm chứng theo bản SLSA hiện hành, vì đã đổi giữa v0.1 và v1.0):

| Cấp | Trọng tâm | Yêu cầu cốt lõi |
|---|---|---|
| L1 | Provenance tồn tại | Build sinh ra provenance mô tả cách tạo artifact |
| L2 | Provenance ký + build service | Build trên dịch vụ có xác thực, provenance được ký |
| L3 | Build cô lập, không giả mạo được | Build platform tăng cường, provenance chống giả mạo |
| (L4 trong v0.1, được tái cấu trúc trong v1.0) | Phụ thuộc + hai người duyệt | Cần kiểm chứng theo spec hiện hành |

Cốt lõi của SLSA là **provenance**: chứng cứ "artifact này được build từ source nào, bằng builder nào, với tham số gì".

### 6.10.3. SBOM — CycloneDX và SPDX

SBOM (Software Bill of Materials) = "danh sách thành phần" của phần mềm, để khi một CVE mới công bố (ví dụ Log4Shell) có thể truy nhanh "sản phẩm nào chứa thành phần này".

Hai định dạng chuẩn:

| Đặc điểm | CycloneDX | SPDX |
|---|---|---|
| Tổ chức | OWASP | Linux Foundation (ISO/IEC 5962:2021) |
| Thiên hướng | Bảo mật / vuln / VEX | License compliance + bảo mật |
| Định dạng | JSON, XML | JSON, YAML, RDF, tag-value |
| Mã định danh thành phần | PURL, CPE | PURL, CPE, SPDX-ID |

Tạo SBOM bằng Trivy hoặc Syft:

```bash
trivy image --format cyclonedx --output sbom.cdx.json myapp:1.0
syft myapp:1.0 -o spdx-json=sbom.spdx.json
```

Cấu trúc CycloneDX (JSON, rút gọn) — các trường chính:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-...",
  "version": 1,
  "metadata": { "timestamp": "2026-06-19T00:00:00Z",
                "component": { "type": "application", "name": "myapp" } },
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "hashes": [ { "alg": "SHA-256", "content": "ab12..." } ]
    }
  ]
}
```

| Trường | Ý nghĩa |
|---|---|
| `bomFormat` / `specVersion` | Định dạng và phiên bản spec |
| `serialNumber` | UUID duy nhất của SBOM (để tham chiếu) |
| `version` | Số lần revise SBOM cho cùng serialNumber |
| `components[].purl` | Package URL — định danh chuẩn `pkg:<type>/<ns>/<name>@<ver>` |
| `components[].hashes` | Băm để xác thực tính toàn vẹn |

PURL là chìa khóa khớp CVE: ví dụ `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` map trực tiếp tới advisory Log4Shell.

### 6.10.4. Ký artifact với cosign / sigstore

Mục tiêu: chứng minh artifact (image, SBOM, blob) **không bị sửa** và **đến từ ai**. Cosign (thuộc Sigstore) hỗ trợ **keyless signing**: thay vì giữ private key dài hạn, dùng OIDC identity (Google/GitHub/CI) để xin chứng chỉ **ngắn hạn** từ Fulcio CA, ký, rồi ghi vào transparency log **Rekor** (bất biến, append-only).

```bash
# Ký keyless: mở OIDC flow, lấy cert ngắn hạn, ký, ghi vào Rekor
COSIGN_EXPERIMENTAL=1 cosign sign myregistry/myapp@sha256:abcd...

# Xác minh: kiểm tra chữ ký + identity được phép + có trong Rekor
cosign verify \
  --certificate-identity "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  myregistry/myapp@sha256:abcd...
```

Vì sao thiết kế keyless: loại bỏ rủi ro rò rỉ private key dài hạn; identity gắn với danh tính workload/CI; transparency log cho phép phát hiện chữ ký lạ.

Tham chiếu image bằng **digest** (`@sha256:...`) chứ không phải tag, vì tag có thể bị đẩy đè (mutable), còn digest là băm nội dung (immutable).

### 6.10.5. Provenance trong CI

Ký kèm chứng thực (attestation) provenance để verify được "build từ đâu":

```bash
cosign attest --predicate provenance.json --type slsaprovenance \
  myregistry/myapp@sha256:abcd...
```

Admission controller (ví dụ Kyverno/Sigstore policy-controller) ở cluster có thể **từ chối** deploy image nào không có chữ ký + provenance hợp lệ — biến chuỗi cung ứng thành policy enforced lúc deploy.

---

## 6.11. Quản lý secret — Vault, dynamic secret, OIDC

### 6.11.1. Vấn đề secret tĩnh

Secret gán cứng / để trong env file: không xoay vòng (rotation), rò rỉ là lộ vĩnh viễn, khó audit "ai dùng khi nào". Giải pháp: **secret manager tập trung** (HashiCorp Vault, AWS Secrets Manager) với secret **động** và **ngắn hạn**.

### 6.11.2. Dynamic secret

**Cơ chế**: thay vì lưu sẵn password DB, Vault **sinh credential theo yêu cầu** với TTL ngắn. Khi app cần truy cập DB, Vault tạo một user DB tạm (qua database secrets engine), trả về cho app, và **tự thu hồi** (revoke) khi hết TTL hoặc lease bị revoke.

```bash
# Bật engine và cấu hình kết nối tới Postgres
vault secrets enable database
vault write database/config/mydb \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@db:5432/app" \
  allowed_roles="app-role" username="vaultadmin" password="..."

# Định nghĩa role: SQL tạo user tạm, TTL 1h
vault write database/roles/app-role \
  db_name=mydb \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" max_ttl="24h"

# App xin credential (mỗi lần khác nhau, sống 1h)
vault read database/creds/app-role
# Key                Value
# lease_id           database/creds/app-role/abcd...
# lease_duration     1h
# password           A1b2-randomgenerated
# username           v-token-app-role-x9...
```

Vì sao tốt: credential ngắn hạn → cửa sổ tấn công nhỏ; mỗi consumer có credential riêng → audit chính xác; revoke tức thì khi nghi ngờ.

### 6.11.3. OIDC / workload identity (loại bỏ secret khởi đầu)

Vấn đề "secret zero": làm sao app/CI **xác thực với Vault** mà không cần một secret cứng để bắt đầu? Lời giải: **OIDC / JWT auth** — workload (GitHub Actions, K8s pod, AWS instance) đã có một **danh tính có chữ ký** (JWT do OIDC provider phát). Vault tin tưởng issuer đó và cấp token theo claim.

```bash
# Cấu hình Vault tin GitHub Actions OIDC
vault auth enable jwt
vault write auth/jwt/config \
  oidc_discovery_url="https://token.actions.githubusercontent.com"

# Role: chỉ workflow main của repo cụ thể mới được, gắn policy
vault write auth/jwt/role/ci-role \
  role_type="jwt" user_claim="actor" bound_audiences="https://vault.company.com" \
  bound_claims_type="glob" \
  bound_claims='{"repository":"org/repo","ref":"refs/heads/main"}' \
  policies="app-policy" ttl="15m"
```

Trong GitHub Actions, runner lấy JWT (`id-token: write`) và đổi lấy Vault token — **không có long-lived secret nào** được lưu. JWT chứa claim như `repository`, `ref`, `actor`, `sub`; Vault ràng buộc (`bound_claims`) để chỉ workflow hợp lệ mới nhận quyền.

---

## 6.12. pre-commit hook — chặn ở máy dev (shift-left tới mức tận cùng)

### 6.12.1. Cơ chế

Git hỗ trợ **hooks**: script trong `.git/hooks/` chạy tại các sự kiện. `pre-commit` chạy **trước khi** commit hoàn tất; nếu hook trả exit code != 0, commit bị hủy. Framework `pre-commit` (Python) quản lý nhiều hook qua một file khai báo và tự cài môi trường cho từng hook.

Đây là điểm shift-left xa nhất: bắt secret/lỗi **trước cả khi** code rời máy dev — secret chưa từng vào lịch sử git (vì một khi đã commit và push, secret coi như đã lộ, phải xoay vòng).

### 6.12.2. `.pre-commit-config.yaml` ví dụ

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks            # chặn secret trước khi commit

  - repo: https://github.com/returntocorp/semgrep
    rev: v1.50.0
    hooks:
      - id: semgrep
        args: ["--config", "p/security-audit", "--error", "--skip-unknown-extensions"]

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key  # bắt block PRIVATE KEY
      - id: check-added-large-files
        args: ["--maxkb=500"]
```

Cài đặt và dùng:

```bash
pip install pre-commit
pre-commit install            # ghi vào .git/hooks/pre-commit
pre-commit run --all-files    # chạy thử trên toàn repo

# Khi dev commit:
git commit -m "feat: ..."
#  → gitleaks, semgrep chạy; nếu fail, commit bị chặn
```

| Trường | Ý nghĩa |
|---|---|
| `repos[].repo` | URL repo chứa định nghĩa hook |
| `repos[].rev` | Tag/commit pin (đảm bảo tái lập, tránh kéo bản mới bất ngờ) |
| `hooks[].id` | Hook cụ thể trong repo đó |
| `hooks[].args` | Tham số truyền vào hook |

### 6.12.3. Lưu ý bảo mật của pre-commit

- pre-commit **không phải biện pháp duy nhất**: dev có thể `git commit --no-verify` bỏ qua hook. Vì vậy phải **lặp lại** kiểm tra ở CI (server-side) — đó là cổng không thể bỏ qua.
- `rev` phải pin để chống supply-chain qua hook (kéo nhầm phiên bản độc hại).
- pre-commit chạy nhanh (chỉ trên file staged); kiểm tra nặng để ở CI.

---

## 6.13. Tổng kết kiến trúc phòng thủ phân tầng

| Điểm chèn | Công cụ tiêu biểu | Loại | Tầng gate |
|---|---|---|---|
| IDE / pre-commit | Semgrep, Gitleaks | SAST, secret | Local (bỏ qua được → cần lặp ở CI) |
| CI build | Semgrep, Trivy fs/config, SCA | SAST, SCA, IaC | Blocking (CRITICAL) + Warning (HIGH) |
| Image build | Trivy image, cosign sign, SBOM | Container, ký, SBOM | Blocking CVE CRITICAL |
| Pre-deploy | cosign verify, admission controller | Provenance/policy | Blocking nếu không ký |
| Runtime | DAST/ZAP, WAF, EDR | DAST, monitoring | Cảnh báo + chặn tấn công |

Nguyên tắc xuyên suốt: **mỗi tầng có vùng mù, chồng các tầng để bù lẫn nhau**; secret bắt càng sớm càng tốt; chỉ chặn build trên rủi ro khai thác được; mọi chính sách là code, versioned và review được.

---

## Phụ lục A — OWASP ZAP (DAST) ví dụ chạy được

ZAP (Zed Attack Proxy) là DAST mã nguồn mở của OWASP. Hai chế độ scan đóng gói sẵn:

```bash
# Baseline scan: passive (spider + phân tích phản hồi), KHÔNG tấn công chủ động.
# Nhanh, an toàn cho CI, ~1-2 phút.
docker run --rm -v "$PWD:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy zap-baseline.py \
  -t https://app.staging.company.com -r baseline-report.html

# Full scan: active attack (gửi payload XSS/SQLi thực) — chậm, dùng staging.
docker run --rm -v "$PWD:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy zap-full-scan.py \
  -t https://app.staging.company.com -r full-report.html
```

| Tham số | Ý nghĩa |
|---|---|
| `-t` | URL mục tiêu |
| `-r` | File báo cáo HTML |
| `-J` | Báo cáo JSON (CI parse) |
| `-c` | File config rule (đặt mức WARN/FAIL/IGNORE từng alert) |
| `-I` | Không trả exit fail trên cảnh báo (cho warning gate) |

Cơ chế baseline vs full: **baseline** chỉ spider và phân tích **bị động** phản hồi (header thiếu, cookie không `Secure/HttpOnly`) nên không gây hại — phù hợp gate CI mọi PR. **Full** thực sự **bắn payload tấn công** vào tham số, có thể tạo dữ liệu rác / kích hoạt side-effect — chỉ chạy trên staging có dữ liệu vứt được, không chạy production. Đây là lý do tách hai chế độ giống nguyên tắc gate phân tầng ở 6.9.
