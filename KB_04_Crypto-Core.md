# Chương 4 — Mật mã học & Nền tảng bảo mật

## Tổng quan

**Mật mã học (cryptography)** là khoa học bảo vệ thông tin bằng ba năng lực cốt lõi: giữ bí mật, bảo đảm toàn vẹn, và chứng minh nguồn gốc. Mọi giao dịch trên Internet (đăng nhập, chuyển tiền, nhắn tin, mua hàng) đều dựa trên các nguyên thủy mật mã để chống đọc trộm, sửa lén và giả mạo. Chương trình bày từng nguyên thủy theo trình tự: **khái niệm → cơ chế → ví dụ → lưu ý bảo mật**.

**Ba mục tiêu nền tảng (CIA, AAA, Non-repudiation):**

- **CIA** — ba mục tiêu bảo mật: **Confidentiality** (bí mật — chỉ chủ thể được phép đọc), **Integrity** (toàn vẹn — dữ liệu không bị sửa trái phép), **Availability** (sẵn sàng — truy cập được khi cần). Mỗi lựa chọn công cụ phải xác định rõ thuộc tính nào đang được bảo vệ.
- **AAA** — ba câu hỏi về chủ thể: **Authentication** (xác thực — "là ai"), **Authorization** (phân quyền — "được làm gì"), **Accounting** (ghi nhật ký — "đã làm gì").
- **Non-repudiation (chống chối bỏ)** — chủ thể không thể phủ nhận hành vi đã thực hiện. Chỉ đạt được bằng chữ ký số với khóa riêng.

**Phân biệt Encoding — Hashing — Encryption:**

- **Encoding** (ví dụ Base64) — chỉ đổi cách biểu diễn dữ liệu, đảo ngược được không cần khóa, **không cung cấp bảo mật**. Base64 mật khẩu là sai lầm phổ biến.
- **Hashing (băm)** — tạo dấu vân tay cố định, **một chiều không đảo ngược**. Dùng kiểm tra toàn vẹn và lưu mật khẩu.
- **Encryption (mã hóa)** — khóa dữ liệu bằng khóa bí mật, đảo ngược được khi có khóa. Đây là nguyên thủy duy nhất bảo đảm bí mật.

**Mã hóa đối xứng** — dùng **một khóa duy nhất** cho cả mã và giải. **AES** là chuẩn phổ biến nhất, nhanh, phù hợp khối lượng dữ liệu lớn. Mã hóa thuần không bảo đảm toàn vẹn; thực tế dùng **AEAD** (AES-GCM, ChaCha20-Poly1305) để gộp bí mật và toàn vẹn.

**Mã hóa bất đối xứng** — dùng **cặp khóa** công khai/riêng tư, giải bài toán trao khóa giữa các bên chưa từng chia sẻ bí mật. **RSA** dựa trên độ khó phân tích thừa số; **ECC** đạt cùng độ an toàn với khóa ngắn hơn; **Diffie-Hellman/ECDHE** cho phép thỏa thuận khóa chung qua kênh hở. Biến thể **ephemeral** (ECDHE) cung cấp **Forward Secrecy**: lộ khóa server về sau không giải được phiên cũ.

**Hàm băm mật mã** — biến dữ liệu thành dấu vân tay cố định với hiệu ứng **avalanche** (đổi một bit input → đổi ~50% bit output) và không đảo ngược. **SHA-256** là khuyến nghị hiện hành; **SHA-3** là dự phòng kiến trúc. **MD5 và SHA-1 đã vỡ** — cấm dùng cho mục đích bảo mật.

**Lưu trữ mật khẩu** — không lưu dạng rõ và không dùng hash thường (quá nhanh). Dùng hàm **chậm có chủ đích, tốn bộ nhớ** (**Argon2**, **bcrypt**, **scrypt**) kèm **salt** (ngẫu nhiên riêng mỗi user) và **pepper** (bí mật chung lưu tách biệt).

**HMAC** — dùng khóa bí mật chung để xác thực toàn vẹn và nguồn gốc thông điệp. Ứng dụng: JWT, chữ ký webhook, ký request API.

**Chữ ký số** — ký bằng **khóa riêng**, kiểm tra bằng **khóa công khai**; bảo đảm đồng thời toàn vẹn, xác thực và chống chối bỏ. Ngược chiều với mã hóa bất đối xứng về vai trò của cặp khóa.

**PKI & X.509** — hệ thống chứng chỉ bảo đảm khóa công khai thuộc đúng chủ thể. **CA (Certificate Authority)** ký bảo đảm **chứng chỉ X.509**; cơ chế **thu hồi** (CRL, OCSP) hủy chứng chỉ bị lộ hoặc cấp sai. Đây là nền tảng của HTTPS.

**Mô hình rủi ro** — bốn khái niệm cần phân biệt: **Vulnerability** (điểm yếu), **Threat** (tác nhân đe dọa), **Exploit** (công cụ khai thác), **Risk** (= Likelihood × Impact). Định danh dùng **CVE** (lỗ hổng cụ thể), **CWE** (loại điểm yếu chung), **CVSS** (thang điểm 0–10).

**Nguyên tắc thiết kế** — gồm **Least Privilege**, **Defense in Depth**, **Zero Trust** và đặc biệt là **nguyên lý Kerckhoffs**: hệ thống phải an toàn ngay cả khi kẻ địch biết toàn bộ cơ chế, chỉ cần khóa được giữ kín. Đây là lý do AES, RSA, SHA-256 đều là chuẩn mở.

> Tài liệu tham chiếu kỹ thuật cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps). Mỗi mục đi từ KHÁI NIỆM → CƠ CHẾ BÊN TRONG (mức bit/byte/bước) → VÍ DỤ THỰC TẾ CHẠY ĐƯỢC → LƯU Ý BẢO MẬT. Các con số kỹ thuật bám theo NIST FIPS / RFC; chỗ nào cần kiểm chứng thêm sẽ ghi rõ.

---

## 4.1. Khung khái niệm nền tảng: CIA, AAA, Non-repudiation

### 4.1.1. Tam giác CIA

Mọi quyết định mật mã đều phục vụ một trong ba mục tiêu của bộ ba CIA. Hiểu rõ "thuộc tính nào đang được bảo vệ" giúp chọn đúng nguyên thủy mật mã (primitive).

| Thuộc tính | Câu hỏi bảo vệ | Nguyên thủy mật mã điển hình | Mất khi nào |
|---|---|---|---|
| Confidentiality (Bí mật) | "Ai được đọc?" | Mã hóa (AES-GCM, ChaCha20, RSA-OAEP) | Eavesdropping, key leak, ECB pattern |
| Integrity (Toàn vẹn) | "Dữ liệu có bị sửa?" | Hash, HMAC, AEAD tag, chữ ký số | Bit-flip, MITM tampering |
| Availability (Sẵn sàng) | "Có truy cập được khi cần?" | Không phải bài toán mật mã thuần (DoS, backup, ransomware) | DDoS, ransomware mã hóa dữ liệu |

Điểm dễ nhầm: **mã hóa KHÔNG đảm bảo toàn vẹn**. AES-CBC giữ bí mật nhưng kẻ tấn công vẫn lật bit ciphertext để thao túng plaintext (bit-flipping). Vì vậy thực tế dùng **AEAD** (Authenticated Encryption with Associated Data) gộp cả C và I.

### 4.1.2. AAA — Authentication, Authorization, Accounting

| A | Định nghĩa | "Là ai / được làm gì / đã làm gì" | Ví dụ kỹ thuật |
|---|---|---|---|
| Authentication | Xác thực danh tính | "Bạn là ai?" | Password + bcrypt, MFA TOTP, client cert mTLS |
| Authorization | Cấp quyền | "Bạn được làm gì?" | RBAC, ABAC, OAuth scopes, IAM policy |
| Accounting (Auditing) | Ghi nhận hành vi | "Bạn đã làm gì?" | Audit log, SIEM, CloudTrail |

Lưu ý phân biệt **Authentication ≠ Authorization**: một JWT hợp lệ chứng minh *bạn là ai* (authn), nhưng claim `scope`/`role` bên trong mới quyết định *bạn làm được gì* (authz). Lỗi phổ biến IDOR/BOLA là authn đúng nhưng authz thiếu.

### 4.1.3. Non-repudiation (Chống chối bỏ)

Non-repudiation = "không thể chối là tôi không làm". Chỉ đạt được bằng **chữ ký số bằng khóa riêng (private key)** mà chỉ chủ thể sở hữu.

- HMAC **không** cho non-repudiation: cả người gửi và người nhận đều biết khóa bí mật chung → người nhận có thể tự giả mạo message → không chứng minh được trước bên thứ ba.
- Chữ ký RSA/ECDSA **có** non-repudiation: chỉ chủ private key ký được, ai cũng verify bằng public key.

---

## 4.2. Ba khái niệm hay bị lẫn: Encoding vs Hashing vs Encryption

| Tiêu chí | Encoding | Hashing | Encryption |
|---|---|---|---|
| Mục đích | Biểu diễn dữ liệu cho truyền/lưu | Toàn vẹn, fingerprint, lưu mật khẩu | Bảo mật (confidentiality) |
| Cần khóa? | Không | Không (HMAC thì có) | Có |
| Đảo ngược? | Có, ai cũng đảo được | KHÔNG (one-way) | Có, nếu có khóa |
| Đầu ra cố định độ dài? | Không | Có (SHA-256 luôn 256-bit) | Không (xấp xỉ độ dài input) |
| Ví dụ | Base64, URL-encode, hex, ASCII | SHA-256, SHA-3, bcrypt | AES, RSA, ChaCha20 |

**Sai lầm chết người:** "tôi Base64 mật khẩu cho an toàn". Base64 KHÔNG phải mã hóa — không có khóa, giải ngược tức thì.

```bash
# Base64 KHÔNG bảo mật gì cả:
$ echo -n 'P@ssw0rd' | base64
UEBzc3cwcmQ=
$ echo -n 'UEBzc3cwcmQ=' | base64 -d
P@ssw0rd     # giải ra ngay, không cần khóa
```

Cơ chế Base64 (RFC 4648): gom **3 byte (24 bit)** input → chia thành **4 nhóm 6 bit** → mỗi nhóm 6 bit (0–63) tra bảng 64 ký tự `A-Za-z0-9+/`. Thiếu byte thì đệm `=`. Vì 6 bit không chia hết byte nên output dài hơn input ~33%.

```
Input :  P        @        s          (3 byte = 24 bit)
ASCII : 0x50     0x40     0x73
bits  : 01010000 01000000 01110011
chia6 : 010100 000100 000001 110011
value :   20      4       1     51
base64:   U       E       B     z
```

---

## 4.3. Mã hóa đối xứng: AES (Advanced Encryption Standard)

### 4.3.1. Tổng quan và lý do thiết kế

AES là chuẩn FIPS 197, dựa trên thuật toán **Rijndael**. Là **block cipher**: xử lý theo khối cố định **128 bit (16 byte)**. Khóa hỗ trợ 3 độ dài → số vòng tương ứng:

| Biến thể | Key size | Số vòng (Nr) | Số word khóa (Nk) |
|---|---|---|---|
| AES-128 | 128 bit (16 byte) | 10 | 4 |
| AES-192 | 192 bit (24 byte) | 12 | 6 |
| AES-256 | 256 bit (32 byte) | 14 | 8 |

Block luôn 128 bit bất kể key size (Nb = 4 word = 128 bit). Khối được biểu diễn dạng **state** — ma trận 4×4 byte, đổ theo cột (column-major):

```
input bytes b0..b15  →  state:
            col0 col1 col2 col3
row0       b0   b4   b8   b12
row1       b1   b5   b9   b13
row2       b2   b6   b10  b14
row3       b3   b7   b11  b15
```

### 4.3.2. Bốn phép biến đổi trong mỗi vòng

Mỗi vòng (trừ vòng cuối bỏ MixColumns) gồm 4 bước trên state 4×4:

**1. SubBytes** — thay thế phi tuyến từng byte qua **S-box** (256 phần tử). S-box = nghịch đảo trong trường Galois GF(2⁸) (đa thức bất khả quy `0x11B`) rồi affine transform. Mục đích: tạo **confusion** (quan hệ key↔ciphertext phức tạp), chống tuyến tính/vi phân.

```
byte 0x53 → S-box[0x53] = 0xED
(tra hàng 0x5, cột 0x3 trong bảng 16×16)
```

**2. ShiftRows** — dịch vòng từng hàng sang trái: hàng 0 dịch 0, hàng 1 dịch 1, hàng 2 dịch 2, hàng 3 dịch 3 byte. Mục đích: **diffusion** theo cột.

```
trước:          sau ShiftRows:
b0 b4 b8 b12    b0  b4  b8  b12   (dịch 0)
b1 b5 b9 b13    b5  b9  b13 b1    (dịch 1)
b2 b6 b10 b14   b10 b14 b2  b6    (dịch 2)
b3 b7 b11 b15   b15 b3  b7  b11   (dịch 3)
```

**3. MixColumns** — mỗi cột nhân với ma trận cố định trong GF(2⁸):

```
| 02 03 01 01 |   | s0 |
| 01 02 03 01 | x | s1 |
| 01 01 02 03 |   | s2 |
| 03 01 01 02 |   | s3 |
```

Mục đích: **diffusion** — một byte input ảnh hưởng cả 4 byte output cột. (Vòng cuối bỏ bước này vì không thêm bảo mật, chỉ tốn chi phí và để decryption đối xứng.)

**4. AddRoundKey** — XOR state với round key 128-bit của vòng. Đây là bước duy nhất đưa khóa vào. Round key sinh từ **key schedule** (Rijndael key expansion) dùng RotWord, SubWord, Rcon.

Trình tự đầy đủ AES-128 (10 vòng):
```
AddRoundKey(K0)                      # whitening trước
for r = 1..9:
    SubBytes → ShiftRows → MixColumns → AddRoundKey(Kr)
round 10:
    SubBytes → ShiftRows → AddRoundKey(K10)   # KHÔNG MixColumns
```

**Vì sao 10/12/14 vòng?** Khóa dài hơn cần nhiều vòng hơn để đạt đủ confusion/diffusion chống tấn công related-key và phân biệt thống kê.

### 4.3.3. Chế độ hoạt động (Modes of Operation)

Block cipher chỉ mã 1 khối 16 byte. Để mã dữ liệu dài cần **mode**.

| Mode | Cần IV/Nonce | Song song hóa | Toàn vẹn? | Vấn đề |
|---|---|---|---|---|
| ECB | Không | Có | Không | Lộ pattern |
| CBC | IV 16 byte (random, unpredictable) | Mã: không / Giải: có | Không | Padding oracle, bit-flip |
| CTR | Nonce + counter | Có | Không | Tái dùng nonce = thảm họa |
| GCM | Nonce 96-bit khuyến nghị | Có | CÓ (tag 128-bit) | Tái dùng nonce phá toàn bộ |

**ECB — vì sao lộ pattern?** Mỗi khối plaintext giống nhau → ciphertext giống nhau (`Ci = E(K, Pi)`). Ảnh ECB lộ đường viền là vì các vùng màu đồng nhất thành các khối giống hệt.

```
ECB:  C1=E(P1)  C2=E(P2)  C3=E(P3)   # P giống → C giống
```

**CBC** — XOR khối trước vào khối hiện tại để khuếch tán:
```
C0 = E(K, P0 XOR IV)
Ci = E(K, Pi XOR C(i-1))
```
IV phải **ngẫu nhiên và không đoán được** (16 byte), nếu không bị tấn công chosen-plaintext (xem TLS 1.0 BEAST).

**CTR** — biến block cipher thành stream cipher: mã hóa bộ đếm rồi XOR plaintext:
```
Ci = Pi XOR E(K, nonce || counter_i)
```
Nếu tái dùng cặp (key, nonce): hai bản mã XOR triệt tiêu keystream → lộ `P1 XOR P2`.

**GCM** = CTR (bảo mật) + GHASH (toàn vẹn). Sinh **authentication tag 128-bit** trên ciphertext + AAD. Nonce khuyến nghị **96 bit (12 byte)**. AAD (Associated Data) được xác thực nhưng không mã hóa (ví dụ header gói tin). Tái dùng nonce trong GCM còn lộ cả khóa xác thực H → giả mạo được.

### 4.3.4. Ví dụ thực tế với OpenSSL

```bash
# Tạo khóa 256-bit (32 byte) và IV 128-bit (16 byte) dạng hex
$ KEY=$(openssl rand -hex 32)   # 64 ký tự hex = 32 byte
$ IV=$(openssl rand -hex 16)    # 32 ký tự hex = 16 byte

# Mã hóa AES-256-CBC
$ echo -n "Secret message" > pt.txt
$ openssl enc -aes-256-cbc -K $KEY -iv $IV -in pt.txt -out ct.bin
$ xxd ct.bin
00000000: 8d2a 1f... (16 byte vì input <16 → pad PKCS#7 lên 1 khối)

# Giải mã
$ openssl enc -d -aes-256-cbc -K $KEY -iv $IV -in ct.bin
Secret message
```

Giải thích tham số: `enc` = symmetric encryption; `-aes-256-cbc` = thuật toán+keysize+mode; `-K` = khóa hex (chữ K hoa, dùng raw key — khác `-k` thường là passphrase qua KDF); `-iv` = IV hex; `-d` = decrypt.

AEAD với GCM (Python, thư viện `cryptography`):
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key   = AESGCM.generate_key(bit_length=256)   # 32 byte
nonce = os.urandom(12)                          # 96-bit nonce
aad   = b"header-v1"                            # xác thực, không mã hóa
aesgcm = AESGCM(key)

ct = aesgcm.encrypt(nonce, b"top secret", aad)  # ct = ciphertext || tag(16B)
print(len(ct))   # = 10 (plaintext) + 16 (tag) = 26

pt = aesgcm.decrypt(nonce, ct, aad)  # raise InvalidTag nếu sửa ct/aad/nonce
```

**Lưu ý bảo mật AES:**
- Luôn ưu tiên **AES-GCM** hoặc **ChaCha20-Poly1305** (AEAD), không CBC trần.
- **Không bao giờ tái dùng nonce** với cùng khóa trong GCM/CTR.
- Không tự cài thuật toán; dùng thư viện đã kiểm chứng (libsodium, BoringSSL).
- ECB chỉ dùng cho dữ liệu ngẫu nhiên đơn khối (gần như không bao giờ trong thực tế).

---

## 4.4. Mã hóa bất đối xứng: RSA, ECC, DH/ECDHE

### 4.4.1. RSA — từng bước toán học

RSA dựa trên độ khó **phân tích thừa số nguyên tố** của số lớn.

**Sinh khóa:**

| Ký hiệu | Ý nghĩa | Ví dụ minh họa (số nhỏ để hiểu) |
|---|---|---|
| p, q | Hai số nguyên tố lớn, bí mật | p=61, q=53 |
| n = p·q | Modulus (công khai), 2048/4096-bit | n=3233 |
| φ(n)=(p-1)(q-1) | Hàm Euler totient, bí mật | 60·52=3120 |
| e | Public exponent, gcd(e,φ)=1, thường 65537 | e=17 |
| d ≡ e⁻¹ mod φ(n) | Private exponent, bí mật | d=2753 |

- Public key = (n, e); Private key = (n, d).
- **Mã hóa:** `c = m^e mod n`
- **Giải mã:** `m = c^d mod n`

Với ví dụ: m=65 → c = 65¹⁷ mod 3233 = 2790 → m = 2790²⁷⁵³ mod 3233 = 65.

**Vì sao 65537 (0x10001)?** Là số Fermat F₄, dạng nhị phân `10000000000000001` chỉ có 2 bit 1 → lũy thừa nhanh (chỉ 17 phép bình phương + 1 nhân) nhưng đủ lớn để tránh tấn công với e nhỏ (e=3 dễ bị Coppersmith/broadcast attack).

**Padding bắt buộc:** RSA "textbook" (không padding) cực kỳ không an toàn (deterministic, malleable). Dùng:
- **OAEP** cho mã hóa (RSAES-OAEP).
- **PSS** cho chữ ký (RSASSA-PSS).

Độ dài khóa: 2048-bit là tối thiểu hiện nay; 3072/4096-bit cho dài hạn. RSA-1024 đã bị coi là yếu.

```bash
# Sinh cặp khóa RSA 4096-bit
$ openssl genrsa -out priv.pem 4096
$ openssl rsa -in priv.pem -pubout -out pub.pem

# Xem chi tiết khóa (modulus, exponent)
$ openssl rsa -in priv.pem -text -noout | head
Private-Key: (4096 bit, 2 primes)
modulus: 00:c3:a1:...        # n
publicExponent: 65537 (0x10001)
privateExponent: ...          # d
prime1: ... prime2: ...        # p, q

# Mã hóa file nhỏ bằng OAEP (RSA chỉ mã được ≤ keysize - padding)
$ echo -n "session-key-material" | \
  openssl pkeyutl -encrypt -pubin -inkey pub.pem \
  -pkeyopt rsa_padding_mode:oaep -out enc.bin
$ openssl pkeyutl -decrypt -inkey priv.pem \
  -pkeyopt rsa_padding_mode:oaep -in enc.bin
session-key-material
```

RSA chỉ mã hóa được dữ liệu nhỏ hơn modulus → thực tế dùng **hybrid encryption**: RSA mã hóa một khóa AES ngẫu nhiên, AES mã hóa dữ liệu lớn.

```
Sơ đồ mã hóa lai (hybrid encryption):

Bên gửi                                              Bên nhận
────────                                             ────────
data (lớn) ──┐
             │
   K_sym ────┼──► AES-GCM(K_sym, data) ─► ciphertext ─────────► AES-GCM giải ─► data
 (ngẫu nhiên)│                                                       ▲
             │                                                       │ K_sym
             └──► RSA-OAEP(pub, K_sym) ─► enc_key ──────────► RSA giải (priv)
                  (bất đối xứng trao khóa)            (đối xứng mã dữ liệu khối lớn)
```

Bất đối xứng (RSA/ECDH) chỉ làm nhiệm vụ **trao khóa phiên** an toàn; khóa đối xứng (AES) gánh phần mã hóa khối lượng dữ liệu lớn vì nhanh hơn nhiều. Đây chính là mô hình TLS dùng cho mọi phiên HTTPS.

### 4.4.2. ECC — Elliptic Curve Cryptography

ECC dựa trên độ khó của **bài toán logarit rời rạc trên đường cong elliptic (ECDLP)**. Ưu điểm: khóa ngắn hơn nhiều mà cùng độ an toàn.

| Độ an toàn tương đương | RSA | ECC |
|---|---|---|
| ~128-bit | 3072-bit | 256-bit (P-256, Curve25519) |
| ~192-bit | 7680-bit | 384-bit (P-384) |
| ~256-bit | 15360-bit | 521-bit (P-521) |

Đường cong dạng Weierstrass: `y² = x³ + ax + b mod p`. Phép toán cơ bản là **point addition** và **scalar multiplication** `Q = k·G` (G là điểm sinh, k là private key, Q là public key). An toàn vì từ Q và G khó tìm ngược k.

Đường cong phổ biến: NIST P-256 (secp256r1), **Curve25519** (X25519 cho ECDH, Ed25519 cho chữ ký) — Curve25519 được ưa chuộng vì thiết kế chống lỗi cài đặt, không có tham số nghi ngờ backdoor.

```bash
# Sinh khóa Ed25519 (chữ ký) — ví dụ SSH key hiện đại
$ ssh-keygen -t ed25519 -C "ops@example.com" -f id_ed25519
# Khóa public chỉ ~68 ký tự, an toàn ~128-bit
```

### 4.4.3. Diffie-Hellman & ECDHE — Forward Secrecy

**DH** cho phép hai bên thỏa thuận khóa chung qua kênh công khai mà không truyền khóa.

```
Công khai: số nguyên tố p, generator g
Alice: chọn a bí mật → gửi A = g^a mod p
Bob  : chọn b bí mật → gửi B = g^b mod p
Khóa chung: Alice tính B^a = g^(ab); Bob tính A^b = g^(ab)  → BẰNG NHAU
Kẻ nghe lén thấy g, p, A, B nhưng không tính được g^(ab) (bài toán DLP)
```

**ECDHE** = DH trên đường cong elliptic, **ephemeral** (khóa tạm thời mỗi phiên). Chữ "E" cuối (ephemeral) là chìa khóa của **Forward Secrecy (PFS)**:

> Nếu khóa riêng dài hạn của server bị lộ trong tương lai, các phiên đã ghi lại trong quá khứ **không** giải mã được, vì khóa phiên dùng cặp ECDHE tạm thời đã bị hủy.

Đây là lý do TLS 1.3 **bắt buộc** dùng (EC)DHE ephemeral, loại bỏ hoàn toàn RSA key exchange tĩnh (vốn không có forward secrecy — lộ private key server giải được mọi phiên cũ đã ghi).

---

## 4.5. Hàm băm mật mã (Cryptographic Hash)

### 4.5.1. Tính chất bắt buộc

| Tính chất | Định nghĩa | Hệ quả nếu vỡ |
|---|---|---|
| Pre-image resistance | Từ h khó tìm m sao cho H(m)=h | Đảo ngược hash |
| Second pre-image | Cho m1, khó tìm m2≠m1 cùng hash | Giả mạo có chủ đích |
| Collision resistance | Khó tìm bất kỳ m1≠m2 cùng hash | Giả chứng chỉ (MD5/SHA-1 đã vỡ) |
| Avalanche effect | Đổi 1 bit input → ~50% bit output đổi | — |

### 4.5.2. SHA-256 — cấu trúc Merkle–Damgård

| Tham số | Giá trị |
|---|---|
| Kích thước output | 256 bit (32 byte) |
| Kích thước block | 512 bit (64 byte) |
| Word size | 32 bit |
| Số vòng nén | 64 |
| Hằng số H ban đầu | 8 word (từ căn bậc 2 của 8 số nguyên tố đầu) |
| Hằng số K | 64 word (từ căn bậc 3 của 64 số nguyên tố đầu) |

**Quy trình (Merkle–Damgård):**
1. **Padding:** thêm 1 bit `1`, rồi các bit `0`, sao cho độ dài ≡ 448 mod 512, rồi 64 bit cuối ghi **độ dài message gốc** (big-endian). Tổng chia hết 512.
2. Chia thành các block 512-bit.
3. Mỗi block: mở rộng 16 word → 64 word (message schedule W), chạy 64 vòng nén cập nhật 8 biến a–h với các hàm Σ, σ, Ch, Maj.
4. Cộng vào hash trung gian (chaining); block cuối ra digest.

```
[H0..H7 init] → compress(block1) → compress(block2) → ... → digest 256-bit
                     ↑ chaining value đưa vào block sau
```

```bash
$ echo -n "abc" | sha256sum
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -
# luôn 64 ký tự hex = 256 bit, dù input dài ngắn thế nào
$ echo -n "abd" | sha256sum   # đổi 1 ký tự → digest hoàn toàn khác (avalanche)
a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9  -
```

**Lỗ hổng length-extension:** vì Merkle–Damgård lộ trạng thái trung gian = digest, kẻ tấn công biết `H(secret||msg)` và độ dài secret có thể tính `H(secret||msg||padding||extra)` mà không biết secret. Đây là lý do **không dùng `H(secret||message)` làm MAC** — phải dùng HMAC. (SHA-3 không bị do cấu trúc sponge.)

### 4.5.3. SHA-3 (Keccak) — cấu trúc Sponge

SHA-3 (FIPS 202) dùng cấu trúc **sponge** khác hẳn Merkle–Damgård:
- State 1600 bit, chia **rate (r)** + **capacity (c)**.
- Giai đoạn **absorb**: XOR block vào phần rate rồi áp hàm hoán vị Keccak-f.
- Giai đoạn **squeeze**: lấy output từ phần rate.
- Miễn nhiễm length-extension. Cũng có biến thể SHAKE128/256 (XOF — output độ dài tùy ý).

SHA-3 là dự phòng kiến trúc cho SHA-2, **không** thay thế vì SHA-2 yếu (SHA-2 vẫn an toàn). Khác biệt giúp đa dạng hóa rủi ro.

### 4.5.4. Vì sao loại bỏ MD5 và SHA-1

| Hàm | Output | Trạng thái | Bằng chứng |
|---|---|---|---|
| MD5 | 128-bit | VỠ HOÀN TOÀN | Collision tạo được trong giây; chứng chỉ CA giả (Flame malware 2012) |
| SHA-1 | 160-bit | VỠ | SHAttered (2017, Google): 2 PDF khác nhau cùng SHA-1; Git đã chuyển dần SHA-256 |
| SHA-256/SHA-3 | 256-bit | An toàn | Khuyến nghị hiện tại |

MD5/SHA-1 chỉ còn chấp nhận cho **checksum không liên quan bảo mật** (phát hiện lỗi truyền ngẫu nhiên), tuyệt đối không dùng cho chữ ký, chứng chỉ, lưu mật khẩu.

---

## 4.6. Lưu trữ mật khẩu an toàn

### 4.6.1. Vì sao không hash thường

Hash thường (SHA-256) **quá nhanh** → GPU thử hàng tỷ ứng viên/giây (brute-force, rainbow table). Cần hàm **chậm có chủ đích** và **có salt**.

| Khái niệm | Định nghĩa | Chống được |
|---|---|---|
| Salt | Chuỗi ngẫu nhiên duy nhất mỗi user, lưu cùng hash | Rainbow table, hash trùng nhau |
| Pepper | Bí mật chung (HSM/biến môi trường), KHÔNG lưu cùng DB | Lộ toàn bộ DB vẫn an toàn nếu pepper không lộ |
| Work factor / cost | Tham số làm hàm chậm hơn (lặp, RAM) | Brute-force GPU/ASIC |

### 4.6.2. bcrypt — định dạng chi tiết

bcrypt sinh chuỗi **60 ký tự** với cấu trúc:

```
$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
└┬┘└┬┘ └───────────────────┬──────────────────────────────┘
 │  │                       │
 │  │   salt(22 ký tự,128-bit) + hash(31 ký tự,184-bit) — base64 bcrypt
 │  └─ cost = 12 → 2^12 = 4096 vòng key setup
 └─ algo version: $2b$ (bản hiện đại)
```

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|---|---|---|---|
| Prefix | 4 ký tự | Version | `$2b$` |
| Cost | 2 ký tự | log2(số vòng) | `12` |
| Salt | 22 ký tự (128-bit) | Salt base64 | `R9h/cIPz0gi.URNNX3kh2O` |
| Hash | 31 ký tự (184-bit) | Digest | `PST9/...MUW` |

Giới hạn: bcrypt cắt input ở **72 byte**. Cost tăng 1 → gấp đôi thời gian.

```python
import bcrypt
pw = b"P@ssw0rd"
hashed = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
# b'$2b$12$....'  — salt nằm trong chuỗi, không cần lưu riêng
assert bcrypt.checkpw(pw, hashed)   # True
```

### 4.6.3. scrypt & Argon2

- **scrypt:** thêm tham số **memory-hard** (N, r, p) → tốn RAM, chống ASIC/GPU vốn yếu về bộ nhớ.
- **Argon2** (winner Password Hashing Competition 2015): chuẩn khuyến nghị hiện nay.
  - **Argon2id** (lai, khuyến nghị mặc định), Argon2i (chống side-channel), Argon2d (chống GPU).
  - Tham số: `m` (memory KiB), `t` (iterations/time), `p` (parallelism).

```
$argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>
         │     │     │    │  │
         │     │     │    │  └ parallelism=4 luồng
         │     │     │    └ iterations=3
         │     │     └ memory=65536 KiB (64 MiB)
         │     └ version 0x13 (19)
         └ biến thể id
```

```bash
# argon2 CLI
$ echo -n "P@ssw0rd" | argon2 mysalt1234 -id -t 3 -m 16 -p 4
Encoded: $argon2id$v=19$m=65536,t=3,p=4$bXlzYWx0MTIzNA$...
```

**Lưu ý:** dùng Argon2id cho hệ mới; bcrypt vẫn chấp nhận được; PBKDF2 chỉ khi bắt buộc tuân thủ (FIPS). Pepper lưu tách biệt khỏi DB (KMS/HSM). Luôn so sánh hash bằng hàm **constant-time** để chống timing attack.

---

## 4.7. HMAC — Hash-based Message Authentication Code

HMAC chứng minh **toàn vẹn + xác thực nguồn gốc** bằng khóa chia sẻ. Công thức (RFC 2104):

```
HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )

K'   = khóa được pad/băm về đúng block size của H (SHA-256: 64 byte)
ipad = byte 0x36 lặp lại (block size lần)
opad = byte 0x5c lặp lại (block size lần)
```

**Vì sao hai lớp (inner+outer) và ipad/opad?** Cấu trúc lồng hai lần chống chính length-extension attack đã nêu ở mục 4.5.2; nếu chỉ `H(K||m)` thì giả mạo được. ipad/opad là hai hằng số khác nhau để hai lần băm dùng khóa "khác nhau", tăng độ vững.

```bash
$ echo -n "msg" | openssl dgst -sha256 -hmac "secretkey"
HMAC-SHA256(stdin)= 3f2a...   # đổi key hoặc msg → MAC đổi hoàn toàn
```

```python
import hmac, hashlib
mac = hmac.new(b"secretkey", b"msg", hashlib.sha256).hexdigest()
# Verify PHẢI dùng compare_digest (constant-time) chống timing:
hmac.compare_digest(mac, received_mac)
```

Ứng dụng: JWT (HS256), API request signing (AWS SigV4), webhook signature (GitHub `X-Hub-Signature-256`), TOTP/HOTP.

---

## 4.8. Chữ ký số — từng bước

Chữ ký số đảm bảo **Integrity + Authentication + Non-repudiation**.

**Ký (bên gửi, dùng PRIVATE key):**
```
1. digest = H(message)                 # băm trước, vì RSA/ECDSA chỉ ký số nhỏ
2. signature = Sign(privKey, digest)   # RSA-PSS: dựa trên digest^d mod n
3. Gửi: message || signature
```

**Verify (bên nhận, dùng PUBLIC key):**
```
1. digest'  = H(message)               # băm lại message nhận được
2. valid    = Verify(pubKey, signature, digest')
3. valid==true ↔ message không sửa VÀ do chủ private key ký
```

So sánh với mã hóa: mã hóa dùng public key để mã (ai cũng mã được, chỉ chủ giải) ; chữ ký dùng **private key để ký** (chỉ chủ ký được, ai cũng verify) — ngược chiều.

```bash
# Ký file
$ openssl dgst -sha256 -sign priv.pem -out sig.bin document.pdf
# Verify
$ openssl dgst -sha256 -verify pub.pem -signature sig.bin document.pdf
Verified OK
```

Thuật toán: **RSA-PSS** (RSA), **ECDSA** (P-256), **Ed25519** (nhanh, an toàn, deterministic — không phụ thuộc RNG khi ký nên tránh lỗi nonce như Sony PS3 ECDSA 2010 dùng nonce cố định làm lộ private key).

---

## 4.9. PKI & X.509

### 4.9.1. Chuỗi tin cậy

```
Root CA (self-signed, trong trust store OS/browser)
   └── Intermediate CA (ký bởi Root)
          └── Leaf/End-entity cert (ký bởi Intermediate) — server của bạn
```

Client tin Leaf vì verify được chuỗi chữ ký lên đến Root đã tin sẵn. Server phải gửi cả **chain** (leaf + intermediate), không cần gửi root.

### 4.9.2. Các trường chứng chỉ X.509 v3

| Trường | Ý nghĩa | Ví dụ |
|---|---|---|
| Version | Phiên bản (v3 = 2) | v3 |
| Serial Number | Số seri duy nhất do CA cấp | `04:A2:...` |
| Signature Algorithm | Thuật toán CA ký | `sha256WithRSAEncryption` / `ecdsa-with-SHA256` |
| Issuer | DN của CA cấp | `CN=R3, O=Let's Encrypt` |
| Validity (Not Before / Not After) | Khoảng hiệu lực | 2026-01-01 → 2026-04-01 |
| Subject | DN chủ thể | `CN=example.com` |
| Subject Public Key Info | Public key + thuật toán | RSA 2048 / EC P-256 |
| **SAN** (Subject Alternative Name) | Danh sách host hợp lệ (BẮT BUỘC, CN bị deprecate) | `DNS:example.com, DNS:www.example.com` |
| Key Usage | Mục đích khóa | `Digital Signature, Key Encipherment` |
| Extended Key Usage | EKU | `TLS Web Server Authentication` |
| Basic Constraints | CA hay không | `CA:FALSE` |
| Signature | Chữ ký CA trên toàn bộ TBSCertificate | — |

**Quan trọng:** trình duyệt hiện đại **bỏ qua CN**, chỉ kiểm tra **SAN**. Cert thiếu SAN → lỗi `ERR_CERT_COMMON_NAME_INVALID`.

```bash
# Xem chi tiết cert của một server
$ openssl s_client -connect example.com:443 -servername example.com </dev/null \
  | openssl x509 -noout -text

# Hoặc kiểm tra nhanh các trường chính
$ echo | openssl s_client -connect example.com:443 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
subject=CN=example.com
issuer=C=US, O=DigiCert Inc, CN=...
notBefore=...  notAfter=...
X509v3 Subject Alternative Name:
    DNS:example.com, DNS:www.example.com
```

```bash
# Tạo CSR (Certificate Signing Request) với SAN
$ openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.csr \
  -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"
```

### 4.9.3. Thu hồi: CRL vs OCSP

| Cơ chế | Mô tả | Nhược điểm |
|---|---|---|
| CRL (Certificate Revocation List) | CA công bố danh sách serial bị thu hồi, client tải về | File lớn, cập nhật chậm |
| OCSP | Client hỏi CA realtime về 1 cert cụ thể | Lộ duyệt web của user cho CA; latency |
| **OCSP Stapling** | Server tự lấy OCSP response (đã CA ký, có timestamp) và "đính" vào TLS handshake | Khắc phục privacy + latency của OCSP |

```bash
# Kiểm tra OCSP stapling
$ openssl s_client -connect example.com:443 -status </dev/null 2>/dev/null \
  | grep -A2 "OCSP Response Status"
OCSP Response Status: successful (0x0)
    Cert Status: good
```

---

## 4.10. Mô hình rủi ro & quản lý lỗ hổng

### 4.10.1. Bốn khái niệm cốt lõi

| Thuật ngữ | Định nghĩa | Ví dụ |
|---|---|---|
| Vulnerability | Điểm yếu trong hệ thống | SQLi, thư viện chưa vá |
| Threat | Tác nhân/sự kiện có thể khai thác điểm yếu | Attacker, ransomware group |
| Exploit | Công cụ/kỹ thuật cụ thể tận dụng vuln | PoC RCE, Metasploit module |
| Risk | Khả năng tổn hại = **Likelihood × Impact** | Vuln có exploit công khai trên server public = risk cao |

> **Risk = Likelihood × Impact.** Một vuln nghiêm trọng (high impact) nhưng chỉ khai thác được từ mạng nội bộ đã cách ly (low likelihood) → risk thấp hơn vuln trung bình trên endpoint public Internet.

### 4.10.2. CVE và CWE

- **CVE** (Common Vulnerabilities and Exposures): định danh **một lỗ hổng cụ thể trong một sản phẩm cụ thể**. Định dạng `CVE-YYYY-NNNNN` (ví dụ `CVE-2021-44228` = Log4Shell).
- **CWE** (Common Weakness Enumeration): phân loại **loại điểm yếu** chung (ví dụ `CWE-79` = XSS, `CWE-89` = SQLi, `CWE-787` = Out-of-bounds Write). Một CVE thường ánh xạ tới một hoặc nhiều CWE.

Quan hệ: CWE là "loại bệnh", CVE là "ca bệnh cụ thể".

### 4.10.3. CVSS v3.1 — từng metric của Base Score

Điểm CVSS Base (0.0–10.0) tính từ 8 metric chia 2 nhóm:

**Exploitability metrics:**

| Metric | Giá trị | Ý nghĩa |
|---|---|---|
| **AV** Attack Vector | Network(N) / Adjacent(A) / Local(L) / Physical(P) | Khai thác từ đâu — N (qua Internet) nguy hiểm nhất |
| **AC** Attack Complexity | Low(L) / High(H) | Điều kiện đặc biệt cần có không |
| **PR** Privileges Required | None(N) / Low(L) / High(H) | Cần quyền gì trước khi khai thác |
| **UI** User Interaction | None(N) / Required(R) | Có cần nạn nhân click/thao tác không |

**Scope + Impact metrics:**

| Metric | Giá trị | Ý nghĩa |
|---|---|---|
| **S** Scope | Unchanged(U) / Changed(C) | Khai thác có vượt ra ngoài component bị ảnh hưởng (ví dụ thoát sandbox/VM) |
| **C** Confidentiality | None/Low/High | Mức lộ dữ liệu |
| **I** Integrity | None/Low/High | Mức sửa đổi dữ liệu |
| **A** Availability | None/Low/High | Mức gián đoạn dịch vụ |

**Vector string ví dụ** (Log4Shell, điểm 10.0 Critical):
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        │    │    │    │    │   │   │   │
        │    │    │    │    │   └───┴───┴── tác động Cao toàn diện
        │    │    │    │    └ Scope Changed (vượt component)
        │    │    │    └ không cần tương tác người dùng
        │    │    └ không cần quyền trước
        │    └ độ phức tạp thấp
        └ khai thác qua mạng
```

Phân ngưỡng định tính: 0.0 None · 0.1–3.9 Low · 4.0–6.9 Medium · 7.0–8.9 High · 9.0–10.0 Critical.

Ngoài Base còn có nhóm **Temporal** (mức trưởng thành exploit, có bản vá chưa) và **Environmental** (tùy chỉnh theo môi trường tổ chức). Lưu ý: CVSS v4.0 đã ra (2023) thay đổi cấu trúc metric — khi triển khai cần kiểm chứng phiên bản đang dùng.

```bash
# Quét vuln và ánh xạ CVE/CVSS trong CI (ví dụ container)
$ trivy image --severity HIGH,CRITICAL myapp:latest
myapp:latest (alpine 3.18)
Total: 2 (HIGH: 1, CRITICAL: 1)
┌──────────┬───────────────┬──────────┬───────────────┐
│ Library  │ Vulnerability │ Severity │ Fixed Version │
├──────────┼───────────────┼──────────┼───────────────┤
│ openssl  │ CVE-2023-xxxx │ CRITICAL │ 3.1.4-r0      │
└──────────┴───────────────┴──────────┴───────────────┘
```

---

## 4.11. Nguyên tắc thiết kế bảo mật (Secure Design Principles)

| Nguyên tắc | Nội dung | Áp dụng thực tế |
|---|---|---|
| Least Privilege | Cấp quyền tối thiểu đủ dùng | IAM scope hẹp, container non-root |
| Defense in Depth | Nhiều lớp phòng thủ độc lập | WAF + input validation + parameterized query |
| Fail Securely | Lỗi thì mặc định từ chối | `deny by default`, exception không lộ stack trace |
| Complete Mediation | Kiểm tra quyền mọi lần truy cập | Không cache quyết định authz cũ |
| Open Design (Kerckhoffs) | An toàn dựa vào KHÓA, không dựa vào giấu thuật toán | Dùng AES công khai, không "secret algo" |
| Economy of Mechanism | Đơn giản nhất có thể | Ít code = ít bug |
| Separation of Duties | Tách vai trò | Người deploy ≠ người duyệt |
| Psychological Acceptability | Bảo mật không cản trở quá mức | SSO thay vì 20 mật khẩu |
| Zero Trust | "Never trust, always verify" | Xác thực mọi request, mTLS nội bộ |
| Secure Defaults | Mặc định an toàn | TLS bật sẵn, port đóng sẵn |

**Kerckhoffs's Principle** là nền tảng triết lý của cả chương: một hệ mật phải an toàn ngay cả khi mọi thứ về nó (trừ khóa) đều công khai. Đây là lý do AES/RSA/SHA-256 đều là chuẩn mở, được công khai mổ xẻ — "security through obscurity" (giấu thuật toán) không phải bảo mật.

---

## 4.12. Tổng kết bản đồ quyết định

| Cần gì | Dùng gì |
|---|---|
| Bí mật dữ liệu khối lượng lớn | AES-256-GCM / ChaCha20-Poly1305 (AEAD) |
| Trao đổi khóa qua kênh hở | ECDHE (forward secrecy) |
| Mã hóa khóa / dữ liệu nhỏ bất đối xứng | RSA-OAEP 3072+ hoặc ECIES |
| Toàn vẹn + xác thực có khóa chung | HMAC-SHA256 |
| Toàn vẹn + xác thực + chống chối bỏ | Chữ ký số Ed25519 / ECDSA / RSA-PSS |
| Fingerprint / checksum bảo mật | SHA-256 / SHA-3 |
| Lưu mật khẩu | Argon2id (hoặc bcrypt) + salt + pepper |
| Danh tính máy chủ trên Internet | X.509 + TLS 1.3 + OCSP stapling |

Quy tắc bao trùm: **không tự cài nguyên thủy mật mã**, dùng thư viện đã kiểm chứng (libsodium, BoringSSL, Go crypto, Python `cryptography`), tuân Kerckhoffs, ưu tiên AEAD và forward secrecy, và luôn đặt câu hỏi "thuộc tính CIA nào đang được bảo vệ?" trước khi chọn công cụ.
