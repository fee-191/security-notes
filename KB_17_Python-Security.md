# Chương 17 — Lập trình & Tự động hóa cho bảo mật

## Tổng quan

Chương này trình bày việc dùng **Python làm ngôn ngữ tự động hóa cho an ninh mạng**: thay thế các thao tác thủ công lặp lại bằng script và công cụ. Đây là nhu cầu bắt buộc vì khối lượng dữ liệu bảo mật vượt khả năng xử lý thủ công — log nhiều GB, hàng nghìn máy chủ, hàng triệu gói tin — trong khi Python cho tốc độ phát triển nhanh và hệ sinh thái thư viện bao phủ gần như mọi tác vụ.

**Định nghĩa cốt lõi.** Tự động hóa bảo mật là quá trình chuyển các tác vụ thu thập, phân tích, ra quyết định và phản ứng sự cố thành mã chạy được, có thể lặp lại và kiểm chứng. Python đóng vai trò **glue language**: phần logic viết bằng Python, phần tính toán nặng giao cho thư viện C đã tối ưu và được audit.

**Các nhóm công cụ trong chương — khái niệm và vấn đề chúng giải quyết:**

- **Nền tảng cú pháp (`bytes`/`str`, `struct`):** phân biệt dữ liệu văn bản (`str`) với dữ liệu nhị phân thô (`bytes`) mà mạng và crypto thực sự truyền; `struct` bóc tách gói tin thành từng trường. Giải quyết: nguồn lỗi số một khi parse packet và tính hash.
- **`socket`:** tạo kết nối TCP/UDP cấp thấp. Giải quyết: xây port scanner — bước trinh sát cơ bản trong kiểm thử an ninh.
- **`requests`:** HTTP client gọi REST API theo cách lập trình. Giải quyết: tự động tạo ticket, gửi cảnh báo, lấy dữ liệu từ Jira/Slack/SIEM.
- **`re` (regex):** mô tả khuôn mẫu để trích thông tin từ văn bản phi cấu trúc. Giải quyết: lọc sự kiện cần thiết trong log hàng triệu dòng.
- **`subprocess` & `os`:** gọi chương trình hệ thống và thao tác file/quyền. Giải quyết: tích hợp công cụ ngoài; đồng thời là điểm nóng số một của **command injection**, chương trình bày cách gọi an toàn.
- **`json`:** định dạng trao đổi dữ liệu giữa các chương trình. Giải quyết: ngôn ngữ chung với API và file cấu hình mà cả người lẫn máy đọc được.
- **`scapy`:** dựng, gửi và sniff gói tin tới từng trường header. Giải quyết: các tác vụ socket thường không làm được — quét kín đáo, phát hiện ARP spoofing.
- **`paramiko`:** client SSHv2 thuần Python. Giải quyết: tự động đăng nhập, chạy lệnh audit cấu hình trên fleet hàng trăm máy chủ.
- **`boto3`:** SDK AWS chính thức. Giải quyết: audit cấu hình cloud (S3 public, security group mở), thu thập log, phản ứng sự cố tự động.
- **`hashlib` & `hmac`:** hàm băm mật mã và mã xác thực thông điệp có khóa. Giải quyết: kiểm tra toàn vẹn file và xác thực nguồn gốc thông điệp (webhook) chống giả mạo.
- **`secrets`:** sinh giá trị ngẫu nhiên bằng CSPRNG của OS. Giải quyết: tạo token/session ID không đoán được, tránh bẫy `random` (Mersenne Twister) vốn dự đoán được.
- **Secure coding & SAST:** tập thói quen viết mã không tạo lỗ hổng (injection, path traversal) và công cụ (Bandit) tự dò anti-pattern. Giải quyết: phát hiện sớm sai sót do con người bỏ sót.
- **IR Agent & Docker:** IR Agent (Incident Response) là ví dụ tổng hợp ghép các phần trên thành luồng đọc log → phát hiện → cảnh báo → phản ứng; Docker đóng gói công cụ cùng dependency vào image bất biến, chạy nhất quán và cô lập khỏi host phân tích.

Các mục sau đi sâu vào cơ chế kỹ thuật của từng thành phần.

> Tài liệu tham chiếu chuyên sâu cho kỹ sư bảo mật (Blue Team / AppSec / DevSecOps). Mỗi mục đi theo cấu trúc: **Là gì → Cơ chế bên trong (tới mức bit/byte/bước/tham số) → Ví dụ thực tế → Lưu ý bảo mật**. Các con số kỹ thuật đều cố gắng bám theo spec/RFC/manual chính thức; những điểm cần kiểm chứng đều được ghi rõ.

---

## 17.1. Vì sao Python thống trị an ninh mạng & tự động hóa

Python được chọn làm "glue language" của bảo mật vì ba lý do kỹ thuật cụ thể, không phải vì "dễ học":

1. **CPython có C-API ổn định** → hầu hết thư viện crypto/network (OpenSSL qua `cryptography`, libpcap qua `scapy`, libssh2/openssh qua `paramiko`) đều có binding C tốc độ cao. Phần logic viết bằng Python, phần nặng chạy bằng C đã được tối ưu và audit.
2. **Mô hình object + duck typing** cho phép viết tool nhanh, parse dữ liệu bán cấu trúc (log, JSON, packet) mà không cần khai báo kiểu cứng nhắc.
3. **Hệ sinh thái packaging** (`pip`, PyPI, wheel) cho phép phân phối tool ngay, và `venv` cô lập dependency — quan trọng khi một host phân tích forensic không được "nhiễm bẩn".

Điểm cần nhớ về mặt bảo mật ngay từ đầu: **GIL (Global Interpreter Lock)** trong CPython khiến đa luồng (`threading`) không chạy song song CPU-bound, nhưng vẫn song song được I/O-bound (socket, file, HTTP). Vì hầu hết tool bảo mật là I/O-bound (chờ mạng, chờ disk), `threading` và `asyncio` vẫn cực kỳ hữu ích; chỉ khi crack hash/bruteforce CPU-bound mới cần `multiprocessing`.

---

## 17.2. Nền tảng cú pháp Python cho bảo mật (ôn nhanh, đào sâu chỗ hay sai)

### 17.2.1. Kiểu dữ liệu và biểu diễn nhị phân

Kỹ sư bảo mật làm việc với byte liên tục, nên phải phân biệt rạch ròi `str` và `bytes` — đây là nguồn bug số 1 khi parse packet/crypto.

| Kiểu | Bản chất | Bất biến? | Dùng khi |
|------|----------|-----------|----------|
| `int` | Số nguyên độ chính xác tùy ý (arbitrary precision) | Có | Đếm, offset, bitmask |
| `bytes` | Dãy byte 0–255, bất biến | Có | Dữ liệu mạng, hash, payload thô |
| `bytearray` | Dãy byte có thể sửa tại chỗ | Không | Build packet, sửa buffer |
| `str` | Dãy Unicode code point | Có | Văn bản, log đã decode |
| `memoryview` | View zero-copy (không sao chép) lên buffer | — | Xử lý buffer lớn không copy |

**Cơ chế bên trong — vì sao `str` ≠ `bytes`:** Một `str` Python 3 là chuỗi *code point* Unicode; nó không có "encoding" nội tại cho tới khi `.encode()`. Một byte mạng (ví dụ byte `0xC3 0xA9`) chỉ trở thành ký tự `é` nếu bạn biết encoding là UTF-8. Trộn lẫn hai loại này khi tính HMAC sẽ ra digest sai.

```python
# Chuyển đổi tường minh — luôn chỉ định encoding
s = "héllo"
b = s.encode("utf-8")        # b'h\xc3\xa9llo'  -> 6 byte (é = 2 byte)
print(len(s), len(b))        # 5 6  -> 5 ký tự nhưng 6 byte (é chiếm 2 byte)
# Biểu diễn hex/độ dài chính xác:
print(b.hex())               # '68c3a96c6c6f'  (mỗi byte = 2 hex digit)
print(len(b))                # 6

# Đọc 1 trường big-endian 4 byte từ packet:
raw = b"\x00\x00\x05\xdc"    # 1500
mtu = int.from_bytes(raw, byteorder="big", signed=False)
print(mtu)                   # 1500

# Đóng gói ngược lại:
print((1500).to_bytes(2, "big").hex())   # '05dc'
```

**Lưu ý:** Khi so sánh token/MAC, đừng dùng `==` trên `str`/`bytes` vì nó short-circuit (dừng sớm khi gặp byte khác → timing leak). Dùng `hmac.compare_digest()` (xem 17.13).

### 17.2.2. struct — đọc/ghi nhị phân theo trường

`struct` là cầu nối giữa byte mạng và kiểu Python. Format string điều khiển byte order và kích thước:

| Ký tự | Kiểu C | Kích thước | Ghi chú |
|-------|--------|-----------|---------|
| `B` | unsigned char | 1 byte | 0–255 |
| `H` | unsigned short | 2 byte | 0–65535 |
| `I` | unsigned int | 4 byte | |
| `Q` | unsigned long long | 8 byte | |
| `s` | char[] | n byte | `4s` = 4 byte raw |
| `!` (prefix) | — | — | network byte order = big-endian, no padding |
| `<` / `>` | — | — | little / big endian |

```python
import struct
# Đọc header IPv4 12 byte đầu: version+IHL(1B), TOS(1B), total_len(2B), id(2B), flags+frag(2B), ttl(1B), proto(1B), checksum(2B)
ip_head = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\xb1\xe6"
ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, csum = struct.unpack("!BBHHHBBH", ip_head)
version = ver_ihl >> 4          # 4
ihl = (ver_ihl & 0x0F) * 4      # 5*4 = 20 byte header length
print(version, ihl, tot_len, ttl, proto)   # 4 20 60 64 6 (proto 6 = TCP)
```

### 17.2.3. List/Dict/Set comprehension & generator

```python
logs = ["ok", "FAIL ip=10.0.0.1", "FAIL ip=10.0.0.2", "ok", "FAIL ip=10.0.0.1"]
fails = [l for l in logs if l.startswith("FAIL")]                  # list comp
ips   = {l.split("ip=")[1] for l in fails}                        # set comp -> unique IP
count = {ip: sum(ip in l for l in fails) for ip in ips}           # dict comp -> đếm
# Generator: lazy, không nạp hết file vào RAM — quan trọng cho log GB
def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:          # generator pattern, đọc từng dòng
            yield line.rstrip("\n")
```

**Vì sao generator quan trọng cho bảo mật:** file log `/var/log/auth.log` có thể vài GB. List comprehension `[l for l in open(...)]` nạp toàn bộ vào RAM → OOM. Generator giữ một dòng tại một thời điểm.

### 17.2.4. Hàm, *args/**kwargs, type hint

```python
from typing import Iterable
def scan_ports(host: str, ports: Iterable[int], timeout: float = 1.0) -> dict[int, bool]:
    """Type hint giúp tool lớn dễ audit; không enforce lúc chạy."""
    ...
```
Type hint không được CPython kiểm tra lúc runtime — chúng phục vụ `mypy`/IDE và việc audit code. Để kiểm thật lúc runtime cần `pydantic` (validate input từ mạng/API).

### 17.2.5. Exception và context manager

```python
import socket
try:
    s = socket.create_connection(("10.0.0.5", 22), timeout=2)
except (socket.timeout, ConnectionRefusedError) as e:
    print("closed/filtered:", e)
except OSError as e:               # bắt nhóm rộng hơn cuối cùng
    print("network error:", e)
else:
    print("open")
    s.close()
finally:
    pass                           # cleanup luôn chạy
```

**Context manager** đảm bảo tài nguyên (socket, file, lock) được giải phóng kể cả khi có exception — tránh leak file descriptor (một dạng DoS tự gây ra khi scan hàng nghìn host):

```python
from contextlib import contextmanager
@contextmanager
def timed_socket(addr, timeout):
    s = socket.create_connection(addr, timeout=timeout)
    try:
        yield s
    finally:
        s.close()      # luôn đóng, kể cả lỗi giữa chừng
```

### 17.2.6. virtualenv & pip — cô lập và pin dependency

```bash
# Tạo môi trường cô lập (Python 3.3+ có sẵn venv)
python3 -m venv .venv
source .venv/bin/activate          # Linux/mac;  .venv\Scripts\activate trên Windows
pip install --upgrade pip
pip install requests scapy paramiko boto3

# Pin chính xác để build tái lập (reproducible) — quan trọng cho audit & supply chain
pip freeze > requirements.txt      # ghi version chính xác: requests==2.32.3 ...
pip install -r requirements.txt

# Kiểm tra lỗ hổng đã biết trong dependency (supply-chain)
pip install pip-audit
pip-audit -r requirements.txt      # tra cứu OSV/PyPI advisory DB
```

**Lưu ý (supply chain):**
- Nên **pin version** (`==`) trong môi trường production; range mở (`>=`) cho phép kẻ tấn công đẩy bản độc qua dependency confusion.
- Cân nhắc **hash-pinning**: `pip install --require-hashes -r requirements.txt` với file chứa `--hash=sha256:...` → chống thay thế artifact trên PyPI/mirror.
- Cẩn thận **typosquatting** (`reqursts`, `python-requests` giả). Kiểm tra tên package chính xác.

---

## 17.3. socket — Port scanner TCP từ con số 0

### Là gì
`socket` là API Python bọc trực tiếp socket BSD của OS. Nó cho phép tạo kết nối TCP/UDP/raw, là nền tảng của mọi tool mạng.

### Cơ chế bên trong — bắt tay TCP 3 bước (3-way handshake)

Một `connect()` TCP thành công nghĩa là OS đã hoàn tất handshake. Diễn ra ở mức segment như sau (cờ TCP nằm ở byte offset 13 của TCP header, 6 bit thấp: URG/ACK/PSH/RST/SYN/FIN):

```
Client                                   Server
  |  --- SYN  seq=x          ----------->  |   (cờ SYN=1)
  |  <-- SYN/ACK seq=y ack=x+1 ----------  |   (SYN=1, ACK=1)
  |  --- ACK  ack=y+1        ----------->  |   (ACK=1)  -> ESTABLISHED
```

| Trường TCP header | Kích thước | Offset | Ý nghĩa | Ví dụ |
|-------------------|-----------|--------|---------|-------|
| Source Port | 2 byte | 0 | Cổng nguồn | 49152 |
| Dest Port | 2 byte | 2 | Cổng đích | 22 |
| Sequence Number | 4 byte | 4 | Số thứ tự byte đầu | 0xABCD1234 |
| Ack Number | 4 byte | 8 | seq mong đợi tiếp theo | |
| Data Offset (4 bit) + Reserved + Flags | 2 byte | 12 | Độ dài header + 9 cờ | SYN=0x02 |
| Window | 2 byte | 14 | Kích thước cửa sổ nhận | 65535 |
| Checksum | 2 byte | 16 | Checksum | |
| Urgent Pointer | 2 byte | 18 | | |

**Trạng thái cổng suy ra từ phản hồi:**
- Nhận **SYN/ACK** → cổng **OPEN** (sau đó client gửi RST nếu là connect-scan để đóng nhanh).
- Nhận **RST** → cổng **CLOSED**.
- Không phản hồi (timeout) → **FILTERED** (firewall drop gói).

### Ví dụ thực tế — TCP connect scanner đa luồng

```python
#!/usr/bin/env python3
import socket
import concurrent.futures as cf

def probe(host: str, port: int, timeout: float = 1.0) -> tuple[int, str]:
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            # connect_ex trả về 0 nếu OS hoàn tất handshake; số errno nếu lỗi
            rc = s.connect_ex((host, port))
        except socket.gaierror:
            return port, "dns-error"
        if rc == 0:
            banner = ""
            try:
                s.settimeout(0.5)
                banner = s.recv(64).decode(errors="replace").strip()  # grab banner
            except OSError:
                pass
            return port, f"open {banner}".strip()
        elif rc == 111:                       # ECONNREFUSED (Linux)
            return port, "closed"
        return port, "filtered"

def scan(host, ports, workers=200):
    results = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, host, p): p for p in ports}
        for fut in cf.as_completed(futs):
            port, state = fut.result()
            if state.startswith("open"):
                results[port] = state
    return dict(sorted(results.items()))

if __name__ == "__main__":
    print(scan("scanme.nmap.org", range(1, 1025)))
```

Output mẫu:
```
{22: 'open SSH-2.0-OpenSSH_6.6.1p1 Ubuntu', 80: 'open'}
```

**Giải thích tham số:**
- `socket.AF_INET` chọn IPv4 (`AF_INET6` cho IPv6).
- `SOCK_STREAM` = TCP; `SOCK_DGRAM` = UDP; `SOCK_RAW` cần root để tạo packet thô.
- `connect_ex` không raise exception khi cổng đóng (trả errno), giảm overhead so với `connect` cho scan diện rộng.
- `ThreadPoolExecutor(max_workers=200)` chạy 200 probe song song; vì là I/O-bound, GIL không cản (thread bị block ở `recv`/`connect` đều nhả GIL).

**Lưu ý bảo mật & pháp lý:**
- Quét host không được phép là hành vi có thể bị truy cứu pháp lý. Chỉ quét tài sản bạn sở hữu hoặc có văn bản cho phép.
- `connect`-scan để lại log đầy đủ (handshake hoàn chỉnh) ở phía mục tiêu — khác với SYN-scan (gửi SYN, nhận SYN/ACK rồi RST, half-open). SYN-scan cần raw socket + quyền root, làm bằng `scapy` (xem 17.8).
- Đặt timeout hợp lý: timeout quá thấp → false "filtered"; quá cao → scan chậm và dễ bị phát hiện do giữ kết nối lâu.

---

## 17.4. requests — Tự động hóa HTTP, REST API, session & auth

### Là gì
`requests` là thư viện HTTP client cấp cao (bọc `urllib3`). Là xương sống của mọi automation gọi REST API (Jira, Slack, SIEM, EDR).

### Cơ chế — vòng đời một request HTTP/1.1

Một request HTTP/1.1 trên dây (TCP payload sau handshake) có dạng văn bản ASCII:

```
GET /rest/api/2/issue/SEC-1 HTTP/1.1\r\n          <- request line
Host: jira.example.com\r\n                         <- header (bắt buộc trong HTTP/1.1)
Authorization: Bearer eyJ...\r\n
Accept: application/json\r\n
User-Agent: python-requests/2.32.3\r\n
\r\n                                               <- dòng trống = hết header
<body nếu có>
```

| Phần | Kích thước | Ý nghĩa | Ví dụ |
|------|-----------|---------|-------|
| Method | biến đổi | Động từ HTTP | `GET`, `POST`, `PUT`, `DELETE` |
| Request-URI | biến đổi | Đường dẫn + query | `/rest/api/2/issue` |
| Version | 8 byte | Phiên bản | `HTTP/1.1` |
| Mỗi header | biến đổi | `Name: Value` kết thúc `\r\n` (CRLF, 2 byte) | |
| Phân tách header/body | 2 byte | `\r\n\r\n` | |

Response: `HTTP/1.1 200 OK\r\n` + header + `\r\n\r\n` + body.

### Ví dụ thực tế 1 — gọi REST API kiểu SIEM/Jira với Session, retry, timeout

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os

def build_session() -> requests.Session:
    s = requests.Session()
    # Session tái dùng kết nối TCP (keep-alive) + cookie -> nhanh hơn nhiều khi gọi N lần
    retries = Retry(
        total=3,                       # thử lại tối đa 3 lần
        backoff_factor=0.5,            # chờ 0.5s, 1s, 2s (exponential)
        status_forcelist=[429, 500, 502, 503, 504],  # retry khi rate-limit/lỗi server
        allowed_methods=["GET", "POST"],
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    # Secret lấy từ biến môi trường, không hardcode
    token = os.environ["JIRA_TOKEN"]
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    })
    return s

def create_ticket(sess, project="SEC", summary="Suspicious login", desc=""):
    payload = {
        "fields": {
            "project": {"key": project},
            "summary": summary,
            "description": desc,
            "issuetype": {"name": "Incident"},
        }
    }
    r = sess.post(
        "https://jira.example.com/rest/api/2/issue",
        json=payload,                  # tự serialize JSON + set Content-Type
        timeout=(3.05, 10),            # (connect timeout, read timeout) - luôn nên đặt
        verify=True,                   # đừng dùng verify=False trong production
    )
    r.raise_for_status()               # raise HTTPError nếu 4xx/5xx
    return r.json()["key"]             # ví dụ "SEC-1234"
```

**Giải thích tham số quan trọng:**
- `timeout=(3.05, 10)`: tuple (connect, read). Không đặt timeout → request có thể treo vĩnh viễn nếu server không phản hồi (treo cả pipeline IR). Giá trị `3.05` tránh trùng bội số của TCP retransmit timer 3s.
- `verify=True`: xác thực chứng chỉ TLS theo CA store. `verify=False` mở cửa MITM — chỉ chấp nhận trong lab tách biệt, và sẽ in `InsecureRequestWarning`.
- `json=payload` vs `data=payload`: `json=` tự `json.dumps` và set header `Content-Type: application/json`; `data=` gửi form-encoded.
- `raise_for_status()`: biến lỗi HTTP thành exception để pipeline IR không "âm thầm" nuốt lỗi.

### Ví dụ thực tế 2 — pattern của một automation / IR agent (gửi alert vào Slack webhook)

```python
def notify_slack(webhook_url: str, text: str, severity: str):
    color = {"high": "#cc0000", "medium": "#e69900", "low": "#36a64f"}.get(severity, "#888")
    body = {"attachments": [{"color": color, "text": text, "footer": "IR-Agent"}]}
    r = requests.post(webhook_url, json=body, timeout=(3, 5))
    r.raise_for_status()
```

Output mẫu khi alert "phát hiện brute-force" được push: Slack hiển thị attachment màu đỏ với text mô tả IP và số lần thử.

**Lưu ý:**
- **SSRF**: nếu URL đích lấy từ input người dùng, kẻ tấn công có thể trỏ tới `http://169.254.169.254/latest/meta-data/` (metadata cloud) để đánh cắp IAM credential. Validate và whitelist host đích; chặn dải IP nội bộ/link-local.
- **Secret trong URL**: không nhúng token vào query string (bị ghi vào access log, history). Dùng header `Authorization`.
- **Header injection / CRLF**: không nối input chưa lọc vào header — ký tự `\r\n` có thể chèn header giả. `requests` chặn phần lớn nhưng vẫn phải validate.

---

## 17.5. re — Regex parse log thực chiến

### Là gì
Module `re` cung cấp regex (PCRE-like). Dùng để trích trường từ log văn bản không cấu trúc.

### Cơ chế — compile & các cấu trúc cốt lõi

`re.compile()` biên dịch pattern thành bytecode NFA một lần, tái dùng nhiều lần (nhanh hơn rất nhiều khi parse hàng triệu dòng).

| Cấu trúc | Ý nghĩa | Ví dụ |
|----------|---------|-------|
| `\d` `\w` `\s` | digit / word char / whitespace | |
| `(?P<name>...)` | nhóm bắt có tên | `(?P<ip>\d+\.\d+\.\d+\.\d+)` |
| `(?:...)` | nhóm không bắt | nhóm logic, không capture |
| `+ * ? {m,n}` | lượng từ | `\d{1,3}` |
| `^ $` | đầu/cuối dòng (với `re.M`) | |
| `\b` | ranh giới từ | |

### Ví dụ thực tế — đếm IP brute-force trong /var/log/auth.log

Một dòng `auth.log` SSH thất bại điển hình:
```
Jun 19 10:21:45 host sshd[2931]: Failed password for invalid user admin from 203.0.113.7 port 51244 ssh2
```

```python
import re
from collections import Counter

# Compile 1 lần; nhóm có tên giúp code đọc được
PAT = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)

def brute_force_offenders(path: str, threshold: int = 5) -> dict:
    by_ip = Counter()
    users_by_ip: dict[str, set] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:                         # generator: từng dòng, không nạp hết
            m = PAT.search(line)
            if m:
                ip = m.group("ip")
                by_ip[ip] += 1
                users_by_ip.setdefault(ip, set()).add(m.group("user"))
    # Chỉ giữ IP vượt ngưỡng
    return {
        ip: {"attempts": n, "users_tried": sorted(users_by_ip[ip])}
        for ip, n in by_ip.items() if n >= threshold
    }

if __name__ == "__main__":
    import json
    print(json.dumps(brute_force_offenders("/var/log/auth.log", 5), indent=2))
```

Output mẫu:
```json
{
  "203.0.113.7": { "attempts": 142, "users_tried": ["admin", "root", "test"] },
  "198.51.100.9": { "attempts": 31, "users_tried": ["oracle"] }
}
```

**Phân tích pattern byte-level:** `\d{1,3}(?:\.\d{1,3}){3}` khớp octet 1–3 chữ số, lặp 3 lần với dấu chấm. Lưu ý nó không kiểm tra octet ≤ 255 — chấp nhận cả `999.999.999.999`. Để validate đúng nên dùng `ipaddress.ip_address()` sau khi trích.

**Lưu ý — ReDoS (Regex Denial of Service):**
- Pattern có **catastrophic backtracking** như `(a+)+$` chạy với input `"aaaa...!"` có độ phức tạp mũ → treo CPU. Khi parse input do attacker kiểm soát (log từ xa, HTTP header), tránh nesting quantifier lồng nhau.
- Module `re` chuẩn không có timeout. Với input không tin cậy, cân nhắc thư viện `regre`/`google-re2` (RE2, không backtracking, đảm bảo tuyến tính) hoặc giới hạn độ dài input trước khi match.

---

## 17.6. subprocess & os — Chạy lệnh hệ thống an toàn

### Là gì
`subprocess` tạo tiến trình con; `os`/`shutil` thao tác file/quyền/môi trường. Đây là điểm nóng số 1 cho **command injection**.

### Cơ chế — shell=False vs shell=True

```
shell=True  -> Python gọi /bin/sh -c "chuỗi lệnh"  -> sh phân tích metachar  ; | & $ ` > <
shell=False -> Python gọi execve(argv[0], argv[], env)  trực tiếp, không qua shell
```

Khi `shell=True`, chuỗi lệnh được `/bin/sh` diễn giải. Nếu một phần chuỗi đến từ input người dùng (`"ping " + user_input`) và `user_input = "; rm -rf /"`, shell thực thi cả hai lệnh. Với `shell=False`, đối số là một phần tử trong list `argv`, không bị shell diễn giải → an toàn.

### Ví dụ thực tế — cách đúng và cách sai

```python
import subprocess, shlex

host = "8.8.8.8"   # giả sử đến từ input

# Sai — command injection:  host = "8.8.8.8; cat /etc/shadow"
# subprocess.run(f"ping -c1 {host}", shell=True)   # đừng làm thế này

# Đúng — argv list, shell=False (mặc định)
res = subprocess.run(
    ["ping", "-c", "1", host],        # mỗi token là phần tử riêng -> không injection
    capture_output=True,              # bắt stdout/stderr
    text=True,                        # decode bytes -> str (theo locale)
    timeout=5,                        # tránh treo vô hạn
    check=False,                      # không raise; tự kiểm res.returncode
)
print(res.returncode, res.stdout[:80])

# Nếu bắt buộc phải dùng shell (vd cần pipe), lọc bằng shlex.quote:
safe = shlex.quote(host)             # "'8.8.8.8; cat /etc/shadow'" -> bị bọc nháy, vô hại
subprocess.run(f"ping -c1 {safe} | tee /tmp/out", shell=True, timeout=5)
```

**Giải thích tham số:**
- `capture_output=True` ≡ `stdout=PIPE, stderr=PIPE`.
- `text=True` (alias `universal_newlines`) decode output. Với dữ liệu nhị phân (pcap, binary) để mặc định `bytes`.
- `timeout=5` raise `TimeoutExpired` nếu vượt — bắt buộc khi gọi tool mạng có thể treo.
- `check=True` raise `CalledProcessError` nếu returncode ≠ 0.

**Lưu ý:**
- `shlex.quote()` chỉ an toàn cho **POSIX sh**, không an toàn cho Windows `cmd.exe` (quy tắc quoting khác). Trên Windows tránh `shell=True` hoàn toàn.
- Không truyền secret qua argv (`ps aux` lộ toàn bộ command line cho mọi user); truyền qua stdin hoặc env.
- `os.system()` luôn dùng shell → tránh hoàn toàn. Dùng `subprocess.run` với list.

---

## 17.7. json — Serialize & xử lý dữ liệu API/cấu hình

### Cơ chế — ánh xạ kiểu

| JSON | Python |
|------|--------|
| object `{}` | `dict` |
| array `[]` | `list` |
| string | `str` |
| number (int) | `int` |
| number (real) | `float` |
| `true`/`false` | `True`/`False` |
| `null` | `None` |

```python
import json
data = json.loads('{"alerts":[{"sev":"high","ip":"1.2.3.4"}]}')   # parse string
text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)  # serialize đẹp
# Đọc/ghi file cấu hình:
with open("rules.json", encoding="utf-8") as f:
    rules = json.load(f)          # load từ file object
```

**Lưu ý:**
- `json` chuẩn an toàn (không thực thi code), khác với `pickle`/`yaml.load` không an toàn (xem dưới). **Tuyệt đối không `pickle.loads()` dữ liệu không tin cậy** — nó có thể thực thi mã tùy ý qua `__reduce__`. Với YAML dùng `yaml.safe_load()`.
- JSON từ nguồn không tin cậy có thể rất sâu/lớn → DoS bộ nhớ. Giới hạn kích thước payload trước khi parse.

---

## 17.8. scapy — Tạo, gửi, sniff gói tin tới mức byte

### Là gì
`scapy` cho phép dựng packet theo từng layer, gửi đi, và sniff/decode — kiểm soát từng trường header.

### Cơ chế — encapsulation từng tầng (decapsulation byte-by-byte)

Một packet `Ethernet / IP / TCP / payload` được đóng gói (encapsulation) từ trên xuống. Trên dây, byte xếp như sau:

```
[ Ethernet header 14B ][ IPv4 header 20B ][ TCP header 20B ][ payload ]
        ^                      ^                  ^
   dst MAC(6) src MAC(6)   ver/ihl, len, ...   src/dst port, seq, flags
   ethertype(2)=0x0800
```

| Tầng | Trường chính | Kích thước | Offset trong tầng | Ví dụ |
|------|-------------|-----------|-------------------|-------|
| Ethernet | dst MAC | 6 byte | 0 | ff:ff:ff:ff:ff:ff |
| Ethernet | src MAC | 6 byte | 6 | |
| Ethernet | EtherType | 2 byte | 12 | 0x0800 = IPv4 |
| IPv4 | Version+IHL | 1 byte | 0 | 0x45 |
| IPv4 | Total Length | 2 byte | 2 | |
| IPv4 | Protocol | 1 byte | 9 | 6=TCP, 17=UDP, 1=ICMP |
| IPv4 | Src/Dst IP | 4+4 byte | 12/16 | |
| TCP | Src/Dst Port | 2+2 byte | 0/2 | |
| TCP | Flags | 6 bit (trong byte 13) | 13 | SYN=0x02 |

### Ví dụ thực tế 1 — SYN scan (half-open), kiểm soát cờ TCP

```python
from scapy.all import IP, TCP, sr1, conf
conf.verb = 0

def syn_scan(target, port, timeout=2):
    pkt = IP(dst=target) / TCP(dport=port, flags="S")   # flags="S" -> chỉ bật cờ SYN
    resp = sr1(pkt, timeout=timeout)                    # gửi 1 gói, nhận 1 phản hồi
    if resp is None:
        return "filtered"                               # không trả lời -> firewall drop
    if resp.haslayer(TCP):
        tcp = resp.getlayer(TCP)
        if tcp.flags == 0x12:                           # SYN+ACK -> open
            # gửi RST để không hoàn tất handshake (half-open, ít log hơn)
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1)
            return "open"
        if tcp.flags == 0x14:                           # RST+ACK -> closed
            return "closed"
    return "unknown"

print(syn_scan("scanme.nmap.org", 80))   # 'open'
```

`flags="S"` đặt byte cờ TCP = `0x02`. `resp.flags == 0x12` nghĩa SYN(0x02)+ACK(0x10). Đây là SYN-scan thật, cần quyền root (raw socket).

### Ví dụ thực tế 2 — sniff và phát hiện ARP spoofing

```python
from scapy.all import sniff, ARP

arp_table = {}   # ip -> mac đã thấy

def on_packet(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:    # op=2 là ARP reply
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            print(f"[!] ARP SPOOF nghi vấn: {ip} đổi từ {arp_table[ip]} sang {mac}")
        arp_table[ip] = mac

# Sniff trên interface, lọc BPF chỉ ARP để giảm tải
sniff(iface="eth0", filter="arp", prn=on_packet, store=False)
```

**Giải thích:** `filter="arp"` là BPF (Berkeley Packet Filter) — biên dịch xuống kernel, lọc trước khi gói lên userspace (hiệu năng cao). `store=False` không giữ gói trong RAM (tránh OOM khi sniff lâu). ARP op=1 là request, op=2 là reply; một IP map sang nhiều MAC trong thời gian ngắn là dấu hiệu ARP poisoning (MITM).

**Lưu ý:** scapy cần `CAP_NET_RAW` (root). Trong Docker phải chạy `--cap-add=NET_RAW` hoặc `--privileged`. Gửi packet thô tới mạng không được phép là tấn công.

---

## 17.9. paramiko — SSH tự động hóa an toàn

### Là gì
`paramiko` là implement thuần Python của SSHv2 (transport, auth, channel). Dùng để tự động hóa thu thập cấu hình, chạy lệnh audit trên fleet server.

### Cơ chế — bắt tay SSHv2 (rút gọn theo RFC 4253)

```
1. TCP connect cổng 22
2. Trao đổi banner:  "SSH-2.0-..."  (cả hai phía gửi version string, kết thúc \r\n)
3. KEXINIT: thương lượng thuật toán (KEX, host key, cipher, MAC, compression)
4. Key exchange (vd curve25519-sha256 / diffie-hellman) -> tạo shared secret
5. Server gửi host key -> client phải xác thực (known_hosts) -> chống MITM
6. Derive session keys -> bật mã hóa
7. Authentication: publickey / password / keyboard-interactive
8. Mở channel -> exec lệnh hoặc shell
```

| Giai đoạn | Gói/trường | Ý nghĩa |
|-----------|-----------|---------|
| Banner | chuỗi ASCII `SSH-2.0-OpenSSH_9.x\r\n` | xác định version |
| KEXINIT | danh sách thuật toán | thương lượng cipher suite |
| Host key | public key của server | client kiểm tra known_hosts |

### Ví dụ thực tế — chạy lệnh audit, xác thực host key đúng cách

```python
import paramiko

def audit_host(host, user, key_path):
    client = paramiko.SSHClient()
    # Nạp known_hosts -> xác thực host key, chống MITM
    client.load_system_host_keys()
    # Đúng: từ chối host lạ. Sai: AutoAddPolicy() bỏ qua kiểm tra -> dễ bị MITM
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
    client.connect(host, username=user, pkey=pkey, timeout=10,
                   auth_timeout=10, banner_timeout=10)
    try:
        # exec_command mở channel, trả về (stdin, stdout, stderr)
        stdin, stdout, stderr = client.exec_command("sshd -T | grep -i permitrootlogin", timeout=10)
        out = stdout.read().decode().strip()
        rc = stdout.channel.recv_exit_status()      # exit code của lệnh từ xa
        return {"host": host, "permit_root": out, "rc": rc}
    finally:
        client.close()
```

**Giải thích tham số:**
- `RejectPolicy()` vs `AutoAddPolicy()`: AutoAdd tự tin tưởng mọi host key mới → vô hiệu hóa chống MITM. Trong production dùng RejectPolicy + known_hosts đã quản lý.
- `Ed25519Key`: dùng key hiện đại; tránh RSA-1024/DSA cũ.
- `recv_exit_status()`: lấy exit code lệnh từ xa (khác với việc đọc được output).
- Các `*_timeout`: tránh treo khi server chậm/lọc gói.

**Lưu ý bảo mật:**
- Không hardcode password/passphrase trong code; nạp từ secret manager hoặc env.
- Lưu private key với quyền `0600`. Dùng passphrase cho key.
- Pin host key trong known_hosts được quản lý tập trung; cảnh báo nếu host key đổi (có thể là MITM hoặc reinstall).

---

## 17.10. boto3 — Tự động hóa AWS (audit, IR trên cloud)

### Là gì
`boto3` là SDK AWS chính thức cho Python. Dùng để audit cấu hình (S3 public, security group mở), thu thập log, và phản ứng sự cố trên cloud.

### Cơ chế — credential chain & ký request SigV4

boto3 tìm credential theo thứ tự (credential provider chain):
1. Tham số code tường minh (tránh — dễ leak).
2. Biến môi trường `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`.
3. File `~/.aws/credentials` (profile).
4. **IAM role** qua instance metadata (EC2) / IRSA (EKS) / ECS task role — **ưu tiên cao nhất về bảo mật** vì credential ngắn hạn, tự xoay vòng.

Mỗi API call được ký bằng **AWS Signature Version 4 (SigV4)**: tạo canonical request → hash SHA-256 → tạo string-to-sign → HMAC-SHA256 nhiều lần với key dẫn xuất từ secret + ngày + region + service → header `Authorization: AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...`. Nhờ đó secret key không bao giờ đi trên dây; chỉ chữ ký đi.

### Ví dụ thực tế — tìm S3 bucket bị public

```python
import boto3
from botocore.exceptions import ClientError

def find_public_buckets():
    s3 = boto3.client("s3")           # credential lấy theo chain ở trên
    findings = []
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        public = False
        # Kiểm tra Public Access Block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(pab.values()):     # nếu có bất kỳ cờ chặn nào tắt
                public = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                public = True             # không có PAB -> rủi ro
        # Kiểm tra ACL có grant cho AllUsers không
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl["Grants"]:
                uri = g.get("Grantee", {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public = True
        except ClientError:
            pass
        if public:
            findings.append(name)
    return findings

if __name__ == "__main__":
    print("Public buckets:", find_public_buckets())
```

Output mẫu:
```
Public buckets: ['legacy-backups-2019', 'marketing-assets']
```

**Giải thích:**
- `boto3.client("s3")` tạo client low-level (1:1 với API); `boto3.resource(...)` là abstraction cao hơn.
- Phân trang: `list_buckets` trả tất cả, nhưng các API như `list_objects_v2` phân trang — dùng `paginator = s3.get_paginator("list_objects_v2")` để duyệt hết.
- `ClientError` mang `e.response["Error"]["Code"]` — cần xử lý phân biệt lỗi quyền (`AccessDenied`) với lỗi "không tồn tại".

**Lưu ý bảo mật:**
- **Least privilege**: gắn IAM policy chỉ với quyền `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:ListAllMyBuckets`. Không dùng key admin cho tool audit.
- **Không hardcode key**. Dùng IAM role / SSO. Nếu phải dùng key, lưu trong Secrets Manager và xoay vòng.
- Bật **CloudTrail** để mọi API call của tool đều được log — chính tool audit của bạn cũng phải được audit.

---

## 17.11. hashlib & hmac — Hash, integrity, xác thực thông điệp

### Là gì
`hashlib` cung cấp hàm băm mật mã (SHA-256, SHA-3, BLAKE2…). `hmac` tạo Message Authentication Code dùng khóa bí mật.

### Cơ chế — kích thước digest và cách HMAC chống length-extension

| Thuật toán | Block size | Digest size | Ghi chú bảo mật |
|-----------|-----------|-------------|-----------------|
| MD5 | 64 byte | 16 byte (128 bit) | **Đã vỡ** (collision). Chỉ dùng checksum không bảo mật |
| SHA-1 | 64 byte | 20 byte (160 bit) | **Đã vỡ** (SHAttered). Không dùng cho chữ ký |
| SHA-256 | 64 byte | 32 byte (256 bit) | An toàn hiện tại |
| SHA-512 | 128 byte | 64 byte (512 bit) | An toàn; nhanh hơn trên CPU 64-bit |
| SHA3-256 | — | 32 byte | Cấu trúc sponge, không bị length-extension |
| BLAKE2b | — | tới 64 byte | Nhanh, có keyed mode |

**HMAC** = `H((K ⊕ opad) || H((K ⊕ ipad) || message))`. Hai lần băm lồng nhau với khóa XOR hai hằng số (`ipad=0x36` lặp, `opad=0x5c` lặp) khiến HMAC miễn nhiễm tấn công **length-extension** mà hash thô (MD5/SHA-1/SHA-256 dạng Merkle–Damgård) mắc phải. Đó là VÌ SAO không bao giờ dùng `sha256(secret || message)` làm MAC tự chế — nó cho phép attacker nối thêm dữ liệu và tính được MAC hợp lệ.

### Ví dụ thực tế — hash file forensic & xác thực webhook

```python
import hashlib, hmac, os

def sha256_file(path: str, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):   # đọc 1MB/lần, file lớn không OOM
            h.update(block)
    return h.hexdigest()        # 64 hex char = 32 byte

# Xác thực HMAC của webhook (vd GitHub/Slack ký payload)
def verify_webhook(secret: bytes, payload: bytes, signature_hex: str) -> bool:
    mac = hmac.new(secret, payload, hashlib.sha256)
    expected = mac.hexdigest()
    # so sánh hằng thời gian (constant-time) -> chống timing attack
    return hmac.compare_digest(expected, signature_hex)
```

**Giải thích:**
- `iter(lambda: f.read(chunk), b"")`: gọi `read` tới khi trả `b""` (EOF) → stream file lớn.
- `hexdigest()` cho SHA-256 luôn dài đúng 64 ký tự hex (32 byte × 2).
- `hmac.compare_digest`: so sánh trong thời gian không phụ thuộc vị trí byte khác nhau → kẻ tấn công không đoán được MAC từng byte qua đo thời gian.

**Lưu ý bảo mật:**
- **Không dùng `hashlib` để lưu mật khẩu**. SHA-256 quá nhanh → brute-force dễ. Dùng **bcrypt / scrypt / Argon2** (qua `argon2-cffi`, `bcrypt`) với salt + cost factor cao.
- MD5/SHA-1 chỉ chấp nhận cho dedup/checksum không an ninh, không cho integrity chống tấn công.

---

## 17.12. secrets — Sinh token an toàn (không dùng random)

### Cơ chế — vì sao `random` nguy hiểm

Module `random` dùng **Mersenne Twister (MT19937)**: deterministic, state 624 × 32-bit. Quan sát đủ 624 output liên tiếp là **khôi phục được toàn bộ state** và dự đoán mọi giá trị tương lai. → không được dùng cho token, session ID, reset password, IV, salt.

`secrets` (Python 3.6+) lấy entropy từ **CSPRNG của OS** (`/dev/urandom` trên Linux, `getrandom(2)`; `BCryptGenRandom` trên Windows) — không dự đoán được.

### Ví dụ thực tế

```python
import secrets
token = secrets.token_urlsafe(32)     # 32 byte entropy -> ~43 ký tự URL-safe
hexer = secrets.token_hex(16)         # 16 byte -> 32 hex char
api_key = secrets.token_bytes(32)     # 32 byte thô
# So sánh secret an toàn:
if secrets.compare_digest(provided, stored):
    ...
```

| Hàm | Đầu vào | Đầu ra | Dùng cho |
|-----|---------|--------|----------|
| `token_bytes(n)` | n byte | bytes | khóa thô, salt |
| `token_hex(n)` | n byte | 2n hex char | token đọc được |
| `token_urlsafe(n)` | n byte | base64url | session token, reset link |

**Lưu ý:** entropy 256-bit (32 byte) là đủ cho mọi mục đích. Đừng dùng `os.urandom` thủ công rồi tự encode khi `secrets` đã chuẩn hóa.

---

## 17.13. Secure coding trong Python — tổng hợp

### 17.13.1. Tránh eval/exec — code injection

```python
# Sai — eval/exec trên input -> RCE: user_input="__import__('os').system('rm -rf /')"
# eval(user_input)

# Đúng — parse có giới hạn:
import ast
val = ast.literal_eval("[1, 2, {'a': 3}]")   # chỉ literal, không gọi hàm/import
```
`eval`/`exec` thực thi mã Python tùy ý. Với dữ liệu từ mạng/người dùng đây là RCE trực tiếp. `ast.literal_eval` chỉ chấp nhận literal an toàn (số, chuỗi, list, dict, tuple, bool, None).

### 17.13.2. Parameterized query — chống SQL injection

```python
import sqlite3
conn = sqlite3.connect("app.db")
user = "admin' OR '1'='1"

# Sai -> SQLi:
# conn.execute(f"SELECT * FROM users WHERE name = '{user}'")

# Đúng -> driver bind tham số, dữ liệu không bao giờ trộn vào câu lệnh
cur = conn.execute("SELECT * FROM users WHERE name = ?", (user,))
rows = cur.fetchall()
```

Với PostgreSQL (`psycopg2`/`psycopg`):
```python
import psycopg2
cur.execute("SELECT * FROM users WHERE email = %s", (email,))   # %s là placeholder, không phải % format
```

**Cơ chế:** placeholder (`?` cho sqlite3, `%s` cho psycopg2) khiến driver gửi câu lệnh và dữ liệu riêng biệt (prepared statement). DB phân tích cú pháp câu lệnh trước, dữ liệu được xử lý thuần như giá trị → không thể đổi cấu trúc query. **Không dùng f-string/`%`/`.format()` để chèn dữ liệu vào SQL.**

### 17.13.3. shlex.quote cho lệnh shell — đã trình bày ở 17.6.

### 17.13.4. Validate input

```python
import ipaddress
def parse_ip(s: str) -> str:
    return str(ipaddress.ip_address(s))   # raise ValueError nếu không hợp lệ -> fail closed
```
Dùng `ipaddress`, `urllib.parse`, `pathlib` để validate IP/URL/path thay vì regex tự chế. Với path, chống **path traversal** (`../../etc/passwd`):
```python
from pathlib import Path
base = Path("/srv/data").resolve()
target = (base / user_supplied).resolve()
if not target.is_relative_to(base):     # Python 3.9+
    raise ValueError("path traversal")
```

### 17.13.5. Quản lý secret qua biến môi trường / vault

```python
import os
token = os.environ["API_TOKEN"]          # KeyError nếu thiếu -> fail loud, tốt hơn None âm thầm
# .env chỉ cho dev cục bộ, không commit; production dùng secret manager (Vault, AWS Secrets Manager)
```

**Quy tắc:**
- Không hardcode secret trong source (bị lộ qua git history vĩnh viễn — phải rotate nếu lỡ commit).
- Quét secret leak trong CI bằng `gitleaks` / `detect-secrets` (xem 17.14).
- `.gitignore` chứa `.env`, `*.pem`, `*.key`.

### 17.13.6. Bảng tổng hợp lỗ hổng & biện pháp

| Lỗ hổng | API nguy hiểm | Biện pháp đúng |
|---------|---------------|----------------|
| Code injection | `eval`, `exec`, `pickle.loads`, `yaml.load` | `ast.literal_eval`, `json`, `yaml.safe_load` |
| Command injection | `os.system`, `subprocess(shell=True)` | `subprocess([...], shell=False)`, `shlex.quote` |
| SQL injection | f-string trong SQL | parameterized query (`?`/`%s`) |
| SSRF | `requests.get(user_url)` | whitelist host, chặn IP nội bộ |
| Path traversal | nối path thô | `Path.resolve()` + `is_relative_to` |
| Weak randomness | `random` cho token | `secrets` |
| Timing attack | `==` so sánh MAC | `hmac.compare_digest` |
| ReDoS | quantifier lồng nhau | RE2/giới hạn input |
| Supply chain | version range mở | pin `==` + `--require-hashes` + `pip-audit` |

---

## 17.14. Kiểm thử bảo mật mã Python (SAST)

Bổ sung cho secure coding: tự động phát hiện anti-pattern.

```bash
# Bandit: SAST cho Python, bắt các pattern nguy hiểm (B602 shell=True, B307 eval, B501 verify=False...)
pip install bandit
bandit -r ./src -ll          # -r đệ quy, -ll chỉ báo mức medium trở lên

# Quét dependency có CVE:
pip-audit -r requirements.txt

# Quét secret bị commit:
pip install detect-secrets
detect-secrets scan > .secrets.baseline
```

Output bandit mẫu:
```
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified.
   Severity: High   Confidence: High
   Location: ./src/runner.py:42
```

Giải thích: `-ll` lọc theo severity; mỗi mã `Bxxx` ứng với một test rule. Tích hợp vào CI để fail build khi xuất hiện High severity.

---

## 17.15. Ghép nối — Một IR Agent mini (kết hợp re + requests + json + secrets)

Pattern thực tế: parser log → phát hiện brute-force → tạo ticket SIEM/Jira → notify Slack. Kết hợp các phần trên:

```
   NGUỒN DỮ LIỆU            PHÂN TÍCH              QUYẾT ĐỊNH             HÀNH ĐỘNG / API
  +--------------+      +---------------+      +----------------+      +------------------+
  | auth.log     | ---> | re: trích IP  | ---> | đếm >= ngưỡng? |--no--> (bỏ qua / log)
  | (đọc dòng    |      | + đếm lần thử |      |  (Counter)     |
  |  bằng        |      | (Counter)     |      +----------------+
  |  generator)  |      +---------------+              | yes
  +--------------+                                     v
                                            +--------------------+      +----------------+
                                            | json.dumps báo cáo | ---> | requests.post  |
                                            +--------------------+      | -> Jira ticket |
                                                                        | -> Slack alert |
                                                                        +----------------+
                                                            (secret lấy từ env, timeout mọi call)
```

Luồng một script tự động hóa luôn đi theo bốn chặng: **nhận dữ liệu → phân tích → ra quyết định theo ngưỡng → gọi API để hành động/cảnh báo**. Mỗi chặng dùng một module ở các mục trên, và secret luôn nạp từ biến môi trường, mọi call mạng đều đặt timeout.

```python
#!/usr/bin/env python3
"""IR Agent mini: phát hiện SSH brute-force và phản ứng."""
import os, re, json, requests
from collections import Counter

PAT = re.compile(r"Failed password for (?:invalid user )?\S+ "
                 r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

def detect(path, threshold=10):
    c = Counter()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = PAT.search(line)
            if m:
                c[m.group("ip")] += 1
    return {ip: n for ip, n in c.items() if n >= threshold}

def respond(offenders, slack_url):
    if not offenders:
        return
    text = "Brute-force phát hiện:\n" + "\n".join(
        f"- {ip}: {n} lần thử" for ip, n in offenders.items())
    requests.post(slack_url, json={"text": text}, timeout=(3, 5)).raise_for_status()

if __name__ == "__main__":
    off = detect("/var/log/auth.log", threshold=10)
    print(json.dumps(off, indent=2))
    respond(off, os.environ["SLACK_WEBHOOK"])   # secret từ env
```

Đây minh họa pattern automation/IR agent: **thu thập → phân tích → quyết định theo ngưỡng → hành động qua API → thông báo**, với secret lấy từ env và timeout trên mọi call mạng.

---

## 17.16. Đóng gói & chạy bằng Docker

### Là gì
Container đóng gói tool + dependency pinned vào image bất biến → chạy nhất quán, cô lập, không "nhiễm bẩn" host phân tích.

### Ví dụ thực tế — Dockerfile multi-stage, non-root, tối thiểu

```dockerfile
# syntax=docker/dockerfile:1
# ---- Stage build: cài dependency vào virtualenv ----
FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt

# ---- Stage runtime: image gọn, không chứa toolchain build ----
FROM python:3.12-slim AS runtime
# Tạo user không đặc quyền -> không chạy bằng root (giảm tác hại nếu RCE)
RUN useradd --create-home --uid 10001 appuser
COPY --from=build /opt/venv /opt/venv
COPY src/ /app/src/
WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER appuser                       # drop privilege
ENTRYPOINT ["python", "-m", "src.ir_agent"]
```

```bash
# Build & chạy, truyền secret qua env (không bake vào image)
docker build -t ir-agent:1.0 .
docker run --rm \
  -e SLACK_WEBHOOK="$SLACK_WEBHOOK" \
  -v /var/log/auth.log:/var/log/auth.log:ro \   # mount log read-only
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  ir-agent:1.0

# Quét lỗ hổng image trước khi deploy:
docker scout cves ir-agent:1.0     # hoặc: trivy image ir-agent:1.0
```

**Giải thích từng directive bảo mật:**
- **Multi-stage**: stage `build` chứa compiler/header; stage `runtime` chỉ copy venv đã cài → image nhỏ, ít attack surface.
- `--require-hashes`: chỉ cài đúng artifact đã hash → chống supply-chain.
- `USER appuser` (uid ≠ 0): nếu tool bị khai thác RCE, attacker không có root trong container.
- `--read-only` + `--cap-drop=ALL` + `no-new-privileges`: filesystem chỉ đọc, bỏ mọi Linux capability, cấm leo thang qua setuid → hardening runtime.
- `:ro` trên volume: tool audit chỉ đọc log, không sửa được (chống tamper).
- `PYTHONDONTWRITEBYTECODE=1`: không ghi `.pyc` (giữ FS sạch khi read-only); `PYTHONUNBUFFERED=1`: log ra ngay (quan trọng để giám sát realtime).
- Nếu tool cần sniff packet (scapy): thêm `--cap-add=NET_RAW` thay vì `--privileged`.

**Lưu ý bảo mật:**
- Pin **digest** của base image (`python:3.12-slim@sha256:...`) không chỉ tag → tag có thể bị đẩy lại.
- Quét image bằng `trivy`/`docker scout` trong CI, fail nếu có CVE Critical.
- Không bao giờ `COPY .env` hay secret vào layer image (layer lưu vĩnh viễn, ai pull image cũng đọc được).

---

## 17.17. Tổng kết các nguyên tắc cốt lõi

1. Phân biệt `bytes` vs `str`; dùng `struct`/`int.from_bytes` để xử lý nhị phân chính xác tới từng byte.
2. I/O-bound → `threading`/`asyncio`; CPU-bound → `multiprocessing` (vì GIL).
3. Mọi call mạng phải có **timeout**; mọi subprocess dùng `shell=False`.
4. Crypto: `secrets` cho token, `hmac.compare_digest` để so sánh, Argon2/bcrypt cho mật khẩu, không dùng MD5/SHA-1 cho integrity.
5. Input không tin cậy: validate (`ipaddress`/`pathlib`), parameterized query, không `eval/exec/pickle`.
6. Secret từ env/vault, pin dependency, quét bằng `bandit`/`pip-audit`/`gitleaks`/`trivy`.
7. Đóng gói Docker non-root, read-only, drop capability, scan trước deploy.


---

## Ghi chú của mình

> *Khu vực ghi chú cá nhân: những điểm từng hiểu sai, phần còn đang tìm hiểu, hoặc kinh nghiệm rút ra khi thực hành — cập nhật dần.*
