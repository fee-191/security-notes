# Chapter 17 — Programming & Automation for Security

## Overview

This chapter covers the use of **Python as an automation language for cybersecurity**: replacing repetitive manual operations with scripts and tools. This is a mandatory need because the volume of security data exceeds what can be processed by hand — multi-gigabyte logs, thousands of servers, millions of packets — while Python offers rapid development speed and a library ecosystem that covers nearly every task.

**Core definition.** Security automation is the process of turning collection, analysis, decision-making, and incident response tasks into runnable code that is repeatable and verifiable. Python plays the role of a **glue language**: the logic is written in Python, while the heavy computation is delegated to optimized and audited C libraries.

**The tool groups in this chapter — their concepts and the problems they solve:**

- **Syntax foundations (`bytes`/`str`, `struct`):** distinguish text data (`str`) from raw binary data (`bytes`) that networks and crypto actually transmit; `struct` breaks a packet apart field by field. Solves: the number-one source of bugs when parsing packets and computing hashes.
- **`socket`:** creates low-level TCP/UDP connections. Solves: building a port scanner — a basic reconnaissance step in security testing.
- **`requests`:** an HTTP client that calls REST APIs programmatically. Solves: automatically creating tickets, sending alerts, and pulling data from Jira/Slack/SIEM.
- **`re` (regex):** describes patterns to extract information from unstructured text. Solves: filtering the events you need out of logs containing millions of lines.
- **`subprocess` & `os`:** invoke system programs and manipulate files/permissions. Solves: integrating external tools; at the same time it is the number-one hotspot for **command injection**, and the chapter shows how to call them safely.
- **`json`:** the data interchange format between programs. Solves: a common language with APIs and configuration files that both humans and machines can read.
- **`scapy`:** builds, sends, and sniffs packets down to individual header fields. Solves: tasks that plain sockets usually cannot do — stealthy scanning, ARP spoofing detection.
- **`paramiko`:** a pure-Python SSHv2 client. Solves: automatically logging in and running configuration-audit commands across a fleet of hundreds of servers.
- **`boto3`:** the official AWS SDK. Solves: auditing cloud configuration (public S3, open security groups), collecting logs, and automated incident response.
- **`hashlib` & `hmac`:** cryptographic hash functions and keyed message authentication codes. Solves: verifying file integrity and authenticating the origin of a message (webhook) against forgery.
- **`secrets`:** generates random values using the OS CSPRNG. Solves: creating unpredictable tokens/session IDs, avoiding the `random` trap (Mersenne Twister), which is predictable.
- **Secure coding & SAST:** the set of habits for writing code that does not introduce vulnerabilities (injection, path traversal) and the tools (Bandit) that automatically detect anti-patterns. Solves: catching human oversights early.
- **IR Agent & Docker:** the IR Agent (Incident Response) is a synthesizing example that stitches the above parts into a flow of reading logs → detection → alerting → response; Docker packages the tool together with its dependencies into an immutable image that runs consistently and is isolated from the analysis host.

The following sections dive into the technical mechanics of each component.

> An in-depth reference for security engineers (Blue Team / AppSec / DevSecOps). Each section follows the structure: **What it is → Internal mechanics (down to the bit/byte/step/parameter level) → Real-world example → Security notes**. All technical figures aim to follow official specs/RFCs/manuals; points that need verification are explicitly flagged.

---

## 17.1. Why Python dominates cybersecurity & automation

Python is chosen as the "glue language" of security for three specific technical reasons, not because it is "easy to learn":

1. **CPython has a stable C-API** → most crypto/network libraries (OpenSSL via `cryptography`, libpcap via `scapy`, libssh2/openssh via `paramiko`) have high-speed C bindings. The logic is written in Python, while the heavy lifting runs in C that has been optimized and audited.
2. **The object model + duck typing** allow tools to be written quickly and semi-structured data (logs, JSON, packets) to be parsed without rigid type declarations.
3. **The packaging ecosystem** (`pip`, PyPI, wheel) allows tools to be distributed immediately, and `venv` isolates dependencies — important when a forensic analysis host must not be "contaminated."

A security point to remember from the very start: the **GIL (Global Interpreter Lock)** in CPython means that multithreading (`threading`) does not run CPU-bound work in parallel, but it can still parallelize I/O-bound work (sockets, files, HTTP). Because most security tools are I/O-bound (waiting on the network, waiting on disk), `threading` and `asyncio` remain extremely useful; only when cracking hashes/brute-forcing (CPU-bound) do you need `multiprocessing`.

---

## 17.2. Python syntax foundations for security (quick review, deep dive where mistakes happen)

### 17.2.1. Data types and binary representation

Security engineers work with bytes constantly, so they must clearly distinguish `str` from `bytes` — this is the number-one source of bugs when parsing packets/crypto.

| Type | Nature | Immutable? | Use when |
|------|----------|-----------|----------|
| `int` | Arbitrary-precision integer | Yes | Counting, offsets, bitmasks |
| `bytes` | Sequence of bytes 0–255, immutable | Yes | Network data, hashes, raw payloads |
| `bytearray` | Sequence of bytes editable in place | No | Building packets, editing buffers |
| `str` | Sequence of Unicode code points | Yes | Text, decoded logs |
| `memoryview` | Zero-copy view over a buffer | — | Processing large buffers without copying |

**Internal mechanics — why `str` ≠ `bytes`:** A Python 3 `str` is a sequence of Unicode *code points*; it has no intrinsic "encoding" until you call `.encode()`. A network byte (for example the bytes `0xC3 0xA9`) only becomes the character `é` if you know the encoding is UTF-8. Mixing these two types when computing an HMAC will produce the wrong digest.

```python
# Explicit conversion — always specify the encoding
s = "héllo"
b = s.encode("utf-8")        # b'h\xc3\xa9llo'  -> 6 bytes (é = 2 bytes)
print(len(s), len(b))        # 5 6  -> 5 characters but 6 bytes (é takes 2 bytes)
# Exact hex representation/length:
print(b.hex())               # '68c3a96c6c6f'  (each byte = 2 hex digits)
print(len(b))                # 6

# Read a 4-byte big-endian field from a packet:
raw = b"\x00\x00\x05\xdc"    # 1500
mtu = int.from_bytes(raw, byteorder="big", signed=False)
print(mtu)                   # 1500

# Pack it back:
print((1500).to_bytes(2, "big").hex())   # '05dc'
```

**Note:** When comparing tokens/MACs, do not use `==` on `str`/`bytes`, because it short-circuits (stops early on the first differing byte → timing leak). Use `hmac.compare_digest()` (see 17.13).

### 17.2.2. struct — read/write binary data field by field

`struct` is the bridge between network bytes and Python types. The format string controls byte order and size:

| Character | C type | Size | Notes |
|-------|--------|-----------|---------|
| `B` | unsigned char | 1 byte | 0–255 |
| `H` | unsigned short | 2 bytes | 0–65535 |
| `I` | unsigned int | 4 bytes | |
| `Q` | unsigned long long | 8 bytes | |
| `s` | char[] | n bytes | `4s` = 4 raw bytes |
| `!` (prefix) | — | — | network byte order = big-endian, no padding |
| `<` / `>` | — | — | little / big endian |

```python
import struct
# Read the first 12 bytes of an IPv4 header: version+IHL(1B), TOS(1B), total_len(2B), id(2B), flags+frag(2B), ttl(1B), proto(1B), checksum(2B)
ip_head = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\xb1\xe6"
ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, csum = struct.unpack("!BBHHHBBH", ip_head)
version = ver_ihl >> 4          # 4
ihl = (ver_ihl & 0x0F) * 4      # 5*4 = 20 byte header length
print(version, ihl, tot_len, ttl, proto)   # 4 20 60 64 6 (proto 6 = TCP)
```

### 17.2.3. List/Dict/Set comprehensions & generators

```python
logs = ["ok", "FAIL ip=10.0.0.1", "FAIL ip=10.0.0.2", "ok", "FAIL ip=10.0.0.1"]
fails = [l for l in logs if l.startswith("FAIL")]                  # list comp
ips   = {l.split("ip=")[1] for l in fails}                        # set comp -> unique IPs
count = {ip: sum(ip in l for l in fails) for ip in ips}           # dict comp -> count
# Generator: lazy, does not load the whole file into RAM — important for GB-sized logs
def read_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:          # generator pattern, read one line at a time
            yield line.rstrip("\n")
```

**Why generators matter for security:** the log file `/var/log/auth.log` can be several GB. A list comprehension `[l for l in open(...)]` loads the entire file into RAM → OOM. A generator holds one line at a time.

### 17.2.4. Functions, *args/**kwargs, type hints

```python
from typing import Iterable
def scan_ports(host: str, ports: Iterable[int], timeout: float = 1.0) -> dict[int, bool]:
    """Type hints make large tools easier to audit; they are not enforced at runtime."""
    ...
```
Type hints are not checked by CPython at runtime — they serve `mypy`/IDEs and code auditing. For real runtime checking you need `pydantic` (to validate input from the network/API).

### 17.2.5. Exceptions and context managers

```python
import socket
try:
    s = socket.create_connection(("10.0.0.5", 22), timeout=2)
except (socket.timeout, ConnectionRefusedError) as e:
    print("closed/filtered:", e)
except OSError as e:               # catch the broader group last
    print("network error:", e)
else:
    print("open")
    s.close()
finally:
    pass                           # cleanup always runs
```

**Context managers** ensure resources (sockets, files, locks) are released even when an exception occurs — avoiding file descriptor leaks (a form of self-inflicted DoS when scanning thousands of hosts):

```python
from contextlib import contextmanager
@contextmanager
def timed_socket(addr, timeout):
    s = socket.create_connection(addr, timeout=timeout)
    try:
        yield s
    finally:
        s.close()      # always closed, even on a mid-way error
```

### 17.2.6. virtualenv & pip — isolate and pin dependencies

```bash
# Create an isolated environment (Python 3.3+ ships with venv)
python3 -m venv .venv
source .venv/bin/activate          # Linux/mac;  .venv\Scripts\activate on Windows
pip install --upgrade pip
pip install requests scapy paramiko boto3

# Pin exactly for reproducible builds — important for audit & supply chain
pip freeze > requirements.txt      # records exact versions: requests==2.32.3 ...
pip install -r requirements.txt

# Check for known vulnerabilities in dependencies (supply chain)
pip install pip-audit
pip-audit -r requirements.txt      # looks up the OSV/PyPI advisory DB
```

**Note (supply chain):**
- Always **pin versions** (`==`) in production environments; open ranges (`>=`) allow an attacker to push a malicious release via dependency confusion.
- Consider **hash-pinning**: `pip install --require-hashes -r requirements.txt` with a file containing `--hash=sha256:...` → protects against artifact substitution on PyPI/mirrors.
- Beware of **typosquatting** (`reqursts`, fake `python-requests`). Verify the exact package name.

---

## 17.3. socket — A TCP port scanner from scratch

### What it is
`socket` is a Python API that wraps the OS's BSD sockets directly. It allows creating TCP/UDP/raw connections and is the foundation of every network tool.

### Internal mechanics — the TCP 3-way handshake

A successful TCP `connect()` means the OS has completed the handshake. At the segment level it proceeds as follows (the TCP flags are at byte offset 13 of the TCP header, in the low 6 bits: URG/ACK/PSH/RST/SYN/FIN):

```
Client                                   Server
  |  --- SYN  seq=x          ----------->  |   (SYN flag=1)
  |  <-- SYN/ACK seq=y ack=x+1 ----------  |   (SYN=1, ACK=1)
  |  --- ACK  ack=y+1        ----------->  |   (ACK=1)  -> ESTABLISHED
```

| TCP header field | Size | Offset | Meaning | Example |
|-------------------|-----------|--------|---------|-------|
| Source Port | 2 bytes | 0 | Source port | 49152 |
| Dest Port | 2 bytes | 2 | Destination port | 22 |
| Sequence Number | 4 bytes | 4 | Sequence number of the first byte | 0xABCD1234 |
| Ack Number | 4 bytes | 8 | Next expected seq | |
| Data Offset (4 bits) + Reserved + Flags | 2 bytes | 12 | Header length + 9 flags | SYN=0x02 |
| Window | 2 bytes | 14 | Receive window size | 65535 |
| Checksum | 2 bytes | 16 | Checksum | |
| Urgent Pointer | 2 bytes | 18 | | |

**Port state inferred from the response:**
- Receive **SYN/ACK** → port is **OPEN** (the client then sends RST if this is a connect-scan, to close quickly).
- Receive **RST** → port is **CLOSED**.
- No response (timeout) → **FILTERED** (a firewall dropped the packet).

### Real-world example — multithreaded TCP connect scanner

```python
#!/usr/bin/env python3
import socket
import concurrent.futures as cf

def probe(host: str, port: int, timeout: float = 1.0) -> tuple[int, str]:
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            # connect_ex returns 0 if the OS completed the handshake; an errno on failure
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

Sample output:
```
{22: 'open SSH-2.0-OpenSSH_6.6.1p1 Ubuntu', 80: 'open'}
```

**Parameter explanation:**
- `socket.AF_INET` selects IPv4 (`AF_INET6` for IPv6).
- `SOCK_STREAM` = TCP; `SOCK_DGRAM` = UDP; `SOCK_RAW` requires root to craft raw packets.
- `connect_ex` does not raise an exception when the port is closed (it returns an errno), reducing overhead versus `connect` for wide scans.
- `ThreadPoolExecutor(max_workers=200)` runs 200 probes in parallel; because this is I/O-bound, the GIL is not a barrier (threads blocked on `recv`/`connect` release the GIL).

**Security & legal note:**
- Scanning a host without authorization is conduct that can be prosecuted. Only scan assets you own or have written permission to test.
- A `connect`-scan leaves complete logs (a full handshake) on the target side — unlike a SYN-scan (sends SYN, receives SYN/ACK, then RST, half-open). A SYN-scan requires a raw socket + root privileges and is done with `scapy` (see 17.8).
- Set a reasonable timeout: too low → false "filtered"; too high → slow scan that is easily detected because connections are held open for a long time.

---

## 17.4. requests — HTTP automation, REST APIs, sessions & auth

### What it is
`requests` is a high-level HTTP client library (wrapping `urllib3`). It is the backbone of any automation that calls REST APIs (Jira, Slack, SIEM, EDR).

### Mechanics — the lifecycle of an HTTP/1.1 request

An HTTP/1.1 request on the wire (the TCP payload after the handshake) takes the form of ASCII text:

```
GET /rest/api/2/issue/SEC-1 HTTP/1.1\r\n          <- request line
Host: jira.example.com\r\n                         <- header (mandatory in HTTP/1.1)
Authorization: Bearer eyJ...\r\n
Accept: application/json\r\n
User-Agent: python-requests/2.32.3\r\n
\r\n                                               <- blank line = end of headers
<body if any>
```

| Part | Size | Meaning | Example |
|------|-----------|---------|-------|
| Method | variable | HTTP verb | `GET`, `POST`, `PUT`, `DELETE` |
| Request-URI | variable | Path + query | `/rest/api/2/issue` |
| Version | 8 bytes | Version | `HTTP/1.1` |
| Each header | variable | `Name: Value` ending in `\r\n` (CRLF, 2 bytes) | |
| Header/body separator | 2 bytes | `\r\n\r\n` | |

Response: `HTTP/1.1 200 OK\r\n` + headers + `\r\n\r\n` + body.

### Real-world example 1 — calling a SIEM/Jira-style REST API with a Session, retries, timeout

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os

def build_session() -> requests.Session:
    s = requests.Session()
    # A Session reuses the TCP connection (keep-alive) + cookies -> much faster when calling N times
    retries = Retry(
        total=3,                       # retry at most 3 times
        backoff_factor=0.5,            # wait 0.5s, 1s, 2s (exponential)
        status_forcelist=[429, 500, 502, 503, 504],  # retry on rate-limit/server errors
        allowed_methods=["GET", "POST"],
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    # Secret TAKEN FROM AN ENVIRONMENT VARIABLE, not hardcoded
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
        json=payload,                  # auto-serializes JSON + sets Content-Type
        timeout=(3.05, 10),            # (connect timeout, read timeout) - always set
        verify=True,                   # never verify=False in production
    )
    r.raise_for_status()               # raise HTTPError on 4xx/5xx
    return r.json()["key"]             # e.g. "SEC-1234"
```

**Explanation of the important parameters:**
- `timeout=(3.05, 10)`: a tuple (connect, read). Not setting a timeout → the request can hang forever if the server does not respond (hanging the entire IR pipeline). The value `3.05` avoids coinciding with multiples of the 3s TCP retransmit timer.
- `verify=True`: validates the TLS certificate against the CA store. `verify=False` opens the door to MITM — only acceptable in an isolated lab, and it will print an `InsecureRequestWarning`.
- `json=payload` vs `data=payload`: `json=` automatically runs `json.dumps` and sets the `Content-Type: application/json` header; `data=` sends form-encoded data.
- `raise_for_status()`: turns HTTP errors into exceptions so the IR pipeline does not "silently" swallow failures.

### Real-world example 2 — the pattern of an automation / IR agent (sending an alert to a Slack webhook)

```python
def notify_slack(webhook_url: str, text: str, severity: str):
    color = {"high": "#cc0000", "medium": "#e69900", "low": "#36a64f"}.get(severity, "#888")
    body = {"attachments": [{"color": color, "text": text, "footer": "IR-Agent"}]}
    r = requests.post(webhook_url, json=body, timeout=(3, 5))
    r.raise_for_status()
```

Sample output when a "brute-force detected" alert is pushed: Slack displays a red attachment with text describing the IP and the number of attempts.

**Note:**
- **SSRF**: if the target URL comes from user input, an attacker can point it at `http://169.254.169.254/latest/meta-data/` (cloud metadata) to steal IAM credentials. Validate and whitelist the target host; block internal/link-local IP ranges.
- **Secret in the URL**: do not embed tokens in the query string (they get written into access logs and history). Use the `Authorization` header.
- **Header injection / CRLF**: do not concatenate unsanitized input into headers — the `\r\n` characters can inject forged headers. `requests` blocks most of this, but you must still validate.

---

## 17.5. re — Regex log parsing in the field

### What it is
The `re` module provides regular expressions (PCRE-like). It is used to extract fields from unstructured text logs.

### Mechanics — compile & the core constructs

`re.compile()` compiles a pattern into NFA bytecode once and reuses it many times (much faster when parsing millions of lines).

| Construct | Meaning | Example |
|----------|---------|-------|
| `\d` `\w` `\s` | digit / word char / whitespace | |
| `(?P<name>...)` | named capture group | `(?P<ip>\d+\.\d+\.\d+\.\d+)` |
| `(?:...)` | non-capturing group | logical grouping, no capture |
| `+ * ? {m,n}` | quantifiers | `\d{1,3}` |
| `^ $` | start/end of line (with `re.M`) | |
| `\b` | word boundary | |

### Real-world example — counting brute-force IPs in /var/log/auth.log

A typical failed SSH `auth.log` line:
```
Jun 19 10:21:45 host sshd[2931]: Failed password for invalid user admin from 203.0.113.7 port 51244 ssh2
```

```python
import re
from collections import Counter

# Compile once; named groups make the code readable
PAT = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)

def brute_force_offenders(path: str, threshold: int = 5) -> dict:
    by_ip = Counter()
    users_by_ip: dict[str, set] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:                         # generator: one line at a time, no full load
            m = PAT.search(line)
            if m:
                ip = m.group("ip")
                by_ip[ip] += 1
                users_by_ip.setdefault(ip, set()).add(m.group("user"))
    # Keep only IPs above the threshold
    return {
        ip: {"attempts": n, "users_tried": sorted(users_by_ip[ip])}
        for ip, n in by_ip.items() if n >= threshold
    }

if __name__ == "__main__":
    import json
    print(json.dumps(brute_force_offenders("/var/log/auth.log", 5), indent=2))
```

Sample output:
```json
{
  "203.0.113.7": { "attempts": 142, "users_tried": ["admin", "root", "test"] },
  "198.51.100.9": { "attempts": 31, "users_tried": ["oracle"] }
}
```

**Byte-level pattern analysis:** `\d{1,3}(?:\.\d{1,3}){3}` matches an octet of 1–3 digits, repeated 3 times with dots. Note that it does not check that octets are ≤ 255 — it accepts `999.999.999.999`. To validate correctly, use `ipaddress.ip_address()` after extracting.

**Note — ReDoS (Regex Denial of Service):**
- Patterns with **catastrophic backtracking** such as `(a+)+$` run with input `"aaaa...!"` have exponential complexity → CPU hang. When parsing attacker-controlled input (remote logs, HTTP headers), avoid nested quantifiers.
- The standard `re` module has no timeout. For untrusted input, consider the `regre`/`google-re2` libraries (RE2, no backtracking, guaranteed linear time) or limit input length before matching.

---

## 17.6. subprocess & os — Running system commands safely

### What it is
`subprocess` spawns child processes; `os`/`shutil` manipulate files/permissions/environment. This is the number-one hotspot for **command injection**.

### Mechanics — shell=False vs shell=True

```
shell=True  -> Python calls /bin/sh -c "command string"  -> sh parses metacharacters  ; | & $ ` > <
shell=False -> Python calls execve(argv[0], argv[], env)  directly, not through a shell
```

When `shell=True`, the command string is interpreted by `/bin/sh`. If part of the string comes from user input (`"ping " + user_input`) and `user_input = "; rm -rf /"`, the shell executes both commands. With `shell=False`, the argument is one element in the `argv` list and is not interpreted by a shell → safe.

### Real-world example — the right and wrong way

```python
import subprocess, shlex

host = "8.8.8.8"   # assume this comes from input

# Wrong — command injection:  host = "8.8.8.8; cat /etc/shadow"
# subprocess.run(f"ping -c1 {host}", shell=True)   # don't do this

# Right — argv list, shell=False (the default)
res = subprocess.run(
    ["ping", "-c", "1", host],        # each token is a separate element -> no injection
    capture_output=True,              # capture stdout/stderr
    text=True,                        # decode bytes -> str (per locale)
    timeout=5,                        # avoid hanging forever
    check=False,                      # don't raise; check res.returncode yourself
)
print(res.returncode, res.stdout[:80])

# If you ABSOLUTELY must use a shell (e.g. you need a pipe), sanitize with shlex.quote:
safe = shlex.quote(host)             # "'8.8.8.8; cat /etc/shadow'" -> wrapped in quotes, harmless
subprocess.run(f"ping -c1 {safe} | tee /tmp/out", shell=True, timeout=5)
```

**Parameter explanation:**
- `capture_output=True` ≡ `stdout=PIPE, stderr=PIPE`.
- `text=True` (alias `universal_newlines`) decodes the output. For binary data (pcap, binaries), leave it as the default `bytes`.
- `timeout=5` raises `TimeoutExpired` if exceeded — mandatory when calling network tools that may hang.
- `check=True` raises `CalledProcessError` if the return code ≠ 0.

**Note:**
- `shlex.quote()` is only safe for **POSIX sh**, not for Windows `cmd.exe` (the quoting rules differ). On Windows, avoid `shell=True` entirely.
- Do not pass secrets via argv (`ps aux` exposes the entire command line to every user); pass them via stdin or env.
- `os.system()` always uses a shell → avoid it entirely. Use `subprocess.run` with a list.

---

## 17.7. json — Serializing & handling API/config data

### Mechanics — type mapping

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
text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)  # pretty serialize
# Read/write a config file:
with open("rules.json", encoding="utf-8") as f:
    rules = json.load(f)          # load from a file object
```

**Note:**
- Standard `json` is safe (it does not execute code), unlike the unsafe `pickle`/`yaml.load` (see below). **Never `pickle.loads()` untrusted data** — it can execute arbitrary code via `__reduce__`. For YAML, use `yaml.safe_load()`.
- JSON from an untrusted source can be very deep/large → memory DoS. Limit the payload size before parsing.

---

## 17.8. scapy — Crafting, sending, and sniffing packets at the byte level

### What it is
`scapy` lets you build packets layer by layer, send them, and sniff/decode them — controlling every header field.

### Mechanics — layer-by-layer encapsulation (byte-by-byte decapsulation)

An `Ethernet / IP / TCP / payload` packet is encapsulated from the top down. On the wire, the bytes are laid out as follows:

```
[ Ethernet header 14B ][ IPv4 header 20B ][ TCP header 20B ][ payload ]
        ^                      ^                  ^
   dst MAC(6) src MAC(6)   ver/ihl, len, ...   src/dst port, seq, flags
   ethertype(2)=0x0800
```

| Layer | Main field | Size | Offset within layer | Example |
|------|-------------|-----------|-------------------|-------|
| Ethernet | dst MAC | 6 bytes | 0 | ff:ff:ff:ff:ff:ff |
| Ethernet | src MAC | 6 bytes | 6 | |
| Ethernet | EtherType | 2 bytes | 12 | 0x0800 = IPv4 |
| IPv4 | Version+IHL | 1 byte | 0 | 0x45 |
| IPv4 | Total Length | 2 bytes | 2 | |
| IPv4 | Protocol | 1 byte | 9 | 6=TCP, 17=UDP, 1=ICMP |
| IPv4 | Src/Dst IP | 4+4 bytes | 12/16 | |
| TCP | Src/Dst Port | 2+2 bytes | 0/2 | |
| TCP | Flags | 6 bits (in byte 13) | 13 | SYN=0x02 |

### Real-world example 1 — SYN scan (half-open), controlling TCP flags

```python
from scapy.all import IP, TCP, sr1, conf
conf.verb = 0

def syn_scan(target, port, timeout=2):
    pkt = IP(dst=target) / TCP(dport=port, flags="S")   # flags="S" -> set only the SYN flag
    resp = sr1(pkt, timeout=timeout)                    # send 1 packet, receive 1 response
    if resp is None:
        return "filtered"                               # no answer -> firewall drop
    if resp.haslayer(TCP):
        tcp = resp.getlayer(TCP)
        if tcp.flags == 0x12:                           # SYN+ACK -> open
            # send RST so the handshake is not completed (half-open, fewer logs)
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=1)
            return "open"
        if tcp.flags == 0x14:                           # RST+ACK -> closed
            return "closed"
    return "unknown"

print(syn_scan("scanme.nmap.org", 80))   # 'open'
```

`flags="S"` sets the TCP flags byte to `0x02`. `resp.flags == 0x12` means SYN(0x02)+ACK(0x10). This is a true SYN-scan and requires root privileges (a raw socket).

### Real-world example 2 — sniff and detect ARP spoofing

```python
from scapy.all import sniff, ARP

arp_table = {}   # ip -> mac seen

def on_packet(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:    # op=2 is an ARP reply
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            print(f"[!] Suspected ARP SPOOF: {ip} changed from {arp_table[ip]} to {mac}")
        arp_table[ip] = mac

# Sniff on the interface, BPF-filter only ARP to reduce load
sniff(iface="eth0", filter="arp", prn=on_packet, store=False)
```

**Explanation:** `filter="arp"` is a BPF (Berkeley Packet Filter) — compiled down into the kernel, filtering before packets reach userspace (high performance). `store=False` does not keep packets in RAM (avoiding OOM during long sniffs). ARP op=1 is a request, op=2 is a reply; one IP mapping to multiple MACs in a short window is a sign of ARP poisoning (MITM).

**Note:** scapy needs `CAP_NET_RAW` (root). In Docker you must run with `--cap-add=NET_RAW` or `--privileged`. Sending raw packets onto a network you are not authorized to use is an attack.

---

## 17.9. paramiko — Secure SSH automation

### What it is
`paramiko` is a pure-Python implementation of SSHv2 (transport, auth, channels). It is used to automate configuration collection and run audit commands across a server fleet.

### Mechanics — the SSHv2 handshake (abridged per RFC 4253)

```
1. TCP connect to port 22
2. Banner exchange:  "SSH-2.0-..."  (both sides send a version string ending in \r\n)
3. KEXINIT: negotiate algorithms (KEX, host key, cipher, MAC, compression)
4. Key exchange (e.g. curve25519-sha256 / diffie-hellman) -> create a shared secret
5. Server sends its host key -> the client must verify it (known_hosts) -> prevents MITM
6. Derive session keys -> enable encryption
7. Authentication: publickey / password / keyboard-interactive
8. Open a channel -> exec a command or a shell
```

| Stage | Packet/field | Meaning |
|-----------|-----------|---------|
| Banner | ASCII string `SSH-2.0-OpenSSH_9.x\r\n` | identifies the version |
| KEXINIT | algorithm list | negotiate the cipher suite |
| Host key | server's public key | client checks known_hosts |

### Real-world example — running an audit command, verifying the host key correctly

```python
import paramiko

def audit_host(host, user, key_path):
    client = paramiko.SSHClient()
    # Load known_hosts -> VERIFY the host key, prevent MITM
    client.load_system_host_keys()
    # Right: reject unknown hosts. Wrong: AutoAddPolicy() skips the check -> easy MITM
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    pkey = paramiko.Ed25519Key.from_private_key_file(key_path)
    client.connect(host, username=user, pkey=pkey, timeout=10,
                   auth_timeout=10, banner_timeout=10)
    try:
        # exec_command opens a channel, returns (stdin, stdout, stderr)
        stdin, stdout, stderr = client.exec_command("sshd -T | grep -i permitrootlogin", timeout=10)
        out = stdout.read().decode().strip()
        rc = stdout.channel.recv_exit_status()      # exit code of the remote command
        return {"host": host, "permit_root": out, "rc": rc}
    finally:
        client.close()
```

**Parameter explanation:**
- `RejectPolicy()` vs `AutoAddPolicy()`: AutoAdd automatically trusts every new host key → disables MITM protection. In production, use RejectPolicy + a managed known_hosts.
- `Ed25519Key`: use a modern key; avoid old RSA-1024/DSA.
- `recv_exit_status()`: retrieves the exit code of the remote command (distinct from being able to read its output).
- The `*_timeout` values: avoid hanging when the server is slow/filtering packets.

**Note:**
- Do not hardcode passwords/passphrases in code; load them from a secret manager or env.
- Store private keys with `0600` permissions. Use a passphrase for keys.
- Pin host keys in a centrally managed known_hosts; alert if a host key changes (it could be MITM or a reinstall).

---

## 17.10. boto3 — AWS automation (audit, cloud IR)

### What it is
`boto3` is the official AWS SDK for Python. It is used to audit configuration (public S3, open security groups), collect logs, and respond to incidents in the cloud.

### Mechanics — the credential chain & SigV4 request signing

boto3 looks for credentials in order (the credential provider chain):
1. Explicit code parameters (avoid — easy to leak).
2. Environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`.
3. The `~/.aws/credentials` file (a profile).
4. **IAM role** via instance metadata (EC2) / IRSA (EKS) / ECS task role — **the highest priority from a security standpoint** because the credentials are short-lived and auto-rotated.

Each API call is signed with **AWS Signature Version 4 (SigV4)**: build a canonical request → SHA-256 hash → build a string-to-sign → HMAC-SHA256 applied multiple times with a key derived from the secret + date + region + service → an `Authorization: AWS4-HMAC-SHA256 Credential=... SignedHeaders=... Signature=...` header. As a result, the secret key never travels on the wire; only the signature does.

### Real-world example — finding publicly exposed S3 buckets

```python
import boto3
from botocore.exceptions import ClientError

def find_public_buckets():
    s3 = boto3.client("s3")           # credentials taken via the chain above
    findings = []
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        public = False
        # Check the Public Access Block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(pab.values()):     # if any blocking flag is off
                public = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                public = True             # no PAB -> risk
        # Check whether the ACL grants to AllUsers
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

Sample output:
```
Public buckets: ['legacy-backups-2019', 'marketing-assets']
```

**Explanation:**
- `boto3.client("s3")` creates a low-level client (1:1 with the API); `boto3.resource(...)` is a higher-level abstraction.
- Pagination: `list_buckets` returns everything, but APIs like `list_objects_v2` are paginated — use `paginator = s3.get_paginator("list_objects_v2")` to iterate through all results.
- `ClientError` carries `e.response["Error"]["Code"]` — you need to distinguish permission errors (`AccessDenied`) from "does not exist" errors.

**Note:**
- **Least privilege**: attach an IAM policy with only the `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:ListAllMyBuckets` permissions. Do not use an admin key for an audit tool.
- **Do not hardcode keys**. Use an IAM role / SSO. If you must use a key, store it in Secrets Manager and rotate it.
- Enable **CloudTrail** so that every API call your tool makes is logged — your audit tool itself must also be auditable.

---

## 17.11. hashlib & hmac — Hashing, integrity, message authentication

### What it is
`hashlib` provides cryptographic hash functions (SHA-256, SHA-3, BLAKE2…). `hmac` creates a Message Authentication Code using a secret key.

### Mechanics — digest sizes and how HMAC defeats length-extension

| Algorithm | Block size | Digest size | Security note |
|-----------|-----------|-------------|-----------------|
| MD5 | 64 bytes | 16 bytes (128 bits) | **Broken** (collisions). Use only as a non-security checksum |
| SHA-1 | 64 bytes | 20 bytes (160 bits) | **Broken** (SHAttered). Do not use for signatures |
| SHA-256 | 64 bytes | 32 bytes (256 bits) | Currently secure |
| SHA-512 | 128 bytes | 64 bytes (512 bits) | Secure; faster on 64-bit CPUs |
| SHA3-256 | — | 32 bytes | Sponge construction, not affected by length-extension |
| BLAKE2b | — | up to 64 bytes | Fast, has a keyed mode |

**HMAC** = `H((K ⊕ opad) || H((K ⊕ ipad) || message))`. The two nested hashings with the key XORed against two constants (`ipad=0x36` repeated, `opad=0x5c` repeated) make HMAC immune to the **length-extension** attack that raw hashes (MD5/SHA-1/SHA-256 in Merkle–Damgård form) are vulnerable to. That is WHY you should never use `sha256(secret || message)` as a homemade MAC — it lets an attacker append data and compute a valid MAC.

### Real-world example — hashing a forensic file & authenticating a webhook

```python
import hashlib, hmac, os

def sha256_file(path: str, chunk=1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):   # read 1MB at a time, large files don't OOM
            h.update(block)
    return h.hexdigest()        # 64 hex chars = 32 bytes

# Verify the HMAC of a webhook (e.g. GitHub/Slack signs the payload)
def verify_webhook(secret: bytes, payload: bytes, signature_hex: str) -> bool:
    mac = hmac.new(secret, payload, hashlib.sha256)
    expected = mac.hexdigest()
    # constant-time comparison -> prevents timing attacks
    return hmac.compare_digest(expected, signature_hex)
```

**Explanation:**
- `iter(lambda: f.read(chunk), b"")`: calls `read` until it returns `b""` (EOF) → streams large files.
- `hexdigest()` for SHA-256 is always exactly 64 hex characters long (32 bytes × 2).
- `hmac.compare_digest`: compares in a time that does not depend on the position of the differing byte → an attacker cannot guess the MAC byte by byte through timing measurements.

**Note:**
- **Do not use `hashlib` to store passwords**. SHA-256 is too fast → easy to brute-force. Use **bcrypt / scrypt / Argon2** (via `argon2-cffi`, `bcrypt`) with a salt + a high cost factor.
- MD5/SHA-1 are only acceptable for non-security dedup/checksums, not for attack-resistant integrity.

---

## 17.12. secrets — Generating tokens securely (do not use random)

### Mechanics — why `random` is dangerous

The `random` module uses the **Mersenne Twister (MT19937)**: deterministic, with a state of 624 × 32-bit words. Observing 624 consecutive outputs is enough to **recover the entire state** and predict every future value. → it must not be used for tokens, session IDs, password resets, IVs, or salts.

`secrets` (Python 3.6+) draws entropy from the **OS CSPRNG** (`/dev/urandom` on Linux, `getrandom(2)`; `BCryptGenRandom` on Windows) — unpredictable.

### Real-world example

```python
import secrets
token = secrets.token_urlsafe(32)     # 32 bytes of entropy -> ~43 URL-safe characters
hexer = secrets.token_hex(16)         # 16 bytes -> 32 hex chars
api_key = secrets.token_bytes(32)     # 32 raw bytes
# Safe secret comparison:
if secrets.compare_digest(provided, stored):
    ...
```

| Function | Input | Output | Used for |
|-----|---------|--------|----------|
| `token_bytes(n)` | n bytes | bytes | raw keys, salts |
| `token_hex(n)` | n bytes | 2n hex chars | readable tokens |
| `token_urlsafe(n)` | n bytes | base64url | session tokens, reset links |

**Note:** 256-bit entropy (32 bytes) is sufficient for every purpose. Do not manually use `os.urandom` and encode it yourself when `secrets` already standardizes this.

---

## 17.13. Secure coding in Python — a synthesis

### 17.13.1. Avoid eval/exec — code injection

```python
# Wrong — eval/exec on input -> RCE: user_input="__import__('os').system('rm -rf /')"
# eval(user_input)

# Right — limited parsing:
import ast
val = ast.literal_eval("[1, 2, {'a': 3}]")   # literals only, no function calls/imports
```
`eval`/`exec` execute arbitrary Python code. With data from the network/user, this is direct RCE. `ast.literal_eval` only accepts safe literals (numbers, strings, lists, dicts, tuples, bools, None).

### 17.13.2. Parameterized queries — preventing SQL injection

```python
import sqlite3
conn = sqlite3.connect("app.db")
user = "admin' OR '1'='1"

# Wrong -> SQLi:
# conn.execute(f"SELECT * FROM users WHERE name = '{user}'")

# Right -> the driver binds the parameter, data is never mixed into the statement
cur = conn.execute("SELECT * FROM users WHERE name = ?", (user,))
rows = cur.fetchall()
```

With PostgreSQL (`psycopg2`/`psycopg`):
```python
import psycopg2
cur.execute("SELECT * FROM users WHERE email = %s", (email,))   # %s is a placeholder, not % formatting
```

**Mechanics:** the placeholder (`?` for sqlite3, `%s` for psycopg2) causes the driver to send the statement and the data separately (a prepared statement). The DB parses the statement first, the data is treated purely as a value → it cannot alter the query structure. **Do not use f-strings/`%`/`.format()` to insert data into SQL.**

### 17.13.3. shlex.quote for shell commands — already covered in 17.6.

### 17.13.4. Validate input

```python
import ipaddress
def parse_ip(s: str) -> str:
    return str(ipaddress.ip_address(s))   # raises ValueError if invalid -> fail closed
```
Use `ipaddress`, `urllib.parse`, `pathlib` to validate IPs/URLs/paths instead of homemade regex. For paths, guard against **path traversal** (`../../etc/passwd`):
```python
from pathlib import Path
base = Path("/srv/data").resolve()
target = (base / user_supplied).resolve()
if not target.is_relative_to(base):     # Python 3.9+
    raise ValueError("path traversal")
```

### 17.13.5. Managing secrets via environment variables / vault

```python
import os
token = os.environ["API_TOKEN"]          # KeyError if missing -> fail loud, better than silently None
# .env is for local dev only, do not commit it; production uses a secret manager (Vault, AWS Secrets Manager)
```

**Rules:**
- Do not hardcode secrets in source (they are exposed permanently via git history — you must rotate them if you accidentally commit one).
- Scan for secret leaks in CI with `gitleaks` / `detect-secrets` (see 17.14).
- `.gitignore` should contain `.env`, `*.pem`, `*.key`.

### 17.13.6. Summary table of vulnerabilities & mitigations

| Vulnerability | Dangerous API | Correct mitigation |
|---------|---------------|----------------|
| Code injection | `eval`, `exec`, `pickle.loads`, `yaml.load` | `ast.literal_eval`, `json`, `yaml.safe_load` |
| Command injection | `os.system`, `subprocess(shell=True)` | `subprocess([...], shell=False)`, `shlex.quote` |
| SQL injection | f-string in SQL | parameterized query (`?`/`%s`) |
| SSRF | `requests.get(user_url)` | whitelist hosts, block internal IPs |
| Path traversal | concatenating raw paths | `Path.resolve()` + `is_relative_to` |
| Weak randomness | `random` for tokens | `secrets` |
| Timing attack | `==` to compare MACs | `hmac.compare_digest` |
| ReDoS | nested quantifiers | RE2/limit input |
| Supply chain | open version ranges | pin `==` + `--require-hashes` + `pip-audit` |

---

## 17.14. Security testing of Python code (SAST)

A complement to secure coding: automatically detect anti-patterns.

```bash
# Bandit: SAST for Python, catches dangerous patterns (B602 shell=True, B307 eval, B501 verify=False...)
pip install bandit
bandit -r ./src -ll          # -r recursive, -ll report medium severity and above only

# Scan dependencies for CVEs:
pip-audit -r requirements.txt

# Scan for committed secrets:
pip install detect-secrets
detect-secrets scan > .secrets.baseline
```

Sample bandit output:
```
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified.
   Severity: High   Confidence: High
   Location: ./src/runner.py:42
```

Explanation: `-ll` filters by severity; each `Bxxx` code corresponds to a test rule. Integrate this into CI to fail the build when a High severity issue appears.

---

## 17.15. Putting it together — A mini IR Agent (combining re + requests + json + secrets)

A real-world pattern: log parser → detect brute-force → create a SIEM/Jira ticket → notify Slack. It combines the parts above:

```
   DATA SOURCE              ANALYSIS              DECISION               ACTION / API
  +--------------+      +---------------+      +----------------+      +------------------+
  | auth.log     | ---> | re: extract IP| ---> | count >= thr?  |--no--> (skip / log)
  | (read lines  |      | + count tries |      |  (Counter)     |
  |  with a      |      | (Counter)     |      +----------------+
  |  generator)  |      +---------------+              | yes
  +--------------+                                     v
                                            +--------------------+      +----------------+
                                            | json.dumps report  | ---> | requests.post  |
                                            +--------------------+      | -> Jira ticket |
                                                                        | -> Slack alert |
                                                                        +----------------+
                                                            (secret from env, timeout on every call)
```

An automation script's flow always follows four stages: **ingest data → analyze → decide by threshold → call an API to act/alert**. Each stage uses one of the modules from the sections above, secrets are always loaded from environment variables, and every network call sets a timeout.

```python
#!/usr/bin/env python3
"""Mini IR Agent: detect SSH brute-force and respond."""
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
    text = "Brute-force detected:\n" + "\n".join(
        f"- {ip}: {n} attempts" for ip, n in offenders.items())
    requests.post(slack_url, json={"text": text}, timeout=(3, 5)).raise_for_status()

if __name__ == "__main__":
    off = detect("/var/log/auth.log", threshold=10)
    print(json.dumps(off, indent=2))
    respond(off, os.environ["SLACK_WEBHOOK"])   # secret from env
```

This illustrates the automation/IR agent pattern: **collect → analyze → decide by threshold → act via API → notify**, with secrets taken from env and a timeout on every network call.

---

## 17.16. Packaging & running with Docker

### What it is
A container packages the tool + pinned dependencies into an immutable image → it runs consistently, isolated, without "contaminating" the analysis host.

### Real-world example — a multi-stage, non-root, minimal Dockerfile

```dockerfile
# syntax=docker/dockerfile:1
# ---- Build stage: install dependencies into a virtualenv ----
FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt

# ---- Runtime stage: lean image, without the build toolchain ----
FROM python:3.12-slim AS runtime
# Create an unprivileged user -> do not run as root (reduces damage if RCE occurs)
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
# Build & run, passing the secret via env (do not bake it into the image)
docker build -t ir-agent:1.0 .
docker run --rm \
  -e SLACK_WEBHOOK="$SLACK_WEBHOOK" \
  -v /var/log/auth.log:/var/log/auth.log:ro \   # mount the log read-only
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  ir-agent:1.0

# Scan the image for vulnerabilities before deploying:
docker scout cves ir-agent:1.0     # or: trivy image ir-agent:1.0
```

**Explanation of each security directive:**
- **Multi-stage**: the `build` stage contains the compiler/headers; the `runtime` stage only copies the installed venv → a smaller image with less attack surface.
- `--require-hashes`: installs only the exact hashed artifact → protects against supply-chain attacks.
- `USER appuser` (uid ≠ 0): if the tool is exploited for RCE, the attacker does not have root inside the container.
- `--read-only` + `--cap-drop=ALL` + `no-new-privileges`: a read-only filesystem, drops all Linux capabilities, forbids escalation via setuid → runtime hardening.
- `:ro` on the volume: the audit tool only reads the log and cannot modify it (anti-tamper).
- `PYTHONDONTWRITEBYTECODE=1`: does not write `.pyc` (keeps the FS clean when read-only); `PYTHONUNBUFFERED=1`: logs appear immediately (important for real-time monitoring).
- If the tool needs to sniff packets (scapy): add `--cap-add=NET_RAW` instead of `--privileged`.

**Note:**
- Pin the base image **digest** (`python:3.12-slim@sha256:...`), not just the tag → tags can be re-pushed.
- Scan the image with `trivy`/`docker scout` in CI, failing if there is a Critical CVE.
- Never `COPY .env` or a secret into an image layer (layers are stored permanently, and anyone who pulls the image can read them).

---

## 17.17. Summary of the core principles

1. Distinguish `bytes` vs `str`; use `struct`/`int.from_bytes` to handle binary data accurately down to the byte.
2. I/O-bound → `threading`/`asyncio`; CPU-bound → `multiprocessing` (because of the GIL).
3. Every network call must have a **timeout**; every subprocess uses `shell=False`.
4. Crypto: `secrets` for tokens, `hmac.compare_digest` for comparison, Argon2/bcrypt for passwords, no MD5/SHA-1 for integrity.
5. Untrusted input: validate (`ipaddress`/`pathlib`), parameterized queries, no `eval/exec/pickle`.
6. Secrets from env/vault, pin dependencies, scan with `bandit`/`pip-audit`/`gitleaks`/`trivy`.
7. Package with Docker as non-root, read-only, dropping capabilities, scanned before deploy.


---

## My notes

> *Personal notes: points I previously misunderstood, areas I'm still exploring, or lessons from hands-on practice — updated over time.*
