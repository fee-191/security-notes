# Chương 8 — SIEM & Wazuh

> Tài liệu tham chiếu chuyên sâu dành cho kỹ sư Blue Team / AppSec / DevSecOps. Mỗi mục đi từ **LÀ GÌ → CƠ CHẾ BÊN TRONG (tới mức bit/byte/bước/tham số) → VÍ DỤ THỰC TẾ → LƯU Ý BẢO MẬT**.

---

## 8.1. SIEM là gì và vì sao tồn tại

### 8.1.1. Định nghĩa và bài toán gốc

**SIEM (Security Information and Event Management)** là lớp phần mềm thu thập, chuẩn hóa, tương quan và lưu trữ sự kiện (event) bảo mật từ toàn bộ hạ tầng, nhằm phát hiện và điều tra mối đe dọa theo thời gian gần thực (near real-time) và phục vụ tuân thủ (compliance).

Thuật ngữ này hợp nhất hai dòng sản phẩm cũ:

| Thuật ngữ | Viết tắt của | Trọng tâm gốc |
|-----------|--------------|---------------|
| SIM | Security Information Management | Lưu trữ log dài hạn, báo cáo compliance, forensic |
| SEM | Security Event Management | Tương quan thời gian thực, alert, dashboard |
| SIEM | Hợp nhất SIM + SEM | Cả hai: real-time correlation **và** long-term retention |

**VÌ SAO tồn tại:** Trong một hệ thống thật, một cuộc tấn công không để lại dấu vết ở một nơi. Một lần đăng nhập SSH brute-force để lại:
- Log `/var/log/auth.log` trên Linux host;
- Log Netflow/connection trên firewall;
- Log từ EDR ghi nhận tiến trình bất thường sau khi vào được;
- Log từ Active Directory nếu kẻ tấn công lateral movement.

Không một con người nào ngồi đọc song song hàng triệu dòng log/ngày từ hàng nghìn nguồn. SIEM giải bài toán **gom về một chỗ + một mô hình dữ liệu chung + tương quan tự động**.

### 8.1.2. Đơn vị dữ liệu: Event, Log, Alert

Cần phân biệt chính xác ba khái niệm thường bị dùng lẫn:

| Khái niệm | Định nghĩa | Ví dụ |
|-----------|------------|-------|
| **Log line / raw event** | Một dòng văn bản (hoặc bản ghi nhị phân) do nguồn sinh ra, định dạng tùy nguồn | `Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2` |
| **Normalized event** | Bản ghi đã được parse thành các trường có tên chuẩn (structured) | `{ "timestamp": ..., "program": "sshd", "srcip": "203.0.113.5", "srcuser": "admin", "action": "auth_failed" }` |
| **Alert** | Kết quả của một rule khớp với một hoặc nhiều event, kèm mức độ nghiêm trọng | `Rule 5710 (level 5): sshd: Attempt to login using a non-existent user` |

---

## 8.2. Kiến trúc SIEM & data pipeline

Mọi SIEM (Splunk, Elastic SIEM, QRadar, Wazuh, Sentinel...) đều thực thi cùng một đường ống logic. Hiểu pipeline này là chìa khóa để hiểu Wazuh ở phần sau.

```
            ┌─────────┐   ┌────────┐   ┌───────────┐   ┌────────┐   ┌──────────┐   ┌───────┐   ┌────────┐
  Sources──▶│ COLLECT │──▶│ PARSE  │──▶│ NORMALIZE │──▶│ ENRICH │──▶│CORRELATE │──▶│ ALERT │──▶│ STORE  │
            └─────────┘   └────────┘   └───────────┘   └────────┘   └──────────┘   └───────┘   └────────┘
             (ship)        (decode)     (field map)     (geoip,      (rules,         (notify)   (index/
                                                         threat       stateful)                  retain)
                                                         intel)
```

### 8.2.1. COLLECT (thu thập)

**LÀ GÌ:** Đưa event từ nguồn về collector. Hai mô hình:

| Mô hình | Cơ chế | Ví dụ giao thức/port |
|---------|--------|----------------------|
| **Push (agent-based)** | Agent cài trên host đọc file/sự kiện, đẩy về manager | Wazuh agent → manager (UDP/TCP 1514); Filebeat → Logstash (5044) |
| **Pull / agentless** | Server kéo log từ nguồn, hoặc nhận qua syslog | Syslog UDP/TCP 514; WMI; SNMP; API polling (cloud) |

**CƠ CHẾ BÊN TRONG — Syslog (RFC 5424) byte-level.** Vì syslog là phương tiện collect phổ biến nhất, ta mổ xẻ một bản ghi:

```
<34>1 2026-06-19T10:22:41.003Z web01 sshd 2931 ID47 - Failed password...
 └┬┘│ └──────────┬──────────┘ └─┬─┘ └─┬┘ └┬┘ └┬┘ │ └──────┬──────┘
  │ │            │              │     │    │    │  │        │
  │ │            │              │     │    │    │  │        └─ MSG (free-form UTF-8, có thể có BOM)
  │ │            │              │     │    │    │  └─ STRUCTURED-DATA ("-" = none)
  │ │            │              │     │    │    └─ MSGID
  │ │            │              │     │    └─ PROCID (PID)
  │ │            │              │     └─ APP-NAME
  │ │            │              └─ HOSTNAME
  │ │            └─ TIMESTAMP (ISO 8601 / RFC 3339)
  │ └─ VERSION (luôn = 1 trong RFC 5424)
  └─ PRI = "<34>"  (Priority value)
```

**Trường PRI giải mã tới mức bit:** PRI là số thập phân trong dấu `< >`, được tính:

```
PRI = Facility × 8 + Severity
```

| Thành phần | Bit | Dải giá trị | Ý nghĩa | Ví dụ với PRI=34 |
|-----------|-----|-------------|---------|------------------|
| Facility | 5 bit cao (PRI >> 3) | 0–23 | Nguồn sinh log | 34 >> 3 = **4** → "security/authorization (auth)" |
| Severity | 3 bit thấp (PRI & 7) | 0–7 | Mức nghiêm trọng | 34 & 7 = **2** → "Critical" |

Bảng Severity (3 bit, RFC 5424 §6.2.1):

| Mã | Tên | Ý nghĩa |
|----|-----|---------|
| 0 | Emergency | Hệ thống không dùng được |
| 1 | Alert | Phải xử lý ngay |
| 2 | Critical | Tình trạng nghiêm trọng |
| 3 | Error | Lỗi |
| 4 | Warning | Cảnh báo |
| 5 | Notice | Bình thường nhưng đáng chú ý |
| 6 | Informational | Thông tin |
| 7 | Debug | Gỡ lỗi |

> **Lưu ý:** RFC 3164 (BSD syslog cũ) giới hạn message ~1024 byte và timestamp không có năm/timezone, dễ gây lệch thời gian khi tương quan. RFC 5424 cho phép message dài hơn (giới hạn theo transport) và timestamp đầy đủ timezone — đây là VÌ SAO nên ưu tiên 5424.

**LƯU Ý BẢO MẬT khi COLLECT:**
- Syslog UDP 514 **không** xác thực, **không** mã hóa, **không** đảm bảo phân phối → kẻ tấn công có thể spoof log (log injection) hoặc làm nghẽn để mất log. Ưu tiên TLS (RFC 5425, syslog over TLS, port 6514) hoặc kênh agent có mã hóa.
- Mất log = mù. Cần đo độ trễ và tỷ lệ rớt gói.

### 8.2.2. PARSE (bóc tách / decode)

**LÀ GÌ:** Biến chuỗi văn bản tự do (MSG) thành các trường rời rạc. Đây là nơi regex/grok/decoder hoạt động.

Ví dụ MSG SSH thô:
```
Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```
Sau parse:
```
action  = "Failed password"
srcuser = "admin"
srcip   = "203.0.113.5"
srcport = 51244
```

### 8.2.3. NORMALIZE (chuẩn hóa)

**LÀ GÌ:** Ánh xạ các trường vừa parse về **một schema chung** để event từ nhiều nguồn khác nhau có thể so sánh/tương quan. Đây là điểm phân biệt SIEM thật với một công cụ grep log.

VÌ SAO cần: nguồn A gọi IP nguồn là `src`, nguồn B gọi là `client_ip`, nguồn C gọi là `SourceAddress`. Không chuẩn hóa thì không thể viết một rule "đếm số lần login fail theo IP nguồn" áp dụng cho cả ba.

Ví dụ trường trước/sau normalize (theo ECS — Elastic Common Schema, hoặc field chuẩn của Wazuh):

| Nguồn | Trường gốc | Trường chuẩn hóa (Wazuh) | Trường chuẩn hóa (ECS) |
|-------|-----------|--------------------------|------------------------|
| sshd | `from 203.0.113.5` | `srcip` | `source.ip` |
| Windows 4625 | `Source Network Address` | `srcip` / `data.win.eventdata.ipAddress` | `source.ip` |
| nginx | `$remote_addr` | `srcip` | `source.ip` |

### 8.2.4. ENRICH (làm giàu)

**LÀ GÌ:** Thêm ngữ cảnh không có trong log gốc:
- **GeoIP:** `203.0.113.5` → country=US, ASN=AS64500. (Wazuh hỗ trợ GeoIP qua tích hợp dashboard/indexer với GeoLite2 mmdb.)
- **Threat intel:** đối chiếu IP/hash với feed IoC (ví dụ AlienVault OTX, AbuseIPDB) → gắn cờ `malicious`.
- **Asset context:** host `web01` thuộc nhóm "production-dmz", owner = team-web.
- **Vulnerability context:** host này có CVE-2024-XXXX đang mở.

### 8.2.5. CORRELATE (tương quan)

**LÀ GÌ:** Logic phát hiện. Hai kiểu:

| Kiểu | Mô tả | Ví dụ |
|------|-------|-------|
| **Stateless** | 1 event khớp 1 pattern → alert | "Có dòng `Failed password`" → alert level 5 |
| **Stateful** | Đếm/nhóm nhiều event theo thời gian/khóa → alert | "≥ 8 lần `Failed password` từ cùng `srcip` trong 120 giây" → brute-force level 10 |

Stateful correlation là một **state machine** đếm sự kiện theo khóa (key) trong cửa sổ trượt (sliding window). Wazuh thực thi bằng cặp tham số `frequency` + `timeframe` (xem 8.7).

### 8.2.6. ALERT & STORE

- **ALERT:** sinh thông báo (gửi email, webhook, Slack, kích hoạt SOAR/active response).
- **STORE:** ghi vào index để truy vấn (Elasticsearch/OpenSearch/Wazuh indexer). Có chính sách retention (ví dụ hot 7 ngày, warm 30 ngày, cold/frozen cho compliance 1 năm).

---

## 8.3. Phân loại công cụ phòng thủ: AV / EDR / SIEM / SOAR / XDR / NDR

VÌ SAO phải phân biệt: các nhóm này hay bị marketing trộn lẫn, nhưng vị trí của chúng trong kiến trúc và dữ liệu chúng nhìn thấy là khác nhau.

| Công cụ | Phạm vi quan sát | Đơn vị dữ liệu | Hành động chính | Ví dụ |
|---------|------------------|----------------|-----------------|-------|
| **AV (Antivirus)** | 1 endpoint | File, signature, hash | Quét/chặn malware đã biết | ClamAV, Defender (chế độ AV) |
| **EDR (Endpoint Detection & Response)** | 1 endpoint, hành vi | Process tree, syscall, registry, network của host | Phát hiện hành vi, cô lập host, kill process | CrowdStrike Falcon, Defender for Endpoint, Wazuh (một phần) |
| **NDR (Network Detection & Response)** | Lưu lượng mạng | Packet, flow, metadata (JA3, DNS, TLS SNI) | Phát hiện C2/exfil/lateral movement | Zeek, Suricata, Corelight |
| **SIEM** | Toàn hạ tầng (log) | Event đã chuẩn hóa từ mọi nguồn | Tương quan, lưu trữ, điều tra, compliance | Wazuh, Splunk, Elastic SIEM |
| **SOAR (Orchestration, Automation & Response)** | Quy trình phản ứng | Case/playbook | Tự động hóa phản ứng (block, ticket, enrich) | Shuffle, TheHive+Cortex, Splunk SOAR |
| **XDR (Extended Detection & Response)** | EDR + NDR + email + cloud, hợp nhất | Sự kiện đa lớp đã tương quan sẵn của 1 vendor | Phát hiện chéo nhiều lớp | Bộ XDR của một hãng đơn |

**Phân biệt cốt lõi:**
- **EDR vs SIEM:** EDR là chuyên gia một endpoint (nhìn sâu telemetry process); SIEM là người tổng hợp toàn cảnh (nhìn rộng, nông hơn per-source). Wazuh thú vị vì nó **vừa là agent kiểu EDR nhẹ vừa là SIEM** (agent thu telemetry endpoint + manager correlation).
- **SIEM vs SOAR:** SIEM *phát hiện*; SOAR *phản ứng theo playbook*. Wazuh có "Active Response" — một dạng SOAR mini tích hợp.
- **XDR vs SIEM:** XDR thường khóa trong hệ sinh thái một vendor và tương quan sẵn; SIEM mở, nhận mọi nguồn, nhưng tự xây correlation.

---

## 8.4. WAZUH — Tổng quan và kiến trúc

### 8.4.1. Wazuh là gì

**Wazuh** là nền tảng bảo mật mã nguồn mở (fork lịch sử từ OSSEC HIDS, mở rộng thêm indexer/dashboard từ hệ Elastic/OpenSearch). Nó cung cấp đồng thời:

- HIDS (Host Intrusion Detection): phân tích log, FIM, rootcheck;
- Quản lý lỗ hổng (Vulnerability Detection);
- SCA (Security Configuration Assessment — kiểm tra cấu hình theo CIS);
- Active Response (phản ứng tự động);
- Tích hợp khung MITRE ATT&CK;
- Vai trò SIEM nhờ indexer + dashboard.

> Lưu ý phiên bản: chi tiết cổng, tên service và cấu trúc một số module thay đổi theo major version (3.x → 4.x). Tài liệu này mô tả theo dòng **4.x**. Các con số quan trọng (port 1514/1515/55000/1516/9200/443) nên đối chiếu lại với phiên bản cụ thể bạn triển khai.

### 8.4.2. Bốn thành phần chính

```
        ┌──────────────────────────────────────────────────────────────┐
        │                         WAZUH SERVER                          │
        │                                                               │
  Agent │   ┌───────────────┐         ┌────────────────────────────┐    │
  (host)│   │  wazuh-manager │         │   FILTER / FORWARD          │    │
  ──────┼──▶│  - analysisd   │────────▶│   Filebeat ──▶ Indexer      │    │
 1514/  │   │  - remoted     │ alerts  │                             │    │
 1515   │   │  - logcollector│ .json   └────────────┬───────────────┘    │
        │   │  - syscheckd   │                      │                    │
        │   │  - active-resp │                      ▼                    │
        │   └───────────────┘            ┌────────────────────┐          │
        └────────────────────────────────│   WAZUH INDEXER    │──────────┘
                                          │  (OpenSearch)      │
                                          └─────────┬──────────┘
                                                    │ 9200 (REST)
                                          ┌─────────▼──────────┐
                                          │  WAZUH DASHBOARD   │ 443
                                          │  (OpenSearch Dash) │
                                          └────────────────────┘
```

| Thành phần | Vai trò | Daemon/process chính | Cổng tiêu biểu |
|-----------|---------|----------------------|----------------|
| **Wazuh agent** | Cài trên endpoint; thu log, FIM, SCA, gửi về manager | `wazuh-agentd`, `wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-execd` | (client) |
| **Wazuh manager (server)** | Nhận, decode, rule, alert, quản lý agent | `wazuh-remoted` (nhận), `wazuh-analysisd` (phân tích), `wazuh-authd` (enroll), `wazuh-modulesd` (vuln/SCA) | 1514 (data), 1515 (enroll), 1516 (cluster), 55000 (API REST) |
| **Wazuh indexer** | Lưu trữ + tìm kiếm alert (OpenSearch) | `wazuh-indexer` | 9200 (REST), 9300 (transport node-to-node) |
| **Wazuh dashboard** | Giao diện web, trực quan hóa, quản lý | `wazuh-dashboard` | 443/5601 |

### 8.4.3. Các daemon bên trong manager và luồng dữ liệu nội bộ

```
agent ─(1514)─▶ wazuh-remoted ─▶ (queue: /var/ossec/queue/sockets/queue)
                                        │
                                        ▼
                                 wazuh-analysisd
                                  ├─ PreDecoding (tách timestamp/host/program)
                                  ├─ Decoding    (decoders/*.xml → trích field)
                                  ├─ Rule matching (rules/*.xml → gán level/id)
                                  └─ nếu khớp ⇒ ghi alert
                                        │
                       ┌────────────────┼─────────────────┐
                       ▼                ▼                 ▼
            /var/ossec/logs/        active-response   archives (nếu bật)
            alerts/alerts.json      (wazuh-execd)     alerts/archives.json
                       │
                       ▼
                   Filebeat ──▶ Wazuh indexer ──▶ Dashboard
```

**Đường đi của một event (decapsulation logic):**
1. Agent đọc dòng log → đóng gói cùng metadata (agent id, location) → mã hóa → gửi qua **1514**.
2. `wazuh-remoted` giải mã, đặt event vào hàng đợi local socket.
3. `wazuh-analysisd` lấy event ra, chạy **PreDecoding → Decoding → Rule matching**.
4. Nếu một rule khớp với level ≥ ngưỡng (`<log_alert_level>`, mặc định 3), event được ghi vào `alerts.json`.
5. Nếu rule có `<active-response>` liên kết, `wazuh-execd` chạy script phản ứng trên agent/manager.
6. `Filebeat` đọc `alerts.json`, đẩy vào **indexer (9200)**.
7. `Dashboard` truy vấn indexer để hiển thị.

---

## 8.5. Luồng agent → manager: enrollment và truyền dữ liệu (byte/port-level)

### 8.5.1. Hai cổng và VÌ SAO tách

| Cổng | Giao thức | Daemon nghe | Mục đích |
|------|-----------|-------------|----------|
| **1515/TCP** | TLS | `wazuh-authd` | **Enrollment** (đăng ký agent, cấp key) — chỉ dùng một lần khi agent gia nhập |
| **1514/UDP hoặc TCP** | Mã hóa khóa chia sẻ (Blowfish/AES tùy cấu hình) | `wazuh-remoted` | **Truyền dữ liệu** event liên tục |
| **1516/TCP** | — | `wazuh-clusterd` | Giao tiếp giữa các manager trong cluster |
| **55000/TCP** | HTTPS | `wazuh-apid` | API quản trị (RBAC, JWT) |

**VÌ SAO tách enrollment (1515) khỏi data (1514):** Enrollment là thao tác nhạy cảm (trao khóa). Tách cổng cho phép quản trị bật `authd` chỉ trong cửa sổ đăng ký rồi tắt, giảm bề mặt tấn công. Kênh data 1514 dùng khóa đối xứng đã trao, tối ưu cho throughput cao và stateless (UDP) hoặc tin cậy (TCP).

### 8.5.2. Quy trình enrollment (state machine, từng bước)

```
   AGENT                                   MANAGER (authd:1515)
     │                                            │
     │ 1. TLS ClientHello ───────────────────────▶│
     │◀── 2. TLS handshake hoàn tất (TLS 1.2/1.3) │
     │                                            │
     │ 3. Gửi yêu cầu enroll:                      │
     │    "OSSEC A:'<agent_name>'" [+ password]    │
     │    (tùy chọn host_name/ip)        ─────────▶│
     │                                            │ 4. authd:
     │                                            │    - kiểm tra password (nếu bật)
     │                                            │    - cấp agent ID (vd 001)
     │                                            │    - sinh client.key entry
     │◀── 5. "OSSEC K:'<id> <name> <ip> <key>'" ──│
     │                                            │
     │ 6. Lưu vào /var/ossec/etc/client.keys       │
     │ 7. Khởi động wazuh-agentd, kết nối 1514     │
     ▼                                            ▼
```

**Cấu trúc một dòng `client.keys`:**

```
001 web01 any 6b2c...e1f9a3...   (64 hex chars = khóa 256-bit dạng pre-shared)
└┬┘ └─┬─┘ └┬┘ └──────────┬─────┘
 │    │    │             └─ Pre-shared key (hex) dùng để mã hóa kênh 1514
 │    │    └─ IP cho phép ("any" = bất kỳ)
 │    └─ Tên agent
 └─ Agent ID (3 chữ số)
```

| Trường | Kích thước | Ý nghĩa | Ví dụ |
|--------|-----------|---------|-------|
| Agent ID | thường 3 ký tự số | Định danh duy nhất agent trong manager | `001` |
| Name | chuỗi | Tên agent | `web01` |
| Allowed IP | chuỗi | IP/`any` được phép kết nối với ID này | `192.0.2.10` |
| Key | 64 hex (≈256-bit) | Khóa chia sẻ để mã hóa/giải mã message 1514 | `6b2c...` |

**LƯU Ý BẢO MẬT:**
- `client.keys` là bí mật cấp host — quyền `640 root:wazuh`. Lộ key cho phép giả mạo agent và inject log giả.
- Bật `<use_password>yes</use_password>` cho authd để chống đăng ký trái phép. Tốt hơn: dùng chứng chỉ (CA verification) cho cả manager-verify-agent và agent-verify-manager để chống MITM ở bước enroll.
- Trùng tên/ID agent gây "agent flapping" — đặt tên duy nhất, ổn định.

### 8.5.3. Định dạng message data trên 1514 (mức khái niệm field)

Một message từ agent gồm các phần logic sau trước khi mã hóa:

```
[counters][random][MSG]
```

| Phần | Mục đích |
|------|----------|
| Counter (global + local) | Chống replay — manager từ chối message có counter cũ |
| Random padding | Làm nhiễu để chống phân tích |
| MSG | Payload thực: `<msg_type>:<location>:<log line>` |

Phần `location` cho biết log đến từ đâu trên agent, ví dụ `/var/log/auth.log`, để analysisd biết áp decoder nào. Toàn bộ được mã hóa bằng khóa trong `client.keys` (Wazuh 4.x mặc định AES, có thể cấu hình Blowfish cho tương thích cũ).

---

## 8.6. File cấu hình `ossec.conf` — mổ xẻ từng khối

`ossec.conf` (đường dẫn `/var/ossec/etc/ossec.conf`) là cấu hình XML chính cho cả manager lẫn agent. Cấu trúc gốc nằm trong thẻ `<ossec_config>`. Dưới đây là các khối quan trọng kèm giải thích từng tham số.

### 8.6.1. Khối `<global>` và alert level (trên manager)

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>     <!-- ghi alerts.json (phục vụ Filebeat/indexer) -->
    <alerts_log>yes</alerts_log>             <!-- ghi alerts.log dạng text -->
    <logall>no</logall>                       <!-- KHÔNG lưu mọi event vào archives -->
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>      <!-- chỉ ghi alert khi rule level >= 3 -->
    <email_alert_level>12</email_alert_level> <!-- gửi email khi level >= 12 -->
  </alerts>
```

| Tham số | Giá trị ví dụ | Ý nghĩa | VÌ SAO |
|---------|---------------|---------|--------|
| `jsonout_output` | yes | Sinh `alerts.json` | Filebeat cần JSON để đẩy indexer |
| `logall` | no | Không lưu *toàn bộ* event vào archives | `logall=yes` sinh dữ liệu khổng lồ — chỉ bật khi cần điều tra/forensic |
| `log_alert_level` | 3 | Ngưỡng ghi alert | Lọc nhiễu — level 0–2 là noise |
| `email_alert_level` | 12 | Ngưỡng gửi mail | Tránh spam — chỉ sự cố nghiêm trọng |

### 8.6.2. Khối `<remote>` (manager nghe agent)

```xml
  <remote>
    <connection>secure</connection>   <!-- secure = mã hóa bằng client.keys -->
    <port>1514</port>
    <protocol>tcp</protocol>          <!-- tcp đảm bảo phân phối; udp nhẹ hơn nhưng có thể rớt -->
    <queue_size>131072</queue_size>
  </remote>
```

| Tham số | Ý nghĩa | Lưu ý |
|---------|---------|-------|
| `connection` | `secure` (mã hóa) hoặc `syslog` (nhận syslog thô) | Dùng `secure` cho agent; `syslog` cho thiết bị không cài agent được |
| `protocol` | tcp/udp | **TCP** ưu tiên: không mất log; UDP cho quy mô cực lớn chịu được mất mát |
| `queue_size` | Số message đệm | Tăng nếu burst lớn để tránh drop |

### 8.6.3. Khối `<client>` (trên agent)

```xml
  <client>
    <server>
      <address>10.0.0.5</address>      <!-- IP/hostname manager -->
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>10.0.0.5</manager_address>
      <port>1515</port>
      <agent_name>web01</agent_name>
    </enrollment>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>        <!-- keepalive mỗi 10s -->
    <time-reconnect>60</time-reconnect>  <!-- thử lại sau 60s nếu mất kết nối -->
  </client>
```

### 8.6.4. Khối `<localfile>` (logcollector — agent đọc nguồn log nào)

```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/myapp/audit.json</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>           <!-- chạy lệnh, lấy output làm log -->
    <frequency>360</frequency>          <!-- mỗi 360s -->
  </localfile>
```

| `log_format` | Dùng cho |
|--------------|----------|
| `syslog` | File text dòng kiểu syslog (auth.log, messages) |
| `json` | Mỗi dòng là một JSON object — Wazuh tự parse field |
| `command` / `full_command` | Lấy output lệnh làm event định kỳ |
| `eventchannel` | Windows Event Log (Security, System, Application) |
| `audit` | Linux auditd |

### 8.6.5. Khối `<syscheck>` và `<rootcheck>` — xem chi tiết ở 8.9.

### 8.6.6. Nạp lại cấu hình

```bash
# Kiểm tra cú pháp cấu hình + rule/decoder trước khi restart (rất quan trọng)
/var/ossec/bin/wazuh-logtest        # test rule/decoder tương tác
/var/ossec/bin/wazuh-analysisd -t   # -t = test mode, báo lỗi cú pháp rồi thoát

# Khởi động lại
systemctl restart wazuh-manager
# hoặc
/var/ossec/bin/wazuh-control restart
```

> **LƯU Ý:** Luôn chạy `wazuh-analysisd -t` trước khi restart production. Một lỗi cú pháp trong `local_rules.xml` khiến analysisd không khởi động → mù toàn bộ.

---

## 8.7. DECODER — bóc tách field từ log thật

### 8.7.1. LÀ GÌ

**Decoder** là quy tắc XML chỉ cho `wazuh-analysisd` cách trích các trường (srcip, srcuser, ...) ra khỏi một dòng log thô. Decoder *không* sinh alert — nó chỉ chuẩn bị dữ liệu cho rule.

Đường dẫn:
- Decoder gốc: `/var/ossec/ruleset/decoders/*.xml` (KHÔNG sửa — bị ghi đè khi update).
- Decoder tùy biến: `/var/ossec/etc/decoders/local_decoder.xml`.

### 8.7.2. Hai loại decoder và thuộc tính

| Loại | Thẻ | Vai trò |
|------|-----|---------|
| **Parent decoder** | `<decoder name="...">` | Nhận diện *chương trình/nguồn* (qua `program_name` hoặc `prematch`) |
| **Child decoder** | `<decoder name="..."><parent>...</parent>` | Trích field cụ thể, chạy sau khi parent khớp |

| Thẻ con | Ý nghĩa | Thứ tự xử lý |
|---------|---------|--------------|
| `<program_name>` | So khớp tên program (lấy từ PreDecoding) | Lọc nhanh trước |
| `<prematch>` | Regex phải khớp trước thì decoder mới chạy `<regex>` | Bộ lọc tầng 1 |
| `<regex>` | Regex trích giá trị; nhóm bắt `()` ánh xạ sang `<order>` | Trích field |
| `<order>` | Danh sách tên field tương ứng nhóm bắt trong regex | Đặt tên |

### 8.7.3. VÍ DỤ THỰC TẾ — decoder cho SSH (đã có sẵn trong Wazuh, ở đây mổ xẻ)

Log thô:
```
Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```

**PreDecoding** (tự động, không cần XML) tách phần header syslog:
```
hostname    = web01
program_name= sshd
timestamp   = Jun 19 10:22:41
log         = "Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2"
```

**Parent decoder** (nhận diện sshd):
```xml
<decoder name="sshd">
  <program_name>^sshd</program_name>
</decoder>
```

**Child decoder** (trích user + ip):
```xml
<decoder name="ssh-failed-invalid">
  <parent>sshd</parent>
  <prematch>^Failed password for invalid user</prematch>
  <regex offset="after_prematch">^ (\S+) from (\d+.\d+.\d+.\d+) port (\d+)</regex>
  <order>srcuser, srcip, srcport</order>
</decoder>
```

Giải thích từng phần:
- `<parent>sshd</parent>`: chỉ chạy nếu parent `sshd` đã khớp.
- `<prematch>`: yêu cầu dòng bắt đầu bằng `Failed password for invalid user`. Nếu không khớp → bỏ qua, tiết kiệm CPU (VÌ SAO: regex đầy đủ tốn kém, prematch là cổng lọc rẻ).
- `offset="after_prematch"`: bắt đầu `<regex>` ngay sau phần đã prematch. Đây là tối ưu để regex ngắn gọn.
- Nhóm bắt `(\S+)`, `(\d+.\d+.\d+.\d+)`, `(\d+)` lần lượt ánh xạ sang `srcuser, srcip, srcport` qua `<order>`.

> Lưu ý cú pháp regex: Wazuh hỗ trợ cú pháp **OS_Regex** nội bộ (nhanh, hạn chế) và **PCRE2** qua thuộc tính `type="pcre2"`. Trong OS_Regex, `\d`, `\S` là lớp ký tự; `.` khớp ký tự bất kỳ. Khi cần regex phức tạp (lookahead...), dùng `<regex type="pcre2">`.

**Kết quả sau decode** (field sẵn sàng cho rule):
```json
{
  "program_name": "sshd",
  "srcuser": "admin",
  "srcip": "203.0.113.5",
  "srcport": "51244"
}
```

### 8.7.4. VÍ DỤ — viết decoder tùy biến cho log ứng dụng tự định nghĩa

Giả sử ứng dụng nội bộ sinh log:
```
Jun 19 11:05:00 app01 paywall: AUTH_FAIL user=jdoe ip=198.51.100.7 reason=bad_token txn=AB12
```

`local_decoder.xml`:
```xml
<decoder name="paywall">
  <program_name>^paywall</program_name>
</decoder>

<decoder name="paywall-authfail">
  <parent>paywall</parent>
  <prematch>^AUTH_FAIL </prematch>
  <regex>user=(\S+) ip=(\d+.\d+.\d+.\d+) reason=(\S+) txn=(\S+)</regex>
  <order>srcuser, srcip, reason, txn_id</order>
</decoder>
```

Kiểm thử ngay bằng `wazuh-logtest`:
```bash
/var/ossec/bin/wazuh-logtest
# Dán dòng log vào stdin:
Jun 19 11:05:00 app01 paywall: AUTH_FAIL user=jdoe ip=198.51.100.7 reason=bad_token txn=AB12
```
Output mẫu:
```
**Phase 1: Completed pre-decoding.
        full event: 'Jun 19 11:05:00 app01 paywall: AUTH_FAIL ...'
        timestamp: 'Jun 19 11:05:00'
        hostname: 'app01'
        program_name: 'paywall'
**Phase 2: Completed decoding.
        name: 'paywall'
        srcuser: 'jdoe'
        srcip: '198.51.100.7'
        reason: 'bad_token'
        txn_id: 'AB12'
**Phase 3: Completed filtering (rules).
        ... (chưa có rule khớp)
```

**LƯU Ý BẢO MẬT:** Decoder sai (regex tham lam, thiếu anchor `^`) có thể trích nhầm field hoặc làm chậm analysisd dưới tải cao → DoS gián tiếp. Luôn neo regex và test với `wazuh-logtest` trước khi triển khai.

---

## 8.8. RULE — phát hiện và phân loại

### 8.8.1. LÀ GÌ

**Rule** quyết định event nào trở thành alert, gán **level** (0–16), `id`, nhóm, và (tùy chọn) ánh xạ MITRE. Rule chạy *sau* decoder, dựa trên field đã trích.

Đường dẫn:
- Rule gốc: `/var/ossec/ruleset/rules/*.xml` (không sửa).
- Rule tùy biến: `/var/ossec/etc/rules/local_rules.xml`.

### 8.8.2. Thuộc tính và thẻ của một rule

| Thuộc tính/Thẻ | Ý nghĩa | Ví dụ |
|----------------|---------|-------|
| `id` | Định danh duy nhất. Khoảng **100000–120000** dành cho rule tùy biến (không trùng rule gốc) | `100100` |
| `level` | Mức nghiêm trọng 0–16 (0 = bỏ qua/không alert) | `10` |
| `<if_sid>` | Chỉ xét nếu rule có ID này đã khớp trước (xâu chuỗi rule) | `<if_sid>5710</if_sid>` |
| `<if_matched_sid>` | Dùng với correlation: rule con khớp khi rule SID kia khớp đủ tần suất | — |
| `<match>` | So khớp chuỗi con (substring) trong log | `<match>AUTH_FAIL</match>` |
| `<regex>` | So khớp regex trong log/field | `<regex>reason=bad_token</regex>` |
| `<field>` | So khớp một field đã decode | `<field name="srcuser">admin</field>` |
| `<frequency>` | Số lần khớp cần để kích hoạt (correlation) | `8` |
| `<timeframe>` | Cửa sổ thời gian (giây) cho `frequency` | `120` |
| `<same_source_ip/>` | Yêu cầu cùng srcip mới đếm (khóa nhóm) | — |
| `<group>` | Nhóm phân loại (authentication_failed, attack...) | `authentication_failures,` |
| `<mitre><id>` | Mã kỹ thuật MITRE ATT&CK | `T1110` |
| `<description>` | Mô tả hiển thị trên alert | — |

### 8.8.3. Thang LEVEL của Wazuh (0–16)

| Level | Ý nghĩa khái quát |
|-------|-------------------|
| 0 | Bỏ qua hoàn toàn (không log) — dùng để giảm FP |
| 1–3 | Thông tin / ít quan trọng |
| 4–6 | Đáng chú ý (lỗi auth đơn lẻ, cấu hình) |
| 7–9 | Quan trọng (nhiều lỗi, hành vi đáng ngờ) |
| 10–12 | Tấn công khả năng cao (brute-force phát hiện) |
| 13–16 | Nghiêm trọng (xâm nhập thành công, hệ thống) |

### 8.8.4. VÍ DỤ — rule stateless ánh vào decoder paywall ở 8.7.4

`local_rules.xml`:
```xml
<group name="paywall,authentication,">

  <!-- Rule cơ sở: một lần AUTH_FAIL của paywall -->
  <rule id="100100" level="5">
    <decoded_as>paywall</decoded_as>
    <field name="reason">bad_token</field>
    <description>Paywall: xác thực thất bại do token sai (user $(srcuser), ip $(srcip))</description>
    <group>authentication_failed,</group>
    <mitre>
      <id>T1078</id>   <!-- Valid Accounts (lạm dụng credential) -->
    </mitre>
  </rule>

</group>
```

Giải thích:
- `<decoded_as>paywall</decoded_as>`: chỉ áp dụng cho event đã được decoder `paywall` xử lý.
- `<field name="reason">bad_token</field>`: khớp field `reason` đã decode.
- `$(srcuser)`, `$(srcip)`: nội suy field vào mô tả alert.

### 8.8.5. VÍ DỤ TRỌNG TÂM — correlation brute-force (frequency + timeframe)

Đây là ví dụ stateful kinh điển: nhiều lần login fail từ cùng IP trong cửa sổ thời gian → một alert brute-force.

```xml
<group name="paywall,authentication,attack,">

  <!-- Rule tương quan: >=8 lần rule 100100 từ CÙNG srcip trong 120 giây -->
  <rule id="100110" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100100</if_matched_sid>
    <same_source_ip />
    <description>Paywall: BRUTE-FORCE token — >=8 lần thất bại từ $(srcip) trong 120s</description>
    <group>authentication_failures,brute_force,</group>
    <mitre>
      <id>T1110</id>   <!-- Brute Force -->
    </mitre>
  </rule>

</group>
```

**CƠ CHẾ BÊN TRONG (state machine của analysisd):**

```
Khởi tạo cho mỗi srcip một bộ đếm + timestamp đầu cửa sổ.

  Sự kiện rule 100100 khớp, srcip=X:
    ┌─ Tìm bucket cho key=X
    │     ├─ Nếu chưa có: tạo bucket{count=1, t0=now}
    │     └─ Nếu có:
    │           ├─ Nếu (now - t0) > timeframe(120s): RESET bucket{count=1, t0=now}
    │           └─ Ngược lại: count++
    │                 └─ Nếu count >= frequency(8): KÍCH HOẠT rule 100110 (level 10) → ALERT
    │                       (sau khi kích hoạt, đặt lại để tránh spam liên tục)
    ▼
```

Bảng minh họa với chuỗi sự kiện (frequency=8, timeframe=120):

| t (s) | srcip | count(X) | Hành động |
|-------|-------|----------|-----------|
| 0 | 203.0.113.5 | 1 | tạo bucket |
| 5 | 203.0.113.5 | 2 | count++ |
| ... | ... | ... | ... |
| 40 | 203.0.113.5 | 8 | **count==8 ≤ 120s → ALERT 100110 level 10** |
| 200 | 203.0.113.5 | 1 | t0 cũ hết hạn (200-0>120) → reset |

**VÌ SAO thiết kế `frequency`+`timeframe`+`same_source_ip`:**
- `same_source_ip` là *khóa nhóm*: không có nó, 8 lần fail từ 8 IP khác nhau (ví dụ password spraying nhẹ phân tán) sẽ gộp nhầm. Có nó, ta tách bucket theo IP để phát hiện đúng brute-force tập trung.
- `timeframe` định nghĩa "tốc độ" — phân biệt brute-force (8 lần/2 phút) với 8 lần fail rải rác cả ngày (người dùng quên mật khẩu).

> Các khóa nhóm khác: `<same_source_user/>`, `<same_destination_ip/>`, `<different_source_ip/>` (cho phát hiện distributed). Ngoài ra `<if_matched_group>` cho phép đếm theo *nhóm* rule thay vì một SID.

### 8.8.6. Ghi đè và điều chỉnh rule gốc (overwrite / `<if_sid>`)

Không sửa file gốc; thay vào đó trong `local_rules.xml`:

```xml
<!-- Hạ level một rule gốc gây nhiễu trong môi trường của bạn -->
<rule id="5710" level="0" overwrite="yes">
  <description>sshd: non-existent user (bị làm câm trong subnet quản trị)</description>
</rule>
```

Hoặc tạo exception có điều kiện:
```xml
<rule id="100200" level="0">
  <if_sid>5710</if_sid>
  <field name="srcip">10.0.0.0/8</field>   <!-- bỏ qua nếu từ mạng nội bộ tin cậy -->
  <description>Bỏ qua sshd fail từ mạng quản trị nội bộ</description>
</rule>
```

---

## 8.9. FIM / Syscheck — giám sát toàn vẹn tệp

### 8.9.1. LÀ GÌ

**FIM (File Integrity Monitoring)** — module `syscheckd` — phát hiện thay đổi của file/thư mục/registry: tạo, sửa, xóa. Dùng để bắt webshell, tampering binary, sửa file cấu hình nhạy cảm.

### 8.9.2. CƠ CHẾ BÊN TRONG

Syscheck duy trì một **CSDL trạng thái** (FIM database, SQLite trong Wazuh 4.x) lưu cho mỗi file:

| Thuộc tính lưu | Kích thước/kiểu | Ý nghĩa |
|----------------|-----------------|---------|
| `size` | int | Kích thước byte |
| `perm` | mode bits | Quyền (rwx) |
| `uid`/`gid` | int | Chủ sở hữu/nhóm |
| `inode` | int | Số inode (Linux) |
| `mtime` | timestamp | Thời điểm sửa nội dung |
| `md5` | 128-bit (32 hex) | Hash MD5 |
| `sha1` | 160-bit (40 hex) | Hash SHA-1 |
| `sha256` | 256-bit (64 hex) | Hash SHA-256 (mặc định khuyến nghị) |

Hai chế độ:

| Chế độ | Cơ chế | Độ trễ phát hiện |
|--------|--------|------------------|
| **Scheduled scan** | Quét định kỳ (`<frequency>`), so sánh hash mới với DB | Theo chu kỳ (giây/giờ) |
| **Real-time** | Dùng `inotify` (Linux) / `ReadDirectoryChangesW` (Windows) để nhận sự kiện kernel tức thì | Gần tức thì |

**VÌ SAO dùng hash chứ không chỉ mtime:** Kẻ tấn công có thể `touch` để khôi phục mtime sau khi sửa. Hash nội dung (SHA-256) bắt được thay đổi nội dung dù metadata bị làm giả. SHA-256 chọn vì kháng va chạm (collision-resistant) tốt hơn MD5/SHA-1.

### 8.9.3. VÍ DỤ — cấu hình `<syscheck>` trong `ossec.conf`

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>            <!-- quét scheduled mỗi 12 giờ -->
  <scan_on_start>yes</scan_on_start>

  <!-- Thư mục web: realtime + report nội dung thay đổi -->
  <directories check_all="yes" realtime="yes" report_changes="yes">/var/www/html</directories>

  <!-- File cấu hình nhạy cảm: theo dõi mọi thuộc tính -->
  <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>

  <!-- Loại trừ để giảm nhiễu -->
  <ignore>/etc/mtab</ignore>
  <ignore>/var/www/html/cache</ignore>
  <ignore type="sregex">.log$</ignore>

  <!-- Không tính hash file lớn để tiết kiệm -->
  <skip_nfs>yes</skip_nfs>
  <nodiff>/etc/ssl/private</nodiff>       <!-- không lưu diff nội dung (chứa secret) -->
</syscheck>
```

| Thuộc tính `<directories>` | Ý nghĩa |
|----------------------------|---------|
| `check_all="yes"` | Kiểm tra size+perm+owner+mtime+inode+các hash |
| `realtime="yes"` | Bật inotify cho thư mục này |
| `report_changes="yes"` | Lưu *diff nội dung* (cho file text) để xem chính xác dòng nào đổi |
| `whodata="yes"` | Dùng auditd để biết *ai* (uid/process) đã thay đổi (cao cấp hơn realtime) |

### 8.9.4. VÍ DỤ — alert FIM mẫu (webshell)

Khi attacker drop `shell.php` vào `/var/www/html`, syscheck (realtime) sinh event, khớp rule FIM gốc (nhóm `syscheck`, các rule 550–554), alert.json:
```json
{
  "rule": { "id": "554", "level": 7, "description": "File added to the system." },
  "syscheck": {
    "path": "/var/www/html/shell.php",
    "event": "added",
    "sha256_after": "9f2c...e1",
    "uid_after": "33", "gname_after": "www-data",
    "mtime_after": "2026-06-19T11:30:02"
  },
  "location": "syscheck"
}
```

**LƯU Ý BẢO MẬT:**
- `report_changes`/`nodiff`: KHÔNG lưu diff của file chứa secret (private key, `/etc/shadow`) — diff được lưu trong DB Wazuh có thể rò bí mật. Dùng `<nodiff>` cho đường nhạy cảm.
- Realtime trên thư mục cực lớn (vd `/`) làm cạn inotify watches kernel (`fs.inotify.max_user_watches`) → mất giám sát thầm lặng. Chỉ realtime nơi cần.

---

## 8.10. Active Response — phản ứng tự động

### 8.10.1. LÀ GÌ

**Active Response (AR)** cho phép Wazuh tự chạy một lệnh (script) khi một rule khớp — ví dụ chặn IP tấn công bằng firewall. Đây là khả năng "SOAR mini" tích hợp, do `wazuh-execd` thực thi trên agent hoặc manager.

### 8.10.2. CƠ CHẾ BÊN TRONG (luồng + state)

```
Rule X khớp (vd brute-force level >=10)
        │
        ▼
analysisd kiểm tra có <active-response> nào liên kết (qua <rules_id> hoặc <level>)
        │  có
        ▼
manager gửi lệnh AR xuống agent đích (qua kênh 1514)
        │
        ▼
wazuh-execd trên agent gọi script trong /var/ossec/active-response/bin/
        ├─ action = "add"     → chặn (vd thêm rule iptables DROP srcip)
        └─ sau <timeout> giây  → tự gọi lại action = "delete" → gỡ chặn
```

Script AR nhận tham số qua **stdin (JSON)** trong Wazuh 4.x: gồm `command` (`add`/`delete`), và `parameters.alert` (toàn bộ alert, có `srcip`). VÌ SAO timeout: chặn vĩnh viễn có rủi ro tự DoS (chặn nhầm IP hợp lệ, hoặc IP NAT chung) — timeout cho phép gỡ tự động.

### 8.10.3. VÍ DỤ THỰC TẾ — chặn IP brute-force bằng firewall-drop

Bước 1 — định nghĩa **command** và **active-response** trong `ossec.conf` (trên manager):
```xml
<!-- Command: trỏ tới script tích hợp sẵn firewall-drop -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>   <!-- /var/ossec/active-response/bin/firewall-drop -->
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Active response: chạy command trên agent có sự kiện, chặn 600s -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>          <!-- local = chạy trên agent nơi sự kiện xảy ra -->
  <rules_id>100110</rules_id>         <!-- chính là rule brute-force ở 8.8.5 -->
  <timeout>600</timeout>              <!-- gỡ chặn sau 600 giây -->
</active-response>
```

| `<location>` | Chạy ở đâu |
|--------------|-----------|
| `local` | Trên agent phát sinh sự kiện |
| `server` | Trên manager |
| `defined-agent` | Trên một agent chỉ định (`<agent_id>`) |
| `all` | Mọi agent (cẩn thận!) |

Bước 2 — `firewall-drop` (script tích hợp) trên Linux agent thực thi tương đương:
```bash
# action=add:
iptables -I INPUT -s 203.0.113.5 -j DROP
# sau 600s, action=delete:
iptables -D INPUT -s 203.0.113.5 -j DROP
```

Bước 3 — alert AR ghi trong `active-responses.log` trên agent:
```
2026-06-19 11:31:00 /var/ossec/active-response/bin/firewall-drop: add - 203.0.113.5 - 1718796660.123456 - 100110
```

**LƯU Ý BẢO MẬT:**
- **Chống self-DoS:** kẻ tấn công spoof srcip = IP gateway/DNS nội bộ trong log để ép Wazuh chặn hạ tầng của chính bạn. Luôn duy trì **allowlist** (script firewall-drop có cơ chế bỏ qua IP trong danh sách trắng); KHÔNG bật AR `all` cho rule dễ bị giả mạo.
- AR chạy bằng quyền cao (iptables cần root) → script AR là bề mặt tấn công; chỉ dùng script đã kiểm duyệt, quyền file chặt.
- Ưu tiên AR `local` thay vì `all` để giới hạn tác động.

---

## 8.11. Vulnerability Detection — phát hiện lỗ hổng (CVE)

### 8.11.1. LÀ GÌ và CƠ CHẾ

Module `wazuh-modulesd` (Vulnerability Detector) đối chiếu **danh sách package đã cài** (do agent gửi qua syscollector) với **CVE feed** để báo host nào có lỗ hổng nào.

Luồng:
```
1. syscollector (trên agent) liệt kê package + version + OS  ──▶ manager
2. Vulnerability Detector tải/cập nhật feed CVE
      (nguồn: NVD, Canonical/Ubuntu OVAL, Red Hat, Debian, Microsoft MSU, ALAS...)
3. Đối chiếu: package P version V vs điều kiện "ảnh hưởng nếu V < V_fixed"
4. Sinh alert nếu khớp, kèm CVE id, CVSS, package, version vá
```

> Lưu ý kiến trúc theo phiên bản: cách cấu hình và nguồn feed của Vulnerability Detection **đã thay đổi đáng kể giữa các minor 4.x** (mô hình feed cũ dựa OVAL/NVD trực tiếp vs mô hình "Vulnerability Detection" mới dựa Content Manager/CTI của Wazuh). Hãy kiểm chứng cú pháp khối cấu hình với tài liệu đúng version đang chạy. Phần dưới minh họa dạng cấu hình OVAL/NVD kiểu cũ để hiểu nguyên lý.

### 8.11.2. VÍ DỤ — cấu hình kiểu cũ (minh họa nguyên lý)

```xml
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>

  <provider name="canonical">          <!-- Ubuntu OVAL -->
    <enabled>yes</enabled>
    <os>focal</os>
    <os>jammy</os>
    <update_interval>1h</update_interval>
  </provider>

  <provider name="nvd">                <!-- NVD bổ sung CVSS/CPE -->
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
```

### 8.11.3. VÍ DỤ — alert CVE mẫu

```json
{
  "rule": { "level": 7, "description": "CVE-2024-XXXX affects openssl" },
  "data": {
    "vulnerability": {
      "cve": "CVE-2024-XXXX",
      "package": { "name": "openssl", "version": "3.0.2-0ubuntu1.10" },
      "severity": "High",
      "cvss": { "cvss3": { "base_score": "7.5" } },
      "status": "Active",
      "reference": "https://ubuntu.com/security/CVE-2024-XXXX"
    }
  }
}
```

**LƯU Ý:** Vulnerability Detection báo **lỗ hổng tiềm năng theo version**, KHÔNG xác nhận khả năng khai thác thực tế (chưa biết có patch backport của distro hay không trong mọi trường hợp). Cần đối chiếu với reachability/exposure trước khi ưu tiên vá — tránh "CVE noise".

---

## 8.12. SCA — Security Configuration Assessment

### 8.12.1. LÀ GÌ

**SCA** kiểm tra cấu hình hệ thống so với baseline (CIS Benchmark, ví dụ "SSH không cho phép root login", "password phải đặt độ phức tạp"). Module này chạy các **policy** dạng YAML trên agent và báo pass/fail từng kiểm tra.

### 8.12.2. CƠ CHẾ — cấu trúc một policy check

Policy SCA (file YAML trong `/var/ossec/ruleset/sca/`) gồm các `checks`, mỗi check có `rules` đánh giá theo logic.

```yaml
policy:
  id: "cis_debian12"
  name: "CIS Debian Linux 12 Benchmark"

checks:
  - id: 5001
    title: "Ensure SSH PermitRootLogin is disabled"
    description: "PermitRootLogin nên = no để chặn đăng nhập root trực tiếp"
    rationale: "Giảm bề mặt brute-force vào tài khoản quyền cao nhất"
    remediation: "Đặt 'PermitRootLogin no' trong /etc/ssh/sshd_config rồi reload sshd"
    condition: all          # tất cả rules phải đúng thì PASS
    rules:
      - 'f:/etc/ssh/sshd_config -> r:^\s*PermitRootLogin\s+no'
```

Cú pháp `rules` (atomic checks):

| Tiền tố | Ý nghĩa | Ví dụ |
|---------|---------|-------|
| `f:` | File tồn tại | `f:/etc/ssh/sshd_config` |
| `f:... -> r:` | File chứa regex | `f:/etc/ssh/sshd_config -> r:^PermitRootLogin no` |
| `c:` | Chạy command, so output | `c:sysctl net.ipv4.ip_forward -> r:= 0$` |
| `d:` | Thư mục tồn tại | `d:/etc/cron.d` |
| `p:` | Process đang chạy | `p:auditd` |
| `r:` | Khóa registry (Windows) | — |

`condition`: `all` (mọi rule đúng), `any` (một rule đúng), `none` (không rule nào đúng).

### 8.12.3. VÍ DỤ — kết quả SCA trên dashboard / alert

```json
{
  "data": {
    "sca": {
      "type": "check",
      "policy": "CIS Debian Linux 12 Benchmark",
      "check": {
        "id": "5001",
        "title": "Ensure SSH PermitRootLogin is disabled",
        "result": "failed",
        "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
      }
    }
  }
}
```

**LƯU Ý:** SCA là *configuration drift detection* — chạy định kỳ. Một host "passed 90%" vẫn có thể có 10% fail là lỗ hổng nghiêm trọng; đọc theo từng check, không chỉ điểm tổng.

---

## 8.13. Tích hợp MITRE ATT&CK

### 8.13.1. LÀ GÌ

**MITRE ATT&CK** là ma trận chuẩn hóa kỹ thuật của attacker theo Tactic (mục tiêu) → Technique (cách làm). Wazuh gắn mã technique (`T####`, sub-technique `T####.###`) vào rule, cho phép dashboard hiển thị tấn công theo ma trận và phục vụ threat hunting.

| Khái niệm | Ví dụ |
|-----------|-------|
| Tactic | `Credential Access` (TA0006) |
| Technique | `T1110` Brute Force |
| Sub-technique | `T1110.001` Password Guessing |

### 8.13.2. VÍ DỤ — gắn MITRE vào rule (đã thấy ở 8.8.5)

```xml
<rule id="100110" level="10" frequency="8" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>Paywall brute-force</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

Trên dashboard, alert này xuất hiện trong module **MITRE ATT&CK**, nhóm theo Tactic `Credential Access`, cho phép trả lời "trong tuần qua có bao nhiêu sự kiện thuộc Credential Access và trên host nào".

**LƯU Ý:** Gắn MITRE đúng technique là phần của detection engineering — gắn sai làm sai lệch coverage report (tưởng đã phủ technique X nhưng thực ra rule bắt việc khác).

---

## 8.14. Detection Engineering — viết, tinh chỉnh rule, FP vs FN

### 8.14.1. FP và FN

| Khái niệm | Định nghĩa | Hậu quả |
|-----------|------------|---------|
| **False Positive (FP)** | Alert nổ nhưng KHÔNG phải tấn công | Mệt mỏi analyst (alert fatigue), bỏ sót alert thật |
| **False Negative (FN)** | Tấn công thật nhưng KHÔNG có alert | Lọt lưới — nguy hiểm nhất |
| **True Positive (TP)** | Alert đúng | Lý tưởng |
| **True Negative (TN)** | Không alert, đúng là an toàn | Lý tưởng |

**Đánh đổi cốt lõi:** Hạ ngưỡng (frequency thấp, level cao cho event đơn lẻ) → giảm FN nhưng tăng FP. Nâng ngưỡng → giảm FP nhưng tăng FN. Detection engineering là tìm điểm cân bằng theo ngữ cảnh tài sản.

Chỉ số định lượng:
```
Precision = TP / (TP + FP)     (alert nổ thì đáng tin tới mức nào)
Recall    = TP / (TP + FN)     (bắt được bao nhiêu phần tấn công thật)
```

### 8.14.2. Quy trình tuning (vòng lặp)

```
1. Viết rule giả thuyết (dựa decoder + field).
2. Test offline với wazuh-logtest trên log mẫu (cả mẫu tấn công lẫn mẫu bình thường).
3. Triển khai ở level THẤP (vd level 3) — quan sát volume, không hành động.
4. Đo FP: tỷ lệ alert là benign. Nếu cao → thêm điều kiện (field/srcip allowlist) hoặc tăng frequency.
5. Đo FN: replay mẫu tấn công đã biết — rule có nổ không?
6. Khi precision đạt, nâng level + (tùy) gắn active-response.
7. Lặp lại định kỳ (môi trường thay đổi → rule lỗi thời).
```

### 8.14.3. VÍ DỤ — tinh chỉnh rule brute-force để giảm FP

Vấn đề: rule 100110 nổ khi proxy/NAT làm nhiều user thật cùng srcip fail. Tinh chỉnh:

```xml
<!-- v2: chỉ tính brute-force khi cùng IP NHƯNG khác user (dấu hiệu dò user),
         và loại trừ dải NAT nội bộ tin cậy -->
<rule id="100111" level="12" frequency="10" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <different_source_user />      <!-- nhiều user khác nhau từ 1 IP = dò tài khoản -->
  <description>Paywall: dò nhiều tài khoản từ $(srcip) (credential stuffing nghi vấn)</description>
  <mitre><id>T1110.004</id></mitre>  <!-- Credential Stuffing -->
</rule>

<!-- Triệt FP: bỏ qua dải office NAT -->
<rule id="100112" level="0">
  <if_sid>100110</if_sid>
  <field name="srcip">^10.20.0.</field>
  <description>Bỏ qua brute-force giả từ NAT văn phòng</description>
</rule>
```

### 8.14.4. Nguyên tắc viết rule tốt

| Nguyên tắc | VÌ SAO |
|-----------|--------|
| Neo regex (`^`, `$`), khớp field thay vì substring khi có thể | Tránh khớp nhầm, nhanh hơn |
| Đặt `id` trong 100000–120000 | Không đụng rule gốc, không bị mất khi update |
| Bắt đầu ở level thấp, nâng dần | Tránh active-response gây hại do FP |
| Tài liệu hóa `<description>` rõ ràng kèm field nội suy | Analyst hiểu ngay khi triage |
| Gắn `<mitre>` đúng | Đo coverage |
| Có cả test case dương tính và âm tính | Đảm bảo không FN và không FP |

---

## 8.15. VÍ DỤ END-TO-END: SSH brute-force từ log thô tới alert dashboard

Ghép toàn bộ chuỗi: **log → predecode → decode → rule stateless → rule correlation → alert → (active response) → indexer → dashboard.**

### Bước 0 — Cấu hình agent đọc auth.log
`ossec.conf` (agent):
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

### Bước 1 — Log thô sinh ra (3 dòng minh họa)
```
Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
Jun 19 10:22:43 web01 sshd[2933]: Failed password for invalid user admin from 203.0.113.5 port 51290 ssh2
... (lặp 8 lần trong ~30s)
```

### Bước 2 — PreDecoding (analysisd)
```
timestamp:    Jun 19 10:22:41
hostname:     web01
program_name: sshd
log:          Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```

### Bước 3 — Decoding (decoder sshd gốc)
```
srcuser: admin
srcip:   203.0.113.5
srcport: 51244
```

### Bước 4 — Rule stateless gốc khớp
Wazuh ship sẵn rule cho việc này:
```xml
<!-- (rule gốc, minh họa) -->
<rule id="5710" level="5">
  <if_sid>5700</if_sid>
  <match>Failed password|authentication failure|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user.</description>
  <group>authentication_failed,invalid_login,</group>
</rule>
```
→ Mỗi dòng fail tạo một alert level 5.

### Bước 5 — Rule correlation gốc khớp (brute-force)
```xml
<!-- (rule gốc, minh họa) — nhiều lần authentication_failed cùng IP -->
<rule id="5712" level="10" frequency="8" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>sshd: brute force trying to get access to the system. Authentication failed.</description>
  <group>authentication_failures,</group>
  <mitre><id>T1110</id></mitre>
</rule>
```
→ Sau lần fail thứ 8 trong 120s từ `203.0.113.5`, alert level 10 nổ.

### Bước 6 — Alert JSON (ghi vào `/var/ossec/logs/alerts/alerts.json`)
```json
{
  "timestamp": "2026-06-19T10:23:11.044+0000",
  "rule": {
    "id": "5712",
    "level": 10,
    "description": "sshd: brute force trying to get access to the system.",
    "groups": ["syslog", "sshd", "authentication_failures"],
    "mitre": { "id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"] },
    "frequency": 8
  },
  "agent": { "id": "001", "name": "web01", "ip": "192.0.2.10" },
  "data": { "srcip": "203.0.113.5", "srcuser": "admin", "srcport": "51244" },
  "decoder": { "name": "sshd" },
  "location": "/var/log/auth.log",
  "full_log": "Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2"
}
```

### Bước 7 — Active Response (tùy chọn) chặn IP
Nếu cấu hình `<active-response>` với `<rules_id>5712</rules_id>`, manager ra lệnh agent web01 chạy `firewall-drop`:
```
iptables -I INPUT -s 203.0.113.5 -j DROP   # tự gỡ sau <timeout>
```

### Bước 8 — Filebeat → Indexer → Dashboard
- `Filebeat` (cấu hình `/etc/filebeat/filebeat.yml` với module `wazuh`) đọc `alerts.json`, đẩy vào index `wazuh-alerts-4.x-2026.06.19` trên indexer (cổng 9200).
- Dashboard truy vấn index, hiển thị alert level 10 trong Security Events; trong module MITRE ATT&CK nó thuộc Tactic *Credential Access* / Technique *T1110*.

### Bước 9 — Kiểm thử toàn chuỗi offline
```bash
# Mô phỏng nhanh: dán dòng log vào logtest để xác nhận decoder + rule
/var/ossec/bin/wazuh-logtest
# input:
Jun 19 10:22:41 web01 sshd[2931]: Failed password for invalid user admin from 203.0.113.5 port 51244 ssh2
```
Output xác nhận Phase 1/2/3 và rule id 5710 → (sau đủ tần suất) 5712.

Sơ đồ tổng kết end-to-end:
```
auth.log line ──▶ logcollector(agent) ──1514──▶ remoted ──▶ analysisd
                                                              │
                       ┌──────────────────────────────────────┘
                       ▼
            PreDecode ▶ Decode(sshd: srcip/srcuser) ▶ Rule 5710(L5) ▶ [×8/120s, same_source_ip] ▶ Rule 5712(L10)
                                                                                                        │
                                          ┌─────────────────────────────────────────────┬─────────────┘
                                          ▼                                             ▼
                                  active-response: firewall-drop              alerts.json ▶ Filebeat ▶ Indexer(9200) ▶ Dashboard(443)
                                  iptables DROP 203.0.113.5
```

---

## 8.16. Tổng kết vận hành & checklist bảo mật Wazuh

| Hạng mục | Khuyến nghị |
|----------|-------------|
| Truyền dữ liệu | TCP 1514 + `crypto_method aes`; enroll qua 1515 có password/CA |
| `client.keys` | Quyền chặt, không lộ; tên agent ổn định, duy nhất |
| Rule/decoder tùy biến | Chỉ trong `local_*.xml`, id 100000+, test bằng `wazuh-logtest` & `analysisd -t` trước restart |
| FIM | Realtime đúng chỗ; `<nodiff>` cho đường chứa secret; canh `inotify` watches |
| Active Response | Allowlist IP hạ tầng; ưu tiên `local`; `timeout` để tự gỡ; script quyền chặt |
| Vuln/SCA | Đối chiếu version đúng feed; đọc theo từng CVE/check, không chỉ điểm tổng |
| Lưu trữ | `logall=no` trừ khi forensic; chính sách retention rõ ràng (hot/warm/cold) |
| Tuning | Vòng lặp đo FP/FN; nâng level dần; review định kỳ |
| API 55000 | Đổi credential mặc định, bật RBAC, giới hạn network |

---

*Hết Chương 8.*
