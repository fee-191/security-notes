# Sổ tay An toàn thông tin

> Blog chia sẻ kiến thức an toàn thông tin bằng tiếng Việt — những gì mình ghi chép, tổng hợp lại trong quá trình học và làm việc. Mình cố gắng giải thích kỹ cơ chế và kèm ví dụ thực tế, vừa để tự ôn lại, vừa hy vọng giúp được các bạn đang học.

Mỗi chương đi theo lối: **khái niệm → cơ chế hoạt động → ví dụ thực tế → lưu ý bảo mật**, ưu tiên hiểu *vì sao* hơn là học thuộc. Mình vẫn đang học mỗi ngày, nên nếu có chỗ chưa chính xác rất mong được góp ý.

---

## Mục lục — 17 chương

### Phần I — Nền tảng
| # | Chương | Nội dung chính |
|---|---|---|
| 01 | **Mạng máy tính (TCP/IP, OSI)** | Encapsulation byte-by-byte, layout header Ethernet/IPv4/IPv6/TCP/UDP, ARP, subnet, TCP handshake & state machine, NAT, DNS, TLS |
| 02 | **Hệ điều hành Linux** | Quyền & SUID/ACL, passwd/shadow, process/namespace, systemd, logging, bash + grep/awk/sed, hardening |
| 03 | **Windows & Active Directory** | Event ID bảo mật, Sysmon, Kerberos vs NTLM, tấn công AD (PtH, Kerberoasting, golden ticket) + dấu hiệu |
| 04 | **Mật mã & Nền tảng bảo mật** | AES/RSA/ECC/DH, hash & lưu mật khẩu, HMAC, chữ ký số, PKI/X.509, CIA/AAA, CVE/CVSS/CWE |

### Phần II — Ứng dụng & DevSecOps
| # | Chương | Nội dung chính |
|---|---|---|
| 05 | **AppSec & OWASP Top 10** | SQLi/XSS/CSRF/SSRF/IDOR (payload + fix), JWT/OAuth2/OIDC, STRIDE, Zero Trust |
| 06 | **DevSecOps: Quét bảo mật & Semgrep** | SAST/DAST/SCA/secret/IaC, Semgrep (AST, viết rule, taint), Gitleaks/Trivy, supply chain (SLSA/SBOM) |
| 07 | **CI/CD & GitOps** | GitLab CI, GitHub Actions, Jenkins, Argo CD/GitOps, git submodule — ví dụ thật từng công cụ |

### Phần III — Giám sát & SOC
| # | Chương | Nội dung chính |
|---|---|---|
| 08 | **SIEM & Wazuh** | Kiến trúc SIEM, Wazuh (decoder/rule, FIM, active response), detection engineering |
| 09 | **ELK Stack & Zabbix** | Elasticsearch/Logstash/Kibana/Beats, Zabbix; khi nào dùng cái nào |
| 10 | **Vận hành SOC & Ứng phó sự cố** | SOC tier, triage, IR lifecycle (NIST/SANS), playbook, threat hunting |

### Phần IV — Phòng thủ mạng & Kiểm thử
| # | Chương | Nội dung chính |
|---|---|---|
| 11 | **IDS/IPS, WAF & Phòng thủ mạng** | Snort/Suricata (rule + ví dụ), ModSecurity + CRS, pfSense, VPN (IPsec/OpenVPN/WireGuard) |
| 12 | **Kiểm thử & Quét lỗ hổng** | Burp Suite, Acunetix, Nmap (kiểu scan + gói tin, NSE) |

### Phần V — Hạ tầng & Đám mây
| # | Chương | Nội dung chính |
|---|---|---|
| 13 | **Bảo mật Đám mây (AWS & GCP)** | IAM, VPC, SG vs NACL, S3, KMS, CloudTrail/GuardDuty, IMDSv2/SSRF, tấn công cloud |
| 14 | **Ảo hóa & Container** | Docker internals, container escape, Kubernetes + bảo mật (RBAC/NetworkPolicy/PSS) |

### Phần VI — Tri thức tấn công, Tuân thủ & Lập trình
| # | Chương | Nội dung chính |
|---|---|---|
| 15 | **Threat Intel & MITRE ATT&CK** | 14 tactic + technique, Kill Chain, Diamond Model, IOC vs IOA, phân tích malware |
| 16 | **Tuân thủ & Quản trị (GRC)** | Risk management, NIST CSF/800-53/61/207, ISO 27001, pháp lý VN |
| 17 | **Python cho An toàn thông tin** | socket/requests/scapy/boto3, port scanner, log parser, gọi API, secure coding |

---

## Gợi ý lộ trình học (theo định hướng)

- **Người mới bắt đầu:** 01 → 02 → 04 → 05. Nắm chắc mạng + Linux + mật mã + lỗ hổng web là gốc của mọi thứ.
- **Hướng Blue Team / SOC:** 01, 02, 03 → 08, 09, 10 → 15. Tập trung giám sát, điều tra, hiểu hành vi tấn công.
- **Hướng AppSec / DevSecOps:** 04, 05 → 06, 07 → 14, 17. Bảo mật từ dòng code tới pipeline tới container.
- **Hướng Cloud / Hạ tầng:** 01, 02 → 13, 14 → 07. Bảo mật hệ thống và môi trường vận hành.
- **Hướng GRC / Tuân thủ:** 04 → 16 → 10. Quản trị rủi ro, khung tiêu chuẩn, pháp lý.

**Cách học hiệu quả:** đọc → tự giải thích lại bằng lời → **gõ lại ví dụ** (lệnh/cấu hình/rule/code) trong lab thật. Kiến thức bảo mật chỉ chắc khi tự tay làm.

---

## Về tài liệu này

Sổ tay này được ghi chép và chia sẻ bởi **Lê Dương Phi**, tự do cho mục đích học tập. Mình không tự nhận là chuyên gia — đây là cách mình hệ thống lại những gì đã học; nếu thấy hữu ích thì bạn cứ dùng để tự ôn hoặc chia sẻ tiếp.

> Nội dung mang tính giáo dục. Mọi kỹ thuật tấn công trình bày ở đây chỉ nhằm hiểu để **phòng thủ** — hãy dùng có trách nhiệm và hợp pháp, chỉ thực hành trên hệ thống bạn được phép.
