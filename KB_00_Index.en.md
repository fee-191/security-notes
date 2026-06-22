# Security Handbook

> A security knowledge base — notes I've collected and organized while learning and working in security. I try to explain the underlying mechanisms in depth and include practical examples, both to revise for myself and hopefully to help others who are studying.

Each chapter follows the same flow: **concept → how it works → practical example → security notes**, favoring understanding *why* over rote memorization. If you spot anything inaccurate, feedback is very welcome.

---

## Contents — 17 chapters

### Part A — Fundamentals
| # | Chapter | Key topics |
|---|---|---|
| 01 | **Computer Networking (TCP/IP, OSI)** | Byte-by-byte encapsulation, Ethernet/IPv4/IPv6/TCP/UDP header layouts, ARP, subnetting, TCP handshake & state machine, NAT, DNS, TLS |
| 02 | **Linux Operating System** | Permissions & SUID/ACL, passwd/shadow, processes/namespaces, systemd, logging, bash + grep/awk/sed, hardening |
| 03 | **Windows & Active Directory** | Security event IDs, Sysmon, Kerberos vs NTLM, AD attacks (PtH, Kerberoasting, golden ticket) + detection |
| 04 | **Cryptography & Security Foundations** | AES/RSA/ECC/DH, hashing & password storage, HMAC, digital signatures, PKI/X.509, CIA/AAA, CVE/CVSS/CWE |

### Part B — Application Security & DevSecOps
| # | Chapter | Key topics |
|---|---|---|
| 05 | **Web Application Security (OWASP Top 10)** | SQLi/XSS/CSRF/SSRF/IDOR (payload + fix), JWT/OAuth2/OIDC, STRIDE, Zero Trust |
| 06 | **DevSecOps & Source Code Scanning** | SAST/DAST/SCA/secret/IaC, Semgrep (AST, rule writing, taint), Gitleaks/Trivy, supply chain (SLSA/SBOM) |
| 07 | **CI/CD & GitOps** | GitLab CI, GitHub Actions, Jenkins, Argo CD/GitOps, git submodule — real examples per tool |

### Part C — Monitoring, Detection & Response
| # | Chapter | Key topics |
|---|---|---|
| 08 | **SIEM & Log Management** | SIEM architecture, Wazuh (decoder/rule, FIM, active response), detection engineering |
| 09 | **Observability & Infrastructure Monitoring** | Elasticsearch/Logstash/Kibana/Beats, Zabbix; when to use which |
| 10 | **SOC Operations & Incident Response** | SOC tiers, triage, IR lifecycle (NIST/SANS), playbooks, threat hunting |

### Part D — Network Defense & Testing
| # | Chapter | Key topics |
|---|---|---|
| 11 | **Network Defense (IDS/IPS, WAF, Firewall, VPN)** | Snort/Suricata (rules + examples), ModSecurity + CRS, pfSense, VPN (IPsec/OpenVPN/WireGuard) |
| 12 | **Penetration Testing & Vulnerability Assessment** | Burp Suite, Acunetix, Nmap (scan types + packets, NSE) |

### Part E — Infrastructure, Virtualization & Cloud
| # | Chapter | Key topics |
|---|---|---|
| 13 | **Cloud Security** | IAM, VPC, SG vs NACL, S3, KMS, CloudTrail/GuardDuty, IMDSv2/SSRF, cloud attacks (AWS & GCP) |
| 14 | **Virtualization & Containers** | Docker internals, container escape, Kubernetes + security (RBAC/NetworkPolicy/PSS) |

### Part F — Offense, Compliance & Automation
| # | Chapter | Key topics |
|---|---|---|
| 15 | **Threat Intelligence & Attack Frameworks** | 14 tactics + techniques, Kill Chain, Diamond Model, IOC vs IOA, malware analysis |
| 16 | **Compliance & Governance (GRC)** | Risk management, NIST CSF/800-53/61/207, ISO 27001, Vietnam regulations |
| 17 | **Programming & Automation for Security** | socket/requests/scapy/boto3, port scanner, log parser, API calls, secure coding |

---

## Suggested learning paths

- **Beginner:** 01 → 02 → 04 → 05. Networking + Linux + crypto + web vulnerabilities are the foundation of everything.
- **Blue Team / SOC:** 01, 02, 03 → 08, 09, 10 → 15. Focus on monitoring, investigation, and understanding attacker behavior.
- **AppSec / DevSecOps:** 04, 05 → 06, 07 → 14, 17. Security from source code to pipeline to container.
- **Cloud / Infrastructure:** 01, 02 → 13, 14 → 07. Securing systems and operating environments.
- **GRC / Compliance:** 04 → 16 → 10. Risk management, standards frameworks, and regulations.

**How to study effectively:** read → explain it back in your own words → **retype the examples** (commands/config/rules/code) in a real lab. Security knowledge only sticks when you do it hands-on.

---

## About

This handbook is written and shared by **Lê Dương Phi**, free for learning purposes. If you find it useful, feel free to use it for your own revision or share it onward.

> This is educational content. Any offensive techniques shown here are meant to help you understand how to defend — use them responsibly and legally, only on systems you are authorized to test.
