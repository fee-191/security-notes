# Appendix — Glossary & Abbreviations

A quick reference for terms and abbreviations used throughout the handbook. Technical terms are kept in English (as used in the industry) with short, plain definitions.

| Term / Abbr. | Full form | Short definition |
|---|---|---|
| **ABAC** | Attribute-Based Access Control | Authorization based on attributes (role, department, time, location...) rather than role alone. |
| **AEAD** | Authenticated Encryption with Associated Data | Encryption that provides both confidentiality and tamper protection (e.g. AES-GCM). |
| **APT** | Advanced Persistent Threat | A sophisticated, organized adversary that maintains long-term access. |
| **AST** | Abstract Syntax Tree | The parsed structure of source code; SAST analyzes this tree instead of matching strings. |
| **Beaconing** | — | Malware periodically "calling home" to its C2 server — a key detection signal. |
| **CORS** | Cross-Origin Resource Sharing | A controlled mechanism letting a web page request resources from another origin. |
| **CSRF** | Cross-Site Request Forgery | Tricks a victim's browser into sending unwanted requests to a site they're logged into. |
| **C2 / C&C** | Command and Control | Infrastructure an attacker uses to control compromised machines. |
| **CVE** | Common Vulnerabilities and Exposures | A public identifier for a specific vulnerability. |
| **CVSS** | Common Vulnerability Scoring System | A 0–10 score rating a vulnerability's severity. |
| **DAI** | Dynamic ARP Inspection | A switch feature that blocks ARP spoofing. |
| **DAST** | Dynamic Application Security Testing | Security testing of a **running** application (black-box). |
| **Dwell time** | — | How long an attacker stays in a system before being detected. |
| **EDR** | Endpoint Detection and Response | Deep endpoint monitoring and response (more capable than antivirus). |
| **FIM** | File Integrity Monitoring | Watches critical files/directories for changes to detect tampering. |
| **GRC** | Governance, Risk & Compliance | Governance, risk management, and compliance. |
| **HMAC** | Hash-based Message Authentication Code | Message authentication code built from a hash plus a secret key. |
| **IAM** | Identity and Access Management | Managing identities and access permissions. |
| **IDOR** | Insecure Direct Object Reference | Accessing another user's resource by changing an ID — a form of broken access control. |
| **IDS / IPS** | Intrusion Detection / Prevention System | Detects / blocks network intrusions. |
| **IMDS** | Instance Metadata Service | A cloud VM's metadata endpoint (169.254.169.254); IMDSv2 mitigates SSRF. |
| **IOC / IOA** | Indicator of Compromise / of Attack | Evidence of compromise (hash, IP...) / signs of attacker behavior. |
| **ISMS** | Information Security Management System | The core of ISO 27001 — a managed approach to security. |
| **ISN** | Initial Sequence Number | The starting sequence number in a TCP handshake. |
| **JWT** | JSON Web Token | A self-contained token (header.payload.signature) for authn/authz. |
| **KMS** | Key Management Service | A managed service for encryption keys (e.g. AWS KMS). |
| **Lateral movement** | — | An attacker moving from one machine to another inside the network. |
| **LOLBIN** | Living Off the Land Binary | Abusing legitimate built-in tools to attack while evading detection. |
| **MFA** | Multi-Factor Authentication | Authentication using more than one factor (password + OTP/key...). |
| **MITM** | Man-in-the-Middle | Intercepting traffic between two parties to eavesdrop or modify it. |
| **MITRE ATT&CK** | — | A knowledge base of real-world attacker tactics and techniques. |
| **MTTD / MTTR** | Mean Time To Detect / Respond | Average time to detect / respond to an incident. |
| **NACL** | Network Access Control List | A **stateless** subnet-level firewall in an AWS VPC. |
| **PKI** | Public Key Infrastructure | The system of CAs, certificates, and chains of trust. |
| **Persistence** | — | Techniques that let an attacker survive a reboot. |
| **Privilege escalation** | — | Gaining higher privileges (admin/root) from a normal user. |
| **RBAC** | Role-Based Access Control | Authorization based on roles. |
| **RCE** | Remote Code Execution | Running code remotely — the most critical class of vulnerability. |
| **Residual risk** | — | The risk that remains after treatment has been applied. |
| **RTO / RPO** | Recovery Time / Point Objective | Target recovery time / maximum acceptable data loss. |
| **SAML** | Security Assertion Markup Language | An enterprise SSO standard. |
| **SAST** | Static Application Security Testing | Security scanning of **static source code** (without running it). |
| **SCA** | Software Composition Analysis | Scanning libraries/dependencies for known CVEs. |
| **SIEM** | Security Information and Event Management | Collecting and correlating logs across the system to detect threats. |
| **SOAR** | Security Orchestration, Automation and Response | Automating incident response workflows (playbooks). |
| **SOP** | Same-Origin Policy | The browser rule isolating resources between different origins. |
| **SQLi** | SQL Injection | Injecting SQL via input to manipulate a query. |
| **SSRF** | Server-Side Request Forgery | Forcing a server to call an attacker-chosen destination (e.g. cloud metadata). |
| **SSO** | Single Sign-On | One login used across multiple services. |
| **TTP** | Tactics, Techniques and Procedures | How an attacker operates (per MITRE ATT&CK). |
| **VPC** | Virtual Private Cloud | A private virtual network in the cloud. |
| **WAF** | Web Application Firewall | A firewall filtering HTTP at the application layer (blocks SQLi/XSS...). |
| **XDR** | Extended Detection and Response | Extends EDR across multiple sources (mail, network, cloud). |
| **XSS** | Cross-Site Scripting | Injecting script that runs in a victim's browser. |
| **Zero Trust** | — | "Never trust, always verify" — no implicit trust based on network location. |

> This glossary grows as the handbook expands. If a useful term is missing, feel free to open an Issue to suggest it.
