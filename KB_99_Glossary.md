# Phụ lục — Thuật ngữ & viết tắt

Bảng tra nhanh các thuật ngữ và viết tắt hay gặp trong sổ tay. Thuật ngữ giữ nguyên tiếng Anh (đúng cách dùng trong ngành), giải nghĩa ngắn gọn bằng tiếng Việt.

| Thuật ngữ / Viết tắt | Đầy đủ | Giải nghĩa ngắn |
|---|---|---|
| **ABAC** | Attribute-Based Access Control | Phân quyền theo thuộc tính (vai trò, phòng ban, giờ, vị trí...) thay vì chỉ theo role. |
| **AEAD** | Authenticated Encryption with Associated Data | Mã hóa vừa giữ bí mật vừa chống sửa đổi (vd AES-GCM). |
| **APT** | Advanced Persistent Threat | Nhóm tấn công tinh vi, có tổ chức, bám trụ lâu dài trong hệ thống. |
| **AST** | Abstract Syntax Tree | Cây cú pháp của mã nguồn; SAST phân tích trên cây này thay vì so chuỗi. |
| **Beaconing** | — | Malware định kỳ "gọi về" máy chủ C2 — một dấu hiệu phát hiện quan trọng. |
| **CORS** | Cross-Origin Resource Sharing | Cơ chế cho phép trang web gọi tài nguyên ở origin khác một cách có kiểm soát. |
| **CSRF** | Cross-Site Request Forgery | Lừa trình duyệt nạn nhân gửi request ngoài ý muốn tới site họ đang đăng nhập. |
| **C2 / C&C** | Command and Control | Hạ tầng attacker dùng để điều khiển máy đã nhiễm. |
| **CVE** | Common Vulnerabilities and Exposures | Mã định danh công khai cho một lỗ hổng cụ thể. |
| **CVSS** | Common Vulnerability Scoring System | Thang điểm 0–10 đánh giá mức nghiêm trọng của lỗ hổng. |
| **DAI** | Dynamic ARP Inspection | Tính năng switch chặn ARP spoofing. |
| **DAST** | Dynamic Application Security Testing | Quét bảo mật ứng dụng **đang chạy** (black-box). |
| **Dwell time** | — | Khoảng thời gian attacker tồn tại trong hệ thống trước khi bị phát hiện. |
| **EDR** | Endpoint Detection and Response | Giám sát & phản ứng sâu trên endpoint (mạnh hơn antivirus). |
| **FIM** | File Integrity Monitoring | Theo dõi thay đổi file/thư mục quan trọng để phát hiện tamper. |
| **GRC** | Governance, Risk & Compliance | Quản trị, quản lý rủi ro và tuân thủ. |
| **HMAC** | Hash-based Message Authentication Code | Mã xác thực thông điệp dựa trên hash + khóa bí mật. |
| **IAM** | Identity and Access Management | Quản lý danh tính và quyền truy cập. |
| **IDOR** | Insecure Direct Object Reference | Truy cập tài nguyên của người khác bằng cách đổi ID — một dạng broken access control. |
| **IDS / IPS** | Intrusion Detection / Prevention System | Hệ thống phát hiện / ngăn chặn xâm nhập. |
| **IMDS** | Instance Metadata Service | Endpoint metadata của máy ảo cloud (169.254.169.254); IMDSv2 chống SSRF. |
| **IOC / IOA** | Indicator of Compromise / of Attack | Dấu hiệu đã bị xâm nhập (hash, IP...) / dấu hiệu hành vi tấn công. |
| **ISMS** | Information Security Management System | Hệ thống quản lý an toàn thông tin (lõi của ISO 27001). |
| **ISN** | Initial Sequence Number | Số thứ tự khởi đầu trong TCP handshake. |
| **JWT** | JSON Web Token | Token tự chứa (header.payload.signature) dùng cho xác thực/ủy quyền. |
| **KMS** | Key Management Service | Dịch vụ quản lý khóa mã hóa (vd AWS KMS). |
| **Lateral movement** | — | Attacker di chuyển từ máy này sang máy khác trong mạng nội bộ. |
| **LOLBIN** | Living Off the Land Binary | Lạm dụng công cụ hợp lệ sẵn có của hệ thống để tấn công, né phát hiện. |
| **MFA** | Multi-Factor Authentication | Xác thực nhiều yếu tố (mật khẩu + OTP/khóa...). |
| **MITM** | Man-in-the-Middle | Tấn công chen giữa hai bên để nghe lén/sửa đổi traffic. |
| **MITRE ATT&CK** | — | Cơ sở tri thức về tactic/technique tấn công thực tế. |
| **MTTD / MTTR** | Mean Time To Detect / Respond | Thời gian trung bình để phát hiện / phản ứng sự cố. |
| **NACL** | Network Access Control List | Firewall **stateless** ở mức subnet trong AWS VPC. |
| **PKI** | Public Key Infrastructure | Hạ tầng khóa công khai (CA, certificate, chuỗi tin cậy). |
| **Persistence** | — | Kỹ thuật giúp attacker trụ lại sau khi máy khởi động lại. |
| **Privilege escalation** | — | Nâng quyền từ user thường lên quyền cao hơn (admin/root). |
| **RBAC** | Role-Based Access Control | Phân quyền theo vai trò. |
| **RCE** | Remote Code Execution | Thực thi mã từ xa — lớp lỗ hổng nghiêm trọng nhất. |
| **Residual risk** | — | Rủi ro tồn dư, phần còn lại sau khi đã áp dụng biện pháp xử lý. |
| **RTO / RPO** | Recovery Time / Point Objective | Mục tiêu thời gian khôi phục / mức dữ liệu tối đa chấp nhận mất. |
| **SAML** | Security Assertion Markup Language | Chuẩn SSO cho doanh nghiệp. |
| **SAST** | Static Application Security Testing | Quét bảo mật **mã nguồn tĩnh** (không chạy). |
| **SCA** | Software Composition Analysis | Quét thư viện/dependency tìm CVE. |
| **SIEM** | Security Information and Event Management | Thu thập & tương quan log toàn hệ thống để phát hiện. |
| **SOAR** | Security Orchestration, Automation and Response | Tự động hóa quy trình phản ứng sự cố (playbook). |
| **SOP** | Same-Origin Policy | Quy tắc trình duyệt cô lập tài nguyên giữa các origin khác nhau. |
| **SQLi** | SQL Injection | Chèn lệnh SQL qua input để thao túng truy vấn. |
| **SSRF** | Server-Side Request Forgery | Ép server gọi tới đích do attacker chỉ định (vd metadata cloud). |
| **SSO** | Single Sign-On | Đăng nhập một lần dùng cho nhiều dịch vụ. |
| **TTP** | Tactics, Techniques and Procedures | Cách thức hành động của attacker (theo MITRE ATT&CK). |
| **VPC** | Virtual Private Cloud | Mạng ảo riêng trong cloud. |
| **WAF** | Web Application Firewall | Tường lửa lọc HTTP ở tầng ứng dụng (chặn SQLi/XSS...). |
| **XDR** | Extended Detection and Response | Mở rộng EDR sang nhiều nguồn (mail, network, cloud). |
| **XSS** | Cross-Site Scripting | Chèn script chạy trong trình duyệt nạn nhân. |
| **Zero Trust** | — | "Never trust, always verify" — không tin tưởng mặc định theo vị trí mạng. |

> Glossary sẽ được bổ sung dần khi sổ tay mở rộng. Thiếu thuật ngữ nào hữu ích, bạn cứ mở Issue đề xuất.
