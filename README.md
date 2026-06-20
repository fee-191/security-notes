# Sổ tay An toàn thông tin

Blog chia sẻ kiến thức an toàn thông tin bằng tiếng Việt — những gì mình ghi chép, tổng hợp lại trong quá trình học và làm việc. Mỗi chương cố gắng giải thích kỹ cơ chế và kèm ví dụ thực tế (lệnh, cấu hình, code), ưu tiên hiểu *vì sao* hơn là học thuộc.

🔗 **Đọc online:** https://fee-191.github.io/security-notes/

> Mình không tự nhận là chuyên gia — đây là cách mình hệ thống lại kiến thức. Nếu có chỗ chưa chính xác, rất mong được góp ý qua Issues.

## Nội dung (17 chương)

| # | Chương | # | Chương |
|---|---|---|---|
| 01 | Mạng máy tính (TCP/IP, OSI) | 10 | Vận hành SOC & Ứng phó sự cố |
| 02 | Hệ điều hành Linux | 11 | IDS/IPS, WAF & Phòng thủ mạng |
| 03 | Windows & Active Directory | 12 | Kiểm thử & Quét lỗ hổng |
| 04 | Mật mã & Nền tảng bảo mật | 13 | Bảo mật Đám mây (AWS & GCP) |
| 05 | AppSec & OWASP Top 10 | 14 | Ảo hóa & Container |
| 06 | DevSecOps: Quét bảo mật & Semgrep | 15 | Threat Intel & MITRE ATT&CK |
| 07 | CI/CD & GitOps | 16 | Tuân thủ & Quản trị (GRC) |
| 08 | SIEM & Wazuh | 17 | Python cho An toàn thông tin |
| 09 | ELK Stack & Zabbix | | |

Nội dung gốc nằm ở các file `KB_*.md`. Trang web `index.html` được sinh tự động từ chúng.

## Tự dựng lại trang web

Sau khi sửa nội dung trong file `KB_*.md`:

```bash
pip install markdown
python3 build_blog.py   # sinh lại index.html
```

## Giấy phép

Nội dung chia sẻ tự do cho mục đích **học tập**, theo [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/deed.vi) — bạn được dùng/chia sẻ, vui lòng ghi nguồn.

> ⚠️ Nội dung mang tính giáo dục, nhằm mục đích **phòng thủ**. Mọi kỹ thuật tấn công trình bày ở đây chỉ để hiểu cách phòng chống — hãy thực hành hợp pháp, chỉ trên hệ thống bạn được phép.

---

✍️ **Lê Dương Phi** · [GitHub](https://github.com/fee-191) · [LinkedIn](https://linkedin.com/in/leduongphi191)
