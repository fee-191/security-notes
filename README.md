# Sổ tay An toàn thông tin

Chỗ này là nơi mình gom lại những thứ học được về an toàn thông tin trong lúc tự học và đi làm.

Lúc đầu mình viết chỉ để tự ôn cho khỏi quên — viết kỹ một chút để sau này đọc lại vẫn hiểu được mình từng hiểu cái gì. Gom mãi thành ra cũng nhiều, nên mình để công khai luôn, biết đâu giúp được ai đó đang học giống mình hồi mới bắt đầu.

Cách mình viết: cố gắng nói **"cái này là gì, sinh ra để giải quyết vấn đề gì"** trước, rồi mới đào vào chi tiết kỹ thuật (cấu trúc, cơ chế bên trong, ví dụ lệnh/cấu hình/code). Mình không thích kiểu học thuộc định nghĩa mà không hiểu bản chất.

**Đọc bản web cho dễ nhìn:** https://fee-191.github.io/security-notes/

> Thấy chỗ nào chưa chuẩn hoặc còn thiếu thì bạn cứ mở Issue cho mình biết nhé, cảm ơn nhiều.

## Có gì trong này

17 chương, đi từ nền tảng rồi tới từng mảng:

Mạng (TCP/IP, OSI) · Linux · Windows & Active Directory · Mật mã · AppSec (OWASP) · DevSecOps & Quét mã nguồn · CI/CD & GitOps · SIEM & Quản lý log · Observability & Giám sát hạ tầng · SOC & Ứng phó sự cố · Phòng thủ mạng (IDS/IPS, WAF, Firewall, VPN) · Kiểm thử & Đánh giá lỗ hổng · Bảo mật Đám mây · Ảo hóa & Container · Threat Intel & Khung tấn công · Tuân thủ/GRC · Lập trình & Tự động hóa cho bảo mật.

Còn mấy mảng mình chưa làm qua (forensics, red team, bảo mật Web3, AI/LLM...) — khi nào tìm hiểu kỹ mình sẽ bổ sung thêm.

## Cấu trúc

Nội dung gốc nằm ở các file `KB_*.md`. Trang web `index.html` được sinh ra từ chúng — sửa file `.md` xong thì chạy lại:

```bash
pip install markdown
python3 build_blog.py
```

## Giấy phép

Chia sẻ tự do cho việc học (CC BY 4.0) — dùng và chia sẻ lại thoải mái, ghi nguồn giúp mình là được. Mọi nội dung ở đây nhằm mục đích học tập và phòng thủ; đừng dùng vào việc phạm pháp.

— Fee · [GitHub](https://github.com/fee-191) · [LinkedIn](https://linkedin.com/in/leduongphi191)
