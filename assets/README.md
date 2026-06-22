# assets

## Đổi ảnh nền cho mode Wibu 🌸

Nền mode Wibu trỏ cố định tới file **`assets/wibu-bg.jpg`**.

**Để đổi nền:** thay file `wibu-bg.jpg` trong thư mục này bằng ảnh của bạn (giữ đúng tên `wibu-bg.jpg`), rồi:

```bash
git add assets/wibu-bg.jpg && git commit -m "chore: update wibu background" && git push
```

Vậy là xong — **không cần rebuild, không cần sửa code**. Vài giây sau khi GitHub Pages cập nhật là nền mới hiện (nhớ Ctrl+F5 để bỏ cache trình duyệt).

Không có file `wibu-bg.jpg` thì mode Wibu tự dùng **nền gradient tím–hồng mặc định**.

**Mẹo:** ảnh ngang, độ phân giải cao (1920×1080+), tông hơi tối để chữ trên panel kính mờ dễ đọc. Đặt tên đúng `wibu-bg.jpg` (định dạng JPG).
