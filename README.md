# LogHandbook

Sổ tra cứu log bảo mật song ngữ (VI/EN) cho threat hunter — tra nhanh một log mới có thể là event gì, field nào nghĩa là gì, severity và ATT&CK ID tương ứng.

**Live:** https://liuchijang.github.io/LogHandbook/

276 entry trên 6 nhóm nguồn log: Windows, Linux, Access log, Kubernetes, vCenter, ESXi. Mỗi entry gồm: mô tả, field cần biết, mẫu log, lệnh tra cứu, nguồn tham khảo và link ATT&CK (nếu có).

## Cấu trúc

- `Log_handbook.html` — giao diện + logic (search, filter, sidebar, VI/EN switch)
- `data.js` — toàn bộ dữ liệu (nguồn log, entry VI/EN) — sửa file này khi thêm/sửa entry
- `validate.js` — kiểm tra trùng ID, severity/ATT&CK ID sai định dạng, thiếu bản dịch EN (kể cả sót tiếng Việt trong field `en`)
- `.github/workflows/` — CI validate trên mỗi push/PR, deploy lên GitHub Pages khi vào `main`

## Thêm/sửa entry

Sửa trực tiếp trong `data.js`, sau đó chạy:

```
npm run validate
```

Chỉ merge khi lệnh trên pass. CI sẽ tự chạy lại kiểm tra này trên mỗi PR.

## License

MIT — xem [LICENSE](LICENSE).
