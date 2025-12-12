# API Keys Configuration Guide

## Multiple API Keys Support

Hệ thống hiện hỗ trợ sử dụng nhiều API keys để tăng tốc độ và phân tán tải (load balancing).

## Cấu hình Etherscan API Keys

Thêm vào file `.env` trong thư mục `scamradar/backend/`:

```env
# Option 1: Sử dụng nhiều keys (khuyến nghị)
ETHERSCAN_KEYS=ZJYVMX6ET1YKH7SPUPTQAU4H85FQPX8AJI,2CYN72Y2EGPY32BA4CRE267U2J4EKJ8YZ1

# Hoặc Option 2: Sử dụng 1 key
ETHERSCAN_API_KEY=ZJYVMX6ET1YKH7SPUPTQAU4H85FQPX8AJI
```

**Lưu ý:** Khi có nhiều keys, hệ thống sẽ tự động phân tán requests giữa các keys khi gọi song song (parallel calls).

## Cấu hình Rarible API Keys

Thêm vào file `.env`:

```env
# Option 1: Sử dụng nhiều keys (khuyến nghị)
RARIBLE_API_KEYS=03f76e77-b405-4029-a8f7-0ff78d16a49f,272de419-da98-42df-9a13-392bdc064d68

# Hoặc Option 2: Sử dụng 1 key
RARIBLE_API_KEY=03f76e77-b405-4029-a8f7-0ff78d16a49f
```

## Cách hoạt động

### Etherscan
- Khi gọi song song 3 loại transactions (ERC20, ERC721, ERC1155), mỗi loại sẽ tự động sử dụng một API key khác nhau
- Round-robin: các requests tiếp theo sẽ luân phiên giữa các keys

### Rarible
- Khi gọi song song nhiều collections, các collections sẽ được phân tán đều giữa các API keys
- Ví dụ: 10 collections với 2 keys → 5 collections/key

## Lợi ích

1. **Tăng tốc độ**: Giảm rate limiting, tăng throughput
2. **Phân tán tải**: Tránh quá tải một API key
3. **Tăng độ tin cậy**: Nếu một key bị lỗi, các key khác vẫn hoạt động

## Kiểm tra cấu hình

Sau khi cập nhật `.env`, khởi động lại backend server để áp dụng thay đổi:

```bash
# Nếu đang chạy, dừng và khởi động lại
cd scamradar/backend
python -m uvicorn app.main:app --reload
```

