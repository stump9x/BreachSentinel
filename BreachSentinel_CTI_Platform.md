# BreachSentinel: Nền tảng Threat Intelligence & Cảnh báo Dữ liệu Lộ lọt Tích hợp AI

**BreachSentinel** là một nền tảng Threat Intelligence hiện đại, mã nguồn mở, được xây dựng trên kiến trúc **Django (Backend), React JS (Frontend) và Go (Microservices)**. Nền tảng được thiết kế đặc biệt cho các đội ngũ phòng thủ không gian mạng (Blue Team) và chuyên gia phân tích tình báo, tập trung mạnh mẽ vào việc **phân tích logs tài khoản lộ lọt, giám sát dữ liệu rò rỉ (data leak/breaches), trinh sát OSINT và thu thập tin tức tình báo từ các mạng xã hội (đặc biệt là X) và dark web**.

Lấy cảm hứng từ các dự án hàng đầu như *Watcher*, *BlueTeam* và *GoSearch*, BreachSentinel kết hợp sức mạnh của AI với tốc độ trinh sát thời gian thực.

---

## 🚀 Tính năng Cốt lõi (Core Capabilities)

### 1. Giám sát & Phân tích Dữ liệu Lộ lọt (Data Leak & Account Breach Analysis)
- **Truy vết Logs Tài khoản (Compromised Credentials):** Tự động phân tích và trích xuất thông tin từ các tập dữ liệu logs lộ lọt (Infostealer malware logs như RedLine, Raccoon, Vidar).
- **Tích hợp Breach Intelligence:** Hỗ trợ tra cứu tức thì thông qua các API hàng đầu như **Hudson Rock, ProxyNova, BreachDirectory** (yêu cầu API Keys) để xác định xem tài khoản nội bộ có nằm trong các đợt rò rỉ dữ liệu hay không.
- **Giám sát Rò rỉ Thông tin (Information Leak Monitoring):** Liên tục rà quét mã nguồn, API keys, và thông tin mật bị lộ trên Pastebin, StackOverflow, GitHub, GitLab, Bitbucket, APKMirror, và các npm registries.

### 2. Trinh sát OSINT & Nguồn tin Mở (Reconnaissance & Open Web Intel)
- **Giám sát Mạng xã hội & X (Twitter) Intelligence:** Tự động thu thập, phân tích và trích xuất các dấu hiệu thỏa hiệp (IOCs) từ các bài đăng trên X của các nhà nghiên cứu bảo mật, các kênh Telegram và diễn đàn ngầm.
- **Tìm kiếm Dấu chân Số (Digital Footprint):** Tích hợp engine trinh sát bằng Go siêu tốc (tương tự *Sherlock/GoSearch*), cho phép tìm kiếm đồng thời username/hồ sơ cá nhân trên hơn **300+ trang web** và dịch vụ trực tuyến để dựng profile của các tác nhân đe dọa (Threat Actors).

### 3. AI-Driven Threat Intelligence (Tình báo Dữ liệu hỗ trợ bởi AI)
- **Báo cáo Tóm tắt Tự động (AI Briefings):** Sử dụng các mô hình AI (như Anthropic API hoặc Hugging Face `google/flan-t5-base`) để tạo các báo cáo đánh giá mối đe dọa hàng ngày dành cho cấp lãnh đạo và chuyên viên phân tích.
- **Phân tích Cảnh báo Thông minh (The Wire):** Gắn thẻ (tagging) tự động các thông tin tình báo với điểm số dựa trên bằng chứng (evidence-based scoring), ánh xạ KEV (Known Exploited Vulnerabilities), điểm CVSS, EPSS và quy kết nhóm tấn công.
- **Trích xuất Thực thể tự động:** Sử dụng `dslim/bert-base-NER` để tự động nhận dạng và trích xuất IP, Domain, Hash, CVE từ các văn bản tình báo thô.

### 4. Giám sát Hạ tầng & Tên miền Đáng ngờ (Domain Surveillance)
- **Phát hiện Tên miền Lừa đảo (Typosquatting & Homograph):** Tích hợp engine `dnstwist` để phát hiện các tên miền nhái theo tổ chức của bạn.
- **Giám sát Certificate Transparency:** Sử dụng `certstream` để tóm gọn các tên miền độc hại mới đăng ký theo thời gian thực.
- **Giám sát Mã băm TLSH:** Sử dụng TLSH fuzzy hashing để phát hiện sự thay đổi nội dung trên các tên miền theo dõi.

### 5. Cập nhật Tin tức Hiện trạng (Situational Awareness)
- **The Wall:** Bảng điều khiển thụ động mang lại cái nhìn tổng quan theo thời gian thực về các chiến dịch Ransomware (tích hợp `ransomware.live`, `ransomlook.io`), CVE mới (từ `cve.circl.lu`) và tin tức bảo mật từ CERT-FR, CERT-EU, US-CERT.

---

## ⚙️ Kiến trúc & Công nghệ (Under the Hood)

BreachSentinel được xây dựng với sự tối ưu hóa cao về hiệu suất và tính riêng tư:
- **Backend & Quản trị:** Django & Django REST Framework. Không thu thập Telemetry, mọi dữ liệu lưu trữ cục bộ (SQLite / PostgreSQL) đảm bảo an toàn cho các hoạt động phòng thủ OPSEC.
- **Frontend & Trực quan hóa:** React JS, Material UI (MUI) cho các bảng biểu KPI, và `deck.gl` để vẽ bản đồ nhiệt không gian mạng (WorldMap).
- **Engine Tìm kiếm & Trinh sát:** Go (Golang) cho khả năng xử lý concurrency đa luồng cực nhanh khi quét 300+ websites.
- **Authentication:** Hỗ trợ SSO / OpenID Connect linh hoạt qua `mozilla-django-oidc`, LDAP, Local Auth.
- **Tích hợp Tình báo:**
  - **TheHive & MISP:** Đồng bộ hóa hai chiều tự động, quản lý case thông minh và xuất/nhập IOCs.
  - **SearxNG:** Tích hợp công cụ tìm kiếm metasearch tôn trọng quyền riêng tư.

---

## 🛠 Hướng dẫn Triển khai Nhanh (Quick Deployment)

Hệ thống có thể được triển khai dễ dàng thông qua Docker:

```bash
# 1. Clone kho lưu trữ
git clone https://github.com/your-org/BreachSentinel.git
cd BreachSentinel

# 2. Cấu hình biến môi trường (API Keys cho AI, Hudson Rock, v.v.)
cp .env.example .env

# 3. Khởi chạy bằng Docker Compose
docker-compose up -d --build
```

Sau khi khởi chạy, truy cập bảng điều khiển quản trị tại `http://localhost:8000`. API Documentation (Swagger UI) có sẵn tại `/api/docs/`.
