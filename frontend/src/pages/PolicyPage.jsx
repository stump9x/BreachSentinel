import { Alert, Chip, Divider, Stack, Typography } from "@mui/material";
import { PageHeader } from "../components/PageHeader";

export default function PolicyPage() {
  return (
    <Stack spacing={2}>
      <PageHeader
        title="Chính sách"
      />

      <Alert severity="info">
        The Wire chỉ lưu các bài viết và metadata công khai để phân tích; không đăng nhập,
        vượt quyền truy cập hay thu thập nội dung riêng tư.
      </Alert>

      <Stack spacing={1.25} divider={<Divider flexItem />}>
        <Stack spacing={0.5}>
          <Typography variant="subtitle1">Nguồn thu thập</Typography>
          <Typography variant="body2" color="text.secondary">
            RSS/Atom từ các nguồn đã cấu hình là luồng chính. Ngoài ra hệ thống nhận dữ liệu
            CERT/CVE, ransomware, nguồn claim công khai và archive defacement; Exa, Searx và
            các tài khoản X đã chọn chỉ đóng vai trò bổ sung khi được cấu hình.
          </Typography>
        </Stack>

        <Stack spacing={0.75}>
          <Typography variant="subtitle1">Lịch cập nhật hiện tại</Typography>
          <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
            <Chip size="small" label="RSS: mỗi 6 phút" />
            <Chip size="small" label="X: mỗi 15 phút" />
            <Chip size="small" label="Searx sites: mỗi 30 phút" />
            <Chip size="small" label="Claim/forum: mỗi 30 phút" />
            <Chip size="small" label="Exa: mỗi 60 phút" />
          </Stack>
          <Typography variant="body2" color="text.secondary">
            CVE chạy theo giờ, ransomware mỗi 30 phút. Các tác vụ có khóa chống chạy chồng;
            nguồn lỗi lặp lại sẽ bị đánh dấu hoặc tắt để bảo vệ worker.
          </Typography>
        </Stack>

        <Stack spacing={0.5}>
          <Typography variant="subtitle1">Lọc và chống trùng</Typography>
          <Typography variant="body2" color="text.secondary">
            Bài viết được chuẩn hóa URL, loại bản trùng, gắn nguồn/thể loại/mức độ ảnh hưởng và
            chỉ đưa vào The Wire khi đạt bộ lọc liên quan. Bài mới được ưu tiên; tin liên quan
            Việt Nam được giữ lâu hơn trong cửa sổ hiển thị.
          </Typography>
        </Stack>

        <Stack spacing={0.5}>
          <Typography variant="subtitle1">Dịch và lưu trữ</Typography>
          <Typography variant="body2" color="text.secondary">
            Tiêu đề và mô tả được dịch bất đồng bộ sau khi ingest. Nếu dịch không đạt chất
            lượng, giao diện giữ nguyên bản tiếng Anh. Housekeeping tự dọn dữ liệu quá hạn theo
            chính sách lưu trữ.
          </Typography>
        </Stack>
      </Stack>
    </Stack>
  );
}
