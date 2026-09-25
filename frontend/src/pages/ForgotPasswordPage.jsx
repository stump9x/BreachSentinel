import { useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Container,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import { ApiError, requestPasswordReset } from "../api/client";

function resetError(error) {
  if (!(error instanceof ApiError)) {
    return error?.message || "Không thể gửi yêu cầu đổi mật khẩu.";
  }
  const payload = error.payload;
  if (payload && typeof payload === "object") {
    for (const key of ["password", "password_confirm", "username", "detail"]) {
      const value = payload[key];
      if (Array.isArray(value) && value.length) return String(value[0]);
      if (typeof value === "string" && value) return value;
    }
  }
  return error.message || "Không thể gửi yêu cầu đổi mật khẩu.";
}

export default function ForgotPasswordPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    setError("");
    setSuccess("");
    if (password !== passwordConfirm) {
      setError("Mật khẩu nhập lại không khớp.");
      return;
    }
    setBusy(true);
    try {
      const data = await requestPasswordReset(
        username.trim(),
        password,
        passwordConfirm
      );
      setSuccess(data?.detail || "Yêu cầu đổi mật khẩu đã được gửi.");
      setPassword("");
      setPasswordConfirm("");
    } catch (err) {
      setError(resetError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box sx={{ minHeight: "100vh", display: "flex", alignItems: "center", py: 6 }}>
      <Container maxWidth="sm">
        <Stack spacing={3} component="form" onSubmit={onSubmit}>
          <Stack direction="row" spacing={1.5} alignItems="center">
            <ShieldOutlinedIcon sx={{ color: "primary.main", fontSize: 42 }} />
            <Typography variant="h3" sx={{ color: "primary.main" }}>
              TS DLLL
            </Typography>
          </Stack>
          <Typography variant="h5">Quên mật khẩu</Typography>
          <Typography color="text.secondary">
            Nhập mật khẩu mới. Mật khẩu chỉ có hiệu lực sau khi quản trị viên xác minh và phê duyệt.
          </Typography>
          {error ? <Alert severity="error">{error}</Alert> : null}
          {success ? <Alert severity="success">{success}</Alert> : null}
          {!success ? (
            <>
              <TextField
                label="Tên đăng nhập"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                required
                fullWidth
              />
              <TextField
                label="Mật khẩu mới"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
                required
                fullWidth
              />
              <TextField
                label="Nhập lại mật khẩu mới"
                type="password"
                value={passwordConfirm}
                onChange={(event) => setPasswordConfirm(event.target.value)}
                autoComplete="new-password"
                required
                fullWidth
              />
              <Button
                type="submit"
                variant="contained"
                disabled={busy || !username.trim() || !password || !passwordConfirm}
              >
                {busy ? "Đang gửi…" : "Gửi yêu cầu đổi mật khẩu"}
              </Button>
            </>
          ) : null}
          <Button component={RouterLink} to="/login" variant="outlined">
            Quay lại đăng nhập
          </Button>
        </Stack>
      </Container>
    </Box>
  );
}
