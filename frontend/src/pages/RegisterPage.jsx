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
import { ApiError, registerAccount } from "../api/client";

function registrationError(error) {
  if (!(error instanceof ApiError)) return error?.message || "Không thể tạo tài khoản.";
  const payload = error.payload;
  if (payload && typeof payload === "object") {
    for (const key of ["username", "password", "password_confirm", "non_field_errors", "detail"]) {
      const value = payload[key];
      if (Array.isArray(value) && value.length) return String(value[0]);
      if (typeof value === "string" && value) return value;
    }
  }
  return error.message || "Không thể tạo tài khoản.";
}

export default function RegisterPage() {
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
      const data = await registerAccount(username.trim(), password, passwordConfirm);
      setSuccess(
        data?.detail ||
          "Yêu cầu tạo tài khoản đã được gửi và đang chờ quản trị viên phê duyệt."
      );
      setPassword("");
      setPasswordConfirm("");
    } catch (err) {
      setError(registrationError(err));
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
          <Typography variant="h5">Tạo tài khoản</Typography>
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
                label="Mật khẩu"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
                required
                fullWidth
              />
              <TextField
                label="Nhập lại mật khẩu"
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
                {busy ? "Đang gửi…" : "Gửi yêu cầu"}
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
