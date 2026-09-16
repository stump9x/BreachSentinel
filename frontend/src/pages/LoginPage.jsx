import { useState } from "react";
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
import { Link as RouterLink } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export default function LoginPage() {
  const { login, error, clearError } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(event) {
    event.preventDefault();
    setBusy(true);
    clearError();
    try {
      await login(username.trim(), password);
    } catch {
      // error surfaced via context
    } finally {
      setBusy(false);
      setPassword("");
    }
  }

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        py: 6,
      }}
    >
      <Container maxWidth="sm">
        <Stack spacing={3} component="form" onSubmit={onSubmit}>
          <Stack direction="row" spacing={1.5} alignItems="center">
            <ShieldOutlinedIcon sx={{ color: "primary.main", fontSize: 42 }} />
            <Typography variant="h3" sx={{ color: "primary.main" }}>
              TS DLLL
            </Typography>
          </Stack>
          {error ? <Alert severity="error">{error}</Alert> : null}
          <TextField
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            fullWidth
          />
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            fullWidth
          />
          <Button type="submit" variant="contained" disabled={busy || !username || !password}>
            {busy ? "Authenticating…" : "Enter console"}
          </Button>
          <Button component={RouterLink} to="/register" variant="outlined">
            Tạo tài khoản
          </Button>
        </Stack>
      </Container>
    </Box>
  );
}
