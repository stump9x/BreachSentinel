import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Chip,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api, buildQuery } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";

const STATUS_LABELS = {
  pending: "Chờ duyệt",
  approved: "Đã phê duyệt",
  rejected: "Đã từ chối",
  revoked: "Đã thu hồi",
};

const STATUS_COLORS = {
  pending: "warning",
  approved: "success",
  rejected: "error",
  revoked: "default",
};

const RESET_STATUS_LABELS = {
  pending: "Chờ duyệt",
  approved: "Đã duyệt",
  rejected: "Đã từ chối",
};

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "—";
}

export default function AccessManagementPage() {
  const [rows, setRows] = useState([]);
  const [filter, setFilter] = useState("pending");
  const [roles, setRoles] = useState({});
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [resetRows, setResetRows] = useState([]);
  const [resetFilter, setResetFilter] = useState("pending");
  const [resetLoading, setResetLoading] = useState(true);
  const [resetBusyId, setResetBusyId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const query = buildQuery({ status: filter || undefined });
      const data = await api.get(`/api/v1/admin/access-requests/${query}`);
      const nextRows = data.results || [];
      setRows(nextRows);
      setRoles((current) => {
        const next = { ...current };
        nextRows.forEach((row) => {
          if (!next[row.id]) next[row.id] = row.role || "analyst";
        });
        return next;
      });
    } catch (err) {
      setError(err.message || "Không thể tải danh sách tài khoản.");
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    load();
  }, [load]);

  const loadPasswordResets = useCallback(async () => {
    setResetLoading(true);
    setError("");
    try {
      const query = buildQuery({ status: resetFilter || undefined });
      const data = await api.get(`/api/v1/admin/password-reset-requests/${query}`);
      setResetRows(data.results || []);
    } catch (err) {
      setError(err.message || "Không thể tải yêu cầu đổi mật khẩu.");
    } finally {
      setResetLoading(false);
    }
  }, [resetFilter]);

  useEffect(() => {
    loadPasswordResets();
  }, [loadPasswordResets]);

  async function runAction(row, action) {
    if (
      (action === "reject" || action === "revoke") &&
      !window.confirm(
        action === "reject"
          ? `Từ chối yêu cầu của ${row.username}?`
          : `Thu hồi quyền truy cập của ${row.username}?`
      )
    ) {
      return;
    }
    setBusyId(row.id);
    setError("");
    setMessage("");
    try {
      const body = action === "approve" ? { role: roles[row.id] || "analyst" } : {};
      await api.post(`/api/v1/admin/access-requests/${row.id}/${action}/`, body);
      const actionLabel = {
        approve: row.status === "approved" ? "Đã cập nhật quyền" : "Đã phê duyệt",
        reject: "Đã từ chối",
        revoke: "Đã thu hồi quyền truy cập",
      };
      setMessage(`${actionLabel[action]} tài khoản ${row.username}.`);
      await load();
    } catch (err) {
      setError(err.message || "Không thể xử lý yêu cầu.");
    } finally {
      setBusyId(null);
    }
  }

  async function runPasswordResetAction(row, action) {
    if (
      !window.confirm(
        action === "approve"
          ? `Duyệt mật khẩu mới cho ${row.username}? Tất cả phiên đăng nhập cũ sẽ bị thu hồi.`
          : `Từ chối yêu cầu đổi mật khẩu của ${row.username}?`
      )
    ) {
      return;
    }
    setResetBusyId(row.id);
    setError("");
    setMessage("");
    try {
      await api.post(
        `/api/v1/admin/password-reset-requests/${row.id}/${action}/`,
        {}
      );
      setMessage(
        action === "approve"
          ? `Đã áp dụng mật khẩu mới cho ${row.username}.`
          : `Đã từ chối yêu cầu đổi mật khẩu của ${row.username}.`
      );
      await loadPasswordResets();
    } catch (err) {
      setError(err.message || "Không thể xử lý yêu cầu đổi mật khẩu.");
    } finally {
      setResetBusyId(null);
    }
  }

  const columns = useMemo(
    () => [
      { id: "username", label: "Tên đăng nhập" },
      {
        id: "status",
        label: "Trạng thái",
        render: (row) => (
          <Chip
            size="small"
            variant="outlined"
            color={STATUS_COLORS[row.status] || "default"}
            label={STATUS_LABELS[row.status] || row.status}
          />
        ),
      },
      {
        id: "requested_at",
        label: "Thời gian đăng ký",
        render: (row) => formatDate(row.requested_at),
      },
      {
        id: "role",
        label: "Quyền",
        render: (row) => (
          <TextField
            select
            size="small"
            value={roles[row.id] || row.role || "analyst"}
            onChange={(event) =>
              setRoles((current) => ({ ...current, [row.id]: event.target.value }))
            }
            disabled={busyId === row.id}
            sx={{ minWidth: 120 }}
          >
            <MenuItem value="analyst">Analyst</MenuItem>
            <MenuItem value="staff">Staff</MenuItem>
          </TextField>
        ),
      },
      {
        id: "review",
        label: "Người xử lý",
        render: (row) => (
          <Stack spacing={0.25}>
            <Typography variant="body2">{row.reviewed_by || "—"}</Typography>
            <Typography variant="caption" color="text.secondary">
              {formatDate(row.reviewed_at)}
            </Typography>
          </Stack>
        ),
      },
      {
        id: "actions",
        label: "Thao tác",
        nowrap: true,
        render: (row) => (
          <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap>
            {row.status !== "approved" ? (
              <Button
                size="small"
                variant="contained"
                disabled={busyId === row.id}
                onClick={() => runAction(row, "approve")}
              >
                Phê duyệt
              </Button>
            ) : (
              <Button
                size="small"
                variant="outlined"
                disabled={busyId === row.id || (roles[row.id] || row.role) === row.role}
                onClick={() => runAction(row, "approve")}
              >
                Cập nhật quyền
              </Button>
            )}
            {row.status === "pending" ? (
              <Button
                size="small"
                color="error"
                disabled={busyId === row.id}
                onClick={() => runAction(row, "reject")}
              >
                Từ chối
              </Button>
            ) : null}
            {row.status === "approved" ? (
              <Button
                size="small"
                color="error"
                disabled={busyId === row.id}
                onClick={() => runAction(row, "revoke")}
              >
                Thu hồi
              </Button>
            ) : null}
          </Stack>
        ),
      },
    ],
    [busyId, roles, filter]
  );

  const resetColumns = useMemo(
    () => [
      { id: "username", label: "Tên đăng nhập" },
      {
        id: "status",
        label: "Trạng thái",
        render: (row) => (
          <Chip
            size="small"
            variant="outlined"
            color={STATUS_COLORS[row.status] || "default"}
            label={RESET_STATUS_LABELS[row.status] || row.status}
          />
        ),
      },
      {
        id: "requested_at",
        label: "Thời gian yêu cầu",
        render: (row) => formatDate(row.requested_at),
      },
      {
        id: "review",
        label: "Người xử lý",
        render: (row) => (
          <Stack spacing={0.25}>
            <Typography variant="body2">{row.reviewed_by || "—"}</Typography>
            <Typography variant="caption" color="text.secondary">
              {formatDate(row.reviewed_at)}
            </Typography>
          </Stack>
        ),
      },
      {
        id: "actions",
        label: "Thao tác",
        nowrap: true,
        render: (row) =>
          row.status === "pending" ? (
            <Stack direction="row" spacing={0.75}>
              <Button
                size="small"
                variant="contained"
                disabled={resetBusyId === row.id}
                onClick={() => runPasswordResetAction(row, "approve")}
              >
                Duyệt mật khẩu mới
              </Button>
              <Button
                size="small"
                color="error"
                disabled={resetBusyId === row.id}
                onClick={() => runPasswordResetAction(row, "reject")}
              >
                Từ chối
              </Button>
            </Stack>
          ) : (
            "—"
          ),
      },
    ],
    [resetBusyId, resetFilter]
  );

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Quản lý truy cập"
        action={
          <Button
            variant="outlined"
            onClick={() => Promise.all([load(), loadPasswordResets()])}
            disabled={loading || resetLoading}
          >
            Làm mới
          </Button>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      {message ? <Alert severity="success">{message}</Alert> : null}
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
        <TextField
          select
          size="small"
          label="Trạng thái"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          sx={{ minWidth: 190 }}
        >
          <MenuItem value="">Tất cả</MenuItem>
          <MenuItem value="pending">Chờ duyệt</MenuItem>
          <MenuItem value="approved">Đã phê duyệt</MenuItem>
          <MenuItem value="rejected">Đã từ chối</MenuItem>
          <MenuItem value="revoked">Đã thu hồi</MenuItem>
        </TextField>
        <Typography variant="body2" color="text.secondary">
          {rows.length} tài khoản
        </Typography>
      </Stack>
      <DataTable
        loading={loading}
        rows={rows}
        columns={columns}
        empty="Không có tài khoản phù hợp."
      />
      <Typography variant="h6" sx={{ pt: 2 }}>
        Yêu cầu đổi mật khẩu
      </Typography>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems={{ sm: "center" }}>
        <TextField
          select
          size="small"
          label="Trạng thái"
          value={resetFilter}
          onChange={(event) => setResetFilter(event.target.value)}
          sx={{ minWidth: 190 }}
        >
          <MenuItem value="">Tất cả</MenuItem>
          <MenuItem value="pending">Chờ duyệt</MenuItem>
          <MenuItem value="approved">Đã duyệt</MenuItem>
          <MenuItem value="rejected">Đã từ chối</MenuItem>
        </TextField>
        <Typography variant="body2" color="text.secondary">
          {resetRows.length} yêu cầu
        </Typography>
      </Stack>
      <DataTable
        loading={resetLoading}
        rows={resetRows}
        columns={resetColumns}
        empty="Không có yêu cầu đổi mật khẩu phù hợp."
      />
    </Stack>
  );
}
