import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { StatusChip } from "../components/StatusChips";

export default function WatchRulesPage() {
  const [rules, setRules] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: "",
    keyword: "",
    target: "all",
    min_severity: "info",
    is_active: true,
  });

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [r, n] = await Promise.all([
        api.get("/api/v1/watch-rules/?page_size=100"),
        api.get("/api/v1/notifications/?page_size=50&ordering=-created_at"),
      ]);
      setRules(r.results || []);
      setAlerts(n.results || []);
    } catch (err) {
      setError(err.message || "Failed to load watch rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function createRule(event) {
    event.preventDefault();
    setError("");
    try {
      await api.post("/api/v1/watch-rules/", form);
      setOpen(false);
      setForm({
        name: "",
        keyword: "",
        target: "all",
        min_severity: "info",
        is_active: true,
      });
      setMsg("Watch rule created");
      await load();
    } catch (err) {
      setError(err.message || "Create failed");
    }
  }

  async function markRead(id) {
    try {
      await api.patch(`/api/v1/notifications/${id}/`, { is_read: true });
      await load();
    } catch (err) {
      setError(err.message || "Update failed");
    }
  }

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Watch Rules"
        subtitle="Keyword alerts across The Wire, leaks, and indicators. Target 'searx' or 'leaks' also drives periodic SearxNG metasearch (GitHub/GitLab/…)."
        action={
          <Stack direction="row" spacing={1}>
            <Button
              variant="outlined"
              onClick={async () => {
                setError("");
                try {
                  const data = await api.post("/api/v1/searx/scan/", {
                    async_mode: true,
                    limit_per_keyword: 15,
                  });
                  setMsg(`Searx sweep queued: ${data.task_id || "ok"}`);
                } catch (err) {
                  setError(err.message || "Searx scan failed");
                }
              }}
            >
              Sweep Searx now
            </Button>
            <Button variant="contained" onClick={() => setOpen(true)}>
              Add rule
            </Button>
          </Stack>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      {msg ? <Alert severity="success" onClose={() => setMsg("")}>{msg}</Alert> : null}

      <Typography variant="h6">Active rules</Typography>
      <DataTable
        loading={loading}
        rows={rules}
        columns={[
          { id: "name", label: "Name" },
          { id: "keyword", label: "Keyword" },
          { id: "target", label: "Target" },
          { id: "min_severity", label: "Min severity" },
          {
            id: "is_active",
            label: "Active",
            render: (row) => (row.is_active ? "yes" : "no"),
          },
        ]}
      />

      <Typography variant="h6" sx={{ pt: 1 }}>
        Alerts
      </Typography>
      <DataTable
        loading={loading}
        rows={alerts}
        empty="No watch hits yet — ingest feeds or wait for matching intel."
        columns={[
          { id: "title", label: "Title" },
          { id: "message", label: "Message" },
          {
            id: "severity",
            label: "Severity",
            render: (row) => <StatusChip value={row.severity} />,
          },
          {
            id: "is_read",
            label: "Read",
            render: (row) =>
              row.is_read ? (
                "yes"
              ) : (
                <Button size="small" onClick={() => markRead(row.id)}>
                  Mark read
                </Button>
              ),
          },
          {
            id: "created_at",
            label: "When",
            render: (row) =>
              row.created_at ? new Date(row.created_at).toLocaleString() : "—",
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>New watch rule</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }} component="form" id="rule-form" onSubmit={createRule}>
            <TextField
              label="Name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              required
              fullWidth
            />
            <TextField
              label="Keyword"
              value={form.keyword}
              onChange={(e) => setForm((f) => ({ ...f, keyword: e.target.value }))}
              required
              helperText="For target searx/leaks: SearxNG quotes simple keywords; domain@email-style strings stay unquoted"
              fullWidth
            />
            <TextField
              select
              label="Target"
              value={form.target}
              onChange={(e) => setForm((f) => ({ ...f, target: e.target.value }))}
            >
              {["all", "threats", "leaks", "searx", "indicators"].map((t) => (
                <MenuItem key={t} value={t}>
                  {t}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              select
              label="Min severity"
              value={form.min_severity}
              onChange={(e) => setForm((f) => ({ ...f, min_severity: e.target.value }))}
            >
              {["info", "low", "medium", "high", "critical"].map((s) => (
                <MenuItem key={s} value={s}>
                  {s}
                </MenuItem>
              ))}
            </TextField>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button type="submit" form="rule-form" variant="contained">
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
