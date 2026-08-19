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
  Switch,
  FormControlLabel,
  TextField,
  Typography,
} from "@mui/material";
import { api } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";

const EMPTY = {
  name: "",
  url: "",
  category: "news",
  confidence: 2,
  country: "",
  country_code: "",
  is_active: true,
  notes: "",
};

export default function FeedSourcesPage() {
  const [rows, setRows] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(EMPTY);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      // Pull full Watcher-scale catalog (API max_page_size=500)
      const data = await api.get(
        "/api/v1/feed-sources/?page_size=500&ordering=confidence,name"
      );
      setRows(data.results || []);
      setTotalCount(data.count ?? (data.results || []).length);
    } catch (err) {
      setError(err.message || "Failed to load feed sources");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function createSource(event) {
    event.preventDefault();
    setError("");
    try {
      await api.post("/api/v1/feed-sources/", {
        ...form,
        confidence: Number(form.confidence) || 2,
      });
      setOpen(false);
      setForm(EMPTY);
      setMsg("RSS source added — next sweep will include it");
      await load();
    } catch (err) {
      setError(err.message || "Create failed");
    }
  }

  async function toggleActive(row) {
    try {
      await api.patch(`/api/v1/feed-sources/${row.id}/`, { is_active: !row.is_active });
      await load();
    } catch (err) {
      setError(err.message || "Update failed");
    }
  }

  async function queueIngest() {
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const data = await api.post("/api/v1/workers/ingest-feeds/", {
        feeds: ["cert"],
        limit: 30,
        async_mode: true,
      });
      setMsg(`RSS ingest queued: ${JSON.stringify(data.tasks || {})}`);
    } catch (err) {
      setError(err.message || "Ingest failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack spacing={2}>
      <PageHeader
        title="RSS Sources"
        subtitle="Watcher-style CERT / breach / news feeds. Add more anytime — Celery sweeps active sources every 5 minutes."
        action={
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" disabled={busy} onClick={queueIngest}>
              Sweep now
            </Button>
            <Button variant="contained" onClick={() => setOpen(true)}>
              Add source
            </Button>
          </Stack>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      {msg ? (
        <Alert severity="success" onClose={() => setMsg("")}>
          {msg}
        </Alert>
      ) : null}

      <Typography variant="body2" color="text.secondary">
        Active: {rows.filter((r) => r.is_active).length} / {totalCount || rows.length} · Full
        Watcher sources.csv (~220) + CERT/breach extras. Feeds that fail a sweep auto-disable;
        staff can re-enable after fixing the URL.
      </Typography>

      <DataTable
        loading={loading}
        rows={rows}
        columns={[
          { id: "name", label: "Name" },
          {
            id: "url",
            label: "URL",
            render: (row) => (
              <Typography
                component="a"
                href={row.url}
                target="_blank"
                rel="noopener noreferrer"
                variant="body2"
                sx={{ color: "primary.main", wordBreak: "break-all" }}
              >
                {row.url}
              </Typography>
            ),
          },
          { id: "category", label: "Category" },
          { id: "confidence", label: "Conf." },
          { id: "country_code", label: "CC" },
          {
            id: "last_status",
            label: "Last",
            render: (row) =>
              row.last_status
                ? `${row.last_status}${row.last_item_count ? ` (${row.last_item_count})` : ""}`
                : "—",
          },
          {
            id: "is_active",
            label: "Active",
            render: (row) => (
              <Switch
                size="small"
                checked={!!row.is_active}
                onChange={() => toggleActive(row)}
              />
            ),
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <form onSubmit={createSource}>
          <DialogTitle>Add RSS / Atom source</DialogTitle>
          <DialogContent>
            <Stack spacing={2} sx={{ mt: 1 }}>
              <TextField
                label="Name"
                required
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              />
              <TextField
                label="Feed URL"
                required
                value={form.url}
                onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
              />
              <TextField
                select
                label="Category"
                value={form.category}
                onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}
              >
                {["cert", "breach", "news", "ransomware", "other"].map((c) => (
                  <MenuItem key={c} value={c}>
                    {c}
                  </MenuItem>
                ))}
              </TextField>
              <TextField
                type="number"
                label="Confidence (1–5)"
                value={form.confidence}
                onChange={(e) => setForm((f) => ({ ...f, confidence: e.target.value }))}
                inputProps={{ min: 1, max: 5 }}
              />
              <TextField
                label="Country code"
                value={form.country_code}
                onChange={(e) => setForm((f) => ({ ...f, country_code: e.target.value }))}
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={form.is_active}
                    onChange={(e) => setForm((f) => ({ ...f, is_active: e.target.checked }))}
                  />
                }
                label="Active"
              />
            </Stack>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button type="submit" variant="contained">
              Save
            </Button>
          </DialogActions>
        </form>
      </Dialog>
    </Stack>
  );
}
