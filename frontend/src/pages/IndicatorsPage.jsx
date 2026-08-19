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
} from "@mui/material";
import { api, buildQuery } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { StatusChip } from "../components/StatusChips";
import { ExternalTitleLink, resolveRecordHref } from "../components/ExternalTitleLink";

const IOC_TYPES = [
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "email",
  "md5",
  "sha1",
  "sha256",
  "cve",
  "filename",
  "other",
];

export default function IndicatorsPage() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [iocType, setIocType] = useState("");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    ioc_type: "domain",
    value: "",
    confidence: "medium",
    source: "manual",
  });
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const qs = buildQuery({
        search: search || undefined,
        ioc_type: iocType || undefined,
        page_size: 50,
        ordering: "-last_seen",
      });
      const data = await api.get(`/api/v1/indicators/${qs}`);
      setRows(data.results || []);
    } catch (err) {
      setError(err.message || "Failed to load indicators");
    } finally {
      setLoading(false);
    }
  }, [search, iocType]);

  useEffect(() => {
    load();
  }, [load]);

  async function createIndicator(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      await api.post("/api/v1/indicators/", form);
      setOpen(false);
      setForm({ ioc_type: "domain", value: "", confidence: "medium", source: "manual" });
      await load();
    } catch (err) {
      setError(err.message || "Create failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Indicators"
        subtitle="IOCs collected from feeds, stealer logs, and OSINT footprints."
        action={
          <Button variant="contained" onClick={() => setOpen(true)}>
            Add IOC
          </Button>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <TextField
          size="small"
          label="Search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          sx={{ minWidth: 220 }}
        />
        <TextField
          select
          size="small"
          label="Type"
          value={iocType}
          onChange={(e) => setIocType(e.target.value)}
          sx={{ minWidth: 160 }}
        >
          <MenuItem value="">All</MenuItem>
          {IOC_TYPES.map((t) => (
            <MenuItem key={t} value={t}>
              {t}
            </MenuItem>
          ))}
        </TextField>
        <Button variant="outlined" onClick={load}>
          Refresh
        </Button>
      </Stack>
      <DataTable
        loading={loading}
        rows={rows}
        columns={[
          { id: "ioc_type", label: "Type" },
          {
            id: "value",
            label: "Value",
            render: (row) => (
              <ExternalTitleLink title={row.value} href={resolveRecordHref(row)} />
            ),
          },
          {
            id: "confidence",
            label: "Confidence",
            render: (row) => <StatusChip value={row.confidence} />,
          },
          { id: "source", label: "Source" },
          {
            id: "is_active",
            label: "Active",
            render: (row) => (row.is_active ? "yes" : "no"),
          },
          {
            id: "last_seen",
            label: "Last seen",
            render: (row) =>
              row.last_seen ? new Date(row.last_seen).toLocaleString() : "—",
          },
        ]}
      />

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Add indicator</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }} component="form" id="ioc-form" onSubmit={createIndicator}>
            <TextField
              select
              label="Type"
              value={form.ioc_type}
              onChange={(e) => setForm((f) => ({ ...f, ioc_type: e.target.value }))}
              required
            >
              {IOC_TYPES.map((t) => (
                <MenuItem key={t} value={t}>
                  {t}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              label="Value"
              value={form.value}
              onChange={(e) => setForm((f) => ({ ...f, value: e.target.value }))}
              required
              fullWidth
            />
            <TextField
              select
              label="Confidence"
              value={form.confidence}
              onChange={(e) => setForm((f) => ({ ...f, confidence: e.target.value }))}
            >
              {["low", "medium", "high", "confirmed"].map((c) => (
                <MenuItem key={c} value={c}>
                  {c}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              label="Source"
              value={form.source}
              onChange={(e) => setForm((f) => ({ ...f, source: e.target.value }))}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button type="submit" form="ioc-form" variant="contained" disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
