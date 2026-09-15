import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  IconButton,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import PolicyOutlinedIcon from "@mui/icons-material/PolicyOutlined";
import { api } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { StatusChip } from "../components/StatusChips";

const ACTIVE = new Set(["queued", "running"]);
const PRESETS = [
  ["threat_intel", "Threat intelligence"],
  ["ransomware_malware", "Ransomware / malware"],
  ["personal_identity", "Identity exposure"],
  ["corporate_espionage", "Corporate exposure"],
];

function copyText(value) {
  navigator.clipboard?.writeText(String(value || "")).catch(() => {});
}

export default function DarkWebInvestigationsPage() {
  const [query, setQuery] = useState("");
  const [preset, setPreset] = useState("threat_intel");
  const [maxPages, setMaxPages] = useState(5);
  const [history, setHistory] = useState([]);
  const [selected, setSelected] = useState(null);
  const [sources, setSources] = useState([]);
  const [messages, setMessages] = useState([]);
  const [question, setQuestion] = useState("");
  const [health, setHealth] = useState(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const loadHistory = useCallback(async () => {
    const data = await api.get(
      "/api/v1/darkweb/investigations/?page_size=20&ordering=-created_at"
    );
    const rows = data.results || data || [];
    setHistory(rows);
    setSelected((current) => {
      if (!current) return rows[0] || null;
      return rows.find((row) => row.id === current.id) || rows[0] || null;
    });
    return rows;
  }, []);

  const loadDetails = useCallback(async (id) => {
    if (!id) {
      setSources([]);
      setMessages([]);
      return;
    }
    const [sourceData, messageData] = await Promise.all([
      api.get(`/api/v1/darkweb/investigations/${id}/sources/?page_size=60`),
      api.get(`/api/v1/darkweb/investigations/${id}/messages/`),
    ]);
    setSources(sourceData.results || sourceData || []);
    setMessages(messageData.results || messageData || []);
  }, []);

  useEffect(() => {
    loadHistory().catch((err) => setError(err.message || "Failed to load investigations"));
  }, [loadHistory]);

  useEffect(() => {
    loadDetails(selected?.id).catch((err) => setError(err.message || "Failed to load evidence"));
  }, [loadDetails, selected?.id, selected?.source_count, selected?.scraped_count]);

  useEffect(() => {
    if (!selected?.id || !ACTIVE.has(selected.status)) return undefined;
    let cancelled = false;
    let inFlight = false;
    async function poll() {
      if (cancelled || inFlight) return;
      inFlight = true;
      try {
        const current = await api.get(`/api/v1/darkweb/investigations/${selected.id}/`);
        if (cancelled) return;
        setSelected(current);
        setHistory((rows) => rows.map((row) => (row.id === current.id ? current : row)));
        if (!ACTIVE.has(current.status)) {
          await loadDetails(current.id);
          setNotice(`Investigation finished with status ${current.status}.`);
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to refresh investigation");
      } finally {
        inFlight = false;
      }
    }
    poll();
    const timer = window.setInterval(poll, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [loadDetails, selected?.id, selected?.status]);

  async function startInvestigation(event) {
    event.preventDefault();
    setBusy("start");
    setError("");
    setNotice("");
    try {
      const row = await api.post("/api/v1/darkweb/investigations/", {
        query: query.trim(),
        preset,
        max_results: 40,
        max_pages: Number(maxPages),
      });
      setSelected(row);
      setSources([]);
      setMessages([]);
      setNotice("Investigation queued. Evidence will appear after Tor collection completes.");
      await loadHistory();
    } catch (err) {
      setError(err.message || "Failed to start investigation");
    } finally {
      setBusy("");
    }
  }

  async function deleteInvestigation(row) {
    setBusy(`delete-${row.id}`);
    setError("");
    try {
      await api.delete(`/api/v1/darkweb/investigations/${row.id}/`);
      if (selected?.id === row.id) {
        setSelected(null);
        setSources([]);
        setMessages([]);
      }
      await loadHistory();
      setNotice("Investigation history deleted.");
    } catch (err) {
      setError(err.message || "Failed to delete investigation");
    } finally {
      setBusy("");
    }
  }

  async function checkHealth() {
    setBusy("health");
    setError("");
    try {
      setHealth(await api.get("/api/v1/darkweb/investigations/health/"));
    } catch (err) {
      setError(err.message || "Tor health check failed");
    } finally {
      setBusy("");
    }
  }

  async function sendFollowup(event) {
    event.preventDefault();
    setBusy("followup");
    setError("");
    try {
      await api.post(`/api/v1/darkweb/investigations/${selected.id}/followup/`, {
        question: question.trim(),
      });
      setQuestion("");
      const data = await api.get(`/api/v1/darkweb/investigations/${selected.id}/messages/`);
      setMessages(data.results || data || []);
    } catch (err) {
      setError(err.message || "Follow-up failed");
    } finally {
      setBusy("");
    }
  }

  const healthy = useMemo(
    () => Number(health?.healthy_probed || 0),
    [health]
  );

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Dark Web Investigations"
        subtitle="Thu thập có kiểm soát qua Tor và phân tích dựa trên bằng chứng."
        action={<PolicyOutlinedIcon color="primary" />}
      />
      <Alert severity="info">
        Defensive intelligence use only. The collector accepts analyst search terms, but fetches only validated v3 .onion links returned by configured search engines.
      </Alert>
      {error ? <Alert severity="error">{error}</Alert> : null}
      {notice ? <Alert severity="success">{notice}</Alert> : null}

      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Button variant="outlined" onClick={checkHealth} disabled={Boolean(busy)}>
          {busy === "health" ? "Checking Tor…" : "Check Tor & engines"}
        </Button>
        {health ? (
          <>
            <Chip
              size="small"
              color={health.enabled && health.tor_enabled ? "success" : "error"}
              label={`Tor: ${health.tor_enabled ? "enabled" : "disabled"}`}
            />
            <Chip
              size="small"
              color={healthy > 0 ? "success" : "warning"}
              label={`Healthy probes: ${healthy}/${health.engines?.length || 0}`}
            />
          </>
        ) : null}
      </Stack>

      <Stack direction={{ xs: "column", lg: "row" }} spacing={2} alignItems="flex-start">
        <Stack spacing={1.5} sx={{ width: { xs: "100%", lg: 360 }, flexShrink: 0 }}>
          <Stack component="form" onSubmit={startInvestigation} spacing={1.5}>
            <TextField
              label="Investigation query"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Actor, company, domain, leak or campaign"
              required
              multiline
              minRows={2}
              helperText="No URL is fetched directly from this field."
            />
            <TextField select label="Analysis preset" value={preset} onChange={(event) => setPreset(event.target.value)}>
              {PRESETS.map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
            </TextField>
            <TextField
              select
              label="Pages to collect"
              value={maxPages}
              onChange={(event) => setMaxPages(event.target.value)}
              helperText="Maximum readable onion pages; capped server-side."
            >
              {[3, 5, 8, 10].map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}
            </TextField>
            <Button type="submit" variant="contained" disabled={Boolean(busy) || query.trim().length < 2}>
              {busy === "start" ? "Queuing…" : "Run investigation"}
            </Button>
          </Stack>

          <Typography variant="h6">History</Typography>
          <DataTable
            rows={history}
            empty="No dark-web investigations yet."
            columns={[
              {
                id: "query",
                label: "Query",
                nowrap: false,
                render: (row) => (
                  <Button
                    size="small"
                    variant={selected?.id === row.id ? "contained" : "text"}
                    onClick={() => setSelected(row)}
                    sx={{ textAlign: "left", whiteSpace: "normal" }}
                  >
                    {row.query}
                  </Button>
                ),
              },
              { id: "status", label: "Status", render: (row) => <StatusChip value={row.status} /> },
              {
                id: "delete",
                label: "",
                render: (row) => (
                  <IconButton
                    size="small"
                    color="error"
                    disabled={ACTIVE.has(row.status) || Boolean(busy)}
                    onClick={() => deleteInvestigation(row)}
                    aria-label={`Delete ${row.query}`}
                  >
                    <DeleteOutlineIcon fontSize="small" />
                  </IconButton>
                ),
              },
            ]}
          />
        </Stack>

        <Stack spacing={2} sx={{ flex: 1, width: "100%", minWidth: 0 }}>
          {!selected ? (
            <Typography color="text.secondary">Start or select an investigation.</Typography>
          ) : (
            <>
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography variant="h6" sx={{ mr: 1 }}>{selected.query}</Typography>
                <StatusChip value={selected.status} />
                {ACTIVE.has(selected.status) ? <CircularProgress size={18} /> : null}
                <Chip size="small" label={`Found: ${selected.source_count || 0}`} />
                <Chip size="small" label={`Scraped: ${selected.scraped_count || 0}`} />
                {selected.provider ? <Chip size="small" variant="outlined" label={`Report: ${selected.provider}`} /> : null}
              </Stack>
              {selected.refined_query ? (
                <Typography variant="body2" color="text.secondary">
                  Search query: {selected.refined_query}
                </Typography>
              ) : null}
              {selected.error_message ? <Alert severity={selected.status === "failed" ? "error" : "warning"}>{selected.error_message}</Alert> : null}

              {(selected.pivots || []).length ? (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap alignItems="center">
                  <Typography variant="body2" color="text.secondary">Suggested pivots:</Typography>
                  {selected.pivots.map((value) => (
                    <Chip key={value} clickable label={value} onClick={() => setQuery(`${selected.query} ${value}`)} />
                  ))}
                </Stack>
              ) : null}

              <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 1.5, p: 2 }}>
                <Typography variant="subtitle1" sx={{ mb: 1 }}>Evidence-grounded report</Typography>
                <Typography component="pre" variant="body2" sx={{ whiteSpace: "pre-wrap", fontFamily: "inherit", m: 0 }}>
                  {selected.summary || (ACTIVE.has(selected.status) ? "Collecting evidence…" : "No report generated.")}
                </Typography>
              </Box>

              <Typography variant="h6">Sources</Typography>
              <DataTable
                rows={sources}
                empty={ACTIVE.has(selected.status) ? "Searching and collecting onion sources…" : "No sources collected."}
                columns={[
                  { id: "engine", label: "Engine" },
                  {
                    id: "title",
                    label: "Source",
                    nowrap: false,
                    render: (row) => (
                      <Stack spacing={0.25}>
                        <Typography variant="body2">{row.title}</Typography>
                        <Stack direction="row" spacing={0.5} alignItems="center">
                          <Typography variant="caption" color="text.secondary" sx={{ wordBreak: "break-all" }}>{row.url}</Typography>
                          <Tooltip title="Copy onion URL">
                            <IconButton size="small" onClick={() => copyText(row.url)}><ContentCopyOutlinedIcon fontSize="inherit" /></IconButton>
                          </Tooltip>
                        </Stack>
                      </Stack>
                    ),
                  },
                  { id: "fetch_status", label: "Fetch", render: (row) => <StatusChip value={row.fetch_status} /> },
                ]}
              />

              <Divider />
              <Typography variant="h6">Evidence follow-up</Typography>
              {messages.map((message) => (
                <Box key={message.id} sx={{ p: 1.5, borderRadius: 1, bgcolor: message.role === "user" ? "action.selected" : "action.hover" }}>
                  <Typography variant="caption" color="text.secondary">{message.role}</Typography>
                  <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>{message.content}</Typography>
                </Box>
              ))}
              <Stack component="form" onSubmit={sendFollowup} direction={{ xs: "column", sm: "row" }} spacing={1}>
                <TextField
                  fullWidth
                  label="Ask about collected evidence"
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  disabled={ACTIVE.has(selected.status) || selected.status === "failed"}
                />
                <Button type="submit" variant="outlined" disabled={Boolean(busy) || question.trim().length < 2}>Ask</Button>
              </Stack>
            </>
          )}
        </Stack>
      </Stack>
    </Stack>
  );
}
