import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Button,
  Chip,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { StatusChip } from "../components/StatusChips";

export default function IntelligencePage() {
  const [briefings, setBriefings] = useState([]);
  const [logs, setLogs] = useState([]);
  const [misp, setMisp] = useState(null);
  const [health, setHealth] = useState(null);
  const [nerText, setNerText] = useState(
    "Observed 203.0.113.10 resolving to threat.example linked to CVE-2024-21762"
  );
  const [nerResult, setNerResult] = useState(null);
  const [latestBriefing, setLatestBriefing] = useState(null);
  const [keyword, setKeyword] = useState("ransomware");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const [b, l, m, h] = await Promise.all([
        api.get("/api/v1/ai/briefings/?page_size=10"),
        api.get("/api/v1/integrations/logs/?page_size=10"),
        api.get("/api/v1/misp/status/"),
        api.get("/api/v1/integrations/health/"),
      ]);
      setBriefings(b.results || []);
      setLogs(l.results || []);
      setMisp(m);
      setHealth(h);
    } catch (err) {
      setError(err.message || "Failed to load intelligence panel");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function generateBriefing() {
    setBusy("briefing");
    setError("");
    setMsg("");
    try {
      const data = await api.post("/api/v1/ai/briefings/generate/", {
        window_hours: 24,
        async_mode: false,
      });
      setLatestBriefing(data);
      setMsg(`Briefing ready via provider=${data.provider}`);
      await load();
    } catch (err) {
      setError(err.message || "Briefing failed");
    } finally {
      setBusy("");
    }
  }

  async function runNer() {
    setBusy("ner");
    setError("");
    try {
      const data = await api.post("/api/v1/ai/extract-entities/", {
        text: nerText,
        persist: true,
      });
      setNerResult(data);
      setMsg(`Extracted entities · persisted ${data.persisted_created}`);
    } catch (err) {
      setError(err.message || "NER failed");
    } finally {
      setBusy("");
    }
  }

  async function syncMisp(direction) {
    setBusy("misp");
    setError("");
    setMsg("");
    try {
      const data = await api.post("/api/v1/misp/sync/", {
        direction,
        limit: 50,
        async_mode: false,
      });
      const statuses = (data.results || []).map((r) => r.status).join(", ");
      setMsg(`MISP ${direction}: ${statuses}`);
      await load();
    } catch (err) {
      setError(err.message || "MISP sync failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <Stack spacing={2}>
      <PageHeader
        title="AI & MISP"
        subtitle="Daily briefings, entity extraction, and MISP import/export. Keys stay in server .env only."
        action={
          <Button variant="outlined" onClick={load}>
            Refresh
          </Button>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      {msg ? <Alert severity="success">{msg}</Alert> : null}

      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        <Chip
          size="small"
          variant="outlined"
          color={health?.ai?.anthropic_configured ? "success" : "default"}
          label={`Anthropic: ${health?.ai?.anthropic_configured ? "on" : "off"}`}
        />
        <Chip
          size="small"
          variant="outlined"
          color={health?.ai?.huggingface_configured ? "success" : "default"}
          label={`HuggingFace: ${health?.ai?.huggingface_configured ? "on" : "off"}`}
        />
        <Chip
          size="small"
          variant="outlined"
          color={misp?.configured ? "success" : "default"}
          label={`MISP: ${misp?.configured ? "configured" : "not configured"}`}
        />
        <Chip
          size="small"
          variant="outlined"
          color={health?.searxng_configured ? "success" : "default"}
          label={`SearxNG: ${health?.searxng_configured ? "on" : "off"}`}
        />
      </Stack>

      <Typography variant="h6">AI briefing</Typography>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <Button
          variant="contained"
          onClick={generateBriefing}
          disabled={Boolean(busy)}
        >
          {busy === "briefing" ? "Generating…" : "Generate 24h briefing"}
        </Button>
        <Button
          variant="outlined"
          disabled={Boolean(busy)}
          onClick={async () => {
            setBusy("weekly");
            setError("");
            try {
              const data = await api.post("/api/v1/ai/weekly-digest/", {});
              setLatestBriefing(data);
              setMsg("Weekly top-5 digest ready");
              await load();
            } catch (err) {
              setError(err.message || "Weekly digest failed");
            } finally {
              setBusy("");
            }
          }}
        >
          Weekly top-5 digest
        </Button>
      </Stack>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems="flex-start">
        <TextField
          label="Keyword summary"
          placeholder="lockbit / CVE-2024 / your domain"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          sx={{ minWidth: 280, flex: 1 }}
        />
        <Button
          variant="outlined"
          color="secondary"
          disabled={Boolean(busy) || !keyword.trim()}
          onClick={async () => {
            setBusy("keyword");
            setError("");
            try {
              const data = await api.post("/api/v1/ai/keyword-summary/", {
                keyword: keyword.trim(),
                window_hours: 168,
              });
              setLatestBriefing(data);
              setMsg(`Keyword summary for "${keyword.trim()}" ready`);
              await load();
            } catch (err) {
              setError(err.message || "Keyword summary failed");
            } finally {
              setBusy("");
            }
          }}
        >
          Summarize keyword
        </Button>
      </Stack>
      {latestBriefing?.content ? (
        <TextField
          label="Latest briefing"
          value={latestBriefing.content}
          multiline
          minRows={8}
          fullWidth
          InputProps={{ readOnly: true }}
        />
      ) : null}

      <Typography variant="h6">Entity extraction</Typography>
      <TextField
        label="Raw intel text"
        value={nerText}
        onChange={(e) => setNerText(e.target.value)}
        multiline
        minRows={4}
        fullWidth
      />
      <Button
        variant="outlined"
        onClick={runNer}
        disabled={Boolean(busy) || !nerText.trim()}
        sx={{ alignSelf: "flex-start" }}
      >
        {busy === "ner" ? "Extracting…" : "Extract & persist IOCs"}
      </Button>
      {nerResult ? (
        <Typography variant="body2" color="text.secondary" component="pre" sx={{ whiteSpace: "pre-wrap" }}>
          {JSON.stringify(nerResult.entities, null, 2)}
        </Typography>
      ) : null}

      <Typography variant="h6">MISP sync</Typography>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <Button
          variant="outlined"
          disabled={Boolean(busy)}
          onClick={() => syncMisp("export")}
        >
          Export IOCs → MISP
        </Button>
        <Button
          variant="outlined"
          color="secondary"
          disabled={Boolean(busy)}
          onClick={() => syncMisp("import")}
        >
          Import MISP → IOCs
        </Button>
        <Button
          variant="contained"
          color="secondary"
          disabled={Boolean(busy)}
          onClick={() => syncMisp("both")}
        >
          Sync both
        </Button>
      </Stack>
      {!misp?.configured ? (
        <Typography variant="body2" color="text.secondary">
          Set MISP_URL and MISP_API_KEY in `.env` to enable live sync. Unconfigured
          runs return status <code>skipped</code>.
        </Typography>
      ) : null}

      <Typography variant="h6">Recent briefings</Typography>
      <DataTable
        rows={briefings}
        columns={[
          { id: "title", label: "Title" },
          { id: "provider", label: "Provider" },
          {
            id: "status",
            label: "Status",
            render: (row) => <StatusChip value={row.status} />,
          },
          {
            id: "counts",
            label: "Counts",
            render: (row) =>
              `T${row.threat_count}/I${row.indicator_count}/L${row.leak_count}`,
          },
          {
            id: "created_at",
            label: "Created",
            render: (row) =>
              row.created_at ? new Date(row.created_at).toLocaleString() : "—",
          },
        ]}
      />

      <Typography variant="h6">Integration logs</Typography>
      <DataTable
        rows={logs}
        columns={[
          { id: "target", label: "Target" },
          { id: "direction", label: "Direction" },
          {
            id: "status",
            label: "Status",
            render: (row) => <StatusChip value={row.status} />,
          },
          { id: "message", label: "Message" },
          { id: "records_processed", label: "Records" },
        ]}
      />
    </Stack>
  );
}
