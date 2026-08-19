import { useState } from "react";
import {
  Alert,
  Button,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api } from "../api/client";
import { PageHeader } from "../components/PageHeader";

const SAMPLE = `https://mail.example.com/login:analyst@example.com:ChangeMe123
URL: https://vpn.example.com
Username: ops
Password: hunter2`;

export default function WorkersPage() {
  const [content, setContent] = useState(SAMPLE);
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  async function parseStealer() {
    setBusy("stealer");
    setError("");
    setMsg("");
    try {
      const data = await api.post("/api/v1/workers/parse-stealer/", {
        content,
        create_leak: true,
        leak_title: "UI stealer ingest",
        async_mode: false,
      });
      setMsg(
        `Stealer parse complete · created ${data.result?.created ?? 0} credentials (leak ${data.result?.leak_id})`
      );
    } catch (err) {
      setError(err.message || "Parse failed");
    } finally {
      setBusy("");
    }
  }

  async function ingestFeeds(feeds) {
    setBusy("feeds");
    setError("");
    setMsg("");
    try {
      const data = await api.post("/api/v1/workers/ingest-feeds/", {
        feeds,
        limit: 25,
        async_mode: true,
      });
      setMsg(`Feed jobs queued: ${JSON.stringify(data.tasks || {})}`);
    } catch (err) {
      setError(err.message || "Feed ingest failed");
    } finally {
      setBusy("");
    }
  }

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Workers"
        subtitle="Trigger Celery jobs for stealer log parsing and intel feed ingestion."
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      {msg ? <Alert severity="success">{msg}</Alert> : null}

      <Typography variant="h6">Parse stealer dump</Typography>
      <TextField
        label="Dump content"
        value={content}
        onChange={(e) => setContent(e.target.value)}
        multiline
        minRows={8}
        fullWidth
      />
      <Button
        variant="contained"
        onClick={parseStealer}
        disabled={Boolean(busy) || !content.trim()}
        sx={{ alignSelf: "flex-start" }}
      >
        {busy === "stealer" ? "Parsing…" : "Parse now (sync)"}
      </Button>

      <Typography variant="h6" sx={{ pt: 2 }}>
        Ingest feeds
      </Typography>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <Button
          variant="outlined"
          disabled={Boolean(busy)}
          onClick={() => ingestFeeds(["cve"])}
        >
          Queue CVE feed
        </Button>
        <Button
          variant="outlined"
          color="secondary"
          disabled={Boolean(busy)}
          onClick={() => ingestFeeds(["ransomware"])}
        >
          Queue ransomware feed
        </Button>
        <Button
          variant="outlined"
          disabled={Boolean(busy)}
          onClick={() => ingestFeeds(["cert"])}
        >
          Queue RSS / CERT / breach news
        </Button>
        <Button
          variant="contained"
          color="secondary"
          disabled={Boolean(busy)}
          onClick={() => ingestFeeds(["all"])}
        >
          Queue all feeds
        </Button>
        <Button
          variant="outlined"
          disabled={Boolean(busy)}
          onClick={async () => {
            setBusy("searx");
            setError("");
            setMsg("");
            try {
              const data = await api.post("/api/v1/searx/scan/", {
                async_mode: true,
                limit_per_keyword: 15,
              });
              setMsg(`Searx leak sweep queued: ${data.task_id || "ok"}`);
            } catch (err) {
              setError(err.message || "Searx scan failed");
            } finally {
              setBusy("");
            }
          }}
        >
          Queue Searx leak sweep
        </Button>
      </Stack>
      <Typography variant="body2" color="text.secondary">
        Feed jobs run asynchronously on Celery. RSS and Searx keyword sweeps run every 5 minutes.
        Create Watch Rules with target <strong>searx</strong> or <strong>leaks</strong> to hunt exposures.
      </Typography>
    </Stack>
  );
}
