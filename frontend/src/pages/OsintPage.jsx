import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Divider,
  FormControlLabel,
  Link,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { StatusChip } from "../components/StatusChips";

function shortenUrl(url) {
  if (!url) return "—";
  try {
    const u = new URL(url);
    const path = `${u.pathname}${u.search}`.replace(/\/$/, "");
    const shortPath = path.length > 48 ? `${path.slice(0, 45)}…` : path || "/";
    return `${u.hostname}${shortPath}`;
  } catch {
    return url.length > 64 ? `${url.slice(0, 61)}…` : url;
  }
}

function engineLabel(engine) {
  const map = {
    x_twitter: "X",
    reddit_search: "Reddit",
    searx: "Searx",
    exa: "Exa",
  };
  return map[engine] || engine || "web";
}

function formatPublished(raw) {
  if (raw == null || raw === "") return "";
  const n = Number(raw);
  let d;
  if (Number.isFinite(n) && n > 1e8) {
    d = new Date(n > 1e12 ? n : n * 1000);
  } else {
    d = new Date(String(raw));
  }
  if (Number.isNaN(d.getTime())) {
    const s = String(raw);
    return s.length > 28 ? `${s.slice(0, 25)}…` : s;
  }
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export default function OsintPage() {
  const [sites, setSites] = useState([]);
  const [username, setUsername] = useState("");
  const [selectedSites, setSelectedSites] = useState([]);
  const [onlyFound, setOnlyFound] = useState(true);
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const [searxConfigured, setSearxConfigured] = useState(null);
  const [searxDoctor, setSearxDoctor] = useState(null);
  const [searxQuery, setSearxQuery] = useState("");
  const [searxPersist, setSearxPersist] = useState(false);
  const [searxBusy, setSearxBusy] = useState(false);
  const [searxHits, setSearxHits] = useState([]);
  const [searxMsg, setSearxMsg] = useState("");
  const [searxChannels, setSearxChannels] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function loadSites() {
      try {
        const [data, status] = await Promise.all([
          api.get("/api/v1/osint/sites/"),
          api.get("/api/v1/searx/status/").catch(() => ({ configured: false })),
        ]);
        if (!cancelled) {
          setSites(data.sites || []);
          const channels = status.channels || [];
          const anyDiscover = channels.some(
            (c) => c.role === "discover" && (c.ok || c.configured)
          );
          setSearxConfigured(
            Boolean(status.configured) ||
              Boolean(status.exa?.configured) ||
              anyDiscover
          );
          setSearxDoctor(status);
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load OSINT catalog");
      }
    }
    loadSites();
    return () => {
      cancelled = true;
    };
  }, []);

  async function runScan(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const payload = {
        username: username.trim(),
        sites: selectedSites,
        only_found: onlyFound,
        persist,
        timeout_seconds: 60,
      };
      const data = await api.post("/api/v1/osint/scan/", payload);
      setResult(data);
    } catch (err) {
      setError(err.message || "Scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function runSearx(event) {
    event.preventDefault();
    setSearxBusy(true);
    setError("");
    setSearxMsg("");
    setSearxHits([]);
    setSearxChannels(null);
    try {
      const data = await api.post("/api/v1/searx/search/", {
        query: searxQuery.trim(),
        persist: searxPersist,
        limit: 40,
        exact: true,
      });
      setSearxHits(data.results || []);
      setSearxChannels(data.channels || null);
      const ch = data.channels || {};
      const parts = Object.entries(ch).map(([name, info]) => {
        const kept = info?.count ?? 0;
        const raw = info?.raw;
        if (typeof raw === "number" && raw > kept) {
          return `${engineLabel(name)}:${kept}/${raw}`;
        }
        return `${engineLabel(name)}:${kept}`;
      });
      const notes = [];
      if (ch.x_twitter?.error && (ch.x_twitter?.count ?? 0) === 0) {
        notes.push(`X: ${ch.x_twitter.error}`);
      }
      if (ch.reddit_search?.error && (ch.reddit_search?.count ?? 0) === 0) {
        notes.push(`Reddit: ${ch.reddit_search.error}`);
      }
      setSearxMsg(
        [
          data.persist
            ? `Found ${data.count} · created ${data.persist.created || 0} leak(s)`
            : `Found ${data.count} result(s)`,
          parts.length ? parts.join(" · ") : null,
          ...notes,
        ]
          .filter(Boolean)
          .join(" — ")
      );
    } catch (err) {
      setError(err.message || "Searx search failed");
    } finally {
      setSearxBusy(false);
    }
  }

  const rows = result?.scan?.results || [];

  return (
    <Stack spacing={2}>
      <PageHeader
        title="OSINT Scan"
        subtitle="Username footprint (Go) + open-web leak hunt (DDG/Brave/Bing + GitLab/npm/SO + X/Reddit + Ahmia onion index). GitHub → GitHub Scanner."
      />
      {error ? <Alert severity="error">{error}</Alert> : null}

      <Typography variant="h6">Username footprint</Typography>
      <Stack spacing={2} component="form" onSubmit={runScan}>
        <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} alignItems="flex-start">
          <TextField
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            helperText="2–64 chars: letters, numbers, . _ -"
            sx={{ minWidth: 240 }}
          />
          <TextField
            select
            label="Sites (optional)"
            value={selectedSites}
            onChange={(e) => setSelectedSites(e.target.value)}
            SelectProps={{ multiple: true }}
            helperText={`${sites.length} sites in catalog · empty = all`}
            sx={{ minWidth: 280, flex: 1 }}
          >
            {sites.map((s) => (
              <MenuItem key={s.name} value={s.name}>
                {s.name} · {s.category}
              </MenuItem>
            ))}
          </TextField>
        </Stack>
        <Stack direction="row" spacing={2} flexWrap="wrap">
          <FormControlLabel
            control={
              <Checkbox checked={onlyFound} onChange={(e) => setOnlyFound(e.target.checked)} />
            }
            label="Only show found"
          />
          <FormControlLabel
            control={
              <Checkbox checked={persist} onChange={(e) => setPersist(e.target.checked)} />
            }
            label="Persist hits as indicators"
          />
          <Button type="submit" variant="contained" disabled={busy || !username.trim()}>
            {busy ? "Scanning…" : "Start scan"}
          </Button>
        </Stack>
      </Stack>

      {result ? (
        <Typography variant="body2" color="text.secondary">
          Found {result.scan?.found ?? 0}/{result.scan?.total ?? 0} in{" "}
          {result.scan?.duration_ms ?? 0}ms
          {result.persisted
            ? ` · persisted ${result.persisted.found_profiles} profiles`
            : ""}
        </Typography>
      ) : null}

      <DataTable
        loading={busy}
        rows={rows}
        empty="Run a scan to see footprint results."
        columns={[
          { id: "site", label: "Site" },
          { id: "category", label: "Category" },
          {
            id: "status",
            label: "Status",
            render: (row) => <StatusChip value={row.status} />,
          },
          {
            id: "url",
            label: "URL",
            render: (row) =>
              row.url ? (
                <Typography
                  component="a"
                  href={row.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  variant="body2"
                  sx={{ color: "secondary.main" }}
                >
                  {row.url}
                </Typography>
              ) : (
                "—"
              ),
          },
          { id: "http_code", label: "HTTP" },
          { id: "latency_ms", label: "ms" },
        ]}
      />

      <Divider sx={{ my: 1 }} />

      <Typography variant="h6">Open-web leak channels</Typography>
      <Typography variant="body2" color="text.secondary">
        {searxConfigured
          ? "Discover via Searx / Exa / X / Reddit cookies → Data Leaks → enrich (Reddit JSON, paste raw, Jina)."
          : "Not configured — set SEARXNG_URL, and/or EXA_API_KEY, and/or X/Reddit cookies (docs/OPEN_WEB_CREDENTIALS.md)."}
      </Typography>
      {searxDoctor?.channels?.length ? (
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ gap: 0.75 }}>
          {searxDoctor.channels.map((ch) => (
            <Typography
              key={ch.id}
              variant="caption"
              component="span"
              sx={{
                px: 1,
                py: 0.35,
                border: "1px solid",
                borderColor: ch.ok ? "success.main" : "divider",
                color: ch.ok ? "success.main" : "text.secondary",
                borderRadius: 0.5,
              }}
              title={ch.detail || ""}
            >
              {ch.label}: {ch.ok ? "ok" : "off"}
            </Typography>
          ))}
          <Typography variant="caption" color="text.secondary" sx={{ alignSelf: "center" }}>
            Packs: {searxDoctor.query_packs ? "on" : "off"} · Enrich:{" "}
            {searxDoctor.enrich ? "on" : "off"}
          </Typography>
        </Stack>
      ) : searxDoctor ? (
        <Typography variant="caption" color="text.secondary">
          Reader: {searxDoctor.web_reader?.ok ? searxDoctor.web_reader.backend : "off"}
          {" · "}
          Packs: {searxDoctor.query_packs ? "on" : "off"}
          {" · "}
          Exa: {searxDoctor.exa?.configured ? "on" : "off"}
          {" · "}
          Enrich: {searxDoctor.enrich ? "on" : "off"}
        </Typography>
      ) : null}
      {searxMsg ? (
        <Alert
          severity={
            searxChannels?.x_twitter?.error && !searxChannels?.x_twitter?.count
              ? "warning"
              : "success"
          }
        >
          {searxMsg}
        </Alert>
      ) : null}
      <Stack spacing={2} component="form" onSubmit={runSearx}>
        <TextField
          label="Keyword / domain / email fragment"
          value={searxQuery}
          onChange={(e) => setSearxQuery(e.target.value)}
          required
          fullWidth
          helperText="Hits must contain the keyword in title/snippet (accent-insensitive for Vietnamese). X/Reddit listed first when present."
        />
        <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap">
          <FormControlLabel
            control={
              <Checkbox
                checked={searxPersist}
                onChange={(e) => setSearxPersist(e.target.checked)}
              />
            }
            label="Persist hits as Data Leaks"
          />
          <Button
            type="submit"
            variant="contained"
            color="secondary"
            disabled={searxBusy || !searxQuery.trim() || searxConfigured === false}
          >
            {searxBusy ? "Searching…" : "Search open-web"}
          </Button>
        </Stack>
      </Stack>

      {searxBusy ? (
        <Box sx={{ py: 4, display: "flex", justifyContent: "center" }}>
          <CircularProgress size={28} />
        </Box>
      ) : !searxHits.length ? (
        <Typography color="text.secondary" sx={{ py: 2 }}>
          No open-web results yet.
        </Typography>
      ) : (
        <Stack
          spacing={0}
          sx={{
            border: "1px solid",
            borderColor: "divider",
            borderRadius: 1,
            overflow: "hidden",
          }}
        >
          {searxHits.map((row, idx) => (
            <Box
              key={`${row.engine || "web"}-${row.url || idx}`}
              sx={{
                px: 1.5,
                py: 1.25,
                borderTop: idx === 0 ? "none" : "1px solid",
                borderColor: "divider",
              }}
            >
              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                flexWrap="wrap"
                useFlexGap
                sx={{ mb: 0.5 }}
              >
                <Chip
                  size="small"
                  label={engineLabel(row.engine)}
                  variant="outlined"
                  sx={{ height: 22 }}
                />
                {formatPublished(row.published) ? (
                  <Typography variant="caption" color="text.secondary">
                    {formatPublished(row.published)}
                  </Typography>
                ) : null}
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  {row.title || "Untitled"}
                </Typography>
              </Stack>
              {row.url ? (
                <Link
                  href={row.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  underline="hover"
                  variant="body2"
                  title={row.url}
                  sx={{
                    display: "inline-block",
                    maxWidth: "100%",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    color: "primary.main",
                  }}
                >
                  {shortenUrl(row.url)}
                </Link>
              ) : null}
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{ mt: 0.5, whiteSpace: "normal", wordBreak: "break-word" }}
              >
                {(row.content || "—").replace(/\s+/g, " ").slice(0, 220)}
                {(row.content || "").length > 220 ? "…" : ""}
              </Typography>
            </Box>
          ))}
        </Stack>
      )}
    </Stack>
  );
}
