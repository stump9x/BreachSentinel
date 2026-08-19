import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  MenuItem,
  Pagination,
  Stack,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import GitHubIcon from "@mui/icons-material/GitHub";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import { api, buildQuery } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { SeverityChip, StatusChip } from "../components/StatusChips";

const HISTORY_PAGE_SIZE = 20;
const REPO_PAGE_SIZE = 25;
const DETAIL_PAGE_SIZE = 100;
const ACTIVE_STATUSES = new Set(["queued", "running"]);
const POLL_MS = 1000;
const FIXED_MAX_FILES = 1500;

function formatLines(lines) {
  if (!Array.isArray(lines) || !lines.length) return "—";
  if (lines.length <= 8) return lines.join(", ");
  return `${lines.slice(0, 8).join(", ")}… (+${lines.length - 8})`;
}

/** Show repo name only — owner is already on the caption line. */
function repoDisplayName(fullName) {
  const value = String(fullName || "");
  const slash = value.indexOf("/");
  return slash >= 0 ? value.slice(slash + 1) : value || "—";
}

export default function GithubScannerPage() {
  const [configured, setConfigured] = useState(null);
  const [keyword, setKeyword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [history, setHistory] = useState([]);
  const [selectedIds, setSelectedIds] = useState(() => new Set());
  const [selected, setSelected] = useState(null);
  const [repos, setRepos] = useState([]);
  const [reposCount, setReposCount] = useState(0);
  const [repoPage, setRepoPage] = useState(1);
  const [alertsOnly, setAlertsOnly] = useState(false);
  const [severity, setSeverity] = useState("");
  const [detailRepo, setDetailRepo] = useState(null);
  const [detailFindings, setDetailFindings] = useState([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const lastProgressRef = useRef("");

  const isActive = Boolean(selected && ACTIVE_STATUSES.has(selected.status));

  const loadHistory = useCallback(async () => {
    const data = await api.get(
      `/api/v1/github/scans/${buildQuery({
        page_size: HISTORY_PAGE_SIZE,
        ordering: "-created_at",
      })}`
    );
    const rows = data.results || [];
    setHistory(rows);
    setSelectedIds((current) => {
      const valid = new Set(rows.map((row) => row.id));
      return new Set([...current].filter((id) => valid.has(id)));
    });
    setSelected((current) => {
      if (!current) return rows[0] || null;
      return rows.find((row) => row.id === current.id) || rows[0] || null;
    });
    return rows;
  }, []);

  const loadRepositories = useCallback(
    async (signal) => {
      if (!selected?.id) {
        setRepos([]);
        setReposCount(0);
        return;
      }
      const data = await api.get(
        `/api/v1/github/scans/${selected.id}/repositories/${buildQuery({
          page: repoPage,
          page_size: REPO_PAGE_SIZE,
        })}`,
        { signal, retries: 0 }
      );
      setRepos(data.results || data || []);
      setReposCount(data.count ?? (data.results || data || []).length);
    },
    [repoPage, selected?.id, selected?.file_count, selected?.status]
  );

  const openDetails = useCallback(
    async (repoRow) => {
      if (!selected?.id || !repoRow?.repository) return;
      setDetailRepo(repoRow);
      setDetailLoading(true);
      setDetailFindings([]);
      setError("");
      try {
        const data = await api.get(
          `/api/v1/github/scans/${selected.id}/findings/${buildQuery({
            repository: repoRow.repository,
            page_size: DETAIL_PAGE_SIZE,
            alerts_only: alertsOnly || undefined,
            severity: severity || undefined,
          })}`
        );
        const rows = data.results || data || [];
        rows.sort((a, b) => {
          if (a.is_text_file !== b.is_text_file) {
            return a.is_text_file ? 1 : -1;
          }
          return (b.score || 0) - (a.score || 0);
        });
        setDetailFindings(rows);
      } catch (err) {
        setError(err.message || "Failed to load file details");
      } finally {
        setDetailLoading(false);
      }
    },
    [alertsOnly, selected?.id, severity]
  );

  useEffect(() => {
    let cancelled = false;
    async function initialize() {
      try {
        const status = await api.get("/api/v1/github/scans/status/");
        if (cancelled) return;
        setConfigured(Boolean(status.configured));
        await loadHistory();
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load GitHub Scanner");
      }
    }
    initialize();
    return () => {
      cancelled = true;
    };
  }, [loadHistory]);

  useEffect(() => {
    const controller = new AbortController();
    loadRepositories(controller.signal).catch((err) => {
      if (err.name !== "AbortError") {
        setError(err.message || "Failed to load repositories");
      }
    });
    return () => controller.abort();
  }, [loadRepositories]);

  useEffect(() => {
    if (!selected || !isActive) return undefined;
    let inFlight = false;
    let cancelled = false;

    async function tick() {
      if (inFlight || cancelled || !selected?.id) return;
      inFlight = true;
      try {
        const scan = await api.get(`/api/v1/github/scans/${selected.id}/`);
        if (cancelled) return;
        const progressKey = [
          scan.status,
          scan.file_count,
          scan.repository_count,
          scan.alert_count,
          scan.api_requests,
          scan.non_text_count,
        ].join(":");
        setSelected((current) => (current?.id === scan.id ? scan : current));
        setHistory((rows) =>
          rows.map((row) => (row.id === scan.id ? scan : row))
        );
        if (progressKey !== lastProgressRef.current) {
          lastProgressRef.current = progressKey;
          await loadRepositories();
        }
        if (!ACTIVE_STATUSES.has(scan.status)) {
          setMessage(`Scan "${scan.keyword}" finished with status ${scan.status}.`);
          setRepoPage(1);
          await loadHistory();
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to refresh scan status");
      } finally {
        inFlight = false;
      }
    }

    // Poll immediately so the first saved batch appears without waiting POLL_MS.
    tick();
    const timer = window.setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [isActive, loadHistory, loadRepositories, selected?.id, selected?.status]);

  async function startScan(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const scan = await api.post("/api/v1/github/scans/", {
        keyword: keyword.trim(),
      });
      lastProgressRef.current = "";
      setSelected(scan);
      setRepoPage(1);
      setRepos([]);
      setDetailRepo(null);
      setDetailFindings([]);
      setMessage(
        `Queued scan for "${scan.keyword}" (up to ${FIXED_MAX_FILES} files). Results stream in as files are found.`
      );
      await loadHistory();
    } catch (err) {
      setError(err.message || "Failed to start GitHub scan");
    } finally {
      setBusy(false);
    }
  }

  async function deleteScans(ids) {
    const unique = [...new Set(ids)].filter(Boolean);
    if (!unique.length) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      let deleted = [];
      let blocked = [];
      if (unique.length === 1) {
        try {
          const result = await api.delete(`/api/v1/github/scans/${unique[0]}/`);
          deleted = result?.deleted || unique;
        } catch (err) {
          if (err.status === 409) {
            blocked = unique;
          } else {
            throw err;
          }
        }
      } else {
        const result = await api.post("/api/v1/github/scans/bulk-delete/", {
          ids: unique,
        });
        deleted = result?.deleted || [];
        blocked = result?.blocked || [];
      }
      setSelectedIds((current) => {
        const next = new Set(current);
        deleted.forEach((id) => next.delete(id));
        return next;
      });
      if (selected && deleted.includes(selected.id)) {
        setSelected(null);
        setRepos([]);
        setDetailRepo(null);
      }
      await loadHistory();
      if (deleted.length) {
        setMessage(`Deleted ${deleted.length} search histor${deleted.length === 1 ? "y" : "ies"}.`);
      }
      if (blocked.length) {
        setError("Cannot delete queued/running scans. Wait for them to finish.");
      }
    } catch (err) {
      setError(err.message || "Failed to delete history");
    } finally {
      setBusy(false);
    }
  }

  function toggleSelected(id) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    setSelectedIds((current) => {
      if (current.size === history.length) return new Set();
      return new Set(history.map((row) => row.id));
    });
  }

  const repoPageCount = Math.max(1, Math.ceil(reposCount / REPO_PAGE_SIZE));
  const detailSensitive = useMemo(
    () =>
      detailFindings
        .filter((row) => (row.alert_types || []).length > 0)
        .sort((a, b) => (b.score || 0) - (a.score || 0)),
    [detailFindings]
  );
  const detailNonTxt = useMemo(
    () =>
      detailFindings.filter(
        (row) => !row.is_text_file && !(row.alert_types || []).length
      ),
    [detailFindings]
  );
  const detailTxt = useMemo(
    () =>
      detailFindings.filter(
        (row) => row.is_text_file && !(row.alert_types || []).length
      ),
    [detailFindings]
  );
  const allHistorySelected =
    history.length > 0 && selectedIds.size === history.length;

  return (
    <Stack spacing={2}>
      <PageHeader
        title="GitHub Scanner"
        subtitle={`Stream keyword hits by repository (max ${FIXED_MAX_FILES} files). Weak single-.txt repos are hidden. Open View for file paths and line numbers.`}
        action={<GitHubIcon color="primary" />}
      />
      {configured === false ? (
        <Alert severity="warning">
          GitHub Scanner is disabled. Add a new read-only GITHUB_TOKEN to the server .env file.
        </Alert>
      ) : null}
      {error ? <Alert severity="error">{error}</Alert> : null}
      {message ? <Alert severity="success">{message}</Alert> : null}

      <Stack
        direction={{ xs: "column", lg: "row" }}
        spacing={2}
        alignItems="stretch"
      >
        <Stack spacing={1.5} sx={{ flex: { lg: "0 0 360px" }, minWidth: 0 }}>
          <Stack component="form" onSubmit={startScan} spacing={1.5}>
            <TextField
              label="Keyword"
              value={keyword}
              onChange={(event) => setKeyword(event.target.value)}
              required
              fullWidth
              placeholder="Enter keyword…"
              helperText={`Exact phrase search · up to ${FIXED_MAX_FILES} files`}
            />
            <Button
              type="submit"
              variant="contained"
              disabled={busy || configured !== true || keyword.trim().length < 2}
            >
              {busy ? "Queuing…" : "Search GitHub"}
            </Button>
          </Stack>

          <Stack
            direction="row"
            spacing={1}
            alignItems="center"
            justifyContent="space-between"
          >
            <Typography variant="h6">Search history</Typography>
            <Button
              size="small"
              color="error"
              disabled={busy || selectedIds.size === 0}
              startIcon={<DeleteOutlineIcon />}
              onClick={() => deleteScans([...selectedIds])}
            >
              Delete ({selectedIds.size})
            </Button>
          </Stack>
          <DataTable
            rows={history}
            empty="No GitHub scans yet."
            columns={[
              {
                id: "select",
                label: (
                  <Checkbox
                    size="small"
                    checked={allHistorySelected}
                    indeterminate={
                      selectedIds.size > 0 && selectedIds.size < history.length
                    }
                    onChange={toggleSelectAll}
                    inputProps={{ "aria-label": "Select all history" }}
                  />
                ),
                nowrap: true,
                sx: { width: 42, px: 0.5 },
                headerSx: { width: 42, px: 0.5 },
                render: (row) => (
                  <Checkbox
                    size="small"
                    checked={selectedIds.has(row.id)}
                    disabled={ACTIVE_STATUSES.has(row.status)}
                    onChange={() => toggleSelected(row.id)}
                    inputProps={{ "aria-label": `Select ${row.keyword}` }}
                  />
                ),
              },
              {
                id: "keyword",
                label: "Keyword",
                sx: { minWidth: 96 },
                render: (row) => (
                  <Button
                    size="small"
                    variant={selected?.id === row.id ? "contained" : "text"}
                    onClick={() => {
                      lastProgressRef.current = "";
                      setSelected(row);
                      setRepoPage(1);
                      setDetailRepo(null);
                    }}
                    sx={{ whiteSpace: "normal", textAlign: "left", lineHeight: 1.3 }}
                  >
                    {row.keyword}
                  </Button>
                ),
              },
              {
                id: "status",
                label: "Status",
                nowrap: true,
                render: (row) => <StatusChip value={row.status} />,
              },
              {
                id: "actions",
                label: "",
                nowrap: true,
                sx: { width: 40, px: 0.5 },
                render: (row) => (
                  <IconButton
                    size="small"
                    color="error"
                    disabled={busy || ACTIVE_STATUSES.has(row.status)}
                    aria-label={`Delete ${row.keyword}`}
                    onClick={() => deleteScans([row.id])}
                  >
                    <DeleteOutlineIcon fontSize="small" />
                  </IconButton>
                ),
              },
            ]}
          />
        </Stack>

        <Stack spacing={1.5} sx={{ flex: 1, minWidth: 0 }}>
          {selected ? (
            <Stack spacing={1}>
              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                flexWrap="wrap"
                useFlexGap
              >
                <Typography variant="h6">
                  Extraction results: {selected.keyword}
                </Typography>
                {isActive ? <CircularProgress size={18} /> : null}
              </Stack>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip label={`Repos: ${selected.repository_count || 0}`} />
                <Chip label={`Files: ${selected.file_count || 0}`} />
                <Chip
                  color="warning"
                  label={`Alerts: ${selected.alert_count || 0}`}
                />
                <Chip
                  color="error"
                  label={`Critical: ${selected.critical_count || 0}`}
                />
                <Chip
                  color="info"
                  label={`Non-.txt: ${selected.non_text_count || 0}`}
                />
                {selected.coverage_limited ? (
                  <Chip
                    color="warning"
                    variant="outlined"
                    label="GitHub result cap reached"
                  />
                ) : null}
              </Stack>
              {selected.error_message ? (
                <Alert severity="error">{selected.error_message}</Alert>
              ) : null}
            </Stack>
          ) : null}

          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
            <FormControlLabel
              control={
                <Switch
                  checked={alertsOnly}
                  onChange={(event) => {
                    setAlertsOnly(event.target.checked);
                  }}
                />
              }
              label="Alerts only (in View)"
            />
            <TextField
              select
              size="small"
              label="Severity filter"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
              sx={{ minWidth: 160 }}
            >
              <MenuItem value="">All</MenuItem>
              {["info", "medium", "high", "critical"].map((value) => (
                <MenuItem key={value} value={value}>
                  {value}
                </MenuItem>
              ))}
            </TextField>
          </Stack>

          <DataTable
            rows={repos}
            empty={
              selected && isActive
                ? "Scanning… new repositories appear as soon as each batch is saved."
                : "Select or start a scan to view results."
            }
            columns={[
              {
                id: "repository",
                label: "Repository",
                nowrap: false,
                sx: { width: "72%" },
                render: (row) => (
                  <Stack spacing={0.25} sx={{ minWidth: 0, pr: 1 }}>
                    <Typography
                      component={row.repository_url ? "a" : "span"}
                      href={row.repository_url || undefined}
                      target="_blank"
                      rel="noreferrer noopener"
                      title={row.repository}
                      sx={{
                        color: row.repository_url ? "secondary.main" : "inherit",
                        display: "block",
                        whiteSpace: "normal",
                        overflowWrap: "anywhere",
                        wordBreak: "break-word",
                        lineHeight: 1.35,
                      }}
                    >
                      {repoDisplayName(row.repository)}
                    </Typography>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{
                        display: "block",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                    >
                      {row.owner || "—"} · {row.non_text_count || 0} non-.txt ·{" "}
                      {row.text_count || 0} .txt
                    </Typography>
                  </Stack>
                ),
              },
              {
                id: "file_count",
                label: "Files",
                nowrap: true,
                align: "right",
                sx: { width: 40, px: 0.5 },
                headerSx: { width: 40, px: 0.5 },
                render: (row) => row.file_count || 0,
              },
              {
                id: "match_total",
                label: "Hits",
                nowrap: true,
                align: "right",
                sx: { width: 40, px: 0.5 },
                headerSx: { width: 40, px: 0.5 },
                render: (row) => row.match_total || 0,
              },
              {
                id: "alert_count",
                label: "Alerts",
                nowrap: true,
                align: "center",
                sx: { width: 56, px: 0.25 },
                headerSx: { width: 56, px: 0.25 },
                render: (row) =>
                  row.alert_count ? (
                    <Chip
                      size="small"
                      color="warning"
                      icon={<WarningAmberIcon />}
                      label={row.alert_count}
                      title="Password / DB / config leaks detected in file content"
                      sx={{ maxWidth: "100%", "& .MuiChip-label": { px: 0.5 } }}
                    />
                  ) : (
                    "—"
                  ),
              },
              {
                id: "details",
                label: "View",
                nowrap: true,
                align: "center",
                sticky: "right",
                width: 68,
                minWidth: 68,
                sx: { width: 68, minWidth: 68, maxWidth: 68, px: 0.25 },
                headerSx: { width: 68, minWidth: 68, maxWidth: 68, px: 0.25 },
                render: (row) => (
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => openDetails(row)}
                    sx={{
                      whiteSpace: "nowrap",
                      minWidth: 56,
                      px: 1,
                      flexShrink: 0,
                    }}
                  >
                    View
                  </Button>
                ),
              },
            ]}
          />
          {selected ? (
            <Stack direction="row" justifyContent="flex-end">
              <Pagination
                count={repoPageCount}
                page={repoPage}
                onChange={(_event, value) => setRepoPage(value)}
                showFirstButton
                showLastButton
              />
            </Stack>
          ) : null}
        </Stack>
      </Stack>

      <Dialog
        open={Boolean(detailRepo)}
        onClose={() => {
          setDetailRepo(null);
          setDetailFindings([]);
        }}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>Details — {detailRepo?.repository || ""}</DialogTitle>
        <DialogContent dividers>
          {detailLoading ? (
            <Stack alignItems="center" py={4}>
              <CircularProgress size={28} />
            </Stack>
          ) : (
            <Stack spacing={2}>
              <Typography variant="body2" color="text.secondary">
                Keyword hit lines (with line numbers) plus any password / DB /
                config secrets found in the same file.
              </Typography>
              <DetailFileGroup
                title="Sensitive exposures"
                rows={detailSensitive}
                emphasize
              />
              <DetailFileGroup title="Other non-.txt files" rows={detailNonTxt} />
              <Collapse in={detailTxt.length > 0}>
                <DetailFileGroup title=".txt files" rows={detailTxt} />
              </Collapse>
              {!detailFindings.length ? (
                <Typography color="text.secondary">
                  No files matched filters.
                </Typography>
              ) : null}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setDetailRepo(null);
              setDetailFindings([]);
            }}
          >
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}

function alertKindLabel(kind) {
  const labels = {
    "private-key": "Private key",
    "github-token": "GitHub token",
    "aws-access-key": "AWS access key",
    "aws-secret-key": "AWS secret key",
    "database-url": "Database URL / credentials",
    "jdbc-url": "JDBC connection",
    "connection-string": "DB connection string",
    "django-secret": "App secret key",
    password: "Password",
    "account-identifier": "Account / DB user",
    "api-key": "API key / token",
    "config-host": "DB / service host",
  };
  return labels[kind] || String(kind || "").replace(/-/g, " ");
}

function formatSnippetBlocks(row) {
  const snippets = Array.isArray(row.match_snippets) ? row.match_snippets : [];
  const keywordBlock = snippets
    .map((item) => {
      const text = String(item?.text || "").trim();
      if (!text) return null;
      const line = item?.line;
      return line ? `L${line}: ${text}` : text;
    })
    .filter(Boolean);
  const secretBlock = row.evidence
    ? String(row.evidence)
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean)
    : [];
  const parts = [];
  if (keywordBlock.length) {
    parts.push(["Keyword hits", keywordBlock.join("\n")]);
  }
  if (secretBlock.length) {
    // Avoid duplicating lines already shown as keyword hits.
    const keywordText = new Set(keywordBlock.map((line) => line.replace(/^L\d+:\s*/, "")));
    const uniqueSecrets = secretBlock.filter((line) => !keywordText.has(line));
    if (uniqueSecrets.length) {
      parts.push(["Sensitive", uniqueSecrets.join("\n")]);
    }
  }
  return parts;
}

function DetailFileGroup({ title, rows, emphasize = false }) {
  if (!rows.length) return null;
  return (
    <Box>
      <Typography variant="subtitle2" sx={{ mb: 1 }}>
        {title} ({rows.length})
      </Typography>
      <Stack spacing={1}>
        {rows.map((row) => {
          const blocks = formatSnippetBlocks(row);
          return (
          <Box
            key={row.id}
            sx={{
              borderBottom: "1px solid",
              borderColor: "divider",
              borderLeft: emphasize ? "3px solid" : "none",
              borderLeftColor: emphasize ? "warning.main" : undefined,
              pl: emphasize ? 1 : 0,
              pb: 1,
            }}
          >
            <Stack
              direction={{ xs: "column", sm: "row" }}
              spacing={1}
              justifyContent="space-between"
              alignItems={{ sm: "center" }}
            >
              <Stack spacing={0.25} sx={{ minWidth: 0 }}>
                <Typography
                  component="a"
                  href={row.html_url}
                  target="_blank"
                  rel="noreferrer noopener"
                  sx={{ color: "secondary.main", wordBreak: "break-all" }}
                >
                  {row.file_path}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Lines: {formatLines(row.match_lines)} · Matches:{" "}
                  {row.keyword_matches || 0} ·{" "}
                  {row.extension ? `.${row.extension}` : "no ext"}
                </Typography>
              </Stack>
              <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                <SeverityChip value={row.severity} />
                {(row.alert_types || []).map((value) => (
                  <Chip
                    key={value}
                    size="small"
                    color="warning"
                    label={alertKindLabel(value)}
                  />
                ))}
              </Stack>
            </Stack>
            {blocks.map(([label, body]) => (
              <Box key={label} sx={{ mt: 0.75 }}>
                <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                  {label}
                </Typography>
                <Typography
                  component="pre"
                  variant="caption"
                  sx={{
                    whiteSpace: "pre-wrap",
                    mt: 0.25,
                    maxWidth: "100%",
                    p: 1,
                    bgcolor: emphasize || label === "Sensitive" ? "action.hover" : "action.selected",
                    borderRadius: 1,
                    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                  }}
                >
                  {body}
                </Typography>
              </Box>
            ))}
          </Box>
          );
        })}
      </Stack>
    </Box>
  );
}
