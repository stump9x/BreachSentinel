import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  FormControlLabel,
  MenuItem,
  Pagination,
  Stack,
  Switch,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import GridViewOutlinedIcon from "@mui/icons-material/GridViewOutlined";
import TableRowsOutlinedIcon from "@mui/icons-material/TableRowsOutlined";
import { Link as RouterLink } from "react-router-dom";
import { api, buildQuery } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import {
  ExternalTitleLink,
  resolveThreatHref,
} from "../components/ExternalTitleLink";
import { WireCard } from "../components/WireCard";
import { WireTagChips } from "../components/WireTagChips";
import { formatWireDateWithRelative, compareWireRows } from "../utils/dateTime";
import { displayThreatTitle } from "../utils/threatTitle";

const POLL_MS = 10000;
const WIRE_MAX_AGE_DAYS = 7;
const WIRE_VIETNAM_PIN_DAYS = 7;
const PAGE_SIZE = 50;
const VIEW_STORAGE_KEY = "wire.view";

function initialViewMode() {
  try {
    const stored = window.localStorage.getItem(VIEW_STORAGE_KEY);
    return stored === "table" ? "table" : "cards";
  } catch {
    return "cards";
  }
}

function wireListQuery({ source, tag, page }) {
  return buildQuery({
    source: source || undefined,
    tag: tag || undefined,
    wire_feed: true,
    page,
    page_size: PAGE_SIZE,
    ordering: "-wire_sort_priority,-published_at,-id",
  });
}

export default function ThreatsPage() {
  const [rows, setRows] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [source, setSource] = useState("");
  const [tag, setTag] = useState("");
  const [live, setLive] = useState(true);
  const [view, setView] = useState(initialViewMode);
  const [newCount, setNewCount] = useState(0);
  const [lastRefresh, setLastRefresh] = useState(null);
  const knownIds = useRef(new Set());
  const firstLoad = useRef(true);

  const pageCount = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  const load = useCallback(
    async ({ silent = false, pageOverride } = {}) => {
      const pageNum = pageOverride ?? page;
      if (!silent) setLoading(true);
      setError("");
      try {
        const qs = wireListQuery({ source, tag, page: pageNum });
        const data = await api.get(`/api/v1/threats/${qs}`);
        const results = [...(data.results || [])].sort((a, b) =>
          compareWireRows(a, b)
        );
        const count = data.count ?? results.length;
        setTotalCount(count);

        if (!firstLoad.current && pageNum === 1) {
          const fresh = results.filter((r) => !knownIds.current.has(r.id));
          if (fresh.length) setNewCount((c) => c + fresh.length);
        }
        firstLoad.current = false;
        if (pageNum === 1) {
          for (const r of results) knownIds.current.add(r.id);
        }
        setRows(results);
        setLastRefresh(new Date());
      } catch (err) {
        setError(err.message || "Failed to load threats");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [source, tag, page]
  );

  useEffect(() => {
    load();
  }, [load]);

  // Live: keep pulling page 1 so newest headlines appear continuously.
  useEffect(() => {
    if (!live) return undefined;
    const id = setInterval(() => {
      if (page === 1) {
        load({ silent: true });
      } else {
        // Still check page 1 for "new items" badge while browsing older pages.
        const qs = wireListQuery({ source, tag, page: 1 });
        api
          .get(`/api/v1/threats/${qs}`)
          .then((data) => {
            const results = data.results || [];
            const fresh = results.filter((r) => !knownIds.current.has(r.id));
            if (fresh.length) setNewCount((c) => c + fresh.length);
            setLastRefresh(new Date());
          })
          .catch(() => {});
      }
    }, POLL_MS);
    return () => clearInterval(id);
  }, [live, load, page, source, tag]);

  const resetFiltersToPage1 = (updater) => {
    firstLoad.current = true;
    knownIds.current = new Set();
    setNewCount(0);
    setPage(1);
    updater();
  };

  const changeView = (_e, next) => {
    if (!next) return;
    setView(next);
    try {
      window.localStorage.setItem(VIEW_STORAGE_KEY, next);
    } catch {
      // storage unavailable (private mode) — keep in-memory preference only
    }
  };

  // Sample numbering: newest card carries the highest ordinal.
  const cardNumber = (index) => totalCount - (page - 1) * PAGE_SIZE - index;

  return (
    <Stack spacing={2}>
      <PageHeader
        title="The Wire"
        subtitle={`Live RSS — impact intel last ${WIRE_MAX_AGE_DAYS} days; Vietnam kept on The Wire (pinned when ≤${WIRE_VIETNAM_PIN_DAYS} days old). Breaches, leaks, ransomware prioritized.`}
        action={
          <Stack direction="row" spacing={1} alignItems="center">
            <Button component={RouterLink} to="/feeds" variant="outlined" size="small">
              RSS sources
            </Button>
            <Button
              variant="outlined"
              onClick={() => {
                setNewCount(0);
                load();
              }}
            >
              Refresh
            </Button>
          </Stack>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      {newCount > 0 ? (
        <Alert
          severity="info"
          action={
            <Stack direction="row" spacing={1}>
              {page !== 1 ? (
                <Button
                  color="inherit"
                  size="small"
                  onClick={() => {
                    setNewCount(0);
                    setPage(1);
                  }}
                >
                  View newest
                </Button>
              ) : null}
              <Button color="inherit" size="small" onClick={() => setNewCount(0)}>
                Dismiss
              </Button>
            </Stack>
          }
        >
          {newCount} new item{newCount === 1 ? "" : "s"} available.
        </Alert>
      ) : null}
      <Stack
        direction={{ xs: "column", sm: "row" }}
        spacing={1.5}
        alignItems={{ sm: "center" }}
      >
        <FormControlLabel
          control={<Switch checked={live} onChange={(e) => setLive(e.target.checked)} />}
          label="Live auto-refresh (10s)"
        />
        <Typography variant="caption" color="text.secondary">
          {lastRefresh
            ? `Updated ${lastRefresh.toLocaleTimeString()} · ${WIRE_MAX_AGE_DAYS}d / VN pin ${WIRE_VIETNAM_PIN_DAYS}d · ${totalCount} items`
            : ""}
        </Typography>
      </Stack>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <TextField
          select
          size="small"
          label="Source"
          value={source}
          onChange={(e) => resetFiltersToPage1(() => setSource(e.target.value))}
          sx={{ minWidth: 180 }}
        >
          <MenuItem value="">All</MenuItem>
          {["manual", "cve_feed", "ransomware", "osint", "cert", "news", "x", "telegram"].map(
            (s) => (
              <MenuItem key={s} value={s}>
                {s}
              </MenuItem>
            )
          )}
        </TextField>
        <TextField
          select
          size="small"
          label="Topic"
          value={tag}
          onChange={(e) => resetFiltersToPage1(() => setTag(e.target.value))}
          sx={{ minWidth: 180 }}
        >
          <MenuItem value="">All</MenuItem>
          <MenuItem value="vietnam">vietnam</MenuItem>
          <MenuItem value="defacement">defacement</MenuItem>
          <MenuItem value="forum">forum</MenuItem>
          <MenuItem value="data-breach">data-breach</MenuItem>
          <MenuItem value="data-leak">data-leak</MenuItem>
          <MenuItem value="cert">cert</MenuItem>
          <MenuItem value="ransomware">ransomware</MenuItem>
          <MenuItem value="x">x</MenuItem>
        </TextField>
        <Box sx={{ ml: { sm: "auto" } }}>
          <ToggleButtonGroup
            size="small"
            exclusive
            value={view}
            onChange={changeView}
            aria-label="View mode"
          >
            <ToggleButton value="cards" aria-label="Cards view">
              <GridViewOutlinedIcon sx={{ fontSize: 16, mr: 0.5 }} />
              Cards
            </ToggleButton>
            <ToggleButton value="table" aria-label="Table view">
              <TableRowsOutlinedIcon sx={{ fontSize: 16, mr: 0.5 }} />
              Table
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>
      </Stack>
      {view === "cards" ? (
        loading ? (
          <Box sx={{ py: 6, display: "flex", justifyContent: "center" }}>
            <CircularProgress size={28} />
          </Box>
        ) : rows.length ? (
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))",
              gap: 2,
            }}
          >
            {rows.map((row, index) => (
              <WireCard key={row.id ?? index} row={row} number={cardNumber(index)} />
            ))}
          </Box>
        ) : (
          <Typography color="text.secondary" sx={{ py: 4 }}>
            No records
          </Typography>
        )
      ) : (
        <DataTable
          loading={loading}
          rows={rows}
          columns={[
            {
              id: "title",
              label: "Title",
              render: (row) => (
                <Stack spacing={0.5}>
                  <ExternalTitleLink
                    title={displayThreatTitle(row)}
                    href={resolveThreatHref(row)}
                  />
                  <WireTagChips row={row} maxTags={5} />
                </Stack>
              ),
            },
            { id: "source", label: "Source" },
            {
              id: "published_at",
              label: "Date",
              render: (row) => (
                <Typography
                  variant="body2"
                  title={`Published ${row.published_at || "—"} · On Wire ${row.created_at || "—"}`}
                >
                  {formatWireDateWithRelative(row)}
                </Typography>
              ),
            },
          ]}
        />
      )}
      <Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1}>
        <Typography variant="body2" color="text.secondary">
          Page {page} of {pageCount} · {PAGE_SIZE} per page
        </Typography>
        <Pagination
          color="primary"
          count={pageCount}
          page={page}
          onChange={(_e, value) => setPage(value)}
          showFirstButton
          showLastButton
        />
      </Stack>
    </Stack>
  );
}
