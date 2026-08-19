import { useEffect, useState } from "react";
import { Alert, Stack, Typography } from "@mui/material";
import { Link as RouterLink } from "react-router-dom";
import Button from "@mui/material/Button";
import { api } from "../api/client";
import { KpiStrip } from "../components/KpiStrip";
import { PageHeader } from "../components/PageHeader";
import { DataTable } from "../components/DataTable";
import { formatWireDateWithRelative, compareByWireDisplayTime } from "../utils/dateTime";
import {
  ExternalTitleLink,
  resolveThreatHref,
} from "../components/ExternalTitleLink";
import { displayThreatTitle } from "../utils/threatTitle";

export default function DashboardPage() {
  const [stats, setStats] = useState({
    indicators: 0,
    threats: 0,
    leaks: 0,
    credentials: 0,
  });
  const [recentThreats, setRecentThreats] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const [ind, threatCount, wire, leak, cred] = await Promise.all([
          api.get("/api/v1/indicators/?page_size=1"),
          api.get("/api/v1/threats/?page_size=1"),
          api.get(
            "/api/v1/threats/?wire_feed=true&page_size=10&ordering=-published_at,-id"
          ),
          api.get("/api/v1/leaks/?page_size=1"),
          api.get("/api/v1/credentials/?page_size=1"),
        ]);
        if (cancelled) return;
        setStats({
          indicators: ind.count ?? 0,
          threats: threatCount.count ?? 0,
          leaks: leak.count ?? 0,
          credentials: cred.count ?? 0,
        });
        setRecentThreats(
          [...(wire.results || [])].sort((a, b) => compareByWireDisplayTime(a, b))
        );
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load overview");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Stack spacing={1}>
      <PageHeader
        title="Overview"
        subtitle="Live counts across IOCs, The Wire, leaks, and stealer credentials."
        action={
          <Button component={RouterLink} to="/osint" variant="contained">
            Run OSINT scan
          </Button>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      <KpiStrip
        items={[
          { label: "Indicators", value: loading ? "…" : stats.indicators },
          { label: "Threats", value: loading ? "…" : stats.threats, accent: "secondary.main" },
          { label: "Data leaks", value: loading ? "…" : stats.leaks, accent: "warning.main" },
          {
            label: "Credentials",
            value: loading ? "…" : stats.credentials,
            accent: "error.main",
          },
        ]}
      />
      <Typography variant="h6" sx={{ mb: 1.5, mt: 1 }}>
        Latest on The Wire
      </Typography>
      <DataTable
        loading={loading}
        rows={recentThreats}
        empty="No threat items yet — ingest feeds from Workers."
        columns={[
          {
            id: "title",
            label: "Title",
            render: (row) => (
              <ExternalTitleLink
                title={displayThreatTitle(row)}
                href={resolveThreatHref(row)}
              />
            ),
          },
          { id: "source", label: "Source" },
          {
            id: "published_at",
            label: "Published",
            render: (row) => formatWireDateWithRelative(row),
          },
        ]}
      />
    </Stack>
  );
}
