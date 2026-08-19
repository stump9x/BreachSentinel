import { useCallback, useEffect, useState } from "react";
import { Alert, Button, MenuItem, Stack, TextField, Typography } from "@mui/material";
import { api, buildQuery } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { SeverityChip, StatusChip } from "../components/StatusChips";
import { ExternalTitleLink } from "../components/ExternalTitleLink";

export default function LeaksPage() {
  const [leaks, setLeaks] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [leakType, setLeakType] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const qs = buildQuery({
        leak_type: leakType || undefined,
        page_size: 40,
        ordering: "-discovered_at",
      });
      const [leakData, credData] = await Promise.all([
        api.get(`/api/v1/leaks/${qs}`),
        api.get("/api/v1/credentials/?page_size=25&ordering=-created_at"),
      ]);
      setLeaks(leakData.results || []);
      setCredentials(credData.results || []);
    } catch (err) {
      setError(err.message || "Failed to load leaks");
    } finally {
      setLoading(false);
    }
  }, [leakType]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Data Leaks"
        subtitle="Breach events, stealer credentials, and open-web exposures (Searx/Exa + page enrich). Wire and GitHub Scanner are unchanged."
        action={
          <Stack direction="row" spacing={1}>
            <Button
              variant="outlined"
              onClick={async () => {
                setError("");
                try {
                  await api.post("/api/v1/searx/scan/", {
                    async_mode: true,
                    limit_per_keyword: 15,
                  });
                  setError("");
                  await load();
                } catch (err) {
                  setError(err.message || "Open-web sweep failed");
                }
              }}
            >
              Open-web sweep
            </Button>
            <Button variant="outlined" onClick={load}>
              Refresh
            </Button>
          </Stack>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      <TextField
        select
        size="small"
        label="Leak type"
        value={leakType}
        onChange={(e) => setLeakType(e.target.value)}
        sx={{ maxWidth: 240 }}
      >
        <MenuItem value="">All</MenuItem>
        {[
          "credentials",
          "stealer_log",
          "source_code",
          "api_key",
          "paste",
          "breach_dump",
          "other",
        ].map((t) => (
          <MenuItem key={t} value={t}>
            {t}
          </MenuItem>
        ))}
      </TextField>

      <Typography variant="h6">Leak events</Typography>
      <DataTable
        loading={loading}
        rows={leaks}
        columns={[
          {
            id: "title",
            label: "Title",
            render: (row) => (
              <ExternalTitleLink title={row.title} href={row.source_url} />
            ),
          },
          { id: "leak_type", label: "Type" },
          {
            id: "severity",
            label: "Severity",
            render: (row) => <SeverityChip value={row.severity} />,
          },
          {
            id: "status",
            label: "Status",
            render: (row) => <StatusChip value={row.status} />,
          },
          { id: "affected_domain", label: "Domain" },
          {
            id: "credential_count",
            label: "Creds",
            render: (row) => row.credential_count ?? row.record_count ?? 0,
          },
          {
            id: "evidence",
            label: "Signals",
            render: (row) => {
              const types = row.metadata?.alert_types;
              if (Array.isArray(types) && types.length) {
                return types.slice(0, 3).join(", ");
              }
              if (row.metadata?.content_fetched) return "enriched";
              return "—";
            },
          },
        ]}
      />

      <Typography variant="h6" sx={{ pt: 2 }}>
        Recent credentials
      </Typography>
      <DataTable
        loading={loading}
        rows={credentials}
        empty="No credentials ingested yet."
        columns={[
          {
            id: "identity",
            label: "Identity",
            render: (row) => (
              <ExternalTitleLink
                title={row.email || row.username || "—"}
                href={row.url}
              />
            ),
          },
          { id: "domain", label: "Domain" },
          { id: "stealer_family", label: "Stealer" },
          {
            id: "password_present",
            label: "Password",
            render: (row) => (row.password_present ? "stored (masked)" : "—"),
          },
          {
            id: "created_at",
            label: "Ingested",
            render: (row) =>
              row.created_at ? new Date(row.created_at).toLocaleString() : "—",
          },
        ]}
      />
    </Stack>
  );
}
