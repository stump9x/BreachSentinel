import { Chip } from "@mui/material";

const SEVERITY = {
  info: "default",
  low: "info",
  medium: "warning",
  high: "error",
  critical: "error",
};

const STATUS = {
  found: "success",
  not_found: "default",
  error: "error",
  unknown: "warning",
  ok: "success",
  new: "info",
  queued: "info",
  running: "warning",
  completed: "success",
  partial: "warning",
  failed: "error",
  scraped: "success",
  skipped: "default",
};

export function SeverityChip({ value }) {
  const v = (value || "").toLowerCase();
  return <Chip size="small" label={v || "—"} color={SEVERITY[v] || "default"} variant="outlined" />;
}

export function StatusChip({ value, label }) {
  const v = (value || "").toLowerCase();
  return <Chip size="small" label={label ?? (v || "—")} color={STATUS[v] || "default"} variant="outlined" />;
}
