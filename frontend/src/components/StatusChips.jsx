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
};

export function SeverityChip({ value }) {
  const v = (value || "").toLowerCase();
  return <Chip size="small" label={v || "—"} color={SEVERITY[v] || "default"} variant="outlined" />;
}

export function StatusChip({ value }) {
  const v = (value || "").toLowerCase();
  return <Chip size="small" label={v || "—"} color={STATUS[v] || "default"} variant="outlined" />;
}
