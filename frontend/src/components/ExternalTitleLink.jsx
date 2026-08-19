import { Link, Typography } from "@mui/material";

/**
 * Clickable title that opens an external URL in a new tab.
 * Falls back to plain text when no safe http(s) URL is available.
 */
export function ExternalTitleLink({ title, href, fallback = "—" }) {
  const label = title || fallback;
  const safe = typeof href === "string" ? href.trim() : "";
  const isHttp = /^https?:\/\//i.test(safe);

  if (!isHttp) {
    return (
      <Typography variant="body2" component="span">
        {label}
      </Typography>
    );
  }

  return (
    <Link
      href={safe}
      target="_blank"
      rel="noopener noreferrer"
      underline="hover"
      variant="body2"
      sx={{ color: "secondary.main", fontWeight: 500 }}
    >
      {label}
    </Link>
  );
}

/** Prefer explicit source_url; for url/domain IOCs derive a browsable link. */
export function resolveRecordHref(row) {
  if (!row || typeof row !== "object") return "";
  if (row.source_url && /^https?:\/\//i.test(row.source_url)) return row.source_url;
  if (row.url && /^https?:\/\//i.test(row.url)) return row.url;
  if (row.ioc_type === "url" && row.value && /^https?:\/\//i.test(row.value)) {
    return row.value;
  }
  if (row.ioc_type === "domain" && row.value) return `https://${row.value}`;
  return "";
}

/** Keep ransomware titles browsable even when an upstream record omits its detail URL. */
export function resolveThreatHref(row) {
  if (!row || typeof row !== "object") return "";
  if (row.source_url && /^https?:\/\//i.test(row.source_url)) return row.source_url;
  if (row.source === "ransomware") return "https://www.ransomware.live/";
  return "";
}
