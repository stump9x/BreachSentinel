/** Feed label, e.g. "scmp-china" — falls back to the source category. */
export function wireFeedName(row) {
  if (!row || typeof row !== "object") return "";
  const payload = row.raw_payload;
  const feed =
    payload && typeof payload === "object" && typeof payload.feed === "string"
      ? payload.feed.trim()
      : "";
  return feed || String(row.source || "");
}
