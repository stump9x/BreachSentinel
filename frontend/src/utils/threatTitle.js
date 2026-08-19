/** Display Wire titles in Vietnamese only. */
export function displayThreatTitle(row) {
  if (!row || typeof row !== "object") return "—";
  const vi = typeof row.title_vi === "string" ? row.title_vi.trim() : "";
  if (vi) return vi;
  return "Đang dịch…";
}
