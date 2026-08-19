const HIDDEN_TAGS = new Set(["news", "rss", "alleged-claim"]);

/** Region-level geo slugs — deprioritized vs country tags. */
const REGION_GEO_SLUGS = new Set([
  "geo-southeast-asia",
  "geo-asia-pacific",
  "geo-middle-east",
  "geo-europe",
  "geo-latin-america",
  "geo-north-america",
  "geo-africa",
  "geo-emea",
]);

/** geo-* / vietnam → ISO 3166-1 alpha-2 for flag emoji. */
const GEO_ISO2 = {
  vietnam: "VN",
  "geo-united-states": "US",
  "geo-united-kingdom": "GB",
  "geo-canada": "CA",
  "geo-australia": "AU",
  "geo-new-zealand": "NZ",
  "geo-china": "CN",
  "geo-russia": "RU",
  "geo-ukraine": "UA",
  "geo-germany": "DE",
  "geo-france": "FR",
  "geo-italy": "IT",
  "geo-spain": "ES",
  "geo-netherlands": "NL",
  "geo-belgium": "BE",
  "geo-poland": "PL",
  "geo-romania": "RO",
  "geo-switzerland": "CH",
  "geo-austria": "AT",
  "geo-sweden": "SE",
  "geo-norway": "NO",
  "geo-denmark": "DK",
  "geo-finland": "FI",
  "geo-ireland": "IE",
  "geo-portugal": "PT",
  "geo-czech-republic": "CZ",
  "geo-slovakia": "SK",
  "geo-greece": "GR",
  "geo-turkey": "TR",
  "geo-israel": "IL",
  "geo-iran": "IR",
  "geo-iraq": "IQ",
  "geo-yemen": "YE",
  "geo-saudi-arabia": "SA",
  "geo-united-arab-emirates": "AE",
  "geo-qatar": "QA",
  "geo-india": "IN",
  "geo-pakistan": "PK",
  "geo-bangladesh": "BD",
  "geo-sri-lanka": "LK",
  "geo-japan": "JP",
  "geo-south-korea": "KR",
  "geo-north-korea": "KP",
  "geo-taiwan": "TW",
  "geo-singapore": "SG",
  "geo-malaysia": "MY",
  "geo-indonesia": "ID",
  "geo-thailand": "TH",
  "geo-philippines": "PH",
  "geo-myanmar": "MM",
  "geo-cambodia": "KH",
  "geo-laos": "LA",
  "geo-brazil": "BR",
  "geo-mexico": "MX",
  "geo-argentina": "AR",
  "geo-chile": "CL",
  "geo-colombia": "CO",
  "geo-south-africa": "ZA",
  "geo-nigeria": "NG",
  "geo-kenya": "KE",
  "geo-egypt": "EG",
};

function slugOf(tag) {
  return String(tag?.slug || tag?.name || "").toLowerCase();
}

export function isGeographyTag(tag) {
  const slug = slugOf(tag);
  return slug === "vietnam" || slug.startsWith("geo-");
}

export function isRegionGeographyTag(tag) {
  return REGION_GEO_SLUGS.has(slugOf(tag));
}

export function geographyIso2(tag) {
  const slug = slugOf(tag);
  return GEO_ISO2[slug] || "";
}

/** Regional-indicator flag emoji from ISO2 (optional; UI prefers flagcdn img). */
export function flagEmojiFromIso2(iso2) {
  const code = String(iso2 || "")
    .trim()
    .toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  return String.fromCodePoint(
    ...[...code].map((ch) => 0x1f1e6 - 65 + ch.charCodeAt(0))
  );
}

/** Official flag PNG (flagcdn) — reliable vs emoji fonts on Windows. */
export function geographyFlagUrl(tag, width = 20) {
  const iso = geographyIso2(tag);
  if (!iso) return "";
  const w = Math.max(16, Math.min(Number(width) || 20, 80));
  return `https://flagcdn.com/w${w}/${iso.toLowerCase()}.png`;
}

export function geographyFlagEmoji(tag) {
  const iso = geographyIso2(tag);
  return iso ? flagEmojiFromIso2(iso) : "";
}

/** "site-example-com" → "example.com" for website chip labels. */
export function formatWebsiteTag(tag) {
  const slug = String(tag?.slug || tag?.name || "");
  const site = slug.replace(/^site-/, "");
  return site.replace(/-(com|org|net|io|me|nz|st|fi|is|news)$/, ".$1");
}

/** Plain country/region name for Chip label (flag rendered separately as img). */
export function geographyTagLabel(tag) {
  const slug = slugOf(tag).replace(/^geo-/, "");
  return slug
    .split("-")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

/** Country tags first, then regions; Vietnam pinned ahead of other countries. */
export function preferCountryGeography(tags) {
  const list = Array.isArray(tags) ? [...tags] : [];
  list.sort((a, b) => {
    const sa = slugOf(a);
    const sb = slugOf(b);
    if (sa === "vietnam" && sb !== "vietnam") return -1;
    if (sb === "vietnam" && sa !== "vietnam") return 1;
    const ra = isRegionGeographyTag(a) ? 1 : 0;
    const rb = isRegionGeographyTag(b) ? 1 : 0;
    return ra - rb;
  });
  return list;
}

/**
 * Website / KEV / topics first, geography last (reserved).
 * Country tags are preferred over region tags; alleged-claim is hidden.
 */
export function orderedWireTags(row, maxTags = 5) {
  const tags = Array.isArray(row?.tags) ? row.tags : [];
  const website = tags.find((tag) => slugOf(tag).startsWith("site-"));
  const geography = preferCountryGeography(tags.filter(isGeographyTag));
  const topics = tags.filter((tag) => {
    const slug = slugOf(tag);
    return (
      !slug.startsWith("site-") &&
      !HIDDEN_TAGS.has(slug) &&
      !isGeographyTag(tag)
    );
  });

  const geoBudget = Math.min(2, geography.length);
  const geoSelected = geography.slice(0, geoBudget);
  const headBudget = Math.max(0, maxTags - geoSelected.length);

  const ordered = [];
  if (website && ordered.length < headBudget) {
    ordered.push({ kind: "website", tag: website });
  }
  if (row?.is_kev && ordered.length < headBudget) {
    ordered.push({ kind: "kev", key: "kev" });
  }
  for (const tag of topics) {
    if (ordered.length >= headBudget) break;
    ordered.push({ kind: "topic", tag });
  }
  ordered.push(
    ...geoSelected.map((tag) => ({ kind: "geography", tag }))
  );
  return ordered.slice(0, Math.max(0, maxTags));
}
