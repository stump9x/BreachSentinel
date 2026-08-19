"""Deterministic country and region tagging for Wire threat content."""

from __future__ import annotations

import re
from urllib.parse import urlparse


# Slugs are prefixed so the UI can always render geographic tags after topics.
# Vietnam keeps its established slug because it also controls Wire retention/priority.
_GEO_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "vietnam",
        (
            "vietnam",
            "viet nam",
            "việt nam",
            "vietnamese",
            "hanoi",
            "ha noi",
            "ho chi minh",
            "saigon",
            # Native / regional scripts often appear in non-EN CTI posts.
            "越南",
            "ベトナム",
            "베트남",
            "เวียดนาม",
            "فيتنام",
        ),
    ),
    ("geo-united-states", ("united states", "u.s.", "usa", "u.s.a.", "washington dc", "美国", "アメリカ", "미국")),
    ("geo-united-kingdom", ("united kingdom", "u.k.", "britain", "british", "england", "scotland", "wales", "英国", "イギリス")),
    ("geo-canada", ("canada", "canadian", "加拿大", "カナダ")),
    ("geo-australia", ("australia", "australian", "澳大利亚", "オーストラリア")),
    ("geo-new-zealand", ("new zealand",)),
    ("geo-china", ("china", "chinese", "beijing", "中国", "中國", "中国の", "中国人")),
    ("geo-russia", ("russia", "russian", "moscow", "俄罗斯", "俄國", "ロシア", "россия")),
    ("geo-ukraine", ("ukraine", "ukrainian", "kyiv", "kiev", "乌克兰", "ウクライナ", "україна")),
    ("geo-germany", ("germany", "german", "德国", "ドイツ", "deutschland")),
    ("geo-france", ("france", "french", "法国", "フランス", "français")),
    ("geo-italy", ("italy", "italian", "意大利", "イタリア")),
    ("geo-spain", ("spain", "spanish", "西班牙", "スペイン", "españa")),
    ("geo-netherlands", ("netherlands", "dutch", "荷兰", "オランダ")),
    ("geo-belgium", ("belgium", "belgian")),
    ("geo-poland", ("poland", "polish", "波兰", "ポーランド", "polska")),
    ("geo-romania", ("romania", "romanian", "罗马尼亚", "ルーマニア", "românia")),
    ("geo-switzerland", ("switzerland", "swiss")),
    ("geo-austria", ("austria", "austrian")),
    ("geo-sweden", ("sweden", "swedish")),
    ("geo-norway", ("norway", "norwegian")),
    ("geo-denmark", ("denmark", "danish")),
    ("geo-finland", ("finland", "finnish")),
    ("geo-ireland", ("ireland", "irish")),
    ("geo-portugal", ("portugal", "portuguese")),
    ("geo-czech-republic", ("czech republic", "czechia", "czech")),
    ("geo-slovakia", ("slovakia", "slovak")),
    ("geo-greece", ("greece", "greek")),
    ("geo-turkey", ("turkey", "türkiye", "turkish", "土耳其", "トルコ")),
    ("geo-israel", ("israel", "israeli", "以色列", "イスラエル")),
    ("geo-iran", ("iran", "iranian", "伊朗", "イラン")),
    ("geo-iraq", ("iraq", "iraqi")),
    ("geo-saudi-arabia", ("saudi arabia", "saudi")),
    ("geo-united-arab-emirates", ("united arab emirates", "u.a.e.", "uae", "emirati")),
    ("geo-qatar", ("qatar", "qatari")),
    ("geo-india", ("india", "indian", "印度", "インド")),
    ("geo-pakistan", ("pakistan", "pakistani")),
    ("geo-bangladesh", ("bangladesh", "bangladeshi")),
    ("geo-sri-lanka", ("sri lanka",)),
    ("geo-japan", ("japan", "japanese", "tokyo", "日本", "東京")),
    ("geo-south-korea", ("south korea", "south korean", "republic of korea", "韩国", "韓國", "한국", "대한민국")),
    ("geo-north-korea", ("north korea", "north korean", "dprk", "朝鲜", "北朝鮮", "북한")),
    ("geo-taiwan", ("taiwan", "taiwanese", "台湾", "台灣", "臺灣")),
    ("geo-singapore", ("singapore", "singaporean", "新加坡")),
    ("geo-malaysia", ("malaysia", "malaysian", "马来西亚", "馬來西亞")),
    ("geo-indonesia", ("indonesia", "indonesian", "印度尼西亚", "インドネシア")),
    ("geo-thailand", ("thailand", "thai", "泰国", "タイ", "ประเทศไทย")),
    ("geo-philippines", ("philippines", "philippine", "filipino", "菲律宾", "フィリピン")),
    ("geo-myanmar", ("myanmar", "burma", "burmese", "缅甸")),
    ("geo-cambodia", ("cambodia", "cambodian", "柬埔寨")),
    ("geo-laos", ("laos", "laotian", "老挝", "寮国")),
    ("geo-brazil", ("brazil", "brazilian", "巴西", "ブラジル")),
    ("geo-mexico", ("mexico", "mexican", "墨西哥")),
    ("geo-argentina", ("argentina", "argentinian")),
    ("geo-chile", ("chile", "chilean")),
    ("geo-colombia", ("colombia", "colombian")),
    ("geo-south-africa", ("south africa", "south african")),
    ("geo-nigeria", ("nigeria", "nigerian")),
    ("geo-kenya", ("kenya", "kenyan")),
    ("geo-egypt", ("egypt", "egyptian", "埃及")),
    ("geo-yemen", ("yemen", "yemeni", "sana'a", "sanaa", "صنعاء", "اليمن")),
    ("geo-southeast-asia", ("southeast asia", "south-east asia", "asean")),
    ("geo-asia-pacific", ("asia pacific", "asia-pacific", "apac")),
    ("geo-middle-east", ("middle east", "middle eastern")),
    ("geo-europe", ("europe", "european union", "eu member", "欧洲", "ヨーロッパ")),
    ("geo-latin-america", ("latin america", "latin american", "latam")),
    ("geo-north-america", ("north america", "north american")),
    ("geo-africa", ("africa", "african union")),
    ("geo-emea", ("emea",)),
)

# Regional-indicator flag emoji (🇻🇳) → ISO2 → geo slug.
_FLAG_EMOJI_RE = re.compile(r"([\U0001F1E6-\U0001F1FF]{2})")

_COUNTRY_CODE_SLUGS = {
    "VN": "vietnam",
    "VNM": "vietnam",
    "US": "geo-united-states",
    "USA": "geo-united-states",
    "GB": "geo-united-kingdom",
    "GBR": "geo-united-kingdom",
    "CA": "geo-canada",
    "AU": "geo-australia",
    "CN": "geo-china",
    "RU": "geo-russia",
    "UA": "geo-ukraine",
    "DE": "geo-germany",
    "FR": "geo-france",
    "IN": "geo-india",
    "JP": "geo-japan",
    "KR": "geo-south-korea",
    "KP": "geo-north-korea",
    "SG": "geo-singapore",
    "MY": "geo-malaysia",
    "ID": "geo-indonesia",
    "TH": "geo-thailand",
    "PH": "geo-philippines",
    "TW": "geo-taiwan",
    "BR": "geo-brazil",
    "MX": "geo-mexico",
    "AR": "geo-argentina",
    "CL": "geo-chile",
    "CO": "geo-colombia",
    "ZA": "geo-south-africa",
    "NG": "geo-nigeria",
    "KE": "geo-kenya",
    "EG": "geo-egypt",
    "YE": "geo-yemen",
    "SA": "geo-saudi-arabia",
    "AE": "geo-united-arab-emirates",
    "QA": "geo-qatar",
    "TR": "geo-turkey",
    "PL": "geo-poland",
    "RO": "geo-romania",
    "NL": "geo-netherlands",
    "BE": "geo-belgium",
    "ES": "geo-spain",
    "IT": "geo-italy",
    "SE": "geo-sweden",
    "NO": "geo-norway",
    "DK": "geo-denmark",
    "FI": "geo-finland",
    "CH": "geo-switzerland",
    "AT": "geo-austria",
    "IE": "geo-ireland",
    "PT": "geo-portugal",
    "GR": "geo-greece",
    "CZ": "geo-czech-republic",
    "SK": "geo-slovakia",
    "PK": "geo-pakistan",
    "BD": "geo-bangladesh",
    "LK": "geo-sri-lanka",
    "NZ": "geo-new-zealand",
    "HK": "geo-china",
    "IR": "geo-iran",
    "IQ": "geo-iraq",
    "IL": "geo-israel",
}

# ccTLD / common second-level cc suffixes → ISO 3166-1 alpha-2.
_COMPOUND_TLD_CODES: dict[str, str] = {
    "co.uk": "GB",
    "org.uk": "GB",
    "ac.uk": "GB",
    "gov.uk": "GB",
    "com.au": "AU",
    "net.au": "AU",
    "org.au": "AU",
    "co.jp": "JP",
    "ne.jp": "JP",
    "or.jp": "JP",
    "com.br": "BR",
    "org.br": "BR",
    "com.vn": "VN",
    "org.vn": "VN",
    "gov.vn": "VN",
    "edu.vn": "VN",
    "co.id": "ID",
    "or.id": "ID",
    "web.id": "ID",
    "com.my": "MY",
    "org.my": "MY",
    "com.sg": "SG",
    "org.sg": "SG",
    "co.kr": "KR",
    "or.kr": "KR",
    "com.tw": "TW",
    "org.tw": "TW",
    "com.tr": "TR",
    "org.tr": "TR",
    "com.mx": "MX",
    "org.mx": "MX",
    "com.ar": "AR",
    "org.ar": "AR",
    "co.za": "ZA",
    "org.za": "ZA",
    "com.ng": "NG",
    "org.ng": "NG",
    "co.nz": "NZ",
    "org.nz": "NZ",
    "com.hk": "HK",
    "org.hk": "HK",
}

_CCTLD_CODES: dict[str, str] = {
    "vn": "VN",
    "uk": "GB",
    "us": "US",
    "de": "DE",
    "fr": "FR",
    "jp": "JP",
    "ru": "RU",
    "in": "IN",
    "au": "AU",
    "br": "BR",
    "id": "ID",
    "th": "TH",
    "ph": "PH",
    "my": "MY",
    "sg": "SG",
    "kr": "KR",
    "tw": "TW",
    "cn": "CN",
    "it": "IT",
    "es": "ES",
    "nl": "NL",
    "pl": "PL",
    "ro": "RO",
    "ua": "UA",
    "za": "ZA",
    "ng": "NG",
    "mx": "MX",
    "ar": "AR",
    "cl": "CL",
    "co": "CO",
    "pe": "PE",
    "ke": "KE",
    "eg": "EG",
    "sa": "SA",
    "ae": "AE",
    "qa": "QA",
    "tr": "TR",
    "se": "SE",
    "no": "NO",
    "dk": "DK",
    "fi": "FI",
    "ch": "CH",
    "at": "AT",
    "ie": "IE",
    "pt": "PT",
    "gr": "GR",
    "cz": "CZ",
    "sk": "SK",
    "pk": "PK",
    "bd": "BD",
    "lk": "LK",
    "nz": "NZ",
    "hk": "HK",
    "ir": "IR",
    "iq": "IQ",
    "il": "IL",
    "ca": "CA",
    "be": "BE",
}

_COUNTRY_NAMES: dict[str, str] = {
    "VN": "Vietnam",
    "US": "United States",
    "GB": "United Kingdom",
    "CA": "Canada",
    "AU": "Australia",
    "CN": "China",
    "RU": "Russia",
    "UA": "Ukraine",
    "DE": "Germany",
    "FR": "France",
    "IT": "Italy",
    "ES": "Spain",
    "NL": "Netherlands",
    "BE": "Belgium",
    "PL": "Poland",
    "RO": "Romania",
    "CH": "Switzerland",
    "AT": "Austria",
    "SE": "Sweden",
    "NO": "Norway",
    "DK": "Denmark",
    "FI": "Finland",
    "IE": "Ireland",
    "PT": "Portugal",
    "GR": "Greece",
    "CZ": "Czech Republic",
    "SK": "Slovakia",
    "TR": "Turkey",
    "IL": "Israel",
    "IR": "Iran",
    "IQ": "Iraq",
    "YE": "Yemen",
    "SA": "Saudi Arabia",
    "AE": "United Arab Emirates",
    "QA": "Qatar",
    "IN": "India",
    "PK": "Pakistan",
    "BD": "Bangladesh",
    "LK": "Sri Lanka",
    "JP": "Japan",
    "KR": "South Korea",
    "TW": "Taiwan",
    "SG": "Singapore",
    "MY": "Malaysia",
    "ID": "Indonesia",
    "TH": "Thailand",
    "PH": "Philippines",
    "BR": "Brazil",
    "MX": "Mexico",
    "AR": "Argentina",
    "CL": "Chile",
    "CO": "Colombia",
    "ZA": "South Africa",
    "NG": "Nigeria",
    "KE": "Kenya",
    "EG": "Egypt",
    "NZ": "New Zealand",
    "HK": "Hong Kong",
}


def country_name_for_code(country_code: str) -> str:
    return _COUNTRY_NAMES.get(str(country_code or "").strip().upper(), "")


def infer_country_from_domain(domain: str) -> tuple[str, str]:
    """Best-effort ISO code + display name from a defaced host / URL."""
    raw = str(domain or "").strip().lower()
    if not raw:
        return "", ""
    if raw.startswith(("http://", "https://")):
        host = (urlparse(raw).hostname or "").lower()
    else:
        host = raw.split("/")[0].split(":")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return "", ""

    suffix2 = ".".join(parts[-2:])
    code = _COMPOUND_TLD_CODES.get(suffix2) or _CCTLD_CODES.get(parts[-1], "")
    if not code:
        return "", ""
    return code, country_name_for_code(code)


def infer_country_from_flag_html(html: str) -> tuple[str, str]:
    """Parse Zone-H / Haxor archive flag icons (``flag flag-us`` + title)."""
    fragment = str(html or "")
    match = re.search(r"flag\s+flag-([a-z]{2})\b", fragment, re.I)
    if not match:
        return "", ""
    code = match.group(1).upper()
    label_match = re.search(
        r"(?:title|alt)=['\"]([^'\"]+)['\"]",
        fragment[match.start() : match.start() + 180],
        re.I,
    )
    if not label_match:
        label_match = re.search(
            r"(?:title|alt)=['\"]([^'\"]+)['\"]",
            fragment[max(0, match.start() - 80) : match.start()],
            re.I,
        )
    name = label_match.group(1).strip() if label_match else ""
    if not name:
        name = country_name_for_code(code)
    return code, name


def _alias_is_latin(alias: str) -> bool:
    """Latin aliases need ASCII word boundaries; CJK/Arabic need substring match."""
    return not re.search(r"[^\x00-\x7f]", alias or "")


def _alias_pattern(alias: str) -> re.Pattern[str]:
    escaped = re.escape(alias).replace(r"\ ", r"[\s-]+")
    if _alias_is_latin(alias):
        # ASCII-only boundaries so CJK neighbors do not block Latin country names,
        # and so "status" does not match "us".
        return re.compile(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", re.IGNORECASE)
    # Native-script aliases: match as literal substring (no \w lookaround —
    # Python \w includes CJK and would break 日本 / 越南 detection).
    return re.compile(escaped)


def iso2_from_flag_emoji(emoji: str) -> str:
    """Convert a regional-indicator pair (🇻🇳) to ISO 3166-1 alpha-2."""
    chars = [c for c in (emoji or "") if "\U0001F1E6" <= c <= "\U0001F1FF"]
    if len(chars) < 2:
        return ""
    c0 = ord(chars[0]) - 0x1F1E6
    c1 = ord(chars[1]) - 0x1F1E6
    if 0 <= c0 <= 25 and 0 <= c1 <= 25:
        return chr(ord("A") + c0) + chr(ord("A") + c1)
    return ""


_GEO_PATTERNS = tuple(
    (slug, tuple(_alias_pattern(alias) for alias in aliases))
    for slug, aliases in _GEO_ALIASES
)


def detect_geography_tag_slugs(*parts: str, country_code: str = "") -> list[str]:
    """Return stable geography slugs found explicitly in content.

    Detects Latin country names, native-script aliases, ISO codes, and flag emoji.
    """
    text = " ".join(str(part or "") for part in parts).strip()
    found: list[str] = []

    code_slug = _COUNTRY_CODE_SLUGS.get(str(country_code or "").strip().upper())
    if code_slug:
        found.append(code_slug)

    if text:
        for match in _FLAG_EMOJI_RE.finditer(text):
            iso2 = iso2_from_flag_emoji(match.group(1))
            slug = _COUNTRY_CODE_SLUGS.get(iso2)
            if slug and slug not in found:
                found.append(slug)

        for slug, patterns in _GEO_PATTERNS:
            if slug not in found and any(pattern.search(text) for pattern in patterns):
                found.append(slug)
    # "South Africa" contains the continent name but the country is more precise.
    if "geo-south-africa" in found and "geo-africa" in found:
        found.remove("geo-africa")
    return found
