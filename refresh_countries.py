# -*- coding: utf-8 -*-
"""Собирает список стран, где доступно веб-приложение Gemini, в виде ISO2-кодов."""

import html
import json
import pathlib
import re
import sys
import urllib.request

import pycountry

URL = "https://support.google.com/gemini/answer/13575153?hl=en"
OUT = pathlib.Path(
    r"ПАПКА_ПРОЕКТА\gemini_countries.json"
)

# Названия, которые не совпадают с базой pycountry.
OVERRIDES = {
    "Åland Islands": "AX",
    "Kosovo": "XK",
    "Saint Martin": "MF",
    "São Tomé and Príncipe": "ST",
    "Antigua and Barbuda": "AG",
    "Antigua & Barbuda": "AG",
    "Bolivia": "BO",
    "Bosnia and Herzegovina": "BA",
    "Brunei": "BN",
    "Cabo Verde": "CV",
    "Cape Verde": "CV",
    "Caribbean Netherlands": "BQ",
    "Christmas Island": "CX",
    "Cocos (Keeling) Islands": "CC",
    "Côte d'Ivoire": "CI",
    "Côte d’Ivoire": "CI",
    "Democratic Republic of the Congo": "CD",
    "Democratic Republic of Congo": "CD",
    "Falkland Islands (Islas Malvinas)": "FK",
    "Faroe Islands": "FO",
    "French Guiana": "GF",
    "French Polynesia": "PF",
    "French Southern and Antarctic Lands": "TF",
    "Heard Island and McDonald Islands": "HM",
    "Hong Kong": "HK",
    "Iran": "IR",
    "Mainland China (Workspace only)": "CN",
    "Macau": "MO",
    "Macao": "MO",
    "Micronesia": "FM",
    "Myanmar": "MM",
    "Myanmar (Burma)": "MM",
    "North Macedonia": "MK",
    "Palestine": "PS",
    "Republic of Cyprus": "CY",
    "Republic of the Congo": "CG",
    "Réunion": "RE",
    "Saint Barthélemy": "BL",
    "Saint Helena, Ascension and Tristan da Cunha": "SH",
    "Saint Kitts and Nevis": "KN",
    "South Georgia and the South Sandwich Islands": "GS",
    "St. Kitts and Nevis": "KN",
    "St. Lucia": "LC",
    "Svalbard and Jan Mayen": "SJ",
    "The Bahamas": "BS",
    "The Gambia": "GM",
    "Timor-Leste": "TL",
    "Türkiye": "TR",
    "Turkey": "TR",
    "U.S. Virgin Islands": "VI",
    "US Virgin Islands": "VI",
    "Vatican City": "VA",
    "Venezuela": "VE",
    "Vietnam": "VN",
    "Viet Nam": "VN",
    "Wallis and Futuna": "WF",
    "Western Sahara": "EH",
    "Uzbekistans": "UZ",
    "Swaziland": "SZ",
    "Eswatini": "SZ",
    "Macedonia": "MK",
    "Ivory Coast": "CI",
    "Cape verde": "CV",
    "Sint Maarten": "SX",
    "Pitcairn Islands": "PN",
    "Norfolk Island": "NF",
    "Turks and Caicos Islands": "TC",
    "Turks and Caicos": "TC",
    "Saint Vincent and the Grenadines": "VC",
    "St. Vincent and the Grenadines": "VC",
    "British Indian Ocean Territory": "IO",
    "Samoa": "WS",
    "American Samoa": "AS",
    "U.S. Minor Outlying Islands": "UM",
    "United States Minor Outlying Islands": "UM",
    "Aleutian Islands": "UM",
}


def norm(s: str) -> str:
    return re.sub(r"[^a-z]", "", s.lower())


def build_index() -> dict[str, str]:
    """Индекс название -> ISO2 по всем полям pycountry."""
    index: dict[str, str] = {}
    for country in pycountry.countries:
        for attr in ("name", "common_name", "official_name"):
            value = getattr(country, attr, None)
            if not value:
                continue
            index.setdefault(value, country.alpha_2)
            index.setdefault(norm(value), country.alpha_2)
    return index


INDEX = build_index()


def to_code(name: str) -> str | None:
    name = name.strip().rstrip(".").strip()
    if not name:
        return None
    if name in OVERRIDES:
        return OVERRIDES[name]
    return INDEX.get(name) or INDEX.get(norm(name))


def main() -> int:
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        page = resp.read().decode("utf-8", errors="replace")

    # Убираем скрипты/стили, разворачиваем в текст
    page = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S | re.I)
    # Ищем блок со странами: заголовок про countries и до следующего заголовка
    m = re.search(
        r"Supported countries[^<]*</h[23]>(.*?)(?:<h[23]|<div[^>]*id=)",
        page,
        flags=re.S | re.I,
    )
    block = m.group(1) if m else page

    # Забираем элементы списка
    items = re.findall(r"<li[^>]*>(.*?)</li>", block, flags=re.S | re.I)
    names = []
    for item in items:
        text = html.unescape(re.sub(r"<[^>]+>", "", item)).strip()
        if text and len(text) < 60:
            names.append(text)

    # На всякий случай дублируем extraction: если <li> не нашлось, режем по <br>
    if len(names) < 100:
        flat = html.unescape(re.sub(r"<[^>]+>", "\n", block))
        names = [ln.strip() for ln in flat.splitlines() if 2 < len(ln.strip()) < 60]

    codes: dict[str, str] = {}
    unmatched: list[str] = []
    for name in names:
        code = to_code(name)
        if code:
            codes[code] = name
        else:
            unmatched.append(name)

    print(f"спарсено названий: {len(names)}")
    print(f"сопоставлено ISO2 : {len(codes)}")
    if unmatched:
        print(f"НЕ РАСПОЗНАНО ({len(unmatched)}):")
        for n in unmatched:
            print("   ", n)

    payload = {
        "source": URL,
        "generated_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(timespec="seconds"),
        "countries": sorted(codes.keys()),
        "names": codes,
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"записано: {OUT}")
    return 1 if unmatched else 0


if __name__ == "__main__":
    sys.exit(main())