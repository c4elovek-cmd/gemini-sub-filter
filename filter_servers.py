# -*- coding: utf-8 -*-
"""
Фильтр подписки ShareSub по доступности Gemini.

Что делает:
  1. Забирает подписку (base64, список vless://-ссылок).
  2. Оставляет по одной ссылке на уникальный адрес host:port.
  3. Для каждого адреса поднимает локальный SOCKS5 через xray и спрашивает
     Gemini тем же путём, которым пойдёт реальный трафик.
  4. Оставляет только те серверы, где Gemini открылся нормально.
  5. Заливает результат в Cloudflare KV, откуда его отдаёт воркер
     c4elovek.online/workgemini (Clash-конфиг или base64 — по User-Agent).

Запуск вручную:  python filter_servers.py
Только проверка без публикации:  python filter_servers.py --no-publish
"""

from __future__ import annotations

import argparse
import atexit
import base64
import gzip
import json
import os
import random
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Windows-консоль по умолчанию не умеет UTF-8 — чиним, иначе эмодзи в логах роняют вывод
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
CURL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"

# Windows: без этого флага каждый дочерний процесс (curl, xray, powershell)
# на секунду мелькает своим окном. При автозапуске из планировщика, где у
# родителя нет консоли, это превращается в спам окон.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Имена адаптеров, которые заворачивают весь трафик в один туннель.
# Пока такой адаптер поднят, проверка бессмысленна: весь интернет идёт
# через текущий сервер клиента, а не через тот, который мы тестируем.
TUN_ADAPTER_PATTERNS = ("tun", "sing-tun", "wintun", "wg", "wireguard", "amnezia")


def log(msg: str = "") -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{stamp}] {msg}", flush=True)


# --------------------------------------------------------------------------
# Конфиг
# --------------------------------------------------------------------------


def load_config(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# Подписка
# --------------------------------------------------------------------------


def fetch_subscription(cfg: dict, timeout: int = 45) -> str:
    """Скачивает подписку и возвращает список vless://-ссылок."""
    sub = cfg["subscription"]
    url = sub["api_url"].format(token=sub["token"])

    req = urllib.request.Request(
        url,
        headers={
            "X-HWID": sub["hwid"],
            "Accept": "text/plain",
            # Формат подписки зависит от User-Agent:
            #   Happ    -> Clash-JSON, Mihomo -> YAML, v2rayNG -> base64 vless.
            # Нам нужны сырые ссылки, поэтому притворяемся v2rayNG.
            "User-Agent": sub.get("user_agent", "v2rayNG/1.11.1"),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")

    # Сервер отдаёт либо base64, либо готовый текст со ссылками.
    if "://" in body[:200]:
        text = body
    else:
        padded = body.strip() + "=" * (-len(body.strip()) % 4)
        try:
            text = base64.b64decode(padded).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"не удалось разобрать base64 подписки: {exc}") from exc

    if "://" not in text[:400]:
        raise RuntimeError(
            "подписка пришла не в формате ссылок (похоже, это конфиг Clash/YAML) — "
            "проверь User-Agent в config.json"
        )

    links = [ln.strip() for ln in text.splitlines() if "://" in ln]
    if not links:
        raise RuntimeError("подписка не вернула ни одной ссылки")
    return links


# --------------------------------------------------------------------------
# Разбор ссылок
# --------------------------------------------------------------------------


@dataclass
class Server:
    """Один уникальный адрес подписки вместе с параметрами подключения."""

    link: str
    scheme: str
    host: str
    port: int
    name: str
    params: dict = field(default_factory=dict)

    @property
    def addr(self) -> str:
        return f"{self.host}:{self.port}"


def _parse_vless(link: str) -> Server | None:
    try:
        parsed = urllib.parse.urlsplit(link)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        if not uuid or not host:
            return None
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        name = urllib.parse.unquote(parsed.fragment or "")
        return Server(
            link=link,
            scheme="vless",
            host=host,
            port=int(port),
            name=name or f"{host}:{port}",
            params={"uuid": uuid, **params},
        )
    except Exception:  # noqa: BLE001
        return None


def _parse_trojan(link: str) -> Server | None:
    try:
        parsed = urllib.parse.urlsplit(link)
        password = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        if not password or not host:
            return None
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        name = urllib.parse.unquote(parsed.fragment or "")
        return Server(
            link=link,
            scheme="trojan",
            host=host,
            port=int(port),
            name=name or f"{host}:{port}",
            params={"password": password, **params},
        )
    except Exception:  # noqa: BLE001
        return None


def _parse_vmess(link: str) -> Server | None:
    try:
        raw = link.split("://", 1)[1]
        raw += "=" * (-len(raw) % 4)
        data = json.loads(base64.b64decode(raw).decode("utf-8", errors="replace"))
        host = data.get("add")
        port = int(data.get("port") or 443)
        if not host:
            return None
        return Server(
            link=link,
            scheme="vmess",
            host=host,
            port=port,
            name=data.get("ps") or f"{host}:{port}",
            params={
                "uuid": data.get("id"),
                "alterId": data.get("aid") or "0",
                "network": data.get("net") or "tcp",
                "host": data.get("host") or "",
                "path": data.get("path") or "",
                "tls": data.get("tls") or "",
                "sni": data.get("sni") or data.get("host") or "",
            },
        )
    except Exception:  # noqa: BLE001
        return None


def _parse_hysteria2(link: str) -> Server | None:
    try:
        parsed = urllib.parse.urlsplit(link)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return None
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        return Server(
            link=link,
            scheme="hysteria2",
            host=host,
            port=int(port),
            name=urllib.parse.unquote(parsed.fragment or "") or f"{host}:{port}",
            params={"password": parsed.username or "", **params},
        )
    except Exception:  # noqa: BLE001
        return None


PARSERS = {
    "vless": _parse_vless,
    "trojan": _parse_trojan,
    "vmess": _parse_vmess,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
}


# --------------------------------------------------------------------------
# Чистка подписей
# --------------------------------------------------------------------------

# Подписи из подписки перегружены мусором после страны: домены в квадратных
# скобках, метки «NEW», служебные пиктограммы. Пользователь просил их убрать,
# поэтому чистим на входе — тогда и подписка, и страница показывают одно и то же.
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")
BRACKET_RE = re.compile(r"\[[^\]]*\]")
# Декораторы вроде «^~2~^» — в подписи они только мешают.
TILDE_RE = re.compile(r"[\^~]{2,}")
JUNK_WORDS_RE = re.compile(r"\b(?:new|bridge|новинка)\b", re.IGNORECASE)
JUNK_CHARS = "⭐⚡📱🔒·"
# Рекламные хвосты вроде «YT без рекламы» — пользователь просил без приписок.
NOISE_TAIL_RE = re.compile(
    r"(?:\s+(?:yt|youtube|no\s+ads?|без\s+рекламы|реклам[аыеы]|free|premium"
    r"|unlocked|без\s+ограничений))+$",
    re.IGNORECASE,
)
# Хвостовой номер узла: #2, № 2, -1, II, ll, AI. К стране отношения не имеет.
TAIL_IDX_RE = re.compile(r"[\s·№#\-]*(?:\d{1,2}|[IVXLC]{1,4}|l{1,2}|AI)\s*$", re.IGNORECASE)


def _fix_case(text: str) -> str:
    """«АЛБАНИЯ» → «Албания». Короткие слова не трогаем: «США» — это США."""
    return " ".join(
        w.capitalize() if len(w) > 3 and w.isupper() else w
        for w in text.split(" ")
    )


def clean_name(raw: str) -> tuple[str, str, str]:
    """Разбирает подпись на (провайдер с флагом, флаг страны, страна).

    Страну берём из самой подписи, а не из GeoIP: сортировка должна идти по
    тому, что пользователь видит в списке, а замер привязан к адресу и меняется
    при каждом запуске. Подпись, наоборот, приходит из подписки целиком.
    """
    text = urllib.parse.unquote(raw or "")
    text = BRACKET_RE.sub(" ", text)
    text = TILDE_RE.sub(" ", text)
    for junk in JUNK_CHARS:
        text = text.replace(junk, " ")
    text = text.replace("№", " ")
    text = JUNK_WORDS_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "", "", ""

    # «DeVPN ⏳2d | 🇩🇪 Bridge | Германия» — провайдер отделён двумя чертами,
    # поэтому хвост собираем из всех частей после первой.
    parts = [p.strip() for p in text.split("|") if p.strip()]
    head = parts[0] if parts else ""
    body = " ".join(parts[1:]) if len(parts) > 1 else text

    match = FLAG_RE.search(body)
    flag = match.group(0) if match else ""
    rest = FLAG_RE.sub(" ", body)
    rest = JUNK_WORDS_RE.sub(" ", rest)
    # Рекламный хвост снимаем до номера: иначе «YT без рекламы» попадёт в страну.
    rest = TAIL_IDX_RE.sub("", rest)
    rest = NOISE_TAIL_RE.sub("", rest)

    # Номер в хвосте убираем до конца: у AkariVPN это «ll 2», где «2» — вторая
    # копия узла, а «ll» — сам номер. С одним проходом осталось бы «ll».
    country = rest
    for _ in range(3):
        trimmed = TAIL_IDX_RE.sub("", country)
        if trimmed == country:
            break
        country = trimmed
    country = _fix_case(re.sub(r"\s+", " ", country).strip(" -–—"))

    return head, flag, country


def _compose_name(head: str, flag: str, country: str, index: int | None) -> str:
    parts = [flag, country]
    if index:
        parts.append(str(index))
    tail = " ".join(p for p in parts if p)
    return f"{head} | {tail}" if head and tail else (tail or head)


def _relink(server: Server) -> str:
    """Переписывает имя прямо в ссылке — иначе клиенты увидят старое."""
    parts = urllib.parse.urlsplit(server.link)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, parts.query,
         urllib.parse.quote(server.name, safe=""))
    )


def normalize_names(servers: list[Server]) -> list[Server]:
    """Чистит подписи и сортирует серверы по странам.

    Сортировка: страна, потом провайдер, потом исходный порядок. Номера внутри
    пары (провайдер, страна) расставляются заново — после удаления доменных
    подсказок половина имён схлопывается в одинаковые, и в Happ они слипаются.
    """
    parsed: list[tuple[Server, str, str, str, int]] = []
    for position, server in enumerate(servers):
        head, flag, country = clean_name(server.name)
        parsed.append((server, head, flag, country, position))

    totals = Counter((item[1], item[3]) for item in parsed)
    counters: Counter[tuple[str, str]] = Counter()
    for server, head, flag, country, _ in parsed:
        key = (head, country)
        counters[key] += 1
        server.name = _compose_name(head, flag, country,
                                    counters[key] if totals[key] > 1 else None)

    parsed.sort(key=lambda item: (item[3].lower(), item[1].lower(), item[4]))
    for server, *_ in parsed:
        server.link = _relink(server)
    return [item[0] for item in parsed]


def country_sort_key(server: Server) -> tuple[str, str]:
    """Ключ «страна, потом провайдер» для выдачи и для страницы."""
    head, _, country = clean_name(server.name)
    return (country.lower(), provider_name(head).lower())


def parse_servers(links: list[str]) -> tuple[list[Server], dict[str, int]]:
    """Парсит ссылки и оставляет по одной на уникальный host:port."""
    skipped: dict[str, int] = {}
    by_addr: dict[tuple[str, int], Server] = {}

    for link in links:
        scheme = link.split("://", 1)[0].lower()
        parser = PARSERS.get(scheme)
        if parser is None:
            skipped[scheme] = skipped.get(scheme, 0) + 1
            continue
        server = parser(link)
        if server is None:
            skipped[f"{scheme}(битая)"] = skipped.get(f"{scheme}(битая)", 0) + 1
            continue
        # Ключ — только адрес: пользователь просил уникальные адресы,
        # а не все 473 однотипные ссылки на одни и те же хосты.
        by_addr.setdefault((server.host, server.port), server)

    return normalize_names(list(by_addr.values())), skipped


# --------------------------------------------------------------------------
# Проверка TUN
# --------------------------------------------------------------------------


def active_tun_adapters() -> list[str]:
    """Имена поднятых TUN-адаптеров. Пустой список — трафик не заворачивается."""
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } "
                "| Select-Object -ExpandProperty Name",
            ],
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
            creationflags=NO_WINDOW,
        )
    except Exception:  # noqa: BLE001
        return []
    if proc.returncode != 0:
        return []
    found = []
    for raw in proc.stdout.splitlines():
        name = raw.strip()
        low = name.lower()
        if any(pat in low for pat in TUN_ADAPTER_PATTERNS):
            found.append(name)
    return found


# Префикс временной папки с конфигом. По нему же ищем свои осиротевшие
# процессы: xray, запущенный нашим скриптом, всегда несёт его в командной строке.
STAMP = "gemcheck_"


def cleanup_orphan_xrays() -> int:
    """Гасит xray-процессы, оставшиеся от прошлых прерванных запусков.

    Если скрипт убили, его дочерние xray остаются висеть и занимают память.
    Ищем строго по метке в командной строке, поэтому ядра Happ и v2rayN
    (которые тоже зовутся xray.exe) не затрагиваются.
    """
    script = (
        f"Get-CimInstance Win32_Process -Filter \"Name='xray.exe'\" "
        f"| Where-Object {{ $_.CommandLine -match '{STAMP}' }} "
        f"| ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            creationflags=NO_WINDOW,
        )
    except Exception:  # noqa: BLE001
        return 0
    return 0 if proc.returncode == 0 else 0


# --------------------------------------------------------------------------
# Конфиг xray
# --------------------------------------------------------------------------


def _reality_params(server: Server) -> dict:
    p = server.params
    reality = {
        "serverName": p.get("sni") or p.get("host") or "",
        "fingerprint": p.get("fp") or "chrome",
        "publicKey": p.get("pbk") or "",
        "spiderX": p.get("spx") or "/",
    }
    if p.get("sid"):
        reality["shortId"] = p["sid"]
    return {k: v for k, v in reality.items() if v}


def build_xray_config(server: Server, socks_port: int) -> dict:
    """Собирает минимальный конфиг xray: один SOCKS-инбаунд, один аутбаунд."""
    p = server.params
    network = (p.get("type") or p.get("network") or "tcp").lower()
    security = (p.get("security") or "").lower()

    if network in ("h2",):
        network = "http"
    if network == "tcp":
        # В свежих версиях xray канал называется raw, tcp остаётся синонимом.
        network = "tcp"

    stream: dict = {"network": network, "security": security or "none"}

    if security == "reality":
        stream["realitySettings"] = _reality_params(server)
    elif security == "tls":
        sni = p.get("sni") or p.get("host") or ""
        if sni:
            stream["tlsSettings"] = {
                "serverName": sni,
                "fingerprint": p.get("fp") or "chrome",
                "allowInsecure": False,
            }
        if p.get("alpn"):
            stream["tlsSettings"]["alpn"] = [
                x.strip() for x in p["alpn"].split(",") if x.strip()
            ]

    path = urllib.parse.unquote(p.get("path") or "/")
    if network == "ws":
        ws = {"path": path}
        host_hdr = p.get("host")
        if host_hdr:
            ws["headers"] = {"Host": host_hdr}
        stream["wsSettings"] = ws
    elif network == "xhttp":
        # У mihomo/xray сетевой тип называется xhttp (бывший splithttp).
        stream["network"] = "xhttp"
        xhttp: dict = {"path": path}
        if p.get("mode"):
            xhttp["mode"] = p["mode"]
        stream["xhttpSettings"] = xhttp
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": p.get("serviceName") or "",
            "multiMode": (p.get("mode") or "") == "multi",
        }
    elif network == "http":
        stream["httpSettings"] = {
            "path": path,
            "headers": {"Host": [p["host"]]} if p.get("host") else {},
        }

    user: dict = {"encryption": "none"}
    if server.scheme == "vless":
        user["id"] = p.get("uuid") or ""
        if p.get("flow"):
            user["flow"] = p["flow"]
    elif server.scheme == "trojan":
        user = {"password": p.get("password") or ""}
    elif server.scheme == "vmess":
        user["id"] = p.get("uuid") or ""
        user["alterId"] = int(p.get("alterId") or 0)
    elif server.scheme in ("hysteria2", "hy2"):
        user = {"password": p.get("password") or ""}

    if server.scheme in ("hysteria2", "hy2"):
        outbound = {
            "protocol": "hysteria2",
            "settings": {
                "servers": [
                    {
                        "address": server.host,
                        "port": server.port,
                        "password": p.get("password") or "",
                        "sni": p.get("sni") or "",
                    }
                ]
            },
        }
        stream = {"network": "udp"}
    else:
        outbound = {
            "protocol": server.scheme,
            "settings": {
                "vnext": [
                    {
                        "address": server.host,
                        "port": server.port,
                        "users": [user],
                    }
                ]
            },
        }

    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [outbound | {"streamSettings": stream}],
    }


# --------------------------------------------------------------------------
# Проверка одного сервера
# --------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_port(port: int, deadline: float) -> bool:
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _curl(port: int, url: str, out: Path, timeout: int, accept: str = "") -> int:
    """Один запрос через SOCKS. Возвращает HTTP-код (0 — связи нет)."""
    cmd = [
        str(CURL), "-s", "-L",
        "--max-time", str(timeout),
        "--socks5-hostname", f"127.0.0.1:{port}",
    ]
    if accept:
        cmd += ["-H", f"Accept: {accept}"]
    else:
        cmd += ["-A", "curl/8.0"]
    cmd += ["-o", str(out), "-w", "%{http_code}", url]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        creationflags=NO_WINDOW,
    )
    code = (proc.stdout or "").strip()[-3:]
    return int(code) if code.isdigit() else 0


# Эндпоинты для определения страны выхода. Первый основной, дальше запасные.
GEO_ENDPOINTS = [
    ("http://ip-api.com/json/?fields=status,countryCode,countryName,query", "json"),
    ("https://api.ip.sb/geoip", "json"),
    ("https://countryinfo.io/api/country/ip", "json"),
]


def probe_country(port: int, timeout: int, tmp: Path) -> tuple[str, str]:
    """Определяет страну выхода. Возвращает (код ISO2 или '', пояснение)."""
    for url, kind in GEO_ENDPOINTS:
        out = tmp / "geo.json"
        try:
            code = _curl(port, url, out, timeout)
        except Exception:  # noqa: BLE001
            continue
        if code != 200 or not out.exists():
            continue
        try:
            data = json.loads(out.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(data, dict):
            continue
        cc = ""
        for field in ("countryCode", "country_code", "country", "countryIso"):
            value = data.get(field)
            if isinstance(value, str) and len(value) == 2 and value.isalpha():
                cc = value.upper()
                break
        if cc:
            return cc, str(data.get("query") or "")
    return "", ""


def load_allowed_countries(path: Path) -> set[str]:
    if not path.exists():
        log(f"ВНИМАНИЕ: нет файла стран {path.name} — проверка региона отключена")
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {c.upper() for c in data.get("countries", [])}


@dataclass
class Result:
    server: Server
    ok: bool
    reason: str
    ms: int
    status: int = 0
    country: str = ""
    exit_ip: str = ""


def _probe_gemini(socks_port: int, check: dict, body_path: Path, timeout: int) -> tuple[int, int, str]:
    """Спрашивает Gemini через SOCKS. Возвращает (код, размер тела, текст)."""
    # Google отвечает 429, когда по нему долбят сразу много адресов.
    # Это не значит, что сервер плохой, поэтому пробуем ещё раз.
    status = 0
    for attempt in range(2):
        status = _curl(
            socks_port,
            check["probe_url"],
            body_path,
            timeout,
            accept=check["user_agent"],
        )
        if status != 429:
            break
        if attempt == 0:
            time.sleep(2.5)

    size = body_path.stat().st_size if body_path.exists() else 0
    text = body_path.read_text(encoding="utf-8", errors="replace") if size else ""
    return status, size, text.lower()


def check_server(server: Server, cfg: dict, xray: Path, allowed: set[str]) -> Result:
    """Поднимает xray на этом сервере и проверяет, откроется ли Gemini.

    Порядок шагов выбран из-за лимитов геосервиса, а не из логики. Региональная
    блокировка в разметке не видна: русский и немецкий выходы отдают одинаковый
    200 OK на /app, /chat и robots.txt. Единственный способ её увидеть — страна
    выхода, но геосервисы отдают бесплатные запросы десятками в минуту, и на
    321 адресах половина запросов отваливалась. Из-за этого в прошлый раз
    151 сервер выпал на гео, не спросив у Gemini ничего.

    Поэтому сначала спрашиваем сам Gemini: это один запрос на сервер и сразу
    отсекает мёртвые. Гео спрашиваем только у тех, кто ответил 200 — таких
    около сотни, лимит перестаёт мешать, и страна определяется почти всегда.
    """
    check = cfg["check"]
    timeout = int(check["timeout_seconds"])
    grace = int(check["startup_grace_seconds"])
    socks_port = _free_port()

    with tempfile.TemporaryDirectory(prefix="gemcheck_") as tmpdir:
        tmp = Path(tmpdir)
        conf_path = tmp / "config.json"
        conf_path.write_text(
            json.dumps(build_xray_config(server, socks_port), ensure_ascii=False),
            encoding="utf-8",
        )

        try:
            proc = subprocess.Popen(
                [str(xray), "run", "-c", str(conf_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=NO_WINDOW,
            )
        except OSError as exc:
            return Result(server, False, f"не запустился xray: {exc}", 0)

        try:
            if not _wait_port(socks_port, time.monotonic() + grace):
                return Result(server, False, "xray не поднял SOCKS", 0)

            started = time.monotonic()

            # --- шаг 1: открывается ли Gemini вообще
            body_path = tmp / "probe.html"
            try:
                status, size, low = _probe_gemini(socks_port, check, body_path, timeout)
            except Exception as exc:  # noqa: BLE001
                return Result(server, False, f"ошибка запроса: {exc}", 0, status=0)

            elapsed = int((time.monotonic() - started) * 1000)

            if proc.poll() is not None:
                return Result(server, False, "xray упал", elapsed, status=status)

            if status not in check["accepted_status"]:
                return Result(
                    server, False, f"Gemini ответил HTTP {status}", elapsed,
                    status=status,
                )

            for marker in check["block_markers"]:
                if marker.lower() in low:
                    return Result(
                        server, False, "Gemini заблокирован регионом", elapsed,
                        status=status,
                    )

            if size < int(check["min_content_bytes"]):
                return Result(
                    server, False, f"мало данных ({size} Б)", elapsed,
                    status=status,
                )

            if not any(m.lower() in low for m in check["good_markers"]):
                return Result(
                    server, False, "нет маркера Gemini в ответе", elapsed,
                    status=status,
                )

            # --- шаг 2: страна выхода, но только для тех, кто уже ответил
            country, exit_ip = probe_country(socks_port, timeout, tmp)

            if not country:
                # Gemini отдал настоящую страницу — сервер работает. Регион не
                # проверен, но выбрасывать рабочий сервер из-за лимита геосервиса
                # хуже, чем оставить одну непроверенную страну.
                return Result(
                    server, True, "страна не определена, но Gemini ответил", elapsed,
                    status=status, country="", exit_ip=exit_ip,
                )

            if allowed and country not in allowed:
                return Result(
                    server, False, f"страна {country} — Gemini недоступен", elapsed,
                    status=status, country=country, exit_ip=exit_ip,
                )

            return Result(
                server, True, f"{country} · HTTP {status}", elapsed,
                status=status, country=country, exit_ip=exit_ip,
            )
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


# --------------------------------------------------------------------------
# Публикация
# --------------------------------------------------------------------------


def fetch_profile(cfg: dict, timeout: int = 30) -> dict:
    """Данные профиля подписки: до какого числа действует, трафик, устройства.

    Нужны странице, чтобы показать «до истечения подписки». Срок берём из
    профиля, а не вычисляем на глаз.
    """
    sub = cfg["subscription"]
    profile_url = sub.get("profile_url") or (
        "https://sub.sharesub.ru/api/subscription-page/{token}"
    ).format(token=sub["token"])

    req = urllib.request.Request(
        profile_url,
        headers={"X-HWID": sub["hwid"], "User-Agent": sub.get("user_agent", "v2rayNG/1.11.1")},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        log(f"  профиль подписки недоступен: {exc}")
        return {}

    def _int(value) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    return {
        "expire_at": data.get("expireAt") or None,
        "title": data.get("displayName") or data.get("profileTitle") or "",
        "status": data.get("status") or "",
        "active": bool(data.get("active")),
        "traffic_used": _int(data.get("usedTrafficBytes")),
        "traffic_limit": _int(data.get("trafficLimitBytes")),
        "devices": _int(data.get("devices")),
        "device_limit": _int(data.get("deviceLimit")),
        "total_hosts": _int(data.get("activeHosts")),
        "sources": _int(data.get("activeSources")),
    }


def provider_name(raw: str) -> str:
    """Достаёт имя провайдера из подписи вроде «AkariVPN ⏳4d | 🇨🇭 Швейцария 2»."""
    if not raw:
        return ""
    head = re.split(r"[⏳|]", raw, maxsplit=1)[0]
    head = FLAG_RE.sub(" ", head)
    head = re.sub(r"[⭐⚡📱🔒·\s]+", " ", head)
    return head.strip(" -–—") or raw.strip()


def server_entry(server: Server, result: Result | None = None) -> dict:
    """Одна строка сервера для метаданных страницы."""
    entry = {
        "addr": server.addr,
        "name": server.name,
        "provider": provider_name(server.name),
        "country": (result.country if result else "") or "",
    }
    if result:
        if result.ms:
            entry["ms"] = result.ms
        if result.exit_ip:
            entry["exit_ip"] = result.exit_ip
    return entry


def _fetch_gzipped(url: str, password: str, fmt: str, timeout: int = 90) -> str:
    """Забирает выдачу сайта в сжатом виде и распаковывает.

    Форматы строит не этот скрипт, а функция сайта: если собирать их здесь,
    через месяц-другой две реализации разойдутся, и зеркало начнёт отдавать
    не то же, что основная ссылка. Сжатие нужно потому, что через домашний
    канал несжатые ответы не доезжают — обрывается примерно на 25 КБ.
    """
    sep = "&" if "?" in url else "?"
    target = f"{url.rstrip('/')}/{password}{sep}format={fmt}&gz=1"
    req = urllib.request.Request(target, headers={
        "User-Agent": "gemini-sub-filter/1.0 (mirror)",
        "Accept-Encoding": "gzip",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        encoding = (resp.headers.get("Content-Encoding") or "").lower()

    # Слоёв может быть два: свой gzip функции плюс gzip на границе Cloudflare.
    # Распаковываем, пока тело остаётся сжатым, и не ориентируемся на
    # заголовок — он описывает только внешний слой.
    for _ in range(3):
        if data[:2] != b"\x1f\x8b":
            break
        data = gzip.decompress(data)
    if encoding and "gzip" in encoding and data[:2] == b"\x1f\x8b":
        raise RuntimeError("тело осталось сжатым после распаковки")
    return data.decode("utf-8")


def publish_mirror(cfg: dict) -> dict[str, str]:
    """Кладёт выдачу в статическое зеркало и возвращает ссылки на форматы.

    Зеркало нужно там, где Cloudflare недоступен: имя фильтруется в некоторых
    сетях по HTTPS, и без VPN подписка не обновляется. Отдаётся оно секретным
    gist, у которого имя каждого файла — случайный токен.

    Чего зеркало НЕ делает: не проверяет пароль. Статика не умеет авторизовывать,
    поэтому защита держится только на невозможности угадать ссылку. Это запасной
    путь, а не основной: как только Cloudflare доступен, лучше основная ссылка.
    """
    mirror = cfg.get("mirror") or {}
    if not mirror.get("enabled"):
        return {}

    gist_id = mirror.get("gist_id", "")
    template = mirror.get("raw_url_template", "")
    files = mirror.get("files", {})
    password = os.environ.get("WG_PASSWORD", "").strip() or mirror.get("password", "")
    public_url = cfg["publish"]["public_url"]

    missing = [n for n, v in (("gist_id", gist_id), ("raw_url_template", template),
                              ("files", files), ("пароль сайта", password)) if not v]
    if missing:
        log(f"  ЗЕРКАЛО ПРОПУЩЕНО — не задано: {', '.join(missing)}")
        log("  Пароль сайта: переменная WG_PASSWORD или mirror.password в config.json")
        return {}

    token = subprocess.run(
        ["gh", "auth", "token"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", creationflags=NO_WINDOW,
    ).stdout.strip()
    if not token:
        log("  ЗЕРКАЛО ПРОПУЩЕНО — нет авторизации gh (gh auth login)")
        return {}

    api = f"https://api.github.com/gists/{gist_id}"
    payload: dict[str, dict] = {}
    urls: dict[str, str] = {}

    for fmt, filename in files.items():
        try:
            body = _fetch_gzipped(public_url, password, fmt)
        except Exception as exc:  # noqa: BLE001
            log(f"  ЗЕРКАЛО '{fmt}': не забрал выдачу — {exc}")
            continue
        payload[filename] = {"content": body}
        urls[fmt] = f"{template}{filename}"
        log(f"  ЗЕРКАЛО '{fmt}': {filename} ({len(body)} Б)")

    if not payload:
        log("  ЗЕРКАЛО ПРОПУЩЕНО — ни один формат не забрался")
        return {}

    # Отправка крупная (Happ-файл под четверть мегабайта), а канал бывает
    # рваный — DNS отваливается на разговоре. Поэтому несколько попыток.
    data = json.dumps(payload).encode("utf-8")
    for attempt in range(3):
        req = urllib.request.Request(api, data=data, method="PATCH")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "gemini-sub-filter")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                if resp.status == 200:
                    log(f"  ЗЕРКАЛО обновлено: ок ({len(payload)} файла)")
                    return urls
        except Exception as exc:  # noqa: BLE001
            log(f"  ЗЕРКАЛО: попытка {attempt + 1} не вышла — {exc}")
            time.sleep(3 * (attempt + 1))

    log("  ЗЕРКАЛО: не обновилось, зеркало осталось с прошлым содержимым")
    return {}


def publish(cfg: dict, links: list[str], meta: dict) -> None:
    """Кладёт отфильтрованную подписку в Cloudflare KV.

    Именно KV, а не файлы в репозитории: Pages раздаёт всё, что лежит в
    репозитории, как обычную статику по прямому пути. Пока данные были
    файлами workgemini.txt, их мог скачать кто угодно без пароля.
    """
    pub = cfg["publish"]
    account = pub["cloudflare_account_id"]
    namespace = pub["kv_namespace_id"]
    token_env = pub.get("token_env", "CF_TOKEN")
    token = os.environ.get(token_env, "").strip()

    if not links:
        log("ПУБЛИКАЦИЯ ПРОПУЩЕНА — пустой список серверов")
        return

    missing = [n for n, v in (("CF-токен", token), ("account_id", account),
                              ("kv_namespace_id", namespace)) if not v]
    if missing:
        log(f"ПУБЛИКАЦИЯ ПРОПУЩЕНА — не задано: {', '.join(missing)}")
        log(f"  Токен положи в переменную окружения {token_env}")
        return

    base = f"https://api.cloudflare.com/client/v4/accounts/{account}/storage/kv/namespaces/{namespace}/values"
    raw = "\n".join(links) + "\n"
    meta_full = dict(meta)
    meta_full["links_format"] = "vless://"
    meta_full["published_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def put(key: str, body: bytes) -> bool:
        req = urllib.request.Request(f"{base}/{key}", data=body, method="PUT")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "text/plain; charset=utf-8")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status in (200, 201)
        except Exception as exc:  # noqa: BLE001
            log(f"  KV '{key}': ОШИБКА — {exc}")
            return False

    log(f"Публикую в Cloudflare KV ({len(links)} серверов)...")
    ok_sub = put("sub", raw.encode("utf-8"))
    log(f"  KV 'sub': {'ок' if ok_sub else 'провал'} ({len(raw)} Б)")

    # Зеркало обновляем до meta, чтобы в meta сразу лежали свежие ссылки,
    # а страница показала их следующей загрузкой.
    log("Обновляю зеркало...")
    mirror_urls = publish_mirror(cfg)
    if mirror_urls:
        meta_full["mirror"] = mirror_urls
        meta_full["mirror_note"] = (
            "Статическое зеркало без пароля: работает там, где Cloudflare "
            "недоступен. Храните ссылку в тайне — это весь уровень защиты."
        )

    ok_meta = put("meta", json.dumps(meta_full, ensure_ascii=False, indent=2).encode("utf-8"))
    log(f"  KV 'meta': {'ок' if ok_meta else 'провал'}")

    if ok_sub and ok_meta:
        log(f"  Готово. Адрес: {pub['public_url']}")


# --------------------------------------------------------------------------
# Главный сценарий
# --------------------------------------------------------------------------


def republish_from_report(cfg: dict) -> int:
    """Публикует результат прошлой проверки, не поднимая xray заново.

    Берём из отчёта адреса, а полные ссылки — свежие из подписки: так в
    публикацию попадут только те серверы, что реально прошли проверку.
    """
    report_path = BASE_DIR / cfg["output"]["dir"] / "report.json"
    if not report_path.exists():
        log(f"Нет отчёта {report_path} — сначала прогони проверку.")
        return 2

    report = json.loads(report_path.read_text(encoding="utf-8"))
    good_addrs = {s["addr"] for s in report.get("servers", []) if s.get("ok")}
    if not good_addrs:
        log("В отчёте нет ни одного рабочего сервера.")
        return 1

    try:
        links = fetch_subscription(cfg)
    except Exception as exc:  # noqa: BLE001
        log(f"ОШИБКА подписки: {exc}")
        return 2

    servers, _ = parse_servers(links)
    by_addr = {s.addr: s for s in servers}

    chosen = [s for s in servers if s.addr in good_addrs]
    missing = good_addrs - set(by_addr)
    log(
        f"Из отчёта рабочих: {len(good_addrs)}; найдено в подписке: {len(chosen)}"
        + (f"; исчезли из подписки: {len(missing)}" if missing else "")
    )
    if not chosen:
        log("Подходящих ссылок не осталось.")
        return 1

    # Порядок не трогаем: parse_servers уже разложил серверы по странам,
    # а good_addrs — множество, и обход по нему дал бы произвольный порядок.
    by_addr = {x.get("addr"): x for x in report.get("servers", [])}
    meta = {
        "updated_at": report.get("generated_at"),
        "checked": report.get("total"),
        "working": len(chosen),
        "subscription": fetch_profile(cfg),
        "servers": [
            {
                **server_entry(s),
                "country": by_addr.get(s.addr, {}).get("country", ""),
                "ms": by_addr.get(s.addr, {}).get("ms"),
                "exit_ip": by_addr.get(s.addr, {}).get("exit_ip", ""),
            }
            for s in chosen
        ],
        "republished_without_recheck": True,
    }
    publish(cfg, [s.link for s in chosen], meta)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Фильтр подписки ShareSub по Gemini")
    ap.add_argument("--config", default=str(BASE_DIR / "config.json"))
    ap.add_argument("--no-publish", action="store_true", help="только проверка")
    ap.add_argument("--limit", type=int, default=0, help="ограничить число серверов")
    ap.add_argument(
        "--skip-tun",
        action="store_true",
        help="не прерываться при активном TUN-адаптере",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="не печатать каждую проверку, только сводку (для автозапуска)",
    )
    ap.add_argument(
        "--publish-only",
        action="store_true",
        help="опубликовать прошлый результат из out/report.json, не проверяя заново",
    )
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    xray = Path(cfg["cores"]["xray"])
    if not xray.exists():
        log(f"НЕ НАЙДЕН xray: {xray}")
        return 2

    # Если скрипт прервут, дочерние xray могут остаться висеть.
    atexit.register(cleanup_orphan_xrays)

    log("=" * 62)
    log("Фильтр подписки ShareSub по доступности Gemini")
    log("=" * 62)

    # Гасим хвосты от прошлых прерванных запусков
    cleanup_orphan_xrays()

    # --- повторная публикация без проверки
    if args.publish_only:
        return republish_from_report(cfg)

    # --- TUN: без этого проверка врёт
    if not cfg["check"].get("skip_tun_check") and not args.skip_tun:
        tuns = active_tun_adapters()
        if tuns:
            log(f"ВНИМАНИЕ: поднят TUN-адаптер {', '.join(tuns)}.")
            log("Весь трафик уже идёт через VPN клиента — проверять серверы")
            log("бессмысленно, результат будет одинаковым для всех.")
            log("Выключи VPN (Happ/v2rayN) в TUN-режиме и запусти скрипт снова.")
            log("Обойти проверку: --skip-tun (в config.json: check.skip_tun_check)")
            return 3

    # --- подписка
    try:
        links = fetch_subscription(cfg)
        log(f"Подписка: {len(links)} ссылок получено")
    except Exception as exc:  # noqa: BLE001
        log(f"ОШИБКА подписки: {exc}")
        return 2

    servers, skipped = parse_servers(links)
    if skipped:
        log(f"Не поддержано схем: {skipped}")
    log(f"Уникальных адресов к проверке: {len(servers)}")

    if args.limit:
        random.shuffle(servers)
        servers = servers[: args.limit]
        log(f"Ограничено до {len(servers)} для теста")

    # --- проверка
    allowed = load_allowed_countries(BASE_DIR / "gemini_countries.json")
    log(f"Стран, где доступен Gemini: {len(allowed) if allowed else 'проверка отключена'}")

    conc = int(cfg["check"]["concurrency"])
    started = time.monotonic()
    results: list[Result] = []
    done = 0
    good = 0

    log(f"Проверяю через xray, параллельность {conc}...")
    with ThreadPoolExecutor(max_workers=conc) as pool:
        futures = {
            pool.submit(check_server, s, cfg, xray, allowed): s for s in servers
        }
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            done += 1
            if res.ok:
                good += 1
                mark = "OK  "
            else:
                mark = "FAIL"
            pct = done / len(servers) * 100
            # В тихом режиме не пишем каждую строку — только прогресс крупным шагом.
            if args.quiet:
                step = max(1, len(servers) // 20)
                if done % step == 0 or done == len(servers):
                    log(f"  {done}/{len(servers)} ({pct:.0f}%) — рабочих {good}")
            else:
                log(
                    f"  [{done:>3}/{len(servers)} {pct:5.1f}%] {mark} "
                    f"{res.server.addr:<22} {res.ms:>5} мс  {res.reason[:42]}"
                )

    elapsed = time.monotonic() - started
    # Порядок в подписке — по странам: parse_servers уже разложил так, внутри
    # страны по провайдеру, а дальше по исходному порядку подписки.
    # Скорость в ключ сортировки не входит: иначе номера вида «Германия 1..5»
    # оказываются переставлены по скорости и идут подряд 3, 1, 2.
    position = {s.addr: i for i, s in enumerate(servers)}
    working = sorted(
        [r for r in results if r.ok],
        key=lambda r: (*country_sort_key(r.server), position.get(r.server.addr, 0)),
    )
    log("-" * 62)
    log(f"Готово за {elapsed:.0f} с.  Рабочих: {good} из {len(results)}")

    if not working:
        log("Рабочих серверов нет. Публиковать нечего.")
        _write_report(cfg, results, working)
        return 1

    # --- сохранение и публикация
    working_links = [r.server.link for r in working]
    _write_report(cfg, results, working)

    if args.no_publish:
        log("--no-publish: публикация пропущена")
        return 0

    meta = {
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checked": len(results),
        "working": len(working),
        "duration_seconds": int(elapsed),
        "subscription": fetch_profile(cfg),
        "servers": [server_entry(r.server, r) for r in working],
    }
    log(f"Публикую в {cfg['publish'].get('public_url', '')}...")
    publish(cfg, working_links, meta)
    return 0


def _write_report(cfg: dict, results: list[Result], working: list[Result]) -> None:
    out_dir = BASE_DIR / cfg["output"]["dir"]
    out_dir.mkdir(parents=True, exist_ok=True)

    b64 = base64.b64encode("\n".join(r.server.link for r in working).encode()).decode()
    (out_dir / "workgemini.txt").write_text(b64, encoding="utf-8")

    by_reason: dict[str, int] = {}
    for r in results:
        key = "прошёл" if r.ok else r.reason.split("—")[0].strip()
        by_reason[key] = by_reason.get(key, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total": len(results),
        "working": len(working),
        "summary": by_reason,
        "servers": [
            {
                "ok": r.ok,
                "addr": r.server.addr,
                "name": r.server.name,
                "ms": r.ms,
                "status": r.status,
                "country": r.country,
                "exit_ip": r.exit_ip,
                "reason": r.reason,
            }
            for r in sorted(results, key=lambda x: (not x.ok, x.ms))
        ],
    }
    (out_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    log(f"Отчёт: {out_dir / 'report.json'}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("Прервано пользователем")
        sys.exit(130)