# -*- coding: utf-8 -*-
"""Зеркало подписки в Yandex Cloud Functions.

Зачем оно нужно. Основной адрес рисует карточку подписки из заголовков
ответа: Subscription-Userinfo даёт трафик и срок, Content-Disposition —
название, Announce — описание. Статическое зеркало на GitHub таких
заголовков не умеет в принципе, там обычный файл, поэтому карточка пустая.

Функция отдаёт те же данные из Object Storage и добавляет те же заголовки,
так что карточка рисуется и здесь. Адрес при этом другой — functions.yandexcloud.net,
а не c4elovek.online, — значит фильтрация по имени основного домена его
не задевает.

Данные берутся из Object Storage, а не с основного адреса намеренно: запрос
изнутри России шёл бы через ту же фильтрацию и мог бы не дойти. Всё, что
нужно функции, выкладывает filter_servers.py при публикации.

Переменные окружения:
    SUB_BUCKET     имя бакета, например gemini-sub
    SUB_TOKEN      секрет из адреса: /<токен>/
    YC_ACCESS_KEY  ключ сервисного аккаунта
    YC_SECRET_KEY  секретный ключ
    YC_ENDPOINT    https://storage.yandexcloud.net
    YC_REGION      ru-central1
"""

import base64
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote

import boto3

BUCKET = os.environ.get("SUB_BUCKET", "")
TOKEN = (os.environ.get("SUB_TOKEN") or "").strip("/")
ENDPOINT = os.environ.get("YC_ENDPOINT", "https://storage.yandexcloud.net")
REGION = os.environ.get("YC_REGION", "ru-central1")

TITLE = "c4elovek.online · Gemini"
PAGE_URL = "https://c4elovek.online/gemini/"

# Те же регулярки, что на основном адресе: порядок важен, Happ проверяется
# первым, иначе его User-Agent сматчился бы по «meta» и ушёл в clash.
UA_CLASH = re.compile(r"clash|mihomo|stash|verge|flclash|sparkle|karing|meta|surfboard", re.I)
UA_HAPP = re.compile(r"happ", re.I)

# Ключи объектов в бакете и тип содержимого для каждого формата.
FORMATS = {
    "links": ("links.txt", "text/plain; charset=utf-8"),
    "base64": ("base64.txt", "text/plain; charset=utf-8"),
    "clash": ("clash.yaml", "text/yaml; charset=utf-8"),
    "happ": ("happ.json", "application/json; charset=utf-8"),
}

_client = None


def storage():
    """Клиент Object Storage. Создаётся один раз на холодный старт."""
    global _client
    if _client is None:
        _client = boto3.client(
            "s3",
            endpoint_url=ENDPOINT,
            region_name=REGION,
            aws_access_key_id=os.environ.get("YC_ACCESS_KEY", ""),
            aws_secret_access_key=os.environ.get("YC_SECRET_KEY", ""),
        )
    return _client


def read_object(key: str) -> str | None:
    """Читает объект из бакета. Отсутствие — не ошибка: на это отвечаем 503."""
    try:
        return storage().get_object(Bucket=BUCKET, Key=key)["Body"].read().decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


def b64(text: str) -> str:
    """base64 из UTF-8 строки. В заголовок латиница не влезет, а названия
    и описание кириллические."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def format_gb(value) -> str:
    """56 ГБ, 1,5 МБ — как показывает карточка."""
    v = int(value or 0)
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    x = float(v)
    i = 0
    while x >= 1024 and i < len(units) - 1:
        x /= 1024
        i += 1
    digits = 0 if (x >= 10 or i >= 3) else 1
    return f"{x:.{digits}f}".replace(".", ",") + " " + units[i]


def format_date_ru(value: str) -> str:
    """Дата 09.10.2026 по московскому времени, независимо от зоны функции."""
    if not value:
        return ""
    ts = parse_time(value)
    if ts is None:
        return ""
    return time.strftime("%d.%m.%Y", time.gmtime(ts + 3 * 3600))


def format_datetime_ru(value: str) -> str:
    """Дата и время 09.10.2026 20:06 по Москве."""
    if not value:
        return ""
    ts = parse_time(value)
    if ts is None:
        return ""
    return time.strftime("%d.%m.%Y %H:%M", time.gmtime(ts + 3 * 3600))


def parse_time(value):
    """ISO 8601 → unix-время. fromisoformat не берёт «Z» на старых сборках."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:  # noqa: BLE001
        return None


def badge(sub: dict) -> str:
    """Плашка состояния: 📦 56 ГБ из 56 ГБ · 📅 до 14.08.2036."""
    used = int(sub.get("traffic_used") or 0)
    limit = int(sub.get("traffic_limit") or 0)
    parts = []
    if used or limit:
        parts.append(
            f"📦 {format_gb(used)} из {format_gb(limit)}" if limit
            else f"📦 {format_gb(used)} · без лимита"
        )
    if sub.get("expire_at"):
        stamp = format_date_ru(sub["expire_at"])
        if stamp:
            parts.append(f"📅 до {stamp}")
    return " · ".join(parts)


def build_announce(meta: dict, server_count: int) -> str:
    """Текст блока описания в карточке. Разделитель строк — пустая строка,
    так же как у ShareSub."""
    sub = meta.get("subscription") or {}
    lines = [f"⚡ c4elovek.online · Gemini · {server_count} серверов"]
    state = badge(sub)
    if state:
        lines.append(state)
    stamp = format_datetime_ru(meta.get("updated_at") or "")
    if stamp:
        lines.append(f"🔄 Обновлено {stamp}")
    lines.append("")
    lines.append("🔒 В списке только те серверы, где Gemini открывается.")
    return "\n".join(lines)


def card_headers(meta: dict, server_count: int) -> dict:
    """Заголовки, из которых клиент собирает карточку.

    Набор повторяет отправляемый основным адресом один в один: часть клиентов
    показывает карточку не целиком, если нет какого-то из полей. Название
    приходится дважды — Content-Disposition читают без base64, поэтому там
    только ASCII, а Profile-Title уже с кодировкой."""
    headers = {}
    sub = meta.get("subscription") or {}
    used = int(sub.get("traffic_used") or 0)
    limit = int(sub.get("traffic_limit") or 0)
    expire = int(parse_time(sub.get("expire_at")) or 0)

    if used or limit or expire:
        # total=0 клиенты читают как «без ограничений» и рисуют бесконечность.
        headers["Subscription-Userinfo"] = (
            f"upload=0; download={used}; total={limit}; expire={expire}"
        )

    headers["Announce"] = "base64:" + b64(build_announce(meta, server_count))
    headers["Profile-Title"] = "base64:" + b64(TITLE)
    headers["Content-Disposition"] = (
        'attachment; filename="c4elovek.online - Gemini"; '
        "filename*=UTF-8''" + quote_utf8(TITLE)
    )
    # Списка меняется раз в сутки, чаще обновлять незачем.
    headers["Profile-Update-Interval"] = "6"
    headers["Profile-Web-Page-Url"] = PAGE_URL
    headers["Subscriptions-Sort-Type"] = "without"
    headers["Support-Url"] = PAGE_URL
    return headers


def quote_utf8(text: str) -> str:
    return quote(text, safe="")


def pick_format(headers: dict, query: dict) -> str:
    """Формат выбирает клиент: либо просит сам, либо определяется по User-Agent."""
    fmt = (query.get("format") or "").strip().lower()
    if fmt:
        return fmt if fmt in FORMATS else "links"
    ua = headers.get("user-agent") or ""
    if UA_HAPP.search(ua):
        return "happ"
    if UA_CLASH.search(ua):
        return "clash"
    return "links"


def answer(status: int, body: str, content_type: str, headers: dict | None = None) -> dict:
    out = {
        "statusCode": status,
        "headers": {
            "Content-Type": content_type,
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            **(headers or {}),
        },
        "body": body,
    }
    return out


def handler(event, context):
    headers = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}
    query = {str(k).lower(): v for k, v in (event.get("queryStringParameters") or {}).items()}
    path = (event.get("path") or "").strip("/")

    # Путь — секретный токен. Без него отвечаем 404 и ни о чём не говорим:
    # подписка защищена невозможностью угадать адрес, пароля здесь нет.
    if not TOKEN or path.split("/")[0] != TOKEN:
        return answer(404, "Not found\n", "text/plain; charset=utf-8")

    if event.get("httpMethod") == "OPTIONS":
        return answer(204, "", "text/plain; charset=utf-8", {"Access-Control-Allow-Headers": "*"})

    meta = {}
    raw_meta = read_object("meta.json")
    if raw_meta:
        try:
            meta = json.loads(raw_meta)
        except Exception:  # noqa: BLE001
            meta = {}

    fmt = pick_format(headers, query)
    key, content_type = FORMATS[fmt]
    body = read_object(key)
    if body is None:
        return answer(503, "Зеркало обновляется, попробуйте через минуту\n",
                      "text/plain; charset=utf-8")

    card = card_headers(meta, int(meta.get("working") or 0))
    # Сжатие просить нельзя: часть клиентов не распаковывает тело само,
    # а cloudflare-адрес отдаёт ответ с identity — иначе приходило
    # «неизвестный тип контента».
    card["Content-Encoding"] = "identity"
    return answer(200, body, content_type, card)