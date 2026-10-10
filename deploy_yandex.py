# -*- coding: utf-8 -*-
"""Разворачивает зеркало подписки в Yandex Cloud.

Что делает:
  1. создаёт бакет в Object Storage, если его ещё нет;
  2. кладёт в него выдачу подписки во всех форматах и метаданные;
  3. собирает функцию из yandex/handler.py и публикует её;
  4. записывает адрес зеркала обратно в config.json.

Нужны учётные данные сервисного аккаунта Yandex Cloud. Положить файл ключа
(.json, что выдаёт консоль) нужно один раз и указать путь в config.json:
    "yandex": {
      "service_account_key": "C:/путь/к/sa.json",
      "folder_id": "b1g...",
      "bucket": "gemini-sub",
      "function": "gemini-sub"
    }

Запуск:
    python deploy_yandex.py            # всё пересоздать и обновить
    python deploy_yandex.py --objects # только обновить данные в бакете
    python deploy_yandex.py --check    # проверить живое зеркало
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import os
import sys
import time
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CFG_PATH = BASE_DIR / "config.json"

FOLDER_API = "https://resourcemanager.api.cloud.yandex.net/v1/folders"
FUNCTION_API = "https://serverless.cloud.yandex.net/apis/functions/v1/functions"
IAM_API = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
STORAGE_ENDPOINT = "https://storage.yandexcloud.net"
RUNTIME = "python312"

# Форматы кладутся теми же именами, какие ждёт функция, плюс метаданные —
# из них она берёт трафик, срок и время обновления для карточки.
OBJECTS = {
    "links": "links.txt",
    "base64": "base64.txt",
    "clash": "clash.yaml",
    "happ": "happ.json",
    "meta": "meta.json",
}

_iam_cache: dict = {}


# --------------------------------------------------------------------------
# мелкие помощники


def log(message: str) -> None:
    print(message, flush=True)


def load_cfg() -> dict:
    return json.loads(CFG_PATH.read_text(encoding="utf-8"))


def save_cfg(cfg: dict) -> None:
    CFG_PATH.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def http(method: str, url: str, *, token: str | None = None, body: bytes | None = None,
         content_type: str | None = None) -> tuple[int, dict]:
    """Запрос к Yandex API. Возвращает код и разобранный JSON."""
    headers = {"Content-Type": content_type or "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return exc.code, {"message": raw[:400].decode("utf-8", "replace")}


# --------------------------------------------------------------------------
# IAM-токен


def iam_token(key_path: str) -> str:
    """Меняет файл ключа сервисного аккаунта на IAM-токен.

    Токен живёт 12 часов, поэтому переиспользуем его, а не берём на каждый
    запрос: обмен требует подписи приватным ключом и заметно медленнее."""
    cached = _iam_cache.get("token")
    if cached and _iam_cache.get("exp", 0) > time.time() + 60:
        return cached

    key = json.loads(Path(key_path).read_text(encoding="utf-8"))
    sa_id = key.get("service_account_id", "")
    if not sa_id:
        raise SystemExit("В файле ключа нет service_account_id")

    issued = int(time.time())
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode()
    ).rstrip(b"=")
    claims = base64.urlsafe_b64encode(json.dumps({
        "aud": IAM_API,
        "iss": sa_id,
        "sub": sa_id,
        "iat": issued,
        "exp": issued + 3600,
    }, separators=(",", ":")).encode()).rstrip(b"=")
    signing_input = header + b"." + claims

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    private = serialization.load_pem_private_key(
        key["private_key"].encode("utf-8"), password=None)
    signature = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    jwt = (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()

    status, out = http("POST", IAM_API, body=jwt.encode())
    if status != 200 or not out.get("iamToken"):
        raise SystemExit(f"IAM отказал: {status} {out.get('message', out)}")

    _iam_cache["token"] = out["iamToken"]
    _iam_cache["exp"] = time.time() + int(out.get("expiresIn", 43200)) - 120
    return out["iamToken"]


# --------------------------------------------------------------------------
# Object Storage


def storage_client(cfg: dict, key_path: str):
    import boto3

    key = json.loads(Path(key_path).read_text(encoding="utf-8"))
    return boto3.client(
        "s3",
        endpoint_url=STORAGE_ENDPOINT,
        region_name="ru-central1",
        aws_access_key_id=key["access_key_id"],
        aws_secret_access_key=key["secret_access_key"],
    )


def ensure_bucket(s3, bucket: str) -> None:
    """Создаёт бакет, если его ещё нет. Уже существующий не трогаем."""
    try:
        s3.head_bucket(Bucket=bucket)
        log(f"  бакет {bucket} уже есть")
        return
    except Exception:  # noqa: BLE001
        pass
    s3.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=False)
    log(f"  бакет {bucket} создан")


def fetch_from_site(cfg: dict, fmt: str) -> str:
    """Забирает готовую выдачу с основного адреса.

    gz=1 включает сжатие: через домашний канал крупные ответы обрываются
    примерно на 25 КБ, в сжатом виде доходят целиком."""
    publish = cfg["publish"]
    password = (cfg.get("mirror") or {}).get("password", "")
    url = f"{publish['public_url']}/{password}?format={fmt}&gz=1"
    req = urllib.request.Request(url, headers={
        "User-Agent": "gemini-sub-filter/deploy_yandex",
        "Accept-Encoding": "gzip",
    })
    with urllib.request.urlopen(req, timeout=300) as resp:
        raw = resp.read()
    for _ in range(3):
        if raw[:2] != b"\x1f\x8b":
            break
        raw = gzip.decompress(raw)
    return raw.decode("utf-8")


def upload_objects(cfg: dict) -> None:
    """Кладёт выдачу в бакет и перечитывает обратно.

    Сверка обязательна: Object Storage принимает запись без ошибки, но если
    ключ случайно перепутан, выдача молча останется старой — а это молчание
    стоит пользователю неработающей подписки."""
    yc = cfg["mirror"]["yandex"]
    s3 = storage_client(cfg, yc["service_account_key"])
    bucket = yc["bucket"]
    ensure_bucket(s3, bucket)

    for fmt, key in OBJECTS.items():
        if fmt == "meta":
            body = fetch_from_site(cfg, "status")
            body = body[body.find("{"):] if not body.lstrip().startswith("{") else body
        else:
            body = fetch_from_site(cfg, fmt)

        s3.put_object(Bucket=bucket, Key=key,
                      Body=body.encode("utf-8"), ContentType="text/plain; charset=utf-8")
        got = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
        ok = got == body
        log(f"  {key:<12} {len(body):>7} Б — {'совпало' if ok else 'НЕ СОВПАЛО'}")
        if not ok:
            raise SystemExit(f"{key}: записанное и прочитанное разошлись, стоп")


# --------------------------------------------------------------------------
# функция


def build_package() -> bytes:
    """Архив с обработчиком и зависимостями — так Yandex и разворачивает."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ("handler.py", "requirements.txt"):
            zf.write(BASE_DIR / "yandex" / name, name)
    return buf.getvalue()


def env_vars(cfg: dict) -> dict:
    yc = cfg["mirror"]["yandex"]
    key = json.loads(Path(yc["service_account_key"]).read_text(encoding="utf-8"))
    return {
        "SUB_BUCKET": yc["bucket"],
        "SUB_TOKEN": yc["token"],
        "YC_ACCESS_KEY": key["access_key_id"],
        "YC_SECRET_KEY": key["secret_access_key"],
        "YC_ENDPOINT": STORAGE_ENDPOINT,
        "YC_REGION": "ru-central1",
    }


def find_function(token: str, name: str) -> dict | None:
    """Ищет функцию по имени — обновлять надо её же сущность, а не создавать
    вторую с тем же именем, что API не даст."""
    status, out = http("GET", f"{FUNCTION_API}?folderId={_folder_id(token)}", token=token)
    if status != 200:
        raise SystemExit(f"Список функций не прочитан: {status} {out.get('message', out)}")
    for fn in out.get("functions", []):
        if fn.get("name") == name:
            return fn
    return None


_folder_cache: dict = {}


def _folder_id(token: str) -> str:
    return _folder_cache.get("id", "")


def resolve_folder(token: str, folder_hint: str) -> str:
    """Идентификатор папки нужен для API.

    Если он уже указан в config.json — берём как есть. Иначе ищем папку по
    имени из подсказки, а если не нашли — берём первую, что видна аккаунту."""
    if folder_hint and folder_hint.startswith(("b1", "b1g")):
        _folder_cache["id"] = folder_hint
        log(f"  папка из конфига: {folder_hint}")
        return folder_hint

    status, out = http("GET", f"{FOLDER_API}?pageSize=100", token=token)
    if status != 200:
        raise SystemExit(f"Папки не прочитались: {status} {out.get('message', out)}")
    folders = out.get("folders", [])
    if not folders:
        raise SystemExit("У аккаунта нет ни одной папки: укажи folder_id вручную")

    chosen = folders[0]
    for folder in folders:
        if folder_hint and folder.get("name") == folder_hint:
            chosen = folder
            break
    _folder_cache["id"] = chosen["id"]
    log(f"  папка {chosen.get('name')} → {chosen['id']}")
    return chosen["id"]


def deploy_function(cfg: dict) -> str:
    yc = cfg["mirror"]["yandex"]
    token = iam_token(yc["service_account_key"])
    folder_id = resolve_folder(token, yc.get("folder_id", ""))
    yc["folder_id"] = folder_id

    spec = {
        "runtime": RUNTIME,
        "entrypoint": "handler.handler",
        "resources": {"memory": "256Mb", "cpu_count": "1"},
        "timeout": "20s",
        "serviceAccount": yc["service_account"],
        "environment": {"vars": env_vars(cfg)},
    }

    payload = build_package()
    s3 = storage_client(cfg, yc["service_account_key"])
    pkg_key = f"functions/{yc['function']}.zip"
    s3.put_object(Bucket=yc["bucket"], Key=pkg_key, Body=payload)
    log(f"  пакет {pkg_key} — {len(payload)} Б")
    spec["package"] = {"bucket": yc["bucket"], "object": pkg_key}

    existing = find_function(token, yc["function"])
    if existing:
        status, out = http("PATCH", f"{FUNCTION_API}/{existing['id']}",
                           token=token, body=json.dumps(spec).encode())
        action = "обновлена"
    else:
        body = dict(spec, name=yc["function"], folderId=folder_id)
        status, out = http("POST", FUNCTION_API, token=token,
                           body=json.dumps(body).encode())
        action = "создана"

    if status not in (200, 201):
        raise SystemExit(f"Функция не развернулась: {status} {out.get('message', out)}")
    log(f"  функция {action}: {out.get('name')} ({out.get('id')})")

    # Пока разворачивается — ждём, иначе проверка сразу после может поймать
    # старую версию и решить, что всё сломано.
    for _ in range(40):
        time.sleep(3)
        status, cur = http("GET", f"{FUNCTION_API}/{out['id']}", token=token)
        if status == 200 and cur.get("status") == "ACTIVE":
            break
    else:
        log("  предупреждение: функция всё ещё не ACTIVE")

    url = f"https://{yc['function']}.functions.yandexcloud.net"
    yc["url"] = url
    return url


# --------------------------------------------------------------------------
# проверка


def check(cfg: dict) -> int:
    yc = cfg.get("mirror", {}).get("yandex") or {}
    url = yc.get("url", "")
    if not url:
        log("  адрес не задан: сначала python deploy_yandex.py")
        return 1
    full = f"{url}/{yc['token']}"

    log(f"  проверяю {full}")
    for label, agent, expect in (
        ("Happ", "Happ/4.7.1/Android/17912108360521999508", "application/json"),
        ("Clash", "ClashMeta/1.18", "text/yaml"),
        ("прочие", "v2rayN/6.23.4", "text/plain"),
    ):
        req = urllib.request.Request(full, headers={"User-Agent": agent})
        with urllib.request.urlopen(req, timeout=120) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            length = hdrs.get("content-length", "?")
        ct = hdrs.get("content-type", "")
        flag = "ок" if expect in ct else "НЕ ТАК"
        log(f"    {label:<7} {ct:<32} {length:>7} Б — {flag}")

    req = urllib.request.Request(full, headers={"User-Agent": "Happ/4.7.1"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
    for name in ("subscription-userinfo", "announce", "profile-title",
                 "content-disposition", "profile-update-interval"):
        log(f"    {name:<24} {'есть' if name in hdrs else 'НЕТ'}")
    announce = hdrs.get("announce", "")
    if announce.startswith("base64:"):
        text = base64.b64decode(announce[7:]).decode("utf-8")
        log("    блок описания:")
        for line in text.splitlines():
            log("      " + line)

    log(f"\n  добавьте на сайт: {full}")
    return 0


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="Зеркало подписки в Yandex Cloud")
    ap.add_argument("--objects", action="store_true", help="обновить только данные")
    ap.add_argument("--check", action="store_true", help="проверить живое зеркало")
    args = ap.parse_args()

    cfg = load_cfg()
    if args.check:
        return check(cfg)

    yc = cfg.setdefault("mirror", {}).setdefault("yandex", {})
    if not yc.get("service_account_key") or not yc.get("folder_id"):
        log("  НЕ НАСТРОЕНО. В config.json нужно:")
        log("    mirror.yandex.service_account_key — путь к файлу ключа (.json)")
        log("    mirror.yandex.service_account     — идентификатор аккаунта")
        log("    mirror.yandex.folder_id            — папка облака")
        log("    mirror.yandex.bucket              — имя бакета")
        log("    mirror.yandex.function            — имя функции")
        log("    mirror.yandex.token               — секрет из адреса")
        return 1

    log("  1. данные в Object Storage")
    upload_objects(cfg)
    if args.objects:
        save_cfg(cfg)
        return 0

    log("\n  2. функция")
    url = deploy_function(cfg)
    save_cfg(cfg)

    log(f"\n  адрес зеркала: {url}/<токен>")
    log("\n  3. проверка")
    return check(cfg)


if __name__ == "__main__":
    sys.exit(main())