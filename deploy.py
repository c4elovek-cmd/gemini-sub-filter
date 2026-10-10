# -*- coding: utf-8 -*-
"""
Раскладывает файлы сайта в репозиторий, из которого собирается Cloudflare Pages.

Это одноразовая установка: загружает Pages-функцию и страницу. Дальше
данные подписки filter_servers.py коммитит сам при каждом прогоне.

  python deploy.py            # залить функцию и страницу
  python deploy.py --check    # только показать, что изменится
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import subprocess
import sys
import time

BASE_DIR = pathlib.Path(__file__).resolve().parent

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# источник -> путь в репозитории
FILES = [
    (BASE_DIR / "pages" / "workgemini.js", "functions/workgemini.js"),
    (BASE_DIR / "pages" / "workgemini_path.js", "functions/workgemini/[[path]].js"),
    (BASE_DIR / "pages" / "gemini.js", "functions/gemini.js"),
    (BASE_DIR / "pages" / "gemini_index.html", "gemini/index.html"),
]

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def gh(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        creationflags=NO_WINDOW,
    )


def gh_bytes(args: list[str]) -> subprocess.CompletedProcess:
    """То же, что gh, но без преобразования окончаний строк.

    Нужна для побайтового сравнения с файлом на диске: в текстовом режиме
    Windows молча переводит CRLF в LF, и файл всегда считается изменившимся,
    даже когда он байт в байт тот же. Из-за этого каждый прогон делал лишний
    коммит без единой правки.
    """
    return subprocess.run(
        ["gh", *args],
        capture_output=True,
        check=False,
        creationflags=NO_WINDOW,
    )


def gh_token() -> str:
    return (gh(["auth", "token"]).stdout or "").strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Залить статику сайта в репозиторий Pages")
    ap.add_argument("--repo", default="c4elovek-cmd/BiographyWebsite")
    ap.add_argument("--branch", default="main")
    ap.add_argument("--check", action="store_true", help="ничего не коммитить, только показать")
    args = ap.parse_args()

    if not gh_token():
        print("Нет авторизации gh. Выполни: gh auth login")
        return 2

    api = f"https://api.github.com/repos/{args.repo}/contents"
    changed = []

    print(f"Репозиторий: {args.repo}@{args.branch}")
    for src, dst in FILES:
        if not src.exists():
            print(f"  НЕТ ФАЙЛА {src}")
            return 2
        body = src.read_bytes()

        head = gh(["api", f"{api}/{dst}?ref={args.branch}", "-q", ".sha"])
        sha = (head.stdout or "").strip()
        if head.returncode == 0 and sha:
            # Забираем файл целиком и сравниваем байты. Запрос с -q .content
            # вместе с raw-заголовком невалиден: gh отдаёт код 1 и пустой
            # вывод, из-за чего любой файл всегда считался изменённым.
            cur = gh_bytes([
                "api", f"{api}/{dst}?ref={args.branch}",
                "--header", "Accept: application/vnd.github.raw",
            ])
            if cur.returncode == 0 and cur.stdout == body:
                print(f"  {dst}: без изменений")
                continue

        changed.append((dst, body))
        print(f"  {dst}: обновлю ({len(body)} Б)")

    if not changed:
        print("\nМенять нечего — сайт уже в нужном состоянии.")
        return 0

    if args.check:
        print(f"\n--check: изменятся {len(changed)} файл(ов), коммит не делаю.")
        return 0

    for dst, body in changed:
        payload = {
            "message": f"gemini: обновление {dst}",
            "content": base64.b64encode(body).decode(),
            "branch": args.branch,
        }
        if (head := gh(["api", f"{api}/{dst}?ref={args.branch}", "-q", ".sha"])).returncode == 0:
            payload["sha"] = (head.stdout or "").strip()

        tmp = BASE_DIR / "out" / "_deploy_payload.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        res = gh(["api", "--method", "PUT", f"{api}/{dst}", "--input", str(tmp)])
        tmp.unlink(missing_ok=True)

        if res.returncode != 0:
            print(f"  ОШИБКА {dst}: {(res.stderr or res.stdout or '')[:300]}")
            return 1
        data = json.loads(res.stdout)
        print(f"  {dst}: закоммичено {data['commit']['sha'][:10]}")

    print("\nГотово. Cloudflare Pages передеплоит автоматически (~2 минуты).")
    print(f"  Подписка: https://c4elovek.online/workgemini")
    print(f"  Страница: https://c4elovek.online/gemini/")

    # Проверяем, доехало ли
    for _ in range(10):
        time.sleep(20)
        probe = gh(["api", f"repos/{args.repo}/deployments?per_page=1"])
        print(f"  деплой: {probe.stdout.strip()[:160]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())