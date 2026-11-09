#!/usr/bin/env python3
"""Синхронизирует удалённую ветку maintainer с официальной main Mullvad.

Запуск из корня: python3 scripts/ru/sync_upstream.py. Требует GitHub CLI gh
и уже настроенной авторизации с правом записи в fork. Через GitHub API читает
оба commit SHA и их родство; PATCH изменяет указатель maintainer только при
fast-forward: новые коммиты продолжают текущую историю без её переписывания.
После изменения повторный GET подтверждает результат. При расхождении — ошибка.

Это внешняя операция записи в GitHub, а не локальная проверка: запускать только
в согласованной цепочке обновления. main, локальные файлы и VPS не изменяются;
код upstream не исполняется. Команда печатает подтверждённый SHA либо ошибку.
Термины: docs/GLOSSARY.md.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Callable

UPSTREAM = "mullvad/dns-blocklists"
FORK = "bakzalitdootvala/dns-blocklists-ru"


def github_call(method: str, endpoint: str, fields: dict | None = None) -> dict:
    """Выполняет HTTP-метод GitHub API через gh; булевы fields передаёт типизированно, возвращает JSON."""
    command = ["gh", "api", "--method", method, endpoint]
    for name, value in (fields or {}).items():
        command.extend(
            [
                "-F" if isinstance(value, bool) else "-f",
                f"{name}={str(value).lower() if isinstance(value, bool) else value}",
            ]
        )
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


def synchronize(api: Callable = github_call) -> str:
    """Продвигает удалённую maintainer только по прямому продолжению истории и возвращает SHA.

    При совпадении SHA ничего не записывает. Иначе проверяет merge base — общий
    коммит истории — и выполняет PATCH с force=False, затем подтверждает GET.
    api можно подменить тестовой функцией; это исключает реальные записи GitHub в тестах.
    """
    target = api("GET", f"repos/{UPSTREAM}/git/ref/heads/main")["object"]["sha"]
    current = api("GET", f"repos/{FORK}/git/ref/heads/maintainer")["object"]["sha"]
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in [current, target]):
        raise ValueError("Получен некорректный SHA")
    if target == current:
        return target
    comparison = api("GET", f"repos/{FORK}/compare/{current}...{target}")
    if comparison["status"] != "ahead" or comparison["merge_base_commit"]["sha"] != current:
        raise ValueError("maintainer разошёлся с upstream; принудительная синхронизация запрещена")
    api("PATCH", f"repos/{FORK}/git/refs/heads/maintainer", {"sha": target, "force": False})
    confirmed = api("GET", f"repos/{FORK}/git/ref/heads/maintainer")["object"]["sha"]
    if confirmed != target:
        raise ValueError("Продвижение maintainer не подтверждено")
    return confirmed


if __name__ == "__main__":
    try:
        print(synchronize())
    except (ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Ошибка синхронизации: {error}", file=sys.stderr)
        raise SystemExit(1)
