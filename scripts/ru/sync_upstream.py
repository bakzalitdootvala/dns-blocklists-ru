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

    При совпадении SHA ничего не записывает. Иначе проверяет цепочку родителей
    upstream и выполняет PATCH с force=False, затем подтверждает GET.
    api можно подменить тестовой функцией; это исключает реальные записи GitHub в тестах.
    """
    target = api("GET", f"repos/{UPSTREAM}/git/ref/heads/main")["object"]["sha"]
    current = api("GET", f"repos/{FORK}/git/ref/heads/maintainer")["object"]["sha"]
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in [current, target]):
        raise ValueError("Получен некорректный SHA")
    if target == current:
        return target
    if not is_ancestor(api, current, target):
        raise ValueError("maintainer разошёлся с upstream; принудительная синхронизация запрещена")
    api("PATCH", f"repos/{FORK}/git/refs/heads/maintainer", {"sha": target, "force": False})
    confirmed = api("GET", f"repos/{FORK}/git/ref/heads/maintainer")["object"]["sha"]
    if confirmed != target:
        raise ValueError("Продвижение maintainer не подтверждено")
    return confirmed


def is_ancestor(api: Callable, current: str, target: str) -> bool:
    """Ищет current среди родителей target без построения diff многомиллионных списков.

    Обходит все родительские ветви merge-коммитов. Не более 128 запросов:
    слишком большое отставание требует ручного разбора, а не бесконечного обхода.
    Повреждённые SHA и превышение лимита останавливают обновление до PATCH.
    """
    pending, visited = [target], set()
    while pending:
        sha = pending.pop()
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("Некорректный SHA родительского коммита")
        if sha == current:
            return True
        if sha in visited:
            continue
        if len(visited) >= 128:
            raise ValueError("Для проверки родства требуется больше 128 коммитов")
        visited.add(sha)
        commit = api("GET", f"repos/{UPSTREAM}/git/commits/{sha}")
        pending.extend(parent["sha"] for parent in commit["parents"])
    return False


if __name__ == "__main__":
    try:
        print(synchronize())
    except (ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Ошибка синхронизации: {error}", file=sys.stderr)
        raise SystemExit(1)
