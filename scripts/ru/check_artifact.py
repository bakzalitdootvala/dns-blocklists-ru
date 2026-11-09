#!/usr/bin/env python3
"""Проверяет целостность готового выпуска output/adguard/ без сети.

Запуск из корня: python3 scripts/ru/check_artifact.py. Читает combined.txt
построчно, заново считает SHA256 и количество правил, сверяет их с manifest.json.
Также проверяет четыре категории, отключённые adult/social и наличие всех
трёх IP-источников. Возвращает код 0 при успехе, 1 при обработанной ошибке.

Это проверка соответствия файла манифесту: она не доказывает вредоносность
каждого домена, свежесть всех входов или работу AdGuard. За эти проверки
отвечают pipeline.py, ip_inputs.py и живой test_ip_response.py.
Файлы, службы и Git не изменяются. Термины: docs/GLOSSARY.md.
"""

import hashlib
import json
import sys
from pathlib import Path

from blocklists import CATEGORIES


def verify(directory: Path) -> dict:
    """Читает combined.txt и manifest.json из directory; возвращает манифест либо ошибку целостности/профиля."""
    manifest = json.loads((directory / "manifest.json").read_text())
    digest = hashlib.sha256()
    count = 0
    with (directory / "combined.txt").open("rb") as stream:
        for line in stream:
            digest.update(line)
            if line.strip() and not line.startswith(b"!"):
                count += 1
    if digest.hexdigest() != manifest["sha256"] or count != manifest["rule_count"] or count == 0:
        raise ValueError("Контрольная сумма или количество правил не совпадает")
    if set(manifest["categories"]) != CATEGORIES or set(manifest["excluded_categories"]) != {
        "adult",
        "social",
    }:
        raise ValueError("Набор категорий не соответствует выбранному профилю")
    if manifest["ip_enforcement"] != "dns_response":
        raise ValueError("В выпуске отсутствует проверка IP-ответов")
    if (
        manifest["ip_rule_count"] <= 0
        or manifest["domain_rule_count"] + manifest["ip_rule_count"] != count
    ):
        raise ValueError("Количество доменных и IP-правил не совпадает")
    if {item["id"] for item in manifest["ip_sources"]} != {
        "hagezi",
        "spamhaus-ipv4",
        "spamhaus-ipv6",
    }:
        raise ValueError("В выпуске отсутствует обязательный IP-источник")
    return manifest


if __name__ == "__main__":
    try:
        result = verify(Path(__file__).resolve().parents[2] / "output/adguard")
        print(f"Целостность подтверждена: {result['rule_count']} правил")
    except (ValueError, OSError, KeyError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        raise SystemExit(1)
