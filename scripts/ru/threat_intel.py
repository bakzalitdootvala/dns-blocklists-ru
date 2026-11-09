#!/usr/bin/env python3
"""Подготавливает IP-источники HaGeZi и Spamhaus для общей DNS-сборки.

Команды из корня: refresh-ips, build-ips и build-drop --input-dir <каталог>.
refresh-ips использует gh и HTTPS, сохраняет снимки HaGeZi и ip-lock.json
в .cache/feeds/. build-ips проверяет снимок и пишет hagezi-ipv4.txt с манифестом
в output/threat-intel/. Неподходящие строки перечисляются в отчёте; слишком
малое число допустимых или слишком много отброшенных записей останавливает сборку.

build-drop читает заранее проверенные ClamAV drop_v4.json/drop_v6.json,
проверяет формат JSON Lines, возраст, семейство IP и данные об источнике,
затем пишет spamhaus-ipv4/ipv6.txt и их манифесты. Уведомления Spamhaus сохраняются.
Эти файлы читает ip_inputs.py: он создаёт правила для combined.txt. Сам модуль
не меняет firewall, не перезапускает AdGuard и не публикует данные в GitHub.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from blocklists import atomic_write, validate_public_network
from pipeline import ROOT, check_age, download, github_json, load_config, now, read_checked


def convert_drop(text: str, family: int, minimum_networks: int = 1) -> tuple[str, dict]:
    """Преобразует проверенный текст DROP JSON Lines в список CIDR и метаданные.

    family равен 4 или 6. Последняя строка обязана содержать metadata с числом
    записей, временем, copyright и terms. Проверяет возраст до 48 часов, уникальность
    пар (cidr, sblid) и минимум уникальных сетей. Разные расследования одной сети
    сохраняются в счётчиках, сама сеть выводится один раз. Файлы не записывает.
    """
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not records or records[-1].get("type") != "metadata":
        raise ValueError("У DROP отсутствует завершающая метаинформация")
    metadata = records.pop()
    if len(records) != metadata["records"] or not records:
        raise ValueError("Количество записей DROP не совпадает с метаданными")
    for field in ["copyright", "terms"]:
        if not isinstance(metadata.get(field), str) or not metadata[field].strip():
            raise ValueError(f"Отсутствует обязательное уведомление: {field}")
    published = datetime.fromtimestamp(metadata["timestamp"], timezone.utc).isoformat()
    check_age(published, 48)
    networks = set()
    evidence = set()
    for record in records:
        value = validate_public_network(record["cidr"])
        if ipaddress.ip_network(value).version != family:
            raise ValueError("Неверное семейство IP в DROP")
        if not record.get("sblid"):
            raise ValueError("Отсутствует ссылка на запись SBL")
        # Одна сеть может иметь несколько расследований SBL. Дубли запрещены
        # по паре сеть/расследование, а итоговые сети всё равно выводятся уникально.
        identity = (value, record["sblid"])
        if identity in evidence:
            raise ValueError("DROP содержит повторяющиеся записи одного расследования")
        evidence.add(identity)
        networks.add(value)
    if len(networks) < minimum_networks:
        raise ValueError("В DROP недостаточно уникальных сетей")
    notices = [
        "# Source: Spamhaus DROP",
        f"# {metadata['copyright']}",
        f"# Terms: {metadata['terms']}",
        f"# Source timestamp: {metadata['timestamp']} ({published})",
        "# Назначение: проверка IP в DNS-ответах; firewall не изменяется.",
    ]
    report = {
        **metadata,
        "source_published_at": published,
        "enforcement": "dns_response",
        "network_count": len(networks),
        "additional_evidence_records": len(records) - len(networks),
    }
    return "\n".join(notices + sorted(networks)) + "\n", report


def refresh_ips(root: Path) -> None:
    """Скачивает настроенные IP-источники по commit SHA и записывает .cache/feeds/ip-lock.json через gh/HTTPS."""
    config = load_config(root)
    cache = root / ".cache/feeds"
    cache.mkdir(parents=True, exist_ok=True)
    retrieved_at = now()
    records = []
    for source in config["ip_sources"]:
        revision = github_json(f"repos/{source['repository']}/commits/{source['ref']}")
        records.append(download(source, revision, cache, retrieved_at))
    atomic_write(
        cache / "ip-lock.json",
        json.dumps({"retrieved_at": retrieved_at, "sources": records}, ensure_ascii=False, indent=2)
        + "\n",
    )


def build_ips(root: Path) -> None:
    """Проверяет локальный снимок HaGeZi и пишет IP-список с манифестом происхождения.

    Отбрасывает непубличные и неверные записи с перечислением в отчёте. Проверяет
    возраст, SHA256, минимум уникальных сетей и предел отброшенных строк.
    Дату последней активности каждого IP не выдумывает: per_indicator_last_seen=None.
    """
    config = load_config(root)
    cache = root / ".cache/feeds"
    lock = json.loads((cache / "ip-lock.json").read_text())
    check_age(lock["retrieved_at"], 48)
    cached = {entry["id"]: entry for entry in lock["sources"]}
    outputs = []
    for source in config["ip_sources"]:
        entry = cached[source["id"]]
        if Path(entry["file"]).name != entry["file"]:
            raise ValueError("Недопустимое имя снимка")
        check_age(entry["commit_at"], config["maximum_source_age_hours"])
        text = read_checked(cache / entry["file"], entry["sha256"], source["maximum_bytes"])
        accepted, rejected = set(), []
        for line in text.splitlines():
            value = line.strip()
            if not value or value.startswith(("#", "!")):
                continue
            try:
                accepted.add(validate_public_network(value))
            except ValueError:
                rejected.append(value)
        if len(accepted) < source["minimum_rules"] or len(rejected) > max(10, len(accepted) // 100):
            raise ValueError("IP-источник содержит недостаточно допустимых записей")
        header = f"# Source: HaGeZi TIF; GPL-3.0\n# Retrieved: {lock['retrieved_at']}\n# Source commit: {entry['commit']}\n# Per-indicator last_seen: unknown; enforcement: dns_response\n"
        artifact = header + "\n".join(sorted(accepted)) + "\n"
        outputs.append((root / "output/threat-intel/hagezi-ipv4.txt", artifact))
        report = {
            **entry,
            "network_count": len(accepted),
            "artifact_sha256": hashlib.sha256(artifact.encode()).hexdigest(),
            "excluded_nonpublic_or_invalid": rejected,
            "per_indicator_last_seen": None,
            "enforcement": "dns_response",
        }
        outputs.append(
            (
                root / "output/threat-intel/hagezi-manifest.json",
                json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            )
        )
    for path, content in outputs:
        atomic_write(path, content)
    print(f"IP-источников обработано: {len(config['ip_sources'])}; применение: DNS-ответы")


def build_drop(input_dir: Path, root: Path) -> None:
    """Читает drop_v4.json/drop_v6.json из input_dir и пишет четыре файла output/threat-intel/.

    Вход должен быть проверен ClamAV до вызова: сама функция антивирус не запускает.
    Лимит файла 5 МБ, минимум 1000 IPv4 и 10 IPv6 сетей. До записи проверяются оба
    семейства; в манифестах сохраняются SHA256 исходника и полученного текстового файла.
    """
    outputs = []
    for family in [4, 6]:
        path = input_dir / f"drop_v{family}.json"
        if path.stat().st_size > 5_000_000:
            raise ValueError("DROP превышает допустимый размер")
        artifact, metadata = convert_drop(path.read_text(), family, {4: 1000, 6: 10}[family])
        metadata["artifact_sha256"] = hashlib.sha256(artifact.encode()).hexdigest()
        metadata["source_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        outputs.append((root / f"output/threat-intel/spamhaus-ipv{family}.txt", artifact))
        outputs.append(
            (
                root / f"output/threat-intel/spamhaus-ipv{family}-manifest.json",
                json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            )
        )
    for path, content in outputs:
        atomic_write(path, content)
    print("Spamhaus DROP обработан; атрибуция сохранена; применение: DNS-ответы")


def main() -> int:
    """Выбирает refresh-ips/build-ips/build-drop; последней команде обязателен --input-dir, ошибки дают ненулевой код."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["refresh-ips", "build-ips", "build-drop"])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--input-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "refresh-ips":
            refresh_ips(args.root)
        elif args.command == "build-ips":
            build_ips(args.root)
        elif args.input_dir is None:
            parser.error("Для build-drop нужен --input-dir с проверенными файлами")
        else:
            build_drop(args.input_dir, args.root)
    except (ValueError, OSError, KeyError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
