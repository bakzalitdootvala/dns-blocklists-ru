"""Подключает проверенные сетевые источники к сборке DNS-фильтра.

pipeline.build() вызывает load_ip_rules() до записи нового combined.txt.
Обязательны HaGeZi IP, Spamhaus IPv4 и Spamhaus IPv6 с манифестами в
output/threat-intel/. Проверяются SHA256 содержимого, даты, число сетей,
семейство IP, разрешение dns_response и уведомления правообладателя Spamhaus.
Число сетей сравнивается с предыдущим output/adguard/manifest.json.

Модуль возвращает правила AdGuard, сведения об источниках и комментарии
с условиями распространения. Файлы не изменяет, к сети не обращается.
Термины: docs/GLOSSARY.md.
"""

import ipaddress
import json
from pathlib import Path

from blocklists import validate_public_network
from ip_rules import compile_networks
from pipeline import check_age, read_checked


def load_ip_rules(root: Path, config: dict) -> tuple[list[str], list[dict], list[str]]:
    """Возвращает (правила, метаданные источников, лицензионные комментарии) для pipeline.build.

    root — корень проекта, config — прочитанный sources.json. Обязательные файлы
    и манифесты берутся из output/threat-intel/, прошлые количества — из
    output/adguard/manifest.json. Ошибки возраста, SHA256, семейства, объёма или
    уведомлений прерывают сборку до изменения combined.txt; сеть не используется.
    """
    directory = root / "output/threat-intel"
    previous_path = root / "output/adguard/manifest.json"
    previous = {}
    if previous_path.exists():
        previous = {
            item["id"]: item for item in json.loads(previous_path.read_text()).get("ip_sources", [])
        }
    sources = [
        (
            "hagezi",
            "hagezi-ipv4.txt",
            next(
                item["minimum_rules"] for item in config["ip_sources"] if item["id"] == "hagezi-ips"
            ),
            None,
        ),
        (
            "spamhaus-ipv4",
            "spamhaus-ipv4.txt",
            config.get("drop_minimum_networks", {}).get("4", 1000),
            4,
        ),
        (
            "spamhaus-ipv6",
            "spamhaus-ipv6.txt",
            config.get("drop_minimum_networks", {}).get("6", 10),
            6,
        ),
    ]
    networks, reports, notices = set(), [], []
    for identifier, filename, minimum, family in sources:
        metadata = json.loads((directory / (identifier + "-manifest.json")).read_text())
        if metadata["enforcement"] != "dns_response":
            raise ValueError(f"Источник не разрешён для DNS-ответов: {identifier}")
        if family:
            check_age(metadata["source_published_at"], 48)
            for field in ["copyright", "terms"]:
                if not isinstance(metadata.get(field), str) or not metadata[field].strip():
                    raise ValueError(f"Отсутствует уведомление {identifier}: {field}")
            notices.extend(
                [
                    f"! {identifier}: {metadata['copyright']}",
                    f"! Terms: {metadata['terms']}",
                    f"! Source published: {metadata['source_published_at']}",
                ]
            )
        else:
            check_age(metadata["retrieved_at"], config["maximum_build_age_hours"])
            check_age(metadata["commit_at"], config["maximum_source_age_hours"])
        content = read_checked(directory / filename, metadata["artifact_sha256"], 5_000_000)
        values = {
            validate_public_network(line.strip())
            for line in content.splitlines()
            if line.strip() and not line.startswith(("#", "!"))
        }
        if len(values) != metadata["network_count"] or len(values) < minimum:
            raise ValueError(f"Некорректное количество сетей: {identifier}")
        if family and any(ipaddress.ip_network(value).version != family for value in values):
            raise ValueError(f"Неверное семейство адресов: {identifier}")
        old_count = previous.get(identifier, {}).get("network_count", 0)
        if old_count and len(values) < old_count * (
            1 - config.get("maximum_rule_drop_fraction", 0.25)
        ):
            raise ValueError(f"Слишком резкое сокращение IP-источника: {identifier}")
        networks.update(values)
        reports.append({**metadata, "id": identifier})
    return compile_networks(sorted(networks)), reports, notices
