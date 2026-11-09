#!/usr/bin/env python3
"""Получает доменные источники и собирает единый фильтр AdGuard Home.

Запуск из корня: python3 scripts/ru/pipeline.py refresh|validate|build.
refresh обращается через gh к GitHub API и скачивает списки по точному commit SHA
в .cache/feeds/; lock.json связывает каждый источник с файлом, датами и SHA256.
validate проверяет config/sources.json и региональные CSV/JSON без загрузки сети.
build читает этот кэш, regional/ru-cis/ и обязательные готовые IP-источники
из output/threat-intel/. Результаты записываются в output/adguard/: combined.txt
для AdGuard, региональный список, наблюдения IP и manifest.json для проверки.

Ошибка входных данных останавливает сборку до записи результатов. Каждый файл
заменяется атомарно; несколько файлов не образуют единую файловую транзакцию.
Сборщик не публикует Git-коммиты, не подключается к VPS и не перезапускает DNS.
Синхронизацию maintainer выполняет отдельный sync_upstream.py. См. docs/GLOSSARY.md.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from blocklists import (
    CATEGORIES,
    Rule,
    atomic_write,
    check_category,
    check_controls,
    compact_rules,
    normalize_domain,
    parse_source,
    render_rules,
)
from recent_threats import compile_reports, render_reports

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{40}\Z")


def now() -> str:
    """Возвращает текущее UTC-время с часовым поясом и точностью до секунды для метаданных."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def check_age(timestamp: str, maximum_hours: int) -> None:
    """Отклоняет дату без часового пояса, старше maximum_hours или более чем на 300 секунд в будущем."""
    value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("Время должно содержать часовой пояс")
    age = (datetime.now(timezone.utc) - value).total_seconds()
    if age < -300 or age > maximum_hours * 3600:
        raise ValueError(f"Недопустимый возраст данных: {timestamp}")


def read_checked(path: Path, expected_sha256: str, maximum_bytes: int) -> str:
    """Читает файл в пределах maximum_bytes, сверяет SHA256 и декодирует UTF-8 с возможным BOM."""
    if path.stat().st_size > maximum_bytes:
        raise ValueError(f"Источник превышает лимит размера: {path.name}")
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError(f"Не совпадает SHA256: {path.name}")
    return content.decode("utf-8-sig")


def github_json(endpoint: str) -> dict:
    """Вызывает gh api с таймаутом 60 секунд и возвращает JSON; авторизацию предоставляет gh или GH_TOKEN."""
    result = subprocess.run(
        ["gh", "api", endpoint], check=True, capture_output=True, text=True, timeout=60
    )
    return json.loads(result.stdout)


def load_config(root: Path) -> dict:
    """Читает config/sources.json, проверяет категории, уникальные id, пути и режим IP dns_response."""
    config = json.loads((root / "config/sources.json").read_text())
    if set(config["categories"]) != CATEGORIES:
        raise ValueError("Набор категорий должен совпадать с согласованными четырьмя")
    seen = set()
    for source in config["sources"] + config.get("ip_sources", []):
        check_category(source["category"])
        if source["id"] in seen or not re.fullmatch(r"[a-z0-9-]+", source["id"]):
            raise ValueError("Повторяющийся или небезопасный идентификатор источника")
        seen.add(source["id"])
        if ".." in Path(source["path"]).parts or Path(source["path"]).is_absolute():
            raise ValueError("Недопустимый путь источника")
        if source["format"] == "ip" and source.get("enforcement") != "dns_response":
            raise ValueError("IP-источник должен проверять DNS-ответы")
    return config


def download(source: dict, revision: dict, cache: Path, verified_at: str) -> dict:
    """Скачивает один источник по revision["sha"] и возвращает его метаданные.

    source задаёт репозиторий, путь, размер и лицензию; verified_at записывается
    как retrieved_at. Файл <id>-<SHA>.txt появляется в cache после проверки размера
    и кодировки. Сетевые и файловые ошибки не скрываются; .download удаляется в finally.
    """
    sha = revision["sha"]
    url = f"https://raw.githubusercontent.com/{source['repository']}/{sha}/{source['path']}"
    request = urllib.request.Request(url, headers={"User-Agent": "dns-blocklists-ru/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(source["maximum_bytes"] + 1)
    if len(data) > source["maximum_bytes"] or not data:
        raise ValueError(f"Недопустимый размер источника {source['id']}")
    data.decode("utf-8-sig")
    path = cache / f"{source['id']}-{sha}.txt"
    temporary = path.with_suffix(".download")
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "id": source["id"],
        "file": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "repository": source["repository"],
        "commit": sha,
        "commit_at": revision["commit"]["committer"]["date"],
        "retrieved_at": verified_at,
        "url": url,
        "bytes": len(data),
        "license": source["license"],
    }


def refresh(root: Path) -> None:
    """Получает текущие commit SHA источников и скачивает доменные списки в .cache/feeds/.

    До загрузки проверяет совпадение удалённой maintainer с upstream main; ветки
    сам не меняет. Три потока скачивают данные, после успеха всех записывается lock.json.
    При ошибке lock не заменяется, хотя отдельные успешно скачанные файлы могут остаться.
    """
    config = load_config(root)
    cache = root / ".cache/feeds"
    cache.mkdir(parents=True, exist_ok=True)
    revisions = {}
    for source in config["sources"]:
        key = (source["repository"], source["ref"])
        if key not in revisions:
            revisions[key] = github_json(f"repos/{key[0]}/commits/{key[1]}")
            if not SHA.fullmatch(revisions[key]["sha"]):
                raise ValueError("GitHub вернул некорректный SHA")
    upstream_sha = revisions[(config["upstream_repository"], "main")]["sha"]
    mirror = github_json(
        f"repos/{config['mirror_repository']}/git/ref/heads/{config['mirror_branch']}"
    )
    if mirror["object"]["sha"] != upstream_sha:
        raise ValueError("maintainer отстаёт от upstream: сначала выполните sync")
    verified_at = now()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(
                download,
                source,
                revisions[(source["repository"], source["ref"])],
                cache,
                verified_at,
            )
            for source in config["sources"]
        ]
        records = [future.result() for future in futures]
    atomic_write(
        cache / "lock.json",
        json.dumps(
            {
                "schema_version": 1,
                "retrieved_at": verified_at,
                "upstream_commit": upstream_sha,
                "sources": records,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )
    print(f"Получено источников: {len(records)}; upstream: {upstream_sha}")


def regional_rule(row: dict, current_domains: dict[str, set[str]]) -> Rule | None:
    """Проверяет строку domains.csv и возвращает Rule либо None.

    Нужны разрешённая категория, scope, HTTPS-ссылка и дата проверки. Для malware
    обязателен requires_feed: домен включается только при наличии в текущем источнике.
    None означает отсутствие актуального подтверждения; неверные поля вызывают ошибку.
    """
    check_category(row["category"])
    if row["scope"] not in {"exact", "suffix", "subdomains"}:
        raise ValueError("Неизвестная область регионального правила")
    evidence = row.get("evidence_url", "")
    if not evidence.startswith("https://") or not urlparse(evidence).hostname:
        raise ValueError("Для регионального правила требуется HTTPS-источник")
    datetime.strptime(row["reviewed_on"], "%Y-%m-%d")
    domain = normalize_domain(row["domain"])
    required = row.get("requires_feed")
    if row["category"] == "malware" and not required:
        raise ValueError("Malware-добавление требует подтверждения текущим feed")
    if required:
        if required not in current_domains:
            raise ValueError(f"Неизвестный подтверждающий источник: {required}")
        if domain not in current_domains[required]:
            return None
    return Rule(domain, row["scope"])


def regional_exception(row: dict) -> Rule:
    """Преобразует строку allowlist.csv в точное исключение; требует scope=exact, дату, ссылку и причину."""
    if row.get("scope") != "exact":
        raise ValueError("Региональное исключение должно иметь scope=exact")
    if not row.get("evidence_url", "").startswith("https://") or not row.get("reason"):
        raise ValueError("Исключению нужны источник и обоснование")
    datetime.strptime(row["reviewed_on"], "%Y-%m-%d")
    return Rule(normalize_domain(row["domain"]), "exact", True)


def build(root: Path) -> None:
    """Собирает output/adguard/ из проверенных доменных, региональных и IP-входов.

    Сначала проверяет обязательные IP-файлы, затем lock, свежесть, SHA256 и объёмы
    доменов. Сокращение источника более разрешённой доли или неверный контрольный
    домен останавливает выпуск. Региональные дополнения и исключения объединяются
    с исходными правилами; manifest содержит происхождение, количества и SHA256.
    Запись выходных файлов начинается только после проверки данных; каждый файл
    заменяется отдельно, manifest записывается последним. Сети и Git-вызовов нет.
    """
    # ip_inputs использует check_age/read_checked из этого модуля; поздний импорт
    # позволяет завершить определение этих функций до загрузки зависимого модуля.
    from ip_inputs import load_ip_rules

    config = load_config(root)
    ip_lines, ip_sources, ip_notices = load_ip_rules(root, config)
    cache = root / ".cache/feeds"
    lock = json.loads((cache / "lock.json").read_text())
    check_age(lock["retrieved_at"], config["maximum_build_age_hours"])
    cached = {entry["id"]: entry for entry in lock["sources"]}
    if set(cached) != {source["id"] for source in config["sources"]}:
        raise ValueError("Состав снимка не совпадает с реестром источников")
    # Предыдущий манифест нужен как база сравнения объёма, а не как новый источник.
    previous_sources = {}
    previous_manifest = root / "output/adguard/manifest.json"
    if previous_manifest.exists():
        previous_sources = {
            entry["id"]: entry for entry in json.loads(previous_manifest.read_text())["sources"]
        }
    all_rules: set[Rule] = set()
    current_domains = {}
    sources_report = []
    upstream_ips = set()
    for source in config["sources"]:
        entry = cached[source["id"]]
        if Path(entry["file"]).name != entry["file"]:
            raise ValueError("Недопустимое имя файла снимка")
        check_age(entry["retrieved_at"], config["maximum_build_age_hours"])
        check_age(entry["commit_at"], config["maximum_source_age_hours"])
        text = read_checked(cache / entry["file"], entry["sha256"], source["maximum_bytes"])
        result = parse_source(text, source["format"], source["minimum_rules"])
        count = len(result.rules)
        unique_count = len(set(result.rules))
        previous = previous_sources.get(source["id"], {})
        previous_count = previous.get("unique_rules", previous.get("input_rules", 0))
        if previous_count and unique_count < previous_count * (
            1 - config.get("maximum_rule_drop_fraction", 0.25)
        ):
            raise ValueError(
                f"Слишком резкое сокращение источника {source['id']}: {previous_count} -> {unique_count}"
            )
        upstream_ips.update(result.ips)
        rules = compact_rules(result.rules)
        all_rules.update(rules)
        if source["id"] == "hagezi-tif":
            current_domains[source["id"]] = {rule.domain for rule in rules if not rule.allow}
        sources_report.append(
            {
                **entry,
                "category": source["category"],
                "input_rules": count,
                "unique_rules": unique_count,
                "excluded_public_suffixes": result.excluded_public_suffixes,
            }
        )
        print(f"{source['id']}: {count}", flush=True)
    regional = []
    skipped = []
    with (root / "regional/ru-cis/domains.csv").open(newline="") as stream:
        for row in csv.DictReader(stream):
            rule = regional_rule(row, current_domains)
            if rule is None:
                skipped.append(row["domain"])
            else:
                regional.append(rule)
    exceptions = []
    allowlist_path = root / "regional/ru-cis/allowlist.csv"
    if allowlist_path.exists():
        with allowlist_path.open(newline="") as stream:
            exceptions = [regional_exception(row) for row in csv.DictReader(stream)]
    # Сравнение одинаковых входов до/после региональных правил: это число имён,
    # дополнительно запрещённых напрямую, а не доля рекламы и не учёт CNAME.
    regional_new_names = []
    ancestors = set()
    for rule in regional:
        labels = rule.domain.split(".")
        ancestors.update(".".join(labels[index:]) for index in range(len(labels)))
    regional_base = {candidate for candidate in all_rules if candidate.domain in ancestors}
    for rule in regional:
        if not any(candidate.matches(rule.domain) for candidate in exceptions):
            # Узкий набор возможных предков позволяет не обходить миллионы правил
            # для каждого имени. check_controls учитывает исключения источников.
            try:
                check_controls(regional_base, [rule.domain])
                regional_new_names.append(rule.domain)
            except ValueError:
                pass
    reports_path = root / "regional/ru-cis/recent-threats.json"
    reports = compile_reports(
        json.loads(reports_path.read_text()), datetime.now(timezone.utc).date()
    )
    report_domains = [Rule(name, "exact") for item in reports for name in item["domains"]]
    all_rules.update(exceptions)
    all_rules.update(regional)
    all_rules = compact_rules(all_rules)
    controls = json.loads((root / "config/controls.json").read_text())
    check_controls(all_rules, controls["allowed"])
    check_controls(all_rules | set(report_domains), controls["allowed"])
    blocked_ancestors = set()
    for domains in controls["blocked"].values():
        for name in domains:
            labels = normalize_domain(name).split(".")
            blocked_ancestors.update(".".join(labels[index:]) for index in range(len(labels)))
    # Контроли используют только правила своего имени и его предков. Один проход
    # по большой базе сохраняет семантику и исключает её повторную индексацию
    # для каждого из десятков контрольных доменов.
    control_rules = {rule for rule in all_rules if rule.domain in blocked_ancestors}
    for category, domains in controls["blocked"].items():
        check_category(category)
        for domain in domains:
            try:
                check_controls(control_rules, [domain])
            except ValueError:
                continue
            raise ValueError(f"Отсутствует контрольная блокировка: {domain}")
    lines = sorted(rule.to_adguard() for rule in all_rules)
    header = "! Title: dns-blocklists-ru\n! Description: Реклама, трекеры, malware и азартные игры; взрослые сайты и соцсети не выделяются в запрещённые категории.\n! Expires: 24 hours\n! License: доменные правила и HaGeZi GPL-3.0; Spamhaus по собственным условиям, см. уведомления ниже и docs/SOURCES.md\n"
    domain_count = len(lines)
    lines = sorted(set(lines) | set(ip_lines))
    combined = header + "\n".join(ip_notices + lines) + "\n" + render_reports(reports)
    report_ip_count = sum(len(item["ips"]) for item in reports)
    report_domain_count = len(report_domains)
    total_count = len(lines) + report_ip_count + report_domain_count
    if len(combined.encode()) > 95_000_000:
        raise ValueError("Фильтр превышает допустимый размер GitHub-файла")
    manifest = {
        "schema_version": 1,
        "verified_at": lock["retrieved_at"],
        "upstream_commit": lock["upstream_commit"],
        "categories": config["categories"],
        "excluded_categories": ["adult", "social"],
        "rule_count": total_count,
        "regional_rule_count": len(regional),
        "regional_new_direct_names": sorted(regional_new_names),
        "recent_reports": reports,
        "regional_exceptions": [rule.domain for rule in exceptions],
        "regional_malware_not_in_current_feed": skipped,
        "ip_enforcement": "dns_response",
        "domain_rule_count": domain_count + report_domain_count,
        "ip_rule_count": len(ip_lines) + report_ip_count,
        "ip_sources": ip_sources,
        "sha256": hashlib.sha256(combined.encode()).hexdigest(),
        "sources": sources_report,
        "allowed_controls": controls["allowed"],
        "blocked_controls": controls["blocked"],
    }
    # До этого места входы проверяются в памяти. Только после всех проверок
    # начинается замена файлов; публикация GitHub выполняется отдельным workflow.
    out = root / "output/adguard"
    atomic_write(out / "combined.txt", combined)
    atomic_write(
        out / "ru-cis.txt",
        "! Региональные дополнения; происхождение: regional/ru-cis/domains.csv\n"
        + "\n".join(render_rules(regional + exceptions))
        + "\n"
        + render_reports(reports),
    )
    atomic_write(
        out / "upstream-ip-observations.txt",
        "# Наблюдения IP из Mullvad; автоматическая блокировка отключена.\n"
        + "\n".join(sorted(upstream_ips))
        + "\n",
    )
    atomic_write(out / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"Собрано {total_count} правил; SHA256 {manifest['sha256']}")


def validate(root: Path) -> None:
    """Проверяет структуру конфигурации и региональных записей без сети; актуальность malware-feed не подтверждает."""
    load_config(root)
    compile_reports(
        json.loads((root / "regional/ru-cis/recent-threats.json").read_text()),
        datetime.now(timezone.utc).date(),
    )
    current = {"hagezi-tif": set()}
    with (root / "regional/ru-cis/domains.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError("Региональный каталог пуст")
    for row in rows:
        regional_rule(row, current)
    allowlist_path = root / "regional/ru-cis/allowlist.csv"
    if allowlist_path.exists():
        with allowlist_path.open(newline="") as stream:
            for row in csv.DictReader(stream):
                regional_exception(row)
    print(f"Каталог проверен: {len(rows)} доменов")


def main() -> int:
    """Разбирает CLI-команду и --root, вызывает refresh/build/validate; обработанные ошибки печатает с кодом 1."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["refresh", "build", "validate"])
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        {"refresh": refresh, "build": build, "validate": validate}[args.command](args.root)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
