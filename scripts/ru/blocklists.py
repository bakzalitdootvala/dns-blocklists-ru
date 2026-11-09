#!/usr/bin/env python3
"""Разбирает доменные списки и предоставляет общие проверки сборщика.

Модуль используется pipeline.py, threat_intel.py и ip_rules.py. На вход функций
поступают текстовые списки и отдельные имена; результат — объекты Rule, отчёты
об исключённых записях или строки формата AdGuard Home. Сеть не используется.
При импорте читаются config/public_suffix_list.dat и public-suffix-source.json:
PSL (Public Suffix List) перечисляет суффиксы независимых владельцев, например
co.nz и github.io, блокировка которых целиком затронула бы множество сайтов.
Контрольная сумма закреплённого PSL проверяется до разбора правил.

Самостоятельной команды запуска нет. atomic_write() записывает файлы вызывающего
сборщика через временный файл и замену имени. Термины: docs/GLOSSARY.md.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

CATEGORIES = frozenset({"adblock", "privacy", "malware", "gambling"})
LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")


def load_public_suffixes() -> tuple[set[str], set[str], set[str]]:
    """Читает PSL и возвращает три множества: точные суффиксы, wildcard и исключения.

    Имена переводятся в ASCII через IDNA. Контрольная сумма и минимум 1000 точных
    суффиксов защищают от повреждённого снимка; нарушение вызывает ValueError.
    """
    config = Path(__file__).resolve().parents[2] / "config"
    content = (config / "public_suffix_list.dat").read_bytes()
    metadata = json.loads((config / "public-suffix-source.json").read_text())
    if hashlib.sha256(content).hexdigest() != metadata["sha256"]:
        raise ValueError("Нарушена целостность Public Suffix List")
    exact, wildcard, exceptions = set(), set(), set()
    for line in content.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        target = (
            exceptions if line.startswith("!") else wildcard if line.startswith("*.") else exact
        )
        line = line.removeprefix("!").removeprefix("*.")
        target.add(line.encode("idna").decode("ascii").lower())
    if len(exact) < 1000:
        raise ValueError("Public Suffix List пуст или повреждён")
    return exact, wildcard, exceptions


# PSL читается один раз при импорте: миллионы доменов используют готовые множества.
PUBLIC_SUFFIXES, WILDCARD_SUFFIXES, SUFFIX_EXCEPTIONS = load_public_suffixes()


def is_public_suffix(domain: str) -> bool:
    """Проверяет, является ли нормализованное имя общей зоной, учитывая исключения PSL."""
    if domain in SUFFIX_EXCEPTIONS:
        return False
    return domain in PUBLIC_SUFFIXES or domain.partition(".")[2] in WILDCARD_SUFFIXES


class PublicSuffixError(ValueError):
    """Ошибка для правила на общий суффикс; parse_source учитывает его в отчёте исключений."""


def normalize_domain(value: str, *, allow_public_suffix: bool = False) -> str:
    """Приводит имя к нижнему регистру и ASCII IDNA, убирает пробелы и конечную точку.

    Возвращает домен без добавления wildcard. IP, неверные метки, RPZ-триггеры и
    общие суффиксы отвергаются через ValueError или его подкласс PublicSuffixError.
    allow_public_suffix разрешён для контрольного запроса (у gov.kg есть сайт),
    но не при создании блокирующего правила.
    """
    value = value.strip().rstrip(".").lower()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError(f"IP не является доменным правилом: {value}")
    try:
        domain = value if value.isascii() else value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Некорректное IDNA-имя") from error
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(not LABEL.fullmatch(x) for x in labels):
        raise ValueError(f"Некорректное доменное имя: {domain}")
    if labels[-1].isdigit() or domain.endswith((".rpz.ip", ".rpz-ip")):
        raise ValueError(f"Недопустимая область блокировки: {domain}")
    if not allow_public_suffix and is_public_suffix(domain):
        raise PublicSuffixError(domain)
    return domain


@dataclass(frozen=True, slots=True)
class Rule:
    """Неизменяемое доменное правило для проверки и вывода в формате AdGuard.

    domain — нормализованное имя; scope: exact (только имя), subdomains (только
    его потомки), suffix (имя и потомки). allow=True обозначает разрешающее исключение.
    """

    domain: str
    scope: str = "exact"
    allow: bool = False

    def matches(self, hostname: str) -> bool:
        """Проверяет hostname с учётом scope; точка перед суффиксом отделяет соседние имена."""
        hostname = normalize_domain(hostname, allow_public_suffix=True)
        exact = hostname == self.domain
        child = hostname.endswith("." + self.domain)
        return (exact and self.scope != "subdomains") or (child and self.scope != "exact")

    def to_adguard(self) -> str:
        """Возвращает строку AdGuard; @@ обозначает исключение, || и *. сохраняют область правила."""
        prefix = "@@" if self.allow else ""
        if self.scope == "suffix":
            return f"{prefix}||{self.domain}^"
        if self.scope == "subdomains":
            return f"{prefix}||*.{self.domain}^"
        return f"{prefix}|{self.domain}^" if self.allow else self.domain


def check_category(category: str) -> None:
    """Отклоняет категорию вне adblock/privacy/malware/gambling, в том числе adult и social."""
    if category not in CATEGORIES:
        raise ValueError(f"Категория не разрешена: {category}")


def parse_domain_rule(text: str, source_format: str) -> Rule:
    """Разбирает одну строку формата mullvad, domains или поддерживаемого подмножества adguard.

    Возвращает Rule с точной областью совпадения. URL-пути, модификаторы браузерных
    правил и неизвестный синтаксис вызывают ValueError, а не безусловную DNS-блокировку.
    """
    text = text.strip()
    allow = False
    scope = "exact"
    if source_format not in {"mullvad", "adguard", "domains"}:
        raise ValueError(f"Неизвестный формат: {source_format}")
    if source_format == "adguard":
        if text.startswith("@@"):
            allow, text = True, text[2:]
        if text.startswith("||") and text.endswith("^"):
            scope, text = "suffix", text[2:-1]
        elif text.startswith("|") and text.endswith("^"):
            text = text[1:-1]
        elif any(char in text for char in "|^@$"):
            raise ValueError("Правило содержит неподдерживаемый синтаксис")
    if text.startswith("*."):
        scope, text = "subdomains", text[2:]
    if any(char in text for char in "*|^@$#/\\: \t\r\n"):
        raise ValueError("Контекстное или недоменное правило")
    return Rule(normalize_domain(text), scope, allow)


def compact_rules(rules: Iterable[Rule]) -> set[Rule]:
    """Убирает дубли; exact и subdomains одного имени объединяет в suffix отдельно для allow/deny."""
    grouped: dict[tuple[str, bool], set[str]] = {}
    for rule in rules:
        grouped.setdefault((rule.domain, rule.allow), set()).add(rule.scope)
    result = set()
    for (domain, allow), scopes in grouped.items():
        if "suffix" in scopes or {"exact", "subdomains"} <= scopes:
            result.add(Rule(domain, "suffix", allow))
        else:
            result.update(Rule(domain, scope, allow) for scope in scopes)
    return result


def render_rules(rules: Iterable[Rule]) -> list[str]:
    """Возвращает отсортированные строки AdGuard после объединения эквивалентных правил."""
    return sorted(rule.to_adguard() for rule in compact_rules(rules))


@dataclass
class SourceResult:
    """Результат parse_source: доменные Rule, отдельные IP и суффиксы, исключённые по PSL."""

    rules: list[Rule]
    ips: list[str]
    excluded_public_suffixes: list[str] = field(default_factory=list)


def validate_public_network(value: str) -> str:
    """Разбирает IP/CIDR строго и возвращает нормализованную сеть, например 8.8.8.8/32.

    Проверяет публичность первого и последнего адресов, исключает multicast и
    reserved на этих границах. Некорректный адрес или префикс вызывает ValueError.
    """
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as error:
        raise ValueError(f"Некорректный IP/CIDR: {value}") from error
    if any(
        not address.is_global or address.is_multicast or address.is_reserved
        for address in [network.network_address, network.broadcast_address]
    ):
        raise ValueError(f"IP/CIDR не является публичным: {value}")
    return str(network)


def parse_source(text: str, source_format: str, minimum_rules: int) -> SourceResult:
    """Разбирает весь текст источника и возвращает SourceResult.

    Комментарии пропускаются, IP учитываются отдельно от доменов. Общие суффиксы
    попадают в отчёт; другие ошибки строки прерывают разбор с её номером.
    minimum_rules относится к уникальным доменным правилам, а не числу строк.
    """
    if "<html" in text[:1024].lower() or "<!doctype" in text[:1024].lower():
        raise ValueError("Вместо списка получен HTML")
    rules, ips = [], []
    excluded_suffixes = set()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("!", "#", ";", "[Adblock")):
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            pass
        else:
            validate_public_network(line)
            ips.append(line)
            continue
        try:
            rules.append(parse_domain_rule(line, source_format))
        except PublicSuffixError as error:
            excluded_suffixes.add(str(error))
        except ValueError as error:
            raise ValueError(f"Строка {number}: {error}") from error
    # Повторы не подтверждают полноту: тысяча копий одного имени — одно правило.
    if len(set(rules)) < minimum_rules:
        raise ValueError(f"Слишком мало уникальных правил: {len(set(rules))} < {minimum_rules}")
    return SourceResult(rules, sorted(set(ips)), sorted(excluded_suffixes))


def check_controls(rules: Iterable[Rule], allowed_domains: Iterable[str]) -> None:
    """Проверяет, что allowed_domains не блокируются доменными правилами.

    Строит индексы запрещающих и разрешающих правил по имени и scope, затем
    проверяет суффиксы каждого контрольного имени. Разрешающее правило имеет приоритет;
    блокировка без исключения вызывает ValueError. IP-ответы эта функция не проверяет.
    """
    blocked: dict[str, set[str]] = {}
    allowed: dict[str, set[str]] = {}
    for rule in rules:
        index = allowed if rule.allow else blocked
        index.setdefault(rule.domain, set()).add(rule.scope)
    for hostname in allowed_domains:
        hostname = normalize_domain(hostname, allow_public_suffix=True)
        matches = {}
        labels = hostname.split(".")
        for offset in range(len(labels) - 1):
            suffix = ".".join(labels[offset:])
            for decision, index in [("blocked", blocked), ("allowed", allowed)]:
                scopes = index.get(suffix, set())
                if (
                    "suffix" in scopes
                    or (offset == 0 and "exact" in scopes)
                    or (offset > 0 and "subdomains" in scopes)
                ):
                    matches[decision] = suffix
        if "blocked" in matches and "allowed" not in matches:
            raise ValueError(f"Контрольный домен заблокирован: {hostname} ({matches['blocked']})")


def atomic_write(path: Path, content: str) -> None:
    """Записывает UTF-8/LF файл с правами 0644 через временный файл в том же каталоге.

    После flush/fsync заменяет целевой путь через os.replace и убирает временный
    файл в finally. Родительский каталог создаётся при необходимости; ошибки I/O
    передаются вызывающему коду. Атомарна замена одного файла, а не набора файлов.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
