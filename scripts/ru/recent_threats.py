"""Создаёт краткосрочные DNS-правила из первичных отчётов об атаках.

pipeline.py читает regional/ru-cis/recent-threats.json и вызывает compile_reports.
Разрешены точные hostname и отдельные публичные IP, срок — ровно 30 суток
от публикации. Дата публикации не считается last_seen вредоносной активности.
render_reports помещает правила в помеченные блоки combined.txt; expire_text
снимает истёкшие блоки для серверного expire_filter.py без сети и пересборки базы.
"""

import re
from datetime import date, timedelta
from ipaddress import ip_address
from urllib.parse import urlparse

START = re.compile(r"! Regional report: ([a-z0-9-]+) expires=(\d{4}-\d{2}-\d{2})\Z")
END = "! End regional report"


def compile_reports(data: dict, today: date) -> list[dict]:
    """Проверяет все отчёты и возвращает действующие с точными правилами.

    Неверная схема/дата/адрес вызывает ValueError; истёкшие записи остаются
    в исходном JSON для проверки происхождения, но не создают правила.
    """
    # Серверное снятие срока использует только expire_text и стандартную библиотеку;
    # PSL и сборщик нужны только при создании новых правил.
    from blocklists import normalize_domain, validate_public_network

    active = []
    seen = set()
    for item in data["reports"]:
        identifier = item["id"]
        if not re.fullmatch(r"[a-z0-9-]+", identifier) or identifier in seen:
            raise ValueError("Некорректный или повторный id отчёта")
        seen.add(identifier)
        evidence = item["evidence_url"]
        # URL попадает в однострочный комментарий фильтра. Перенос строки
        # нельзя отдавать render_reports: он превратит продолжение в DNS-правило.
        if not isinstance(evidence, str) or any(
            char.isspace() or ord(char) < 32 or ord(char) == 127 for char in evidence
        ):
            raise ValueError("Ссылка источника должна быть одной строкой без управляющих символов")
        url = urlparse(evidence)
        if url.scheme != "https" or not url.hostname:
            raise ValueError("Нужен первичный HTTPS-источник")
        published = date.fromisoformat(item["published_on"])
        expires = date.fromisoformat(item["expires_on"])
        if published > today or expires != published + timedelta(days=30):
            raise ValueError("Срок отчёта должен составлять 30 суток от прошедшей даты публикации")
        if not item["target_countries"] or any(
            not re.fullmatch(r"[A-Z]{2}", country) for country in item["target_countries"]
        ):
            raise ValueError("Нужны коды стран подтверждённых целей")
        if item["last_seen"] is not None:
            observed = date.fromisoformat(item["last_seen"])
            if observed > published:
                raise ValueError("Наблюдение не может быть позже цитируемого отчёта")
        rules = []
        for name in item["domains"]:
            rules.append(f"|{normalize_domain(name)}^")
        for value in item["ips"]:
            address = ip_address(value)  # CIDR здесь намеренно не допускается.
            validate_public_network(str(address))
            rules.append(f"|{address}|")
        if not rules or len(rules) != len(set(rules)):
            raise ValueError("Пустой отчёт или повтор индикатора")
        if today < expires:
            active.append({**item, "rules": sorted(rules)})
    return active


def render_reports(reports: list[dict]) -> str:
    """Сериализует проверенные отчёты в блоки с явными границами и сроком удаления."""
    return "".join(
        f"! Regional report: {item['id']} expires={item['expires_on']}\n"
        f"! Evidence: {item['evidence_url']}\n" + "\n".join(item["rules"]) + f"\n{END}\n"
        for item in reports
    )


def expire_text(text: str, today: date) -> str:
    """Удаляет только целые истёкшие блоки; остальные байты UTF-8 текста сохраняет.

    Оборванный, вложенный или некорректный маркер вызывает ValueError до записи
    файлов. Одинаковое правило вне блока не удаляется: у него другой источник.
    """
    result = []
    inside = False
    expired = False
    for line in text.splitlines(keepends=True):
        value = line.rstrip("\r\n")
        if value.startswith("! Regional report:"):
            match = START.fullmatch(value)
            if inside or not match:
                raise ValueError("Некорректное начало блока отчёта")
            inside = True
            expired = today >= date.fromisoformat(match[2])
        if value == END:
            if not inside:
                raise ValueError("Конец отчёта без начала")
            if not expired:
                result.append(line)
            inside = expired = False
            continue
        if not expired:
            result.append(line)
    if inside:
        raise ValueError("Незавершённый блок отчёта")
    return "".join(result)
