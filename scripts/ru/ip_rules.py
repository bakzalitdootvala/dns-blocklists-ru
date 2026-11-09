#!/usr/bin/env python3
"""Переводит IP и CIDR-сети в строки фильтра combined.txt для AdGuard Home.

Вызывается ip_inputs.load_ip_rules(); файлов и сетевых подключений не создаёт.
CIDR — запись диапазона адресов через длину общего префикса, например /24.
Для одного адреса создаётся |IP|, а для сети — регулярное выражение /^...$/.
Сети не раскрываются в перечень миллионов отдельных адресов. Совпадение должно
охватывать весь IP, чтобы число внутри доменного имени не стало блокировкой.

IPv4 обрабатывается по четырём десятичным числам, IPv6 — по восьми 16-битным
группам с учётом сокращения нулей через ::. Вход AdGuard предполагается в его
канонической форме net.IP.String(). Корректность диапазонов проверяют
tests/test_ip_rules.py, фактическое поведение — test_ip_response.py.
Термины и разбор регулярного выражения: docs/GLOSSARY.md.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from blocklists import validate_public_network

DIGITS = "0123456789abcdef"


def alternatives(parts: list[str]) -> str:
    """Объединяет уникальные варианты через | в группу (?:...), которая не сохраняет отдельное совпадение."""
    parts = list(dict.fromkeys(parts))
    return parts[0] if len(parts) == 1 else "(?:" + "|".join(parts) + ")"


def digit_class(low: int, high: int) -> str:
    """Возвращает одну цифру или класс допустимых цифр между low и high включительно."""
    return DIGITS[low] if low == high else "[" + DIGITS[low : high + 1] + "]"


@lru_cache(maxsize=4096)
def number_pattern(low: int, high: int, base: int) -> str:
    """Строит regex для целых low..high в системе base=10 или base=16 без ведущих нулей.

    Диапазон делится по длине записи и старшим цифрам, поэтому 0..255 не требует
    256 отдельных альтернатив. Результаты повторных диапазонов кэшируются в памяти.
    """
    if base not in (10, 16) or low < 0 or high < low:
        raise ValueError("Некорректный числовой диапазон")

    def digits(value: int) -> str:
        """Преобразует число в десятичную либо строчную шестнадцатеричную запись выбранной base."""
        return str(value) if base == 10 else format(value, "x")

    def tail(length: int) -> str:
        """Строит regex для произвольного хвоста фиксированной длины в выбранной системе счисления."""
        if length == 0:
            return ""
        pattern = digit_class(0, base - 1)
        return pattern if length == 1 else pattern + "{" + str(length) + "}"

    def equal_length(first: str, last: str) -> str:
        """Рекурсивно разбивает диапазон строк одинаковой длины на нижнюю границу, середину и верхнюю границу."""
        if first == last:
            return first
        if first == "0" * len(first) and last == DIGITS[base - 1] * len(last):
            return tail(len(first))
        if first[0] == last[0]:
            return first[0] + equal_length(first[1:], last[1:])
        lo, hi = int(first[0], base), int(last[0], base)
        count = len(first) - 1
        pieces = [DIGITS[lo] + equal_length(first[1:], DIGITS[base - 1] * count)]
        if lo + 1 <= hi - 1:
            pieces.append(digit_class(lo + 1, hi - 1) + tail(count))
        pieces.append(DIGITS[hi] + equal_length("0" * count, last[1:]))
        return alternatives(pieces)

    pieces = []
    for length in range(len(digits(low)), len(digits(high)) + 1):
        start = max(low, 0 if length == 1 else base ** (length - 1))
        end = min(high, base**length - 1)
        pieces.append(equal_length(digits(start), digits(end)))
    return alternatives(pieces)


def network_pattern(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """Создаёт regex с якорями ^/$ для канонической строки IP внутри network.

    IPv4 собирается по октетам (числам 0..255). Для IPv6 учитываются допустимые
    нулевые группы, которые могут сокращаться через ::. Адреса сети не перечисляются;
    валидность публичного диапазона проверяет вызывающий compile_networks().
    """
    if network.version == 4:
        first, last = network.network_address.packed, network.broadcast_address.packed
        body = r"\.".join(number_pattern(lo, hi, 10) for lo, hi in zip(first, last))
    else:
        first, last = int(network.network_address), int(network.broadcast_address)
        bounds = [
            ((first >> shift) & 65535, (last >> shift) & 65535) for shift in range(112, -1, -16)
        ]
        groups = [number_pattern(lo, hi, 16) for lo, hi in bounds]
        variants = [":".join(groups)]
        # Каноническая IPv6-строка сокращает последовательность нулевых групп.
        # Добавляем допустимые положения ::, не перечисляя адреса внутри сети.
        for start in range(8):
            for end in range(start + 2, 9):
                if all(lo == 0 for lo, _ in bounds[start:end]):
                    variants.append(":".join(groups[:start]) + "::" + ":".join(groups[end:]))
        body = alternatives(variants)
    return "^" + body + "$"


def compile_networks(values: list[str]) -> list[str]:
    """Возвращает уникальные отсортированные IP-правила AdGuard из списка IP/CIDR.

    Один адрес выводится как |IP|, диапазон — как /^regex$/. Якоря не дают совпасть
    с адресом внутри hostname. Неподходящая сеть или правило длиннее 60000 байт
    вызывает ValueError. Число правил зависит от числа сетей, а не адресов внутри них.
    """
    lines = set()
    for value in values:
        network = ipaddress.ip_network(validate_public_network(value))
        if network.num_addresses == 1:
            # Голый IP может совпасть с числом внутри hostname; | ограничивает оба края.
            line = "|" + str(network.network_address) + "|"
        else:
            line = "/" + network_pattern(network) + "/"
        if len(line.encode()) > 60000:
            raise ValueError(f"Правило CIDR превышает безопасную длину: {network}")
        lines.add(line)
    return sorted(lines)
