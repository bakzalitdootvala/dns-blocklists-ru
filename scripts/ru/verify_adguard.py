#!/usr/bin/env python3
"""Проверяет готовый DNS-сервис на контрольных доменах проекта.

Запуск: python3 scripts/ru/verify_adguard.py --dns-port <порт>.
Читает config/controls.json либо --controls; для каждого имени запускает dig
отдельно для A (IPv4) и AAAA (IPv6). Ожидаемые блокировки должны возвращать
нулевые адреса обоих семейств; --allow-loopback-blocks дополнительно допускает
локальные адреса старых hosts-фильтров. Разрешённому имени нужен реальный IP,
при этом оба типа запроса должны завершиться NOERROR, даже если один ответ пуст.

--api-url дополнительно проверяет решение HTTP API AdGuard, --filter-id —
происхождение блокировки. Этот режим рассчитан на доступный без авторизации
изолированный API; он не сбрасывает учётные данные рабочего сервера.
Результат — JSON в stdout и код 0/1. Конфигурация сервиса не изменяется;
запросы к проверяемому DNS могут привести к его обращениям к внешним DNS.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def verify_domain(host: str, expected_blocked: bool, args: argparse.Namespace) -> dict:
    """Сверяет DNS-ответы одного host с expected_blocked и возвращает отдельные результаты A/AAAA.

    При --api-url сначала проверяет решение AdGuard и при необходимости filter_id.
    Затем вызывает dig: NOERROR проверяется для каждого типа, отсутствие AAAA
    разрешено только обычному домену при наличии другого реального IP. SERVFAIL,
    неожиданная блокировка, пропавший ответ блокировки или неверный источник — ошибка.
    allow_loopback_blocks дополнительно принимает 127.0.0.0/8 и ::1 как ответы
    старых hosts-фильтров; для обычных публичных сайтов такие ответы запрещены.
    """
    if args.api_url:
        query = urllib.parse.urlencode({"name": host})
        with urllib.request.urlopen(
            f"{args.api_url}/control/filtering/check_host?{query}", timeout=15
        ) as response:
            decision = json.load(response)
        actual = decision.get("reason", "").startswith("Filtered")
        if actual != expected_blocked:
            raise ValueError(f"Неожиданное решение фильтра для {host}: {decision.get('reason')}")
        if (
            expected_blocked
            and args.filter_id is not None
            and not any(
                item.get("filter_list_id") == args.filter_id for item in decision.get("rules", [])
            )
        ):
            raise ValueError(f"Домен {host} блокируется другим фильтром")
    addresses = []
    responses = {}
    # Общий список адресов недостаточен: успешный A не должен скрыть SERVFAIL AAAA.
    for record_type in ["A", "AAAA"]:
        result = subprocess.run(
            [
                "dig",
                "@" + args.dns_server,
                "-p",
                str(args.dns_port),
                host,
                record_type,
                "+time=5",
                "+tries=1",
                "+noall",
                "+comments",
                "+answer",
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if result.returncode:
            raise ValueError(f"Ошибка DNS-запроса для {host}: {result.returncode}")
        status = re.search(r"\bstatus:\s*([A-Z0-9]+),", result.stdout)
        if status is None or status.group(1) != "NOERROR":
            raise ValueError(
                f"Ошибка DNS {record_type} для {host}: {status.group(1) if status else 'нет RCODE'}"
            )
        typed_addresses = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 5 or fields[2] != "IN" or fields[3] != record_type:
                continue
            address = ipaddress.ip_address(fields[4])
            if address.version != (4 if record_type == "A" else 6):
                raise ValueError(f"Неверное семейство IP в ответе {record_type} для {host}")
            typed_addresses.append(address)
        if expected_blocked:
            if not typed_addresses or any(
                not (
                    address.is_unspecified
                    or (getattr(args, "allow_loopback_blocks", False) and address.is_loopback)
                )
                for address in typed_addresses
            ):
                raise ValueError(f"Для {host} {record_type} ожидался отдельный ответ блокировки")
        elif any(address.is_unspecified or address.is_loopback for address in typed_addresses):
            raise ValueError(f"Обычный домен {host} заблокирован для {record_type}")
        responses[record_type] = {"rcode": status.group(1), "address_count": len(typed_addresses)}
        addresses.extend(typed_addresses)
    if not addresses:
        raise ValueError(f"Обычный домен {host} не получил реальный IP")
    return {
        "domain": host,
        "blocked": expected_blocked,
        "address_count": len(addresses),
        "responses": responses,
    }


def main() -> int:
    """Читает контрольные имена из JSON, проверяет их шестью потоками и печатает отчёт; сервис не перенастраивает."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--controls",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "config/controls.json",
    )
    parser.add_argument("--dns-server", default="127.0.0.1")
    parser.add_argument("--dns-port", type=int, default=5353)
    parser.add_argument("--api-url")
    parser.add_argument("--filter-id", type=int)
    parser.add_argument(
        "--allow-loopback-blocks",
        action="store_true",
        help="Допустить локальные IP как блокировку старых hosts-фильтров; только для запрещённых имён",
    )
    args = parser.parse_args()
    try:
        controls = json.loads(args.controls.read_text())
        cases = [(host, False) for host in controls["allowed"]]
        cases.extend((host, True) for domains in controls["blocked"].values() for host in domains)
        if not cases:
            raise ValueError("Набор проверок пуст")
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda case: verify_domain(*case, args), cases))
        print(
            json.dumps({"passed": len(results), "results": results}, ensure_ascii=False, indent=2)
        )
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Проверка не пройдена: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
