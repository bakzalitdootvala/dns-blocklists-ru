#!/usr/bin/env python3
"""Проверяет IP-фильтр на отдельном процессе настоящего AdGuard Home.

Запуск: python3 scripts/ru/test_ip_response.py --binary <AdGuardHome> --root .
Дополнительно: --ordinary-controls, --report <JSON>, --scratch-dir <каталог>.
Требуются предварительно проверенный бинарник AdGuard и установленный dig.
Модуль читает output/adguard/combined.txt и три списка output/threat-intel/.
Он запускает локальный тестовый DNS, возвращающий заранее заданные IP для
имён *.ipcheck.test, и AdGuard, который должен отфильтровать эти ответы.
К вредоносным IP подключений нет: адреса передаются только внутри DNS-пакетов.

Проверяются границы сетей, CNAME, несколько адресов, исключение, HTTPS hints,
источник блокировки, отключение/включение фильтра и повторное обновление.
--ordinary-controls запускает verify_adguard.py с запросами к внешнему DNS.
По умолчанию внешний DNS — Google через HTTPS по IP, без зависимости от bootstrap.
API тестового AdGuard доступен без пароля только на loopback (127.0.0.1).

Временные конфиги и процессы очищаются в finally; SIGTERM проходит через этот
путь. JSON-отчёт при --report сохраняется отдельно. Рабочие службы VPS, firewall
и Git модуль не меняет. Подробности терминов: docs/GLOSSARY.md.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import ipaddress
import json
import os
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

FILTER_ID = 987654323


def encode_name(name: str) -> bytes:
    """Кодирует контролируемое ASCII-имя в DNS-пакет: длина метки, её байты и конечный ноль."""
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\0"


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Читает имя с заданного смещения, включая DNS-указатели сжатия; возвращает имя и конец исходного поля."""
    labels = []
    end = None
    seen = set()
    while packet[offset]:
        if offset in seen:
            raise ValueError("Цикл сжатия имени DNS")
        seen.add(offset)
        length = packet[offset]
        # Два старших бита 11 обозначают DNS-указатель на имя в другом месте пакета.
        if length & 192 == 192:
            if end is None:
                end = offset + 2
            offset = ((length & 63) << 8) | packet[offset + 1]
            continue
        if length > 63:
            raise ValueError("Некорректная метка DNS")
        labels.append(packet[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += length + 1
    return ".".join(labels).lower(), end if end is not None else offset + 1


def record(name: str, kind: int, data: bytes) -> bytes:
    """Собирает бинарную DNS-запись name с типом kind, классом IN, TTL 30 секунд и переданным телом data."""
    return encode_name(name) + struct.pack("!HHIH", kind, 1, 30, len(data)) + data


class Fixture(socketserver.ThreadingUDPServer):
    """Локальный UDP DNS-сервер: сопоставляет тестовое имя с режимом и адресами из словаря answers."""

    daemon_threads = True

    def __init__(self, port: int, answers: dict[str, tuple[str, list[str]]]):
        """Сохраняет тестовые ответы и привязывает UDP-сокет только к 127.0.0.1:port."""
        self.answers = answers
        super().__init__(("127.0.0.1", port), FixtureHandler)


class FixtureHandler(socketserver.BaseRequestHandler):
    """Обработчик одного запроса к Fixture; формирует A/AAAA, CNAME или HTTPS record из заданных данных."""

    def handle(self) -> None:
        """Читает имя и тип запроса, собирает ответ из self.server.answers и отправляет его запросившему клиенту."""
        packet, connection = self.request
        name, end = decode_name(packet, 12)
        kind, _ = struct.unpack_from("!HH", packet, end)
        mode, addresses = self.server.answers.get(name, ("plain", []))
        records = []
        target = "target.ipcheck.test" if mode == "cname" else name
        if mode == "cname":
            records.append(record(name, 5, encode_name(target)))
        for value in addresses:
            address = ipaddress.ip_address(value)
            if kind == (1 if address.version == 4 else 28):
                records.append(record(target, kind, address.packed))
        # Тип 65 — HTTPS record. Ключи 4/6 внутри его параметров означают
        # ipv4hint/ipv6hint: адреса-подсказки, которые тоже должен фильтровать AdGuard.
        if kind == 65 and mode == "https":
            address = ipaddress.ip_address(addresses[0])
            key = 4 if address.version == 4 else 6
            data = struct.pack("!H", 1) + b"\0" + struct.pack("!HH", key, len(address.packed))
            records.append(record(name, 65, data + address.packed))
        # 0x8180: ответ на рекурсивный запрос с кодом NOERROR. ID копируется
        # из запроса, чтобы клиент связал ответ именно с отправленным вопросом.
        header = struct.pack(
            "!HHHHHH", struct.unpack_from("!H", packet)[0], 0x8180, 1, len(records), 0, 0
        )
        connection.sendto(header + packet[12 : end + 4] + b"".join(records), self.client_address)


def dns_query(port: int, name: str, kind: int) -> dict:
    """Посылает один UDP DNS-запрос на локальный port; проверяет ID и усечение, возвращает rcode и records."""
    transaction = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack("!HHHHHH", transaction, 0x100, 1, 0, 0, 0)
    packet += encode_name(name) + struct.pack("!HH", kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.sendto(packet, ("127.0.0.1", port))
        response, _ = client.recvfrom(65535)
    identifier, flags, questions, count, _, _ = struct.unpack_from("!HHHHHH", response)
    if identifier != transaction or flags & 0x200:
        raise ValueError("Несовпадение идентификатора или усечённый DNS-ответ")
    offset = 12
    for _ in range(questions):
        _, offset = decode_name(response, offset)
        offset += 4
    records = []
    for _ in range(count):
        owner, offset = decode_name(response, offset)
        rtype, _, _, length = struct.unpack_from("!HHIH", response, offset)
        offset += 10
        data = response[offset : offset + length]
        value = str(ipaddress.ip_address(data)) if rtype in (1, 28) else data.hex()
        records.append({"owner": owner, "type": rtype, "value": value})
        offset += length
    return {"rcode": flags & 15, "records": records}


def is_blocked(response: dict, kind: int) -> bool:
    """Распознаёт режим null_ip: NOERROR и непустой набор только нулевых A либо AAAA адресов заданного kind."""
    addresses = [item["value"] for item in response["records"] if item["type"] == kind]
    return (
        response["rcode"] == 0
        and bool(addresses)
        and all(ipaddress.ip_address(value).is_unspecified for value in addresses)
    )


def api(port: int, path: str, data: dict | None = None):
    """Вызывает локальный HTTP API тестового AdGuard: GET без data, POST с JSON; возвращает разобранный ответ или None."""
    body = None if data is None else json.dumps(data).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/control/{path}",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def read_networks(root: Path) -> dict:
    """Читает три готовых IP-списка из output/threat-intel/; возвращает сети по источникам, пустой список запрещён."""
    sources = {}
    for name in ("hagezi-ipv4", "spamhaus-ipv4", "spamhaus-ipv6"):
        values = (root / "output/threat-intel" / (name + ".txt")).read_text().splitlines()
        networks = [
            ipaddress.ip_network(value) for value in values if value and not value.startswith("#")
        ]
        if not networks:
            raise ValueError(f"Пустой источник {name}")
        sources[name] = networks
    manifest = json.loads((root / "output/adguard/manifest.json").read_text())
    recent = [
        ipaddress.ip_network(value)
        for item in manifest.get("recent_reports", [])
        for value in item["ips"]
    ]
    if recent:
        sources["regional-reports"] = recent
    return sources


def make_cases(sources: dict) -> tuple[list[dict], dict]:
    """Создаёт ожидаемые результаты и ответы тестового DNS независимо от regex-компилятора.

    Берёт 64 равномерные позиции каждого IPv4-списка и все IPv6-сети; проверяет
    границы, середину и соседей. Добавляет CNAME, смешанные ответы, исключение,
    числовые hostname и HTTPS hints. Ожидаемое попадание в сеть вычисляет ipaddress.
    """
    # Ожидания считаются по числовым диапазонам ipaddress, а не по нашим regex:
    # ошибка компилятора не должна автоматически повториться в ожидаемом ответе.
    ranges = {}
    for version in (4, 6):
        networks = [net for group in sources.values() for net in group if net.version == version]
        collapsed = list(ipaddress.collapse_addresses(networks))
        ranges[version] = (
            [int(net.network_address) for net in collapsed],
            [int(net.broadcast_address) for net in collapsed],
        )

    def listed(address) -> bool:
        """Ищет адрес бинарным поиском среди объединённых диапазонов его семейства IPv4/IPv6."""
        starts, ends = ranges[address.version]
        index = bisect.bisect_right(starts, int(address)) - 1
        return index >= 0 and int(address) <= ends[index]

    cases = []
    answers = {}
    for source, networks in sources.items():
        selected = (
            networks
            if networks[0].version == 6 or len(networks) <= 64
            else [networks[index * (len(networks) - 1) // 63] for index in range(64)]
        )
        for network in selected:
            first, last = int(network.network_address), int(network.broadcast_address)
            for number in sorted({first - 1, first, (first + last) // 2, last, last + 1}):
                if not 0 <= number < 2**network.max_prefixlen:
                    continue
                address = (
                    ipaddress.ip_address(number)
                    if network.version == 4
                    else ipaddress.IPv6Address(number)
                )
                name = f"case-{len(cases)}.ipcheck.test"
                answers[name] = ("plain", [str(address)])
                cases.append(
                    {
                        "name": name,
                        "address": str(address),
                        "kind": 1 if network.version == 4 else 28,
                        "blocked": listed(address),
                        "source": source,
                        "network": str(network),
                    }
                )
    good = {4: "1.1.1.1", 6: "2606:4700:4700::1111"}
    for value in good.values():
        if listed(ipaddress.ip_address(value)):
            raise ValueError(f"Контрольный разрешённый IP входит в исходные списки: {value}")
    for version in (4, 6):
        bad = next(
            case["address"]
            for case in cases
            if case["blocked"] and case["kind"] == (1 if version == 4 else 28)
        )
        for label, mode, addresses, blocked in (
            ("good", "plain", [good[version]], False),
            ("cname", "cname", [bad], True),
            ("mixed", "plain", [good[version], bad], True),
        ):
            name = f"{label}-v{version}.ipcheck.test"
            answers[name] = (mode, addresses)
            cases.append(
                {
                    "name": name,
                    "address": addresses[0],
                    "kind": 1 if version == 4 else 28,
                    "blocked": blocked,
                    "scenario": label,
                }
            )
        name = f"https-v{version}.ipcheck.test"
        answers[name] = ("https", [bad])
        answers[f"https-good-v{version}.ipcheck.test"] = ("https", [good[version]])
    bad4 = next(case["address"] for case in cases if case["blocked"] and case["kind"] == 1)
    cidr4 = next(
        case["address"]
        for case in cases
        if case["blocked"] and case.get("source") == "spamhaus-ipv4"
    )
    for name, address, blocked in (
        ("allow.ipcheck.test", bad4, False),
        ("child.allow.ipcheck.test", bad4, True),
        (cidr4 + ".ipcheck.test", good[4], False),
        (bad4 + ".ipcheck.test", good[4], False),
        ("prefix-" + bad4 + ".ipcheck.test", good[4], False),
    ):
        answers[name] = ("plain", [address])
        cases.append(
            {
                "name": name,
                "address": address,
                "kind": 1,
                "blocked": blocked,
                "scenario": "allow-or-numeric-name",
            }
        )
    return cases, answers


def choose_ports(base: int) -> tuple[int, int, int]:
    """Ищет свободную тройку портов для DNS AdGuard, HTTP API и тестового DNS; пробные сокеты закрывает."""
    for start in range(base, base + 500, 3):
        sockets = []
        try:
            for port, kind in (
                (start, socket.SOCK_DGRAM),
                (start, socket.SOCK_STREAM),
                (start + 1, socket.SOCK_STREAM),
                (start + 2, socket.SOCK_DGRAM),
            ):
                connection = socket.socket(socket.AF_INET, kind)
                sockets.append(connection)
                connection.bind(("127.0.0.1", port))
            return start, start + 1, start + 2
        except OSError:
            continue
        finally:
            for connection in sockets:
                connection.close()
    raise OSError("Не найдены свободные локальные порты")


def run(args: argparse.Namespace, report: dict) -> None:
    """Запускает изолированный стенд, проверяет фильтр и заполняет изменяемый report.

    args задаёт бинарник, корень, каталоги и опции. Читает кандидат, запускает
    Fixture и AdGuard, подтверждает ID фильтра, проверяет DNS-ответы, выполняет
    мутацию отключением фильтрации и повторное обновление. Опционально запускает
    контроли реальных доменов. Ошибка передаётся main(); finally завершает процессы,
    удаляет временный каталог и проверяет освобождение использованных портов.
    """
    root = args.root.resolve()
    candidate = root / "output/adguard/combined.txt"
    if not candidate.is_file():
        raise ValueError(f"Нет итогового фильтра: {candidate}")
    if shutil.which("dig") is None:
        raise ValueError("Для проверки нужен установленный dig")
    sources = read_networks(root)
    cases, answers = make_cases(sources)
    manifest = json.loads((root / "output/adguard/manifest.json").read_text())
    report_names = [name for item in manifest.get("recent_reports", []) for name in item["domains"]]
    for name in report_names:
        for query_name, expected in [(name, True), ("unlisted-child." + name, False)]:
            answers[query_name] = ("plain", ["1.1.1.1", "2606:4700:4700::1111"])
            for kind in (1, 28):
                cases.append(
                    {
                        "name": query_name,
                        "kind": kind,
                        "address": "1.1.1.1" if kind == 1 else "2606:4700:4700::1111",
                        "blocked": expected,
                        "scenario": "regional-report-exact-domain",
                    }
                )
    dns_port, api_port, fixture_port = choose_ports(args.port_base)
    report["ports"] = {"dns": dns_port, "api": api_port, "fixture": fixture_port}
    report["sources"] = {name: len(values) for name, values in sources.items()}
    report["candidate_bytes"] = candidate.stat().st_size
    digest = hashlib.sha256()
    with candidate.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    report["candidate_sha256"] = digest.hexdigest()
    report["binary_version"] = subprocess.run(
        [str(args.binary.resolve()), "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    fixture = Fixture(fixture_port, answers)
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="adguard-ip-response-", dir=args.scratch_dir
        ) as temporary:
            work = Path(temporary)
            # Проверка срока меняет только собственную копию; артефакт репозитория
            # и рабочий фильтр сервера остаются неизменными.
            installed_candidate = work / "candidate.txt"
            shutil.copyfile(candidate, installed_candidate)
            config = {
                "http": {"address": f"127.0.0.1:{api_port}"},
                "users": [],
                "dns": {
                    "bind_hosts": ["127.0.0.1"],
                    "port": dns_port,
                    "ratelimit": 0,
                    "upstream_dns": [
                        args.upstream,
                        f"[/ipcheck.test/]127.0.0.1:{fixture_port}",
                    ]
                    + [f"[/{name}/]127.0.0.1:{fixture_port}" for name in report_names],
                    "bootstrap_dns": ["1.1.1.1"],
                    "cache_enabled": False,
                    "use_private_ptr_resolvers": False,
                },
                "filtering": {
                    "filtering_enabled": True,
                    "protection_enabled": True,
                    "blocking_mode": "null_ip",
                    "filters_update_interval": 0,
                    "safe_fs_patterns": [str(work / "*")],
                },
                "filters": [
                    {
                        "enabled": True,
                        "url": str(installed_candidate),
                        "name": "IP response test",
                        "id": FILTER_ID,
                    }
                ],
                "user_rules": ["@@|allow.ipcheck.test^"],
                "querylog": {"enabled": True, "file_enabled": False},
                "statistics": {"enabled": False},
                "schema_version": 29,
            }
            config_path = work / "AdGuardHome.yaml"
            config_path.write_text(json.dumps(config))
            started = time.monotonic()
            with (work / "service.log").open("w+") as log:
                process = subprocess.Popen(
                    [
                        str(args.binary.resolve()),
                        "--no-check-update",
                        "-c",
                        str(config_path),
                        "-w",
                        str(work),
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                try:
                    deadline = started + 180
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            log.seek(0)
                            raise RuntimeError("AdGuard Home завершился: " + log.read()[-6000:])
                        try:
                            api(api_port, "status")
                            break
                        except (OSError, ValueError):
                            time.sleep(0.2)
                    else:
                        raise TimeoutError("AdGuard Home не запустился за 180 секунд")
                    report["startup_seconds"] = round(time.monotonic() - started, 3)
                    refreshed = time.monotonic()
                    report["refresh"] = api(api_port, "filtering/refresh", {"whitelist": False})
                    report["refresh_seconds"] = round(time.monotonic() - refreshed, 3)
                    report["filter_status"] = api(api_port, "filtering/status")
                    # Проверяем происхождение: блокировку обязан дать подключённый
                    # фильтр FILTER_ID, а не встроенная защита или посторонний список.
                    provenance = []
                    for source in sources:
                        case = next(
                            case
                            for case in cases
                            if case["blocked"] and case.get("source") == source
                        )
                        result = api(
                            api_port,
                            "filtering/check_host?"
                            + urllib.parse.urlencode({"name": case["address"]}),
                        )
                        if not any(
                            item.get("filter_list_id") == FILTER_ID
                            for item in result.get("rules", [])
                        ):
                            raise AssertionError(
                                f"Не подтверждён источник блокировки IP {case['address']}: {result}"
                            )
                        provenance.append(
                            {"source": source, "ip": case["address"], "decision": result}
                        )
                    report["provenance"] = provenance
                    failures = []
                    results = []
                    for case in cases:
                        response = dns_query(dns_port, case["name"], case["kind"])
                        actual = is_blocked(response, case["kind"])
                        values = [
                            item["value"]
                            for item in response["records"]
                            if item["type"] == case["kind"]
                        ]
                        passed = actual == case["blocked"] and (
                            actual or (response["rcode"] == 0 and case["address"] in values)
                        )
                        entry = {**case, "passed": passed, "response": response}
                        results.append(entry)
                        if not passed:
                            failures.append(entry)
                    report["cases"] = results
                    report["passed"] = sum(item["passed"] for item in results)
                    report["failed"] = len(failures)
                    report["https_hints"] = {
                        f"IPv{version}": dns_query(dns_port, f"https-v{version}.ipcheck.test", 65)
                        for version in (4, 6)
                    }
                    report["https_fixture"] = {
                        f"IPv{version}": dns_query(
                            fixture_port, f"https-v{version}.ipcheck.test", 65
                        )
                        for version in (4, 6)
                    }
                    report["https_good_hints"] = {
                        f"IPv{version}": dns_query(
                            dns_port, f"https-good-v{version}.ipcheck.test", 65
                        )
                        for version in (4, 6)
                    }
                    for family, response in report["https_hints"].items():
                        baseline = report["https_fixture"][family]
                        if baseline["rcode"] != 0 or not any(
                            item["type"] == 65 for item in baseline["records"]
                        ):
                            raise AssertionError(f"Fixture не вернул HTTPS {family} hint")
                        if response != {"rcode": 0, "records": []}:
                            raise AssertionError(f"Вредоносный HTTPS {family} hint не заблокирован")
                        good_response = report["https_good_hints"][family]
                        if good_response["rcode"] != 0 or not any(
                            item["type"] == 65 for item in good_response["records"]
                        ):
                            raise AssertionError(f"Разрешённый HTTPS {family} hint потерян")
                    report["dig"] = []
                    for name, kind in (
                        ("cname-v4.ipcheck.test", "A"),
                        ("cname-v6.ipcheck.test", "AAAA"),
                        ("allow.ipcheck.test", "A"),
                        ("child.allow.ipcheck.test", "A"),
                    ):
                        result = subprocess.run(
                            [
                                "dig",
                                "@127.0.0.1",
                                "-p",
                                str(dns_port),
                                name,
                                kind,
                                "+time=5",
                                "+tries=1",
                                "+noall",
                                "+comments",
                                "+answer",
                            ],
                            capture_output=True,
                            text=True,
                            check=True,
                            timeout=10,
                        )
                        report["dig"].append({"name": name, "type": kind, "output": result.stdout})
                    # Живая мутация: отключаем только тестовую фильтрацию. Исходные
                    # IP должны вернуться, затем блокировка обязана восстановиться.
                    mutation_cases = [
                        next(case for case in cases if case["blocked"] and case["kind"] == kind)
                        for kind in (1, 28)
                    ]
                    api(api_port, "filtering/config", {"enabled": False, "interval": 0})
                    try:
                        report["mutation"] = []
                        for mutation_case in mutation_cases:
                            response = dns_query(
                                dns_port, mutation_case["name"], mutation_case["kind"]
                            )
                            caught = not is_blocked(response, mutation_case["kind"]) and any(
                                item["value"] == mutation_case["address"]
                                for item in response["records"]
                            )
                            report["mutation"].append(
                                {
                                    "kind": mutation_case["kind"],
                                    "filtering_disabled_detected": caught,
                                    "response": response,
                                }
                            )
                            if not caught:
                                raise AssertionError("Тест не обнаружил отключение фильтрации")
                    finally:
                        api(api_port, "filtering/config", {"enabled": True, "interval": 0})
                    for mutation_case, entry in zip(mutation_cases, report["mutation"]):
                        entry["restored_blocking"] = is_blocked(
                            dns_query(dns_port, mutation_case["name"], mutation_case["kind"]),
                            mutation_case["kind"],
                        )
                        if not entry["restored_blocking"]:
                            raise AssertionError("Фильтрация не восстановилась после мутации")
                    mutation_case = mutation_cases[0]
                    refreshed = time.monotonic()
                    report["repeat_refresh"] = api(
                        api_port, "filtering/refresh", {"whitelist": False}
                    )
                    report["repeat_refresh_seconds"] = round(time.monotonic() - refreshed, 3)
                    if not is_blocked(dns_query(dns_port, mutation_case["name"], 1), 1):
                        raise AssertionError("Блокировка потеряна после повторного обновления")
                    status_path = Path(f"/proc/{process.pid}/status")
                    if status_path.exists():
                        report["memory"] = [
                            line
                            for line in status_path.read_text().splitlines()
                            if line.startswith(("VmRSS:", "VmHWM:"))
                        ]
                    if args.ordinary_controls:
                        result = subprocess.run(
                            [
                                "python3",
                                str(root / "scripts/ru/verify_adguard.py"),
                                "--dns-port",
                                str(dns_port),
                                "--api-url",
                                f"http://127.0.0.1:{api_port}",
                                "--filter-id",
                                str(FILTER_ID),
                            ],
                            capture_output=True,
                            text=True,
                            timeout=300,
                        )
                        report["ordinary_controls"] = {
                            "returncode": result.returncode,
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                        }
                        if result.returncode:
                            raise AssertionError("Обычные DNS-контроли не прошли: " + result.stderr)
                    if report_names:
                        from datetime import date

                        from recent_threats import expire_text

                        expiry_day = max(
                            date.fromisoformat(item["expires_on"])
                            for item in manifest["recent_reports"]
                        )
                        original_text = installed_candidate.read_text()
                        installed_candidate.write_text(expire_text(original_text, expiry_day))
                        api(api_port, "filtering/refresh", {"whitelist": False})
                        report["expiry"] = []
                        # Эти имена получают от fixture разрешённые адреса: после
                        # снятия C2-блока их не должен удерживать исчезнувший запрет.
                        for name in report_names:
                            for kind in (1, 28):
                                response = dns_query(dns_port, name, kind)
                                passed = (
                                    response["rcode"] == 0
                                    and bool(response["records"])
                                    and not is_blocked(response, kind)
                                )
                                report["expiry"].append(
                                    {"name": name, "kind": kind, "passed": passed}
                                )
                                if not passed:
                                    raise AssertionError(
                                        f"Истёкший C2-домен остаётся заблокированным: {name}"
                                    )
                        report["expiry_ip"] = []
                        permanent_networks = [
                            net
                            for source, nets in sources.items()
                            if source != "regional-reports"
                            for net in nets
                        ]
                        for network in sources.get("regional-reports", []):
                            address = network.network_address
                            case = next(
                                case
                                for case in cases
                                if case.get("source") == "regional-reports"
                                and case["address"] == str(address)
                            )
                            expected = any(
                                address.version == net.version and address in net
                                for net in permanent_networks
                            )
                            response = dns_query(dns_port, case["name"], case["kind"])
                            passed = is_blocked(response, case["kind"]) == expected and (
                                expected
                                or any(
                                    item["value"] == str(address) for item in response["records"]
                                )
                            )
                            report["expiry_ip"].append(
                                {"ip": str(address), "blocked_by_base": expected, "passed": passed}
                            )
                            if not passed:
                                raise AssertionError(
                                    f"Неверный результат снятия срока IP: {address}"
                                )
                        installed_candidate.write_text(original_text)
                        api(api_port, "filtering/refresh", {"whitelist": False})
                        if not is_blocked(dns_query(dns_port, report_names[0], 1), 1):
                            raise AssertionError(
                                "C2-блокировка не вернулась после восстановления тестовой копии"
                            )
                    if failures:
                        raise AssertionError(
                            f"Не прошли {len(failures)} из {len(results)} IP-проверок; первая: {failures[0]}"
                        )
                finally:
                    # Все пути (успех, ошибка, SIGTERM) проходят через эту уборку.
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                    log.seek(0)
                    report["service_log_tail"] = log.read()[-4000:]
    finally:
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=5)
        report["cleanup"] = {
            "process_stopped": process is None or process.poll() is not None,
            "fixture_stopped": not thread.is_alive(),
        }
        for port, kind in (
            (dns_port, socket.SOCK_DGRAM),
            (api_port, socket.SOCK_STREAM),
            (fixture_port, socket.SOCK_DGRAM),
        ):
            with socket.socket(socket.AF_INET, kind) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", port))
        report["cleanup"]["ports_released"] = True


def main() -> int:
    """Обрабатывает CLI, сохраняет JSON-отчёт и возвращает 0/1/130; SIGTERM превращает в прерывание с уборкой."""

    def interrupt(signum, frame):
        """Преобразует SIGTERM в KeyboardInterrupt, чтобы run() выполнил finally и остановил дочерний AdGuard."""
        raise KeyboardInterrupt(f"Получен сигнал {signum}")

    signal.signal(signal.SIGTERM, interrupt)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--report", type=Path)
    parser.add_argument("--port-base", type=int, default=15353)
    parser.add_argument("--scratch-dir", type=Path)
    parser.add_argument("--ordinary-controls", action="store_true")
    parser.add_argument("--upstream", default="https://8.8.8.8/dns-query")
    args = parser.parse_args()
    if args.scratch_dir:
        args.scratch_dir.mkdir(parents=True, exist_ok=True)
    report = {"filter_id": FILTER_ID}
    code = 0
    try:
        run(args, report)
    except KeyboardInterrupt as error:
        report["error"] = str(error) or "Проверка прервана"
        code = 130
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        code = 1
    finally:
        report["success"] = code == 0
        output = json.dumps(report, ensure_ascii=False, indent=2)
        if args.report:
            args.report.write_text(output + "\n")
        print(
            json.dumps(
                {
                    key: value
                    for key, value in report.items()
                    if key not in ("cases", "filter_status", "dig", "service_log_tail")
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
