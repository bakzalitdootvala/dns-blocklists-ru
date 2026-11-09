#!/usr/bin/env python3
"""Снимает истёкшие временные C2-блоки в установленном фильтре AdGuard Home.

systemd timer вызывает CLI с --source, --cache и --service. Только при изменении
текста останавливается указанная служба, атомарно заменяются источник и кэш,
затем служба запускается и проверяется DNS. Ошибка восстанавливает обе копии.
Постоянные правила, YAML и firewall не меняются. Нет загрузок из сети, кроме
проверочного DNS к loopback. --check печатает ожидаемое изменение без записи;
--as-of разрешён только вместе с --check для испытания будущего срока.
Зависимости: Python 3.10+, systemctl, dig; права root для рабочего запуска.
"""

import argparse
import fcntl
import hashlib
import os
import subprocess
import tempfile
import time
from datetime import date, datetime, timezone
from pathlib import Path

from recent_threats import expire_text


def replace(path: Path, content: bytes, mode: int) -> None:
    """Заменяет файл через fsync и rename в том же каталоге; сохраняет переданные права."""
    descriptor, temporary = tempfile.mkstemp(prefix=".dns-expiry-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def install(source: Path, cache: Path, text: str, service) -> None:
    """Согласованно заменяет две копии и вызывает service(stop/start).

    service(start) должен проверить готовность DNS. При ошибке восстанавливаются
    исходные байты и права обеих копий; ошибка не скрывается даже после отката.
    """
    before = [(path, path.read_bytes(), path.stat().st_mode & 0o777) for path in (source, cache)]
    try:
        service("stop")
        for path, _, mode in before:
            replace(path, text.encode(), mode)
        service("start")
    except BaseException:
        service("stop")
        for path, content, mode in before:
            replace(path, content, mode)
        service("start")
        raise


def control_service(name: str, dns_port: int, action: str) -> None:
    """Управляет systemd и после start ждёт корректный A-ответ example.com до 60 секунд."""
    subprocess.run(["systemctl", action, name], check=True, timeout=90)
    if action != "start":
        return
    for _ in range(30):
        result = subprocess.run(
            [
                "dig",
                "@127.0.0.1",
                "-p",
                str(dns_port),
                "example.com",
                "A",
                "+time=1",
                "+tries=1",
                "+noall",
                "+comments",
                "+answer",
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode == 0 and "status: NOERROR" in result.stdout:
            answers = [
                line.split() for line in result.stdout.splitlines() if not line.startswith(";")
            ]
            if any(
                len(parts) >= 5 and parts[3] == "A" and parts[4] != "0.0.0.0" for parts in answers
            ):
                return
        time.sleep(1)
    raise RuntimeError("AdGuard не подтвердил готовность DNS после снятия срока")


def main() -> None:
    """Разбирает пути CLI, блокирует параллельный запуск, проверяет срок и выводит SHA256 результата."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--service", default="AdGuardHome.service")
    parser.add_argument("--dns-port", type=int, default=5353)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--as-of", type=date.fromisoformat)
    args = parser.parse_args()
    if args.as_of and not args.check:
        parser.error("--as-of допускается только с --check")
    today = args.as_of or datetime.now(timezone.utc).date()
    # Блокировка относится к каталогу источника; административный deploy обязан
    # остановить timer перед заменой файлов и включить его после проверки.
    with (args.source.parent / ".expiry.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = args.source.read_text()
        after = expire_text(before, today)
        if before != after and not args.check:
            install(
                args.source,
                args.cache,
                after,
                lambda action: control_service(args.service, args.dns_port, action),
            )
        print(
            f"date={today} changed={before != after} check={args.check} "
            f"sha256={hashlib.sha256(after.encode()).hexdigest()}"
        )


if __name__ == "__main__":
    main()
