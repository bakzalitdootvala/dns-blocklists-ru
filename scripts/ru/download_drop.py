#!/usr/bin/env python3
"""Скачивает исходные JSON Lines Spamhaus DROP для последующей проверки.

Запуск: python3 scripts/ru/download_drop.py .cache/drop. Получает официальные
IPv4/IPv6-файлы по HTTPS и записывает drop_v4.json, drop_v6.json и download.json.
Последний содержит время загрузки и SHA256 байтов. В пределах часа неизменённый
локальный снимок используется повторно; повреждённый кэш вызывает ошибку.
Часовой параметр URL позволяет отличить новый запрос от старой копии CDN.

Содержимое скачанных JSON здесь не разбирается. После команды вызывающая
цепочка обязана выполнить ClamAV, затем threat_intel.py build-drop проверяет
формат и время публикации самого источника. Сетевой таймаут — 60 секунд на запрос;
лимит — 5 МБ на файл. Фильтр AdGuard и firewall модуль не изменяет.
"""

import argparse
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from blocklists import atomic_write


def download_drop(directory: Path) -> None:
    """Сохраняет два исходных DROP-файла и квитанцию download.json в directory.

    Неизменённый кэш младше 3600 секунд возвращается без сети. При загрузке файлы
    заменяются по очереди; квитанция записывается после обоих успешных запросов.
    При частичной ошибке могут остаться скачанные файлы, но вызывающая цепочка
    не должна переходить к сборке. Содержимое DROP здесь не разбирается и не сканируется.
    """
    directory.mkdir(parents=True, exist_ok=True)
    receipt_path = directory / "download.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        elapsed = time.time() - receipt["downloaded_epoch"]
        if 0 <= elapsed < 3600:
            for name, expected in receipt["sha256"].items():
                if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
                    raise ValueError("Кэш DROP повреждён; повторная загрузка допускается через час")
            print("Использован неизменённый снимок DROP, полученный менее часа назад")
            return
    # Ключ часа меняет URL новой загрузки; локальная квитанция выше предотвращает
    # повторный сетевой запрос в течение часа при сохранённом кэше.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    hashes = {}
    for family in [4, 6]:
        name = f"drop_v{family}.json"
        url = f"https://www.spamhaus.org/drop/{name}?generation={stamp}"
        request = urllib.request.Request(
            url, headers={"User-Agent": "dns-blocklists-ru/1.0", "Cache-Control": "no-cache"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(5_000_001)
        if not data or len(data) > 5_000_000:
            raise ValueError("Недопустимый размер DROP")
        temporary = directory / (name + ".download")
        temporary.write_bytes(data)
        temporary.replace(directory / name)
        hashes[name] = hashlib.sha256(data).hexdigest()
    atomic_write(
        receipt_path, json.dumps({"downloaded_epoch": time.time(), "sha256": hashes}) + "\n"
    )
    print("DROP загружен; до разбора требуется ClamAV")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    download_drop(parser.parse_args().directory)
