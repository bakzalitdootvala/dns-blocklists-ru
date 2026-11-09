# Сборка и проверки

## Зависимости

Собственный сборщик использует Python 3.10+ и стандартную библиотеку.
Для живых проверок нужны `dig` (пакет dnsutils) и AdGuard Home 0.107.80.
Для загрузки Spamhaus нужен ClamAV с актуальными сигнатурами; собственные
Python-скрипты не устанавливают пакетов и не имеют внешних Python-зависимостей.
Для получения commit SHA и синхронизации нужен GitHub CLI `gh` с доступом
к репозиторию. Для проверки разработки нужны Ruff 0.17.3, pre-commit и Gitleaks.
Бинарник Ruff должен находиться в `.venv/bin/ruff`; зависимости перечислены
в `requirements-dev.txt`. `pre-commit install` подключает согласованные хуки.

Пример установки среды:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
pre-commit install
```

## DNS-фильтр

```sh
make check
make refresh
make ips
python3 scripts/ru/download_drop.py .cache/drop
clamscan --infected .cache/drop
python3 scripts/ru/threat_intel.py build-drop --input-dir .cache/drop
make build
python3 scripts/ru/check_artifact.py
```

`make refresh` сначала проверяет/продвигает `maintainer`, затем получает
исходники по конкретным commit SHA. Кэш и lock находятся в `.cache/feeds/`.
`make build` использует доменные и IP-снимки без сети, проверяет контрольные домены
и создаёт `output/adguard/combined.txt`, региональный файл и манифест.
Повторная сборка одного lock и одного каталога даёт те же байты.

Для штатного обновления также можно использовать `./build` после синхронизации
`maintainer`. Исходная сборка Mullvad находится в ветке `maintainer` и имеет
собственные зависимости; она не требуется для нашего фильтра.

## Обязательные IP-источники

```sh
make ips
```

HaGeZi IP и оба файла Spamhaus подготавливаются до сборки DNS-фильтра.
Непубличные адреса отбрасываются
с записью в манифест. Отсутствие индивидуального `last_seen` явно обозначается.
Список не устанавливает правила firewall.

Spamhaus DROP скачивается не чаще одного раза в час; штатный workflow делает
это в общей цепочке ежедневно в 06:23 UTC (09:23 по Москве).
Часовой параметр URL исключает повторное использование старого CDN-кэша;
`download_drop.py` повторно использует проверяемые по SHA256 локальные байты
в течение часа. До разбора скачанные JSON Lines проверяются ClamAV.
Затем `python3 scripts/ru/threat_intel.py build-drop --input-dir <каталог>`
проверяет типы, семейства IP, число записей, исходное время и атрибуцию.
Сетевые артефакты и итоговый DNS-фильтр сохраняют отдельные условия Spamhaus.
Сборка проверяет SHA256, число сетей, семейство IP и свежесть: DROP до 48 часов,
HaGeZi до 48 часов с момента получения и до 168 часов с момента commit.
Падение числа сетей более чем на 25% останавливает выпуск.
При ошибке IP-источника рабочий `combined.txt` не заменяется.

## Проверка перед публикацией

- `make check` — Ruff, все unit-тесты, данные, целостность артефакта и diff.
- `pre-commit run --all-files` — согласованные проверки.
- `gitleaks dir --redact --no-banner .` — дополнительно весь рабочий каталог.
- `actionlint .github/workflows/*.yml` — проверка workflow при наличии actionlint.
- `python3 scripts/ru/test_ip_response.py --binary <AdGuardHome> --root .
  --ordinary-controls --report <report.json>` — изолированный живой AdGuard,
  синтетические DNS-ответы с IP из списков, границы сетей и обычные сайты.
  Подключений к вредоносным IP тест не выполняет; меняются только DNS-ответы.

После проверки развертывания временные процессы и конфиги удаляются.
Секреты и адреса конкретного VPS не входят в артефакты публичного репозитория.
