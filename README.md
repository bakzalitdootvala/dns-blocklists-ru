<h1 align="center">🛡️ dns-blocklists-ru</h1>

<p align="center">
  <strong>DNS-фильтр для AdGuard Home с дополнениями для России и СНГ</strong>
</p>

<p align="center">
  <a href="BUILDING.md"><img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&amp;logo=python&amp;logoColor=white" alt="Python: 3.10+"></a>
  <a href="docs/GLOSSARY.md#adguard-home-и-adguard-dns"><img src="https://img.shields.io/badge/AdGuard%20Home-DNS-68BC71?style=flat-square&amp;logo=adguard&amp;logoColor=white" alt="AdGuard Home: DNS"></a>
  <a href="docs/GLOSSARY.md#ip-ipv4-ipv6-октет-и-16-битная-группа"><img src="https://img.shields.io/badge/IP-IPv4%20%2B%20IPv6-0891B2?style=flat-square" alt="IP: IPv4 + IPv6"></a>
  <a href="https://github.com/mullvad/dns-blocklists"><img src="https://img.shields.io/badge/Mullvad-upstream-D9A441?style=flat-square&amp;logo=mullvad&amp;logoColor=white" alt="Mullvad: upstream"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/badge/%D0%9A%D0%BE%D0%B4-GPLv3-64748B?style=flat-square" alt="Код: GPLv3"></a>
</p>

<p align="center">
  <a href="COMBINATIONS.md"><img src="https://img.shields.io/badge/%D0%91%D0%BB%D0%BE%D0%BA%D0%B8%D1%80%D1%83%D0%B5%D0%BC-%D1%80%D0%B5%D0%BA%D0%BB%D0%B0%D0%BC%D1%83-2563EB?style=flat-square" alt="Блокируем: рекламу"></a>
  <a href="COMBINATIONS.md"><img src="https://img.shields.io/badge/%D0%91%D0%BB%D0%BE%D0%BA%D0%B8%D1%80%D1%83%D0%B5%D0%BC-%D1%82%D1%80%D0%B5%D0%BA%D0%B5%D1%80%D1%8B-7C3AED?style=flat-square" alt="Блокируем: трекеры"></a>
  <a href="COMBINATIONS.md"><img src="https://img.shields.io/badge/%D0%91%D0%BB%D0%BE%D0%BA%D0%B8%D1%80%D1%83%D0%B5%D0%BC-malware-DC2626?style=flat-square" alt="Блокируем: malware"></a>
  <a href="COMBINATIONS.md"><img src="https://img.shields.io/badge/%D0%91%D0%BB%D0%BE%D0%BA%D0%B8%D1%80%D1%83%D0%B5%D0%BC-%D0%B0%D0%B7%D0%B0%D1%80%D1%82%D0%BD%D1%8B%D0%B5%20%D0%B8%D0%B3%D1%80%D1%8B-D97706?style=flat-square" alt="Блокируем: азартные игры"></a>
</p>

<p align="center">
  <a href="#connect">Подключение</a> ·
  <a href="COMBINATIONS.md">Категории</a> ·
  <a href="docs/REGIONAL_COVERAGE.md">Покрытие регионов</a> ·
  <a href="BUILDING.md">Сборка</a> ·
  <a href="docs/GLOSSARY.md">Глоссарий</a>
</p>

---

Этот проект собирает фильтр, по которому AdGuard Home блокирует рекламу, трекеры,
вредоносные домены и азартные игры. Основа — готовые списки
[Mullvad DNS blocklists](https://github.com/mullvad/dns-blocklists), к которым
мы добавляем правила для России и СНГ и проверку IP из HaGeZi TIF и Spamhaus DROP.
Взрослый контент и социальные сети не включены в запрещённые категории.
Рекламный или вредоносный домен может блокироваться независимо от тематики сайта,
который к нему обращается.

Начните с [глоссария терминов с примерами](docs/GLOSSARY.md).
Назначение каталогов описано в локальных README; для `.github/` — в [CONTENTS.md](.github/CONTENTS.md).

<a id="connect"></a>

## Подключение к AdGuard Home

Готовый файл находится в `output/adguard/combined.txt`. Для подключения
опубликованной версии добавьте следующий URL в «Фильтры → DNS-чёрные списки»;
перед подключением убедитесь, что по нему доступен файл:

```text
https://raw.githubusercontent.com/bakzalitdootvala/dns-blocklists-ru/main/output/adguard/combined.txt
```

Файл содержит доменные правила и правила проверки IP в DNS-ответах.
Например, неизвестный домен отвечает адресом из Spamhaus DROP — AdGuard
возвращает ответ блокировки вместо этого адреса. CIDR обозначает диапазон IP;
сборщик преобразует его в одно регулярное выражение без перечисления всей сети.
`output/threat-intel/` хранит исходные сетевые наборы и сведения об их происхождении.
Правила firewall не изменяются. Прямое подключение по IP DNS-фильтр не остановит.

Обновление фильтра проверяет контрольные домены и останавливается при ошибках.
Последний проверенный файл сохраняется; неудачный запуск виден в GitHub Actions.
Возраст опубликованного снимка указан в `output/adguard/manifest.json`.
Если он превышает 48 часов, проверьте workflow «Обновить источники и опубликовать DNS-фильтр после проверки AdGuard».

## Ветки и обновления

- `maintainer` — точная копия `main` официального `mullvad/dns-blocklists`.
  Обновляется только fast-forward; собственные коммиты в неё не добавляются.
- `main` — пользовательская ветка по умолчанию: русская документация,
  сборщик, региональный каталог, проверки и готовые фильтры.

В workflow ветки `main` задан ежедневный запуск в 06:23 UTC. Он обновляет `maintainer`,
получает доменные и IP-данные, проверяет их свежесть и SHA256, собирает
единый фильтр, проверяет его на живом AdGuard Home и публикует результат.
Ошибка любого обязательного источника или теста останавливает публикацию.
Синхронизация ветки и сборка выполняются в одном задании; изменение указателя
ветки (ref) не используется как способ запустить другое задание.

<details>
<summary><strong>Откуда сборщик получает данные Mullvad</strong></summary>

Актуальные исходники оригинальной сборки доступны в ветке `maintainer`.
Собственная сборка использует готовые данные из свежего SHA этой ветки;
исполняемый код upstream автоматически в `main` не сливается.
Сборщик скачивает готовые списки из удалённого репозитория Mullvad по путям
`output/relay/`, указанным в `config/sources.json`, и сохраняет снимки в `.cache/feeds/`.
Готовый фильтр: `output/adguard/`; команды описаны в [BUILDING.md](BUILDING.md).

</details>

## Источники

- Четыре опубликованные категории Mullvad: `adblock`, `privacy`, `malware`, `gambling`.
- HaGeZi TIF — глобальные malware, phishing и scam-домены.
- `regional/ru-cis/domains.csv` — региональные правила со ссылками на доказательства.
- `regional/ru-cis/recent-threats.json` — точные C2 из свежих первичных отчётов на 30 суток.
  [Региональное покрытие и настройка снятия срока](docs/REGIONAL_COVERAGE.md).
- HaGeZi TIF IP и Spamhaus DROP — адреса и сети для проверки DNS-ответов.

[Происхождение, лицензии и ограничения](docs/SOURCES.md) ·
[Региональные данные](regional/ru-cis/README.md) ·
[Сборка и проверки](BUILDING.md) · [Профиль категорий](COMBINATIONS.md).

Один голый домен сохраняется как точное правило; пара домен/wildcard объединяется
без расширения исходной области. Контекстные браузерные правила с URL-путями,
`$third-party`, `$domain` и косметическими селекторами не преобразуются в
безусловные DNS-запреты нашим сборщиком. Готовые результаты Mullvad считаются
опубликованной DNS-политикой upstream: удалённые при их исходной сборке условия
восстановить невозможно.

## Границы защиты

DNS-фильтр проверяет имена в DNS-запросах и адреса в DNS-ответах.
Если один ответ содержит разрешённый и запрещённый адрес, AdGuard блокирует
ответ целиком. Точное доменное исключение разрешает ответ для этого имени.
Он не анализирует содержимое HTTPS, не блокирует прямые подключения по IP
и не гарантирует фильтрацию собственного DNS браузера или приложения.

Контрольные домены проверяют выбранные сценарии, а не все сайты интернета.
Рекламные блоки, авторизация, видео и другие части сайта могут зависеть от
дополнительных доменов. Ложную блокировку сообщайте через Issues со ссылкой
на правило и домен; не публикуйте пароли, клиентские UUID и историю посещений.

География домена, IP или владельца не является основанием для блокировки.
Каталог не обещает полного перечня всех вредоносных адресов мира.

## Лицензии

Код и применимые доменные списки распространяются по GPL-3.0 с сохранением
уведомлений исходных проектов. Данные Spamhaus имеют собственные условия:
название источника, copyright и исходные дата/время сохранены в каждом файле.
[LICENSE.md](LICENSE.md) и [реестр источников](docs/SOURCES.md) описывают границы.


## Карта репозитория

| Каталог | Что открыть и зачем |
|---|---|
| [.github/](.github/CONTENTS.md) | Автоматические задания и формы обращений |
| [config/](config/README.md) | Источники, ограничения, контрольные имена и PSL |
| [docs/](docs/README.md) | Глоссарий, происхождение данных и результаты проверок |
| [regional/](regional/README.md) | Региональные домены, исключения, C2-отчёты и доказательства |
| [scripts/](scripts/README.md) | Скрипты; в ru/ находится собственный сборщик |
| [tests/](tests/README.md) | Поведенческие проверки сборщика и защит |
| [output/](output/README.md) | Готовый AdGuard-фильтр и проверенные IP-источники |
| [templates/](templates/README.md) | Systemd service и timer для снятия срока C2 |

<details>
<summary><strong>Корневые файлы и локальные рабочие каталоги</strong></summary>

Корневой `build` обновляет источники и собирает профиль; `Makefile` объединяет
команды разработки. `BUILDING.md` описывает их запуск, `COMBINATIONS.md` — категории,
`AGENTS.md` — правила работы агента, `LICENSE.md` — лицензию.
`requirements-dev.txt` закрепляет Ruff, `pyproject.toml` задаёт его настройки.
`.pre-commit-config.yaml` описывает проверки перед коммитом, `.gitleaks.toml` —
настройки поиска секретов. `.gitignore` исключает служебные файлы из Git,
`.ignore` уточняет поиск локальных материалов агентом. Локальный `info/` содержит
личный план и не публикуется; `.cache/`, `.venv/`, `.ruff_cache/`, `__pycache__/`
и `.git/` служебные и не требуют README внутри каждого вложенного каталога.

</details>
