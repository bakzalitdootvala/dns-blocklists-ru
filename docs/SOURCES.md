# Источники и условия использования

Сборщик фиксирует URL, commit SHA, SHA256 байтов и время получения
в `output/adguard/manifest.json`. Время commit описывает снимок репозитория;
оно не доказывает время последней вредоносной активности каждого домена.

## Доменный фильтр

| Источник | Используемые файлы | Условия |
|---|---|---|
| [Mullvad DNS blocklists](https://github.com/mullvad/dns-blocklists) | `output/relay/relay_{adblock,privacy,malware,gambling}.txt` | [GPL-3.0](https://github.com/mullvad/dns-blocklists/blob/main/LICENSE.md) |
| [HaGeZi](https://github.com/hagezi/dns-blocklists) | `adblock/tif.txt` | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| Региональный каталог | `regional/ru-cis/domains.csv` | Собственная подборка фактов с первичными ссылками; GPL-3.0 |

Mullvad агрегирует OISD Small, Frellwit, AdGuard DNS/Mobile, HaGeZi и EasyPrivacy.
Действующий состав определяется `inventory/group_vars/all.yml` upstream,
а не только README. Для источников применимы их исходные уведомления:
[OISD](https://oisd.nl/?p=faq),
[Frellwit](https://github.com/lassekongo83/Frellwits-filter-lists/blob/master/LICENSE),
[AdGuard](https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE),
[EasyList/EasyPrivacy](https://easylist.to/pages/licence.html).
Преобразования Firebog входят в опубликованный результат Mullvad;
они не считаются доказательством сохранения всех исходных браузерных условий.

Mullvad malware содержит собственные домены имитации Mullvad.
Глобальное malware-покрытие данного форка обеспечивает отдельно подключённый TIF.

Браузерные Cyrillic/RU AdList используются как источники исследования,
а не как безусловные DNS-входы. `$domain`, `$third-party`, URL-пути,
косметические правила и scriptlets имеют контекст, которого у DNS нет.
Списки взрослого контента и социальных сетей не подключаются.

### Проверенные региональные дополнения

`regional/ru-cis/ad-services.json` хранит первичные ссылки на инструкции Метрики,
Рейтинга Mail.ru, Segmento и справочник рекламных поставщиков
[Google Authorized Buyers](https://developers.google.com/authorized-buyers/rtb/data).
Google подтверждает связь hostname с рекламным оператором; весь справочник
не импортируется, поскольку содержит обычные `mail.ru` и `yandex.ru`.
Выбранные служебные имена ограничены exact. Международные Weborama и Hybrid
не считаются российскими компаниями. RU AdList используется для исследования;
его CC-BY-3.0 не заменяется лицензией GPL и его браузерные правила не импортируются.

`recent-threats.json` содержит отдельные фактические C2-индикаторы из
[первичного отчёта Securelist об Arra Ghouls](https://securelist.ru/tr/new-cyber-threat-arra-ghouls-attacks-russian-organizations/117588/).
20 hostname и 24 IPv4 опубликованы 9 ноября 2026, цели — Россия и Беларусь.
Текст статьи не копируется. Дата последней активности каждого адреса неизвестна;
правила действуют 30 суток от публикации, до 9 декабря 2026 UTC.
Произвольные IP-соседи, родительские домены, почтовые отправители и общие
Google/GitHub-сервисы к этому набору не добавляются.

Обзор стран, исключённых источников и порядок обновления:
[REGIONAL_COVERAGE.md](REGIONAL_COVERAGE.md).

## Сетевые индикаторы

### HaGeZi TIF IP

Источник: [ips/tif.txt](https://github.com/hagezi/dns-blocklists/blob/main/ips/tif.txt).
Условия: GPL-3.0. Выход: `output/threat-intel/hagezi-ipv4.txt` и отдельный manifest.
У источника нет индивидуальных `last_seen`, назначения IP и региона жертв.
Непубличные/некорректные записи перечисляются в manifest как исключённые.
Текущие публичные адреса включаются в правила проверки DNS-ответов.

### Spamhaus DROP

Источники: [IPv4 JSON Lines](https://www.spamhaus.org/drop/drop_v4.json) и
[IPv6 JSON Lines](https://www.spamhaus.org/drop/drop_v6.json).
Условия: [DROP Fair Use](https://www.spamhaus.org/blocklists/drop-fair-use-policy/),
[разрешение распространения plain text](https://www.spamhaus.com/faqs/drop/).
Эти данные не перелицензируются под GPL.

Название Spamhaus, copyright, исходные дата/время и ссылка на условия
сохраняются в каждом текстовом файле. Метаданные сохраняются отдельно.
Поле `rir` обозначает региональный интернет-регистратор, а не страну адреса
и не регион жертв. ASN-DROP не подключается. Частота загрузки — раз в сутки;
повторные ручные загрузки должны быть разделены минимум одним часом.

## Ограничения покрытия

Нет подтверждённого открытого feed, который содержал бы все вредоносные IP
мира либо полную актуальную разметку атак по жертвам RU/CIS.
IP-репутация, активный malware C2 и адрес исследовательского сканера различаются.
Сетевые списки блокируют DNS-ответы с совпавшим IP; firewall не изменяется.

На 2026-11-08 проверка источников показала:
- Feodo recommended содержит наблюдения марта 2026: не проходит проверку свежести.
- SSLBL IP прекращён с 2025-01-03 и возвращает пустые данные.
- ThreatFox и URLhaus требуют Auth-Key; отдельный доступ не настроен.
- IPsum смешивает вредоносную активность и входящее сканирование.
- Актуальная база Maltrail Trails имеет отдельную ограничительную лицензию.

Эти источники не включены в сборку. Реестр отражает проверенные ограничения,
а не обещание их будущей интеграции.

## Public Suffix List

`config/public_suffix_list.dat` — закреплённый снимок
[Public Suffix List](https://github.com/publicsuffix/list) с лицензией MPL-2.0.
Точный commit и SHA256 находятся в `config/public-suffix-source.json`.
Сохраняются исходные лицензионные комментарии и private-раздел общих платформ.
Правила для целых public suffix, например `co.nz` или `github.io`, не попадают
в фильтр; manifest перечисляет исключённые суффиксы по каждому источнику.
Отдельный вредоносный поддомен такой платформы может блокироваться.
Снимок PSL обновляется явно с проверкой лицензии, SHA256 и тестов.

Минимум источника считается по уникальным нормализованным правилам.
Падение их количества более чем на 25% относительно предыдущего принятого
снимка останавливает выпуск и требует проверки причины.
