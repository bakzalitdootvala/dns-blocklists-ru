"""Проверяет точность доменных правил и защиту от чрезмерной блокировки.

Тесты вызывают blocklists.py напрямую: exact, wildcard, suffix, исключения,
IDNA, категории, PSL, минимумы источников и отдельный учёт IP. Используют
искусственные строки; интернет, AdGuard и публикация GitHub не требуются.
Запуск полного набора: python3 -m unittest discover -s tests -v.
Ошибки обнаруживаются утверждениями unittest. Термины: docs/GLOSSARY.md.
"""

import importlib.util
import pathlib
import sys
import unittest

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts/ru/blocklists.py"


def load_builder():
    """Загружает локальный blocklists.py по пути; отсутствие файла возвращает None для понятной ошибки setUp."""
    if not MODULE.exists():
        return None
    spec = importlib.util.spec_from_file_location("ru_blocklists", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = load_builder()


class RuleTests(unittest.TestCase):
    """Проверки семантики доменного правила: что оно должно и не должно блокировать."""

    def setUp(self):
        """Проверяет наличие модуля до каждого сценария, чтобы отсутствие кода не выглядело успешным тестом."""
        self.assertIsNotNone(builder, "Сборщик scripts/ru/blocklists.py должен существовать")

    def test_exact_rule_does_not_match_subdomains_or_suffix_tricks(self):
        """Точное имя не должно захватывать его поддомены и имя с добавленным чужим суффиксом."""
        rule = builder.parse_domain_rule("ads.example.org", "mullvad")
        self.assertTrue(rule.matches("ads.example.org"))
        self.assertFalse(rule.matches("sub.ads.example.org"))
        self.assertFalse(rule.matches("ads.example.org.attacker.test"))
        self.assertEqual(rule.to_adguard(), "ads.example.org")

    def test_wildcard_excludes_apex_and_is_label_bounded(self):
        """Wildcard охватывает потомков, но исключает само имя и похожие имена без границы точки."""
        rule = builder.parse_domain_rule("*.ads.example.org", "mullvad")
        self.assertTrue(rule.matches("a.b.ads.example.org"))
        self.assertFalse(rule.matches("ads.example.org"))
        self.assertFalse(rule.matches("badads.example.org"))
        self.assertFalse(rule.matches("ads.example.org.attacker.test"))

    def test_adblock_suffix_matches_apex_and_children_only(self):
        """Правило ||имя^ должно охватывать имя и потомков, не захватывая соседнее имя."""
        rule = builder.parse_domain_rule("||ads.example.org^", "adguard")
        self.assertTrue(rule.matches("ads.example.org"))
        self.assertTrue(rule.matches("sub.ads.example.org"))
        self.assertFalse(rule.matches("notads.example.org"))

    def test_contextual_rules_cannot_become_unconditional_dns_rules(self):
        """Модификаторы браузера, URL-пути, regex и RPZ-строки не должны превращаться в доменный запрет."""
        for text in [
            "||ads.example.org^$third-party",
            "||ads.example.org^$domain=example.com",
            "example.org##.ad",
            "||example.org/ads",
            "/ads.*/",
            "24.0.247.18.71.rpz.ip",
        ]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                builder.parse_domain_rule(text, "adguard")

    def test_ips_and_tlds_are_not_domain_rules(self):
        """IP, целые доменные зоны и некорректные имена должны отклоняться доменным парсером."""
        for text in [
            "1.2.3.4",
            "2001:db8::1",
            "*.ru",
            "ru",
            "*",
            "-bad.example",
            "x..example",
            "localhost",
        ]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                builder.parse_domain_rule(text, "mullvad")

    def test_dns_labels_with_underscore_preserve_exact_scope(self):
        """Допустимая DNS-метка с underscore сохраняется, не расширяясь на весь общий домен."""
        rule = builder.parse_domain_rule("fb_servpub-a.akamaihd.net", "mullvad")
        self.assertEqual(rule.to_adguard(), "fb_servpub-a.akamaihd.net")
        self.assertFalse(rule.matches("other.akamaihd.net"))

    def test_idna_and_case_normalization(self):
        """Кириллическое имя в верхнем регистре приводится к ожидаемой ASCII IDNA-форме."""
        self.assertEqual(
            builder.parse_domain_rule("ПРИМЕР.РФ", "mullvad").domain, "xn--e1afmkfd.xn--p1ai"
        )

    def test_exact_and_wildcard_pair_compacts_without_changing_scope(self):
        """Дубли и пара имя/*.имя объединяются, а отдельное точное правило остаётся точным."""
        rules = [
            builder.parse_domain_rule(x, "mullvad")
            for x in ["ads.example.org", "*.ads.example.org", "ads.example.org", "only.example.org"]
        ]
        self.assertEqual(builder.render_rules(rules), ["only.example.org", "||ads.example.org^"])

    def test_exception_keeps_its_scope(self):
        """Разрешающее исключение сохраняет исходную область и не разрешает соседний домен."""
        rule = builder.parse_domain_rule("@@||safe.example.org^", "adguard")
        self.assertTrue(rule.allow)
        self.assertEqual(rule.to_adguard(), "@@||safe.example.org^")
        self.assertFalse(rule.matches("other.example.org"))

    def test_selected_categories_reject_adult_and_social(self):
        """Профиль принимает четыре выбранные категории и отклоняет adult/social/неизвестные."""
        for category in ["adult", "social", "unknown"]:
            with self.subTest(category=category), self.assertRaises(ValueError):
                builder.check_category(category)
        for category in ["adblock", "privacy", "malware", "gambling"]:
            builder.check_category(category)

    def test_controls_stop_publication_on_blocked_normal_domain(self):
        """Блокировка разрешённого контрольного имени должна остановить проверку."""
        rules = [builder.parse_domain_rule("||example.org^", "adguard")]
        with self.assertRaisesRegex(ValueError, "safe.example.org"):
            builder.check_controls(rules, ["safe.example.org"])

    def test_empty_or_html_input_fails_instead_of_publishing_empty_filter(self):
        """Пустые данные, одни комментарии и HTML-страница ошибки не считаются рабочим источником."""
        for text in ["", "! Only comments\n", "<html>error</html>"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                builder.parse_source(text, "mullvad", minimum_rules=1)

    def test_source_reports_ips_separately(self):
        """IP из доменного файла учитывается отдельно и не выдаётся как доменное правило."""
        result = builder.parse_source("ads.example.org\n8.8.8.8\n", "mullvad", minimum_rules=1)
        self.assertEqual(result.ips, ["8.8.8.8"])
        self.assertEqual([x.to_adguard() for x in result.rules], ["ads.example.org"])

    def test_ip_indicators_reject_private_or_reserved_networks(self):
        """Непубличные, служебные и multicast-примеры отклоняются; публичный IP нормализуется в /32."""
        for value in [
            "127.0.0.1",
            "10.0.0.0/8",
            "0.0.0.0/0",
            "192.0.2.1",
            "::1",
            "fc00::/7",
            "224.0.0.1",
            "ff00::/8",
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                builder.validate_public_network(value)
        self.assertEqual(builder.validate_public_network("8.8.8.8"), "8.8.8.8/32")


if __name__ == "__main__":
    unittest.main()


class InputGuardTests(unittest.TestCase):
    """Проверки минимального числа уникальных правил и границ общих платформ."""

    def test_repeated_lines_do_not_satisfy_minimum_unique_rules(self):
        """Повтор одного домена пять раз не должен удовлетворять минимуму пяти уникальных правил."""
        with self.assertRaises(ValueError):
            builder.parse_source("ads.example.org\n" * 5, "mullvad", minimum_rules=5)

    def test_public_suffixes_and_shared_hosting_suffixes_are_rejected(self):
        """Общий суффикс вроде github.io запрещён к блокировке целиком, конкретный поддомен допустим."""
        for text in ["||co.nz^", "*.org.nz", "||github.io^", "*.cloudfront.net"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                builder.parse_domain_rule(text, "adguard")
        self.assertEqual(
            builder.parse_domain_rule("project.github.io", "mullvad").domain, "project.github.io"
        )


class PublicSuffixSourceTests(unittest.TestCase):
    """Проверка учёта исключённых суффиксов при разборе полного источника."""

    def test_source_excludes_shared_suffix_but_keeps_specific_abusive_hostname(self):
        """Парсер исключает общий servebbs.net с записью в отчёт и сохраняет правило его поддомена."""
        result = builder.parse_source(
            "||servebbs.net^\n||bad.servebbs.net^\n", "adguard", minimum_rules=1
        )
        self.assertEqual([rule.to_adguard() for rule in result.rules], ["||bad.servebbs.net^"])
        self.assertEqual(result.excluded_public_suffixes, ["servebbs.net"])
