"""Проверяет происхождение данных и ограничения регионального каталога.

Вызывает функции pipeline напрямую с искусственными строками и временными
файлами. Проверяет SHA256, возраст, подтверждение malware текущим источником,
обязательность ссылок и точность исключений.
GitHub, VPS и внешние DNS не используются.
"""

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/ru"))
try:
    import pipeline
except ModuleNotFoundError:
    pipeline = None


class PipelineTests(unittest.TestCase):
    """Проверки условий допуска доменов к сборке."""

    def test_public_suffix_can_be_queried_but_cannot_be_blocking_rule(self):
        """gov.kg имеет собственный сайт: контрольный DNS-запрос допустим, общий запрет зоны — нет."""
        from blocklists import check_controls, normalize_domain

        check_controls([], ["gov.kg"])
        with self.assertRaises(ValueError):
            normalize_domain("gov.kg")

    def setUp(self):
        """Требует существующий модуль pipeline перед каждым тестом."""
        self.assertIsNotNone(pipeline, "Модуль сборки должен существовать")

    def test_sha256_mismatch_rejects_cached_source(self):
        """Байты локального источника с неверной заявленной SHA256 не принимаются."""
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "source.txt"
            path.write_text("ads.example.org\n")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                pipeline.read_checked(path, "0" * 64, 1000)

    def test_stale_verification_is_not_mistaken_for_fresh_data(self):
        """Старая дата источника должна вызвать ошибку проверки возраста."""
        with self.assertRaises(ValueError):
            pipeline.check_age("2020-01-01T00:00:00+00:00", 48)

    def test_regional_malware_is_enabled_only_while_present_in_current_feed(self):
        """Региональный malware-домен включается только при его наличии в указанном текущем источнике."""
        from blocklists import Rule

        row = {
            "domain": "bad.example.org",
            "category": "malware",
            "scope": "exact",
            "evidence_url": "https://example.com/report",
            "reviewed_on": "2026-11-08",
            "requires_feed": "hagezi-tif",
        }
        self.assertIsNone(pipeline.regional_rule(row, {"hagezi-tif": set()}))
        self.assertEqual(
            pipeline.regional_rule(row, {"hagezi-tif": {"bad.example.org"}}),
            Rule("bad.example.org"),
        )

    def test_region_record_without_evidence_is_rejected(self):
        """Региональное правило без ссылки на доказательство должно быть отклонено."""
        row = {
            "domain": "ads.example.org",
            "category": "adblock",
            "scope": "exact",
            "evidence_url": "",
            "reviewed_on": "2026-11-08",
            "requires_feed": "",
        }
        with self.assertRaises(ValueError):
            pipeline.regional_rule(row, {})

    def test_region_data_cannot_enable_social_category(self):
        """Региональный CSV не может включить запрещённую профилем категорию social."""
        row = {
            "domain": "social.example.org",
            "category": "social",
            "scope": "suffix",
            "evidence_url": "https://example.com/report",
            "reviewed_on": "2026-11-08",
            "requires_feed": "",
        }
        with self.assertRaises(ValueError):
            pipeline.regional_rule(row, {})

    def test_regional_exception_is_exact_and_needs_evidence(self):
        """Исключение разрешает ровно имя; попытка расширить scope на поддомены отклоняется."""
        row = {
            "domain": "yastatic.net",
            "scope": "exact",
            "evidence_url": "https://example.com/docs",
            "reviewed_on": "2026-11-08",
            "reason": "Общий CDN",
        }
        rule = pipeline.regional_exception(row)
        self.assertEqual(rule.to_adguard(), "@@|yastatic.net^")
        self.assertFalse(rule.matches("tracking.yastatic.net"))
        row["scope"] = "suffix"
        with self.assertRaises(ValueError):
            pipeline.regional_exception(row)


if __name__ == "__main__":
    unittest.main()
