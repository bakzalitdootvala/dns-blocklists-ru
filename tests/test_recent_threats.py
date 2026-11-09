"""Проверяет точность и срок временных C2-правил из первичных отчётов.

Даты заданы явно: тесты не зависят от календаря машины. Проверяется результат
сборки и удаления блока, включая запрет подсетей и сохранность постоянных правил.
"""

import copy
import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/ru"))
import recent_threats


class RecentThreatsTests(unittest.TestCase):
    """Не позволяет расширить временный запрет или продлить его датой загрузки."""

    def setUp(self):
        """Создаёт первичный отчёт с отдельным именем и одним публичным IP."""
        self.data = {
            "reports": [
                {
                    "id": "case",
                    "evidence_url": "https://example.org/report",
                    "published_on": "2026-11-09",
                    "expires_on": "2026-12-09",
                    "target_countries": ["RU", "BY"],
                    "last_seen": None,
                    "domains": ["bad.example.org"],
                    "ips": ["8.8.4.4"],
                }
            ]
        }

    def test_exact_rules_and_expiration_boundary(self):
        """В день истечения ни домен, ни IP уже не входят в результат."""
        active = recent_threats.compile_reports(self.data, date(2026, 12, 8))
        self.assertEqual(active[0]["rules"], ["|8.8.4.4|", "|bad.example.org^"])
        self.assertEqual(recent_threats.compile_reports(self.data, date(2026, 12, 9)), [])

    def test_invalid_or_extended_dates_are_rejected(self):
        """Дата чтения не может продлить 30 суток от публикации; будущая публикация запрещена."""
        for published, expires in [("2026-11-09", "2027-01-01"), ("2026-12-01", "2026-12-31")]:
            data = copy.deepcopy(self.data)
            data["reports"][0].update(published_on=published, expires_on=expires)
            with self.assertRaises(ValueError):
                recent_threats.compile_reports(data, date(2026, 11, 9))

    def test_evidence_url_cannot_inject_filter_rules(self):
        """Перенос строки/управляющий символ в ссылке не может добавить правило через комментарий."""
        for suffix in ["\n||example.org^", "\r||example.org^", "\tpath", " path", "\x00", "\x7f"]:
            data = copy.deepcopy(self.data)
            data["reports"][0]["evidence_url"] += suffix
            with self.assertRaises(ValueError):
                recent_threats.compile_reports(data, date(2026, 11, 9))

    def test_networks_private_ips_and_public_suffixes_rejected(self):
        """Отчёт допускает только отдельные публичные IP и реальные hostname, не целые сети/TLD."""
        for key, value in [("ips", "8.8.4.0/24"), ("ips", "127.0.0.1"), ("domains", "co.uk")]:
            data = copy.deepcopy(self.data)
            data["reports"][0][key] = [value]
            with self.assertRaises(ValueError):
                recent_threats.compile_reports(data, date(2026, 11, 9))

    def test_expiry_preserves_permanent_identical_rule(self):
        """Удаляется только подписанный временный блок, даже если то же правило есть в основной базе."""
        active = recent_threats.compile_reports(self.data, date(2026, 11, 9))
        base = "! Title: example\n|bad.example.org^\n||ads.example.net^\n"
        combined = base + recent_threats.render_reports(active)
        self.assertEqual(recent_threats.expire_text(combined, date(2026, 12, 8)), combined)
        self.assertEqual(recent_threats.expire_text(combined, date(2026, 12, 9)), base)

    def test_malformed_block_does_not_silently_delete_rest_of_file(self):
        """Оборванный или вложенный блок даёт ошибку вместо потери остального фильтра."""
        for text in [
            "! Regional report: case expires=2026-12-09\n|bad.example.org^\n",
            "! End regional report\n",
            "! Regional report: case expires=2026-12-09\n! Regional report: x expires=2026-12-09\n",
        ]:
            with self.assertRaises(ValueError):
                recent_threats.expire_text(text, date(2027, 1, 1))


if __name__ == "__main__":
    unittest.main()
