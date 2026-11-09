"""Проверяет преобразование Spamhaus DROP на искусственных JSON Lines.

sample() создаёт запись CIDR и завершающую metadata. Сценарии портят дату,
число записей, семейство, публичность, copyright или уникальность расследований.
Тесты не скачивают Spamhaus и не утверждают вредоносность использованных IP;
проверяются только формат, ограничения и сохранение информации об источнике.
"""

import json
import pathlib
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts/ru"))
try:
    import threat_intel
except ModuleNotFoundError:
    threat_intel = None


class DropTests(unittest.TestCase):
    """Проверки допуска DROP-снимка и точного учёта сетей/расследований."""

    def setUp(self):
        """Проверяет наличие модуля threat_intel."""
        self.assertIsNotNone(threat_intel, "Модуль IP-источников должен существовать")

    def sample(self, timestamp=None, count=1, cidr="8.8.8.0/24"):
        """Возвращает двухстрочный DROP-пример; timestamp/count/cidr позволяют отдельно испортить нужное свойство."""
        return "\n".join(
            [
                json.dumps({"cidr": cidr, "sblid": "SBLTEST", "rir": "arin"}),
                json.dumps(
                    {
                        "type": "metadata",
                        "timestamp": timestamp or int(time.time()),
                        "records": count,
                        "copyright": "Spamhaus copyright fixture",
                        "terms": "https://www.spamhaus.org/drop/terms/",
                    }
                ),
            ]
        )

    def test_fresh_drop_preserves_attribution_and_enables_dns_response(self):
        """Свежий пример сохраняет сеть, copyright, terms и режим dns_response без выдуманной географии."""
        artifact, metadata = threat_intel.convert_drop(self.sample(), 4)
        self.assertIn("8.8.8.0/24", artifact)
        self.assertIn("Spamhaus copyright fixture", artifact)
        self.assertIn("https://www.spamhaus.org/drop/terms/", artifact)
        self.assertEqual(metadata["enforcement"], "dns_response")
        self.assertNotIn("country", metadata)

    def test_stale_source_is_rejected_even_if_download_is_fresh(self):
        """Публикация восемь дней назад отвергается независимо от момента получения текста."""
        with self.assertRaises(ValueError):
            threat_intel.convert_drop(self.sample(timestamp=int(time.time()) - 8 * 86400), 4)

    def test_truncated_drop_fails_record_count(self):
        """Заявленные две записи при одной фактической означают повреждённый снимок."""
        with self.assertRaises(ValueError):
            threat_intel.convert_drop(self.sample(count=2), 4)

    def test_wrong_ip_family_and_private_network_are_rejected(self):
        """IPv6 в IPv4-файле и приватная IPv4-сеть вызывают ошибку."""
        for cidr in ["10.0.0.0/8", "2001:4860::/32"]:
            with self.subTest(cidr=cidr), self.assertRaises(ValueError):
                threat_intel.convert_drop(self.sample(cidr=cidr), 4)

    def test_missing_source_notice_is_rejected(self):
        """Пустой copyright не должен позволять выпуск списка без обязательной атрибуции."""
        text = self.sample().replace("Spamhaus copyright fixture", "")
        with self.assertRaises(ValueError):
            threat_intel.convert_drop(text, 4)

    def test_duplicate_networks_do_not_satisfy_drop_record_count(self):
        """Повтор одной пары сеть/расследование должен отклоняться."""
        lines = self.sample(count=2).splitlines()
        text = "\n".join([lines[0], lines[0], lines[1]])
        with self.assertRaises(ValueError):
            threat_intel.convert_drop(text, 4)

    def test_distinct_investigations_of_one_network_preserve_both_record_count_and_unique_count(
        self,
    ):
        """Два разных SBL одной сети сохраняются в счётчиках, но не засчитываются как две уникальные сети."""
        lines = self.sample(count=2).splitlines()
        second = json.loads(lines[0])
        second["sblid"] = "SBLOTHER"
        text = "\n".join([lines[0], json.dumps(second), lines[1]])
        artifact, metadata = threat_intel.convert_drop(text, 4)
        self.assertEqual(metadata["records"], 2)
        self.assertEqual(metadata["network_count"], 1)
        self.assertEqual(artifact.count("8.8.8.0/24"), 1)
        with self.assertRaises(ValueError):
            threat_intel.convert_drop(text, 4, minimum_networks=2)


if __name__ == "__main__":
    unittest.main()
