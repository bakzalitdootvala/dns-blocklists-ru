"""Проверяет обнаружение изменения combined.txt относительно manifest.json.

Создаёт два маленьких файла во временном каталоге и вызывает check_artifact.verify.
Манифест содержит SHA256 другого содержимого: проверка обязана выдать ValueError.
Сеть и настоящий output/ не используются. Запуск: unittest discover -s tests.
"""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts/ru"))
try:
    import check_artifact
except ModuleNotFoundError:
    check_artifact = None


class ArtifactTests(unittest.TestCase):
    """Регрессионная проверка контрольной суммы готового фильтра."""

    def setUp(self):
        """Требует наличия модуля проверки готового файла перед запуском сценария."""
        self.assertIsNotNone(check_artifact, "Проверка артефакта должна существовать")

    def test_changed_filter_fails_manifest_check(self):
        """Изменённые байты фильтра должны быть отвергнуты даже при подходящем числе правил и категориях."""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            (root / "combined.txt").write_text("changed.example\n")
            manifest = {
                "sha256": hashlib.sha256(b"original.example\n").hexdigest(),
                "rule_count": 1,
                "categories": ["adblock", "privacy", "malware", "gambling"],
                "excluded_categories": ["adult", "social"],
                "ip_enforcement": "dns_response",
                "domain_rule_count": 0,
                "ip_rule_count": 1,
                "ip_sources": [
                    {"id": name} for name in ["hagezi", "spamhaus-ipv4", "spamhaus-ipv6"]
                ],
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                check_artifact.verify(root)


if __name__ == "__main__":
    unittest.main()
