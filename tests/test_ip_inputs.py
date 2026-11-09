"""Проверяет обязательные IP-компоненты и часовое повторное использование DROP.

Использует временный проект из test_build_integration.py и вызывает настоящую
сборку после порчи одного свойства входа. Для download_drop подменён HTTP-клиент:
сеть не используется, проверяется количество запросов и SHA256 локального кэша.
Реальный фильтр и удалённые источники не изменяются.
"""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts/ru"))
import download_drop
import ip_inputs
import test_build_integration


class IPInputTests(unittest.TestCase):
    """Сценарии отказа IP-сборки и сохранения действующего локального результата."""

    def test_invalid_ip_sources_preserve_published_filter(self):
        """Неверные адреса, семейство, режим, дата, атрибуция и резкое сокращение не заменяют старый фильтр."""
        for kind in ["private", "family", "disabled", "stale-hagezi", "missing-notice", "shrink"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = pathlib.Path(folder)
                test_build_integration.BuildIntegrationTests().fixture(root)
                import pipeline

                pipeline.build(root)
                output = root / "output/adguard/combined.txt"
                before = output.read_bytes()
                directory = root / "output/threat-intel"
                identifier = "hagezi" if kind == "stale-hagezi" else "spamhaus-ipv4"
                path = directory / (identifier + "-manifest.json")
                metadata = json.loads(path.read_text())
                if kind in ["private", "family"]:
                    data = "10.0.0.0/8\n" if kind == "private" else "2001:4860::/32\n"
                    (directory / "spamhaus-ipv4.txt").write_text(data)
                    metadata["artifact_sha256"] = hashlib.sha256(data.encode()).hexdigest()
                elif kind == "disabled":
                    metadata["enforcement"] = "disabled"
                elif kind == "stale-hagezi":
                    metadata["retrieved_at"] = "2020-01-01T00:00:00Z"
                elif kind == "missing-notice":
                    metadata["copyright"] = ""
                else:
                    manifest_path = root / "output/adguard/manifest.json"
                    manifest = json.loads(manifest_path.read_text())
                    for item in manifest["ip_sources"]:
                        item["network_count"] = 10
                    manifest_path.write_text(json.dumps(manifest))
                path.write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):
                    pipeline.build(root)
                self.assertEqual(before, output.read_bytes())

    def test_required_ip_components_are_in_artifact(self):
        """Все три IP-источника и уведомление Spamhaus должны присутствовать в результате load_ip_rules."""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            test_build_integration.BuildIntegrationTests().fixture(root)
            config = json.loads((root / "config/sources.json").read_text())
            rules, reports, notices = ip_inputs.load_ip_rules(root, config)
            self.assertEqual(len(rules), 3)
            self.assertEqual(
                {item["id"] for item in reports}, {"hagezi", "spamhaus-ipv4", "spamhaus-ipv6"}
            )
            self.assertIn("Spamhaus fixture copyright", "\n".join(notices))

    def test_downloader_reuses_hourly_snapshot_and_rejects_changed_cache(self):
        """Повтор в течение часа не делает HTTP-запросов; изменение скачанных байтов вызывает ошибку."""
        with tempfile.TemporaryDirectory() as folder:
            directory = pathlib.Path(folder)
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = b"fixture bytes"
            with mock.patch.object(
                download_drop.urllib.request, "urlopen", return_value=response
            ) as request:
                download_drop.download_drop(directory)
                self.assertEqual(request.call_count, 2)
                download_drop.download_drop(directory)
                self.assertEqual(request.call_count, 2)
                (directory / "drop_v6.json").write_text("changed")
                with self.assertRaises(ValueError):
                    download_drop.download_drop(directory)
                self.assertEqual(request.call_count, 2)
