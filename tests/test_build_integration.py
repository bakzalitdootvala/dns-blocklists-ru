"""Проверяет полный вызов pipeline.build() на маленьком локальном проекте.

Каждый тест создаёт TemporaryDirectory с четырьмя доменными источниками,
тремя IP-компонентами, контрольными именами и манифестами. Сеть не используется.
Проверки сравнивают реальные выходные байты: воспроизводимость, наличие IP
и исключения, сохранность предыдущего combined.txt при плохом входе.
Рабочие output/ репозитория не изменяются; временные каталоги удаляются.
Запуск: python3 -m unittest discover -s tests -p test_build_integration.py -v.
"""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts/ru"))
import pipeline


class BuildIntegrationTests(unittest.TestCase):
    """Сценарии сборки с настоящими файлами и искусственными источниками во временном каталоге."""

    def test_recent_reports_reach_filter_and_invalid_metadata_preserves_output(self):
        """Полная сборка включает C2-домен/IP; неверный срок или ссылка не заменяет готовый фильтр."""
        from datetime import timedelta

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.fixture(root)
            today = datetime.now(timezone.utc).date()
            path = root / "regional/ru-cis/recent-threats.json"
            report = {
                "id": "case",
                "evidence_url": "https://example.org/report",
                "published_on": str(today),
                "expires_on": str(today + timedelta(days=30)),
                "target_countries": ["RU"],
                "last_seen": None,
                "domains": ["c2.example.org"],
                "ips": ["1.0.0.1"],
            }
            path.write_text(json.dumps({"reports": [report]}))
            pipeline.build(root)
            output = root / "output/adguard/combined.txt"
            before = output.read_bytes()
            self.assertIn(b"\n|c2.example.org^\n", before)
            self.assertIn(b"\n|1.0.0.1|\n", before)
            from check_artifact import verify

            verify(output.parent)
            for field, invalid in [
                ("expires_on", str(today + timedelta(days=31))),
                ("evidence_url", "https://example.org/report\n||safe.example.org^"),
            ]:
                path.write_text(json.dumps({"reports": [{**report, field: invalid}]}))
                with self.assertRaises(ValueError):
                    pipeline.build(root)
                self.assertEqual(output.read_bytes(), before)

    def fixture(self, root):
        """Создаёт минимальный проект в root, достаточный для вызова production-сборщика.

        Сниженные минимумы применяются только в тестовой конфигурации. IP здесь —
        тестовые данные, а не утверждение о вредоносности адресов; все SHA256 рассчитаны
        по созданным файлам, даты свежие относительно времени запуска теста.
        """
        for folder in ["config", ".cache/feeds", "regional/ru-cis", "output/adguard"]:
            (root / folder).mkdir(parents=True, exist_ok=True)
        sources = []
        entries = []
        stamp = datetime.now(timezone.utc).isoformat()
        for category in ["adblock", "privacy", "malware", "gambling"]:
            identifier = "test-" + category
            data = (category + ".example.org\n").encode()
            (root / ".cache/feeds" / f"{identifier}.txt").write_bytes(data)
            sources.append(
                {
                    "id": identifier,
                    "repository": "fixture/source",
                    "ref": "main",
                    "path": identifier + ".txt",
                    "format": "mullvad",
                    "category": category,
                    "minimum_rules": 1,
                    "maximum_bytes": 1000,
                    "license": "GPL-3.0",
                }
            )
            entries.append(
                {
                    "id": identifier,
                    "file": identifier + ".txt",
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "retrieved_at": stamp,
                    "commit_at": stamp,
                    "commit": "a" * 40,
                }
            )
        config = {
            "categories": ["adblock", "privacy", "malware", "gambling"],
            "sources": sources,
            "maximum_source_age_hours": 168,
            "maximum_build_age_hours": 48,
            "ip_sources": [
                {
                    "id": "hagezi-ips",
                    "category": "malware",
                    "path": "ips.txt",
                    "format": "ip",
                    "enforcement": "dns_response",
                    "minimum_rules": 1,
                }
            ],
            "drop_minimum_networks": {"4": 1, "6": 1},
        }
        (root / "config/sources.json").write_text(json.dumps(config))
        (root / "config/controls.json").write_text(
            json.dumps(
                {
                    "allowed": ["safe.example.org"],
                    "blocked": {c: [c + ".example.org"] for c in config["categories"]},
                }
            )
        )
        (root / ".cache/feeds/lock.json").write_text(
            json.dumps({"retrieved_at": stamp, "upstream_commit": "a" * 40, "sources": entries})
        )
        (root / "regional/ru-cis/domains.csv").write_text(
            "domain,category,scope,evidence_url,reviewed_on,requires_feed\n"
        )
        (root / "regional/ru-cis/recent-threats.json").write_text(json.dumps({"reports": []}))

        directory = root / "output/threat-intel"
        directory.mkdir(parents=True)
        for name, value in [
            ("hagezi", "9.9.9.9/32"),
            ("spamhaus-ipv4", "8.8.8.0/24"),
            ("spamhaus-ipv6", "2001:4860::/32"),
        ]:
            filename = "hagezi-ipv4.txt" if name == "hagezi" else name + ".txt"
            data = (value + "\n").encode()
            (directory / filename).write_bytes(data)
            metadata = {
                "artifact_sha256": hashlib.sha256(data).hexdigest(),
                "network_count": 1,
                "enforcement": "dns_response",
                "retrieved_at": stamp,
                "commit_at": stamp,
                "source_published_at": stamp,
                "copyright": "Spamhaus fixture copyright",
                "terms": "https://www.spamhaus.org/drop/terms/",
            }
            (directory / (name + "-manifest.json")).write_text(json.dumps(metadata))

    def test_ip_inputs_are_required_and_corruption_preserves_previous_filter(self):
        """Отсутствующий IP-манифест, неверный SHA, старая дата и неверный счётчик сохраняют прежний combined.txt."""
        for failure in ["missing", "sha", "stale", "count"]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                root = pathlib.Path(folder)
                self.fixture(root)
                pipeline.build(root)
                artifact = root / "output/adguard/combined.txt"
                before = artifact.read_bytes()
                directory = root / "output/threat-intel"
                path = directory / "spamhaus-ipv6-manifest.json"
                data = json.loads(path.read_text())
                if failure == "missing":
                    path.unlink()
                else:
                    if failure == "sha":
                        data["artifact_sha256"] = "0" * 64
                    elif failure == "stale":
                        data["source_published_at"] = "2020-01-01T00:00:00Z"
                    else:
                        data["network_count"] = 2
                    path.write_text(json.dumps(data))
                with self.assertRaises((ValueError, OSError)):
                    pipeline.build(root)
                self.assertEqual(artifact.read_bytes(), before)

    def test_actual_build_preserves_exact_names_and_is_reproducible(self):
        """Полная сборка включает домены и три IP-правила; повтор с теми же входами даёт идентичные байты."""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            self.fixture(root)
            pipeline.build(root)
            out = root / "output/adguard/combined.txt"
            original = out.read_bytes()
            actual = [line for line in original.decode().splitlines() if not line.startswith("!")]
            self.assertEqual(
                [line for line in actual if "example.org" in line],
                [
                    "adblock.example.org",
                    "gambling.example.org",
                    "malware.example.org",
                    "privacy.example.org",
                ],
            )
            self.assertIn("|9.9.9.9|", actual)
            self.assertTrue(any(line.startswith("/^") for line in actual))
            manifest = json.loads((root / "output/adguard/manifest.json").read_text())
            self.assertEqual(manifest["ip_enforcement"], "dns_response")
            self.assertEqual(manifest["ip_rule_count"], 3)
            pipeline.build(root)
            self.assertEqual(out.read_bytes(), original)

    def test_corrupted_input_cannot_replace_previous_outputs(self):
        """Повреждение доменного снимка после успешной сборки не должно перезаписать готовый фильтр."""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            self.fixture(root)
            pipeline.build(root)
            out = root / "output/adguard/combined.txt"
            original = out.read_bytes()
            (root / ".cache/feeds/test-adblock.txt").write_text("<html>error</html>")
            with self.assertRaises(ValueError):
                pipeline.build(root)
            self.assertEqual(out.read_bytes(), original)

    def test_new_false_positive_cannot_replace_previous_outputs(self):
        """Конфликт с разрешённым контрольным доменом останавливает сборку и сохраняет прежние байты."""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            self.fixture(root)
            pipeline.build(root)
            out = root / "output/adguard/combined.txt"
            original = out.read_bytes()
            controls = json.loads((root / "config/controls.json").read_text())
            controls["allowed"].append("adblock.example.org")
            (root / "config/controls.json").write_text(json.dumps(controls))
            with self.assertRaises(ValueError):
                pipeline.build(root)
            self.assertEqual(out.read_bytes(), original)

    def test_large_unique_rule_drop_preserves_previous_release(self):
        """Сокращение источника с трёх уникальных правил до одного должно остановить новый выпуск."""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            self.fixture(root)
            source = root / ".cache/feeds/test-adblock.txt"
            lock_path = root / ".cache/feeds/lock.json"
            lock = json.loads(lock_path.read_text())
            source.write_text("adblock.example.org\nold1.example.org\nold2.example.org\n")
            lock["sources"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            lock_path.write_text(json.dumps(lock))
            pipeline.build(root)
            artifact = root / "output/adguard/combined.txt"
            previous = artifact.read_bytes()
            source.write_text("adblock.example.org\n")
            lock["sources"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            lock_path.write_text(json.dumps(lock))
            with self.assertRaises(ValueError):
                pipeline.build(root)
            self.assertEqual(artifact.read_bytes(), previous)

    def test_exact_allowlist_is_wired_into_actual_filter(self):
        """Разрешающее правило из CSV должно реально попасть в combined.txt рядом с блокирующим правилом."""
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            self.fixture(root)
            source = root / ".cache/feeds/test-adblock.txt"
            source.write_text("adblock.example.org\n||safe.example.org^\n")
            lock_path = root / ".cache/feeds/lock.json"
            lock = json.loads(lock_path.read_text())
            lock["sources"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            lock_path.write_text(json.dumps(lock))
            config_path = root / "config/sources.json"
            config = json.loads(config_path.read_text())
            config["sources"][0]["format"] = "adguard"
            config_path.write_text(json.dumps(config))
            (root / "regional/ru-cis/allowlist.csv").write_text(
                "domain,scope,evidence_url,reviewed_on,reason\nsafe.example.org,exact,https://example.org/docs,2026-11-08,Общий CDN\n"
            )
            pipeline.build(root)
            content = (root / "output/adguard/combined.txt").read_text().splitlines()
            self.assertIn("@@|safe.example.org^", content)
            self.assertIn("||safe.example.org^", content)


if __name__ == "__main__":
    unittest.main()
