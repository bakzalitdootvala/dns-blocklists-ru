"""Проверяет обновление двух копий фильтра и восстановление при отказе перезапуска."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/ru"))
import expire_filter


class ExpireFilterTests(unittest.TestCase):
    """Использует настоящие временные файлы и заменяет только systemd-вызов."""

    def test_update_and_rollback_preserve_both_copies(self):
        """Отказ start восстанавливает источник и кэш, повторный start запускает старый фильтр."""
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / name for name in ("source", "cache")]
            paths[0].write_text("source old\n")
            paths[1].write_text("cache old\n")
            calls = []

            def service(action):
                """Имитирует единственный отказ первого старта после реальной записи файлов."""
                calls.append(action)
                if calls == ["stop", "start"]:
                    self.assertEqual(paths[0].read_text(), "new\n")
                    self.assertEqual(paths[1].read_text(), "new\n")
                    raise RuntimeError("start failed")

            with self.assertRaises(RuntimeError):
                expire_filter.install(paths[0], paths[1], "new\n", service)
            self.assertEqual(paths[0].read_text(), "source old\n")
            self.assertEqual(paths[1].read_text(), "cache old\n")
            self.assertEqual(calls, ["stop", "start", "stop", "start"])

    def test_success_updates_source_and_cache(self):
        """Успешное обновление меняет обе копии и оставляет прежние права файлов."""
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / name for name in ("source", "cache")]
            for path in paths:
                path.write_text("old\n")
                path.chmod(0o600)
            calls = []
            expire_filter.install(paths[0], paths[1], "new\n", calls.append)
            self.assertEqual(calls, ["stop", "start"])
            for path in paths:
                self.assertEqual(path.read_text(), "new\n")
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
