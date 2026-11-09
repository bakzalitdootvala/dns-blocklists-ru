"""Проверяет синхронизацию maintainer через имитацию GitHub API.

Каждый сценарий передаёт synchronize() собственную функцию api вместо gh.
Проверяются fast-forward, отсутствие лишней записи, отказ при расхождении
истории и повторное чтение результата. Настоящих GitHub-запросов и Git-записей нет.
Запуск: python3 -m unittest discover -s tests -p test_sync.py -v.
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts/ru"))
try:
    import sync_upstream
except ModuleNotFoundError:
    sync_upstream = None


class SyncTests(unittest.TestCase):
    """Проверки переходов состояния удалённой ветки на управляемых ответах API."""

    def setUp(self):
        """Проверяет наличие sync_upstream перед сценарием."""
        self.assertIsNotNone(sync_upstream, "Модуль синхронизации должен существовать")

    def test_fast_forward_advances_actual_ref(self):
        """Допустимое продолжение истории меняет SHA один раз и обязательно использует force=False."""
        state = {"sha": "a" * 40, "writes": 0}

        def api(method, endpoint, fields=None):
            """Имитирует чтение веток, сравнение истории и запись SHA с проверкой запрета force."""
            if endpoint.startswith("repos/mullvad/"):
                return {"object": {"sha": "b" * 40}}
            if "/compare/" in endpoint:
                return {"status": "ahead", "merge_base_commit": {"sha": "a" * 40}}
            if method == "PATCH":
                if fields != {"sha": "b" * 40, "force": False}:
                    raise AssertionError("Разрешено только безопасное продвижение")
                state["sha"] = fields["sha"]
                state["writes"] += 1
            return {"object": {"sha": state["sha"]}}

        result = sync_upstream.synchronize(api)
        self.assertEqual(state["sha"], "b" * 40)
        self.assertEqual(state["writes"], 1)
        self.assertEqual(result, "b" * 40)

    def test_noop_does_not_write(self):
        """Совпавшие SHA приводят только к чтению API, без записи ветки."""

        def api(method, endpoint, fields=None):
            """Возвращает одинаковые SHA и отклоняет любой метод кроме GET."""
            self.assertEqual(method, "GET")
            return {"object": {"sha": "b" * 40}}

        self.assertEqual(sync_upstream.synchronize(api), "b" * 40)

    def test_divergence_is_not_forced(self):
        """Разошедшаяся история должна завершить синхронизацию ошибкой без записи."""

        def api(method, endpoint, fields=None):
            """Имитирует разные ветки с третьим общим предком и разрешает только чтение."""
            self.assertEqual(method, "GET")
            if "/compare/" in endpoint:
                return {"status": "diverged", "merge_base_commit": {"sha": "c" * 40}}
            return {"object": {"sha": ("b" if endpoint.startswith("repos/mullvad/") else "a") * 40}}

        with self.assertRaises(ValueError):
            sync_upstream.synchronize(api)

    def test_failed_update_is_not_reported_as_success(self):
        """Если повторное чтение не подтверждает целевой SHA, синхронизация обязана сообщить ошибку."""

        def api(method, endpoint, fields=None):
            """Принимает вызов записи, но оставляет прежний SHA, имитируя неподтверждённое обновление."""
            if "/compare/" in endpoint:
                return {"status": "ahead", "merge_base_commit": {"sha": "a" * 40}}
            return {"object": {"sha": ("b" if endpoint.startswith("repos/mullvad/") else "a") * 40}}

        with self.assertRaises(ValueError):
            sync_upstream.synchronize(api)


if __name__ == "__main__":
    unittest.main()
