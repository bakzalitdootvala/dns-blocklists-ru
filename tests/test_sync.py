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

    def test_ancestry_uses_commit_parents_without_generating_diff(self):
        """Большие файлы не мешают проверке родства: читаются parents, compare не вызывается."""
        calls = []

        def api(method, endpoint, fields=None):
            """Возвращает цепочку из двух коммитов и запрещает запрос тяжёлого diff."""
            calls.append(endpoint)
            self.assertEqual(method, "GET")
            self.assertNotIn("/compare/", endpoint)
            self.assertEqual(endpoint, "repos/mullvad/dns-blocklists/git/commits/" + "b" * 40)
            return {"parents": [{"sha": "a" * 40}]}

        self.assertTrue(sync_upstream.is_ancestor(api, "a" * 40, "b" * 40))
        self.assertEqual(len(calls), 1)

    def test_merge_parents_and_traversal_limit(self):
        """Родство во второй ветви merge учитывается, бесконечная история останавливает обход."""

        def merged(method, endpoint, fields=None):
            """Даёт два разных родителя с искомым current во второй ветви."""
            return {"parents": [{"sha": "c" * 40}, {"sha": "a" * 40}]}

        self.assertTrue(sync_upstream.is_ancestor(merged, "a" * 40, "b" * 40))
        calls = []

        def endless(method, endpoint, fields=None):
            """Порождает уникального предка для проверки ограниченного числа запросов."""
            calls.append(endpoint)
            return {"parents": [{"sha": f"{len(calls):040x}"}]}

        with self.assertRaisesRegex(ValueError, "128"):
            sync_upstream.is_ancestor(endless, "a" * 40, "b" * 40)
        self.assertEqual(len(calls), 128)

    def test_fast_forward_advances_actual_ref(self):
        """Допустимое продолжение истории меняет SHA один раз и обязательно использует force=False."""
        state = {"sha": "a" * 40, "writes": 0}

        def api(method, endpoint, fields=None):
            """Имитирует чтение веток, сравнение истории и запись SHA с проверкой запрета force."""
            if "/git/commits/" in endpoint:
                return {"parents": [{"sha": "a" * 40}]}
            if endpoint.startswith("repos/mullvad/"):
                return {"object": {"sha": "b" * 40}}
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
            if "/git/commits/" in endpoint:
                return {"parents": []}
            return {"object": {"sha": ("b" if endpoint.startswith("repos/mullvad/") else "a") * 40}}

        with self.assertRaises(ValueError):
            sync_upstream.synchronize(api)

    def test_failed_update_is_not_reported_as_success(self):
        """Если повторное чтение не подтверждает целевой SHA, синхронизация обязана сообщить ошибку."""

        def api(method, endpoint, fields=None):
            """Принимает вызов записи, но оставляет прежний SHA, имитируя неподтверждённое обновление."""
            if "/git/commits/" in endpoint:
                return {"parents": [{"sha": "a" * 40}]}
            return {"object": {"sha": ("b" if endpoint.startswith("repos/mullvad/") else "a") * 40}}

        with self.assertRaises(ValueError):
            sync_upstream.synchronize(api)


if __name__ == "__main__":
    unittest.main()
