"""Проверяет разбор ответов dig без настоящих DNS-запросов.

subprocess.run подменяется функцией, возвращающей заданные A/AAAA и RCODE —
код результата DNS-запроса. Тесты не позволяют успешному IPv4 скрыть ошибку
IPv6 и отличают допустимое отсутствие AAAA от SERVFAIL. Используется unittest;
сетевые службы и файлы рабочего фильтра не изменяются.
"""

import argparse
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts/ru"))
import verify_adguard


class DNSVerificationTests(unittest.TestCase):
    """Проверки полноты результата verify_domain для обоих семейств IP."""

    def test_loopback_block_requires_explicit_compatibility_option(self):
        """Старый hosts-фильтр с 127.0.0.1 допускается только в явно выбранном режиме проверки."""
        with patch.object(
            verify_adguard.subprocess,
            "run",
            side_effect=self.dig({"A": ["127.0.0.1", "0.0.0.0"], "AAAA": ["::"]}),
        ):
            with self.assertRaises(ValueError):
                verify_adguard.verify_domain("test.example.org", True, self.args())
            args = self.args()
            args.allow_loopback_blocks = True
            self.assertTrue(verify_adguard.verify_domain("test.example.org", True, args)["blocked"])

    def test_public_address_cannot_hide_beside_loopback_block(self):
        """Режим совместимости не принимает обычный адрес рядом с локальным ответом блокировки."""
        args = self.args()
        args.allow_loopback_blocks = True
        with patch.object(
            verify_adguard.subprocess,
            "run",
            side_effect=self.dig({"A": ["127.0.0.1", "8.8.8.8"], "AAAA": ["::"]}),
        ):
            with self.assertRaises(ValueError):
                verify_adguard.verify_domain("test.example.org", True, args)

    def test_ordinary_site_cannot_resolve_to_loopback(self):
        """Публичный обычный сайт с ответом localhost не считается доступным."""
        with patch.object(
            verify_adguard.subprocess, "run", side_effect=self.dig({"A": ["127.0.0.1"], "AAAA": []})
        ):
            with self.assertRaises(ValueError):
                verify_adguard.verify_domain("test.example.org", False, self.args())

    def args(self):
        """Возвращает аргументы проверки без HTTP API, чтобы тестировать только ответы dig."""
        return argparse.Namespace(
            api_url=None, filter_id=None, dns_server="127.0.0.1", dns_port=5353
        )

    def dig(self, answers, statuses=None):
        """Создаёт подмену subprocess.run с заданными адресами и DNS-статусами отдельно для A/AAAA."""
        statuses = statuses or {"A": "NOERROR", "AAAA": "NOERROR"}

        def run(command, **kwargs):
            """Возвращает имитацию вывода dig для типа записи, найденного в переданной команде."""
            record_type = next(item for item in ["A", "AAAA"] if item in command)
            addresses = answers[record_type]
            if "+short" in command:
                text = "\n".join(addresses) + "\n"
            else:
                text = f";; ->>HEADER<<- opcode: QUERY, status: {statuses[record_type]}, id: 1\n"
                text += (
                    "\n".join(
                        f"test.example.org. 10 IN {record_type} {address}" for address in addresses
                    )
                    + "\n"
                )
            return subprocess.CompletedProcess(command, 0, text, "")

        return run

    def test_blocked_ipv4_cannot_hide_missing_ipv6_block_response(self):
        """Нулевой A при пустом AAAA недостаточен для подтверждения блокировки домена."""
        with patch.object(
            verify_adguard.subprocess, "run", side_effect=self.dig({"A": ["0.0.0.0"], "AAAA": []})
        ):
            with self.assertRaises(ValueError):
                verify_adguard.verify_domain("test.example.org", True, self.args())

    def test_successful_ipv4_cannot_hide_ipv6_servfail(self):
        """Реальный IPv4 не должен скрывать SERVFAIL в отдельном запросе AAAA."""
        with patch.object(
            verify_adguard.subprocess,
            "run",
            side_effect=self.dig(
                {"A": ["93.184.215.14"], "AAAA": []}, {"A": "NOERROR", "AAAA": "SERVFAIL"}
            ),
        ):
            with self.assertRaises(ValueError):
                verify_adguard.verify_domain("test.example.org", False, self.args())

    def test_blocking_requires_valid_null_answers_for_both_types(self):
        """Блокировка подтверждается отдельными NOERROR-ответами 0.0.0.0 и ::."""
        with patch.object(
            verify_adguard.subprocess,
            "run",
            side_effect=self.dig({"A": ["0.0.0.0"], "AAAA": ["::"]}),
        ):
            result = verify_adguard.verify_domain("test.example.org", True, self.args())
            self.assertEqual(result["address_count"], 2)

    def test_ipv4_only_site_can_return_noerror_nodata_for_aaaa(self):
        """Обычному IPv4-сайту разрешён пустой успешный AAAA при наличии реального A."""
        with patch.object(
            verify_adguard.subprocess,
            "run",
            side_effect=self.dig({"A": ["93.184.215.14"], "AAAA": []}),
        ):
            result = verify_adguard.verify_domain("test.example.org", False, self.args())
            self.assertEqual(result["address_count"], 1)


if __name__ == "__main__":
    unittest.main()
