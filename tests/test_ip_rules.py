"""Проверяет математическое соответствие CIDR и регулярных выражений.

Сравнивает результат regex с независимым членством адреса в ipaddress.ip_network.
Покрывает длины префиксов IPv4 1..32 и IPv6 1..128, границы и соседей, сжатие ::,
отсутствие совпадений внутри hostname и ограниченный размер результата.
Псевдослучайные примеры воспроизводимы за счёт фиксированных seed.
Файлы и сеть не используются; реальный AdGuard проверяет test_ip_response.py.
"""

import ipaddress
import pathlib
import random
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/ru"))
try:
    import ip_rules
except ModuleNotFoundError:
    ip_rules = None


class IPRegexTests(unittest.TestCase):
    """Проверки диапазонов чисел и сетей независимо от реализации DNS-сервера."""

    def setUp(self):
        """Проверяет наличие модуля компилятора IP-правил."""
        self.assertIsNotNone(ip_rules, "Компилятор IP-правил должен существовать")

    def test_decimal_octet_ranges_exhaustively(self):
        """Для выбранных интервалов перебирает все 0..255 и отклоняет запись с ведущими нулями."""
        for low, high in [(0, 255), (0, 0), (8, 12), (16, 31), (100, 199), (128, 255), (250, 255)]:
            pattern = re.compile("^" + ip_rules.number_pattern(low, high, 10) + "$")
            for value in range(256):
                self.assertEqual(
                    bool(pattern.fullmatch(str(value))), low <= value <= high, (low, high, value)
                )
            self.assertFalse(pattern.fullmatch("001"))

    def test_hexadecimal_ranges_exhaustively(self):
        """Для выбранных интервалов перебирает все 0..65535 и сверяет границы шестнадцатеричного regex."""
        for low, high in [(0, 65535), (0, 15), (256, 511), (32768, 65535), (0x1230, 0x123F)]:
            pattern = re.compile("^" + ip_rules.number_pattern(low, high, 16) + "$")
            for value in range(65536):
                self.assertEqual(
                    bool(pattern.fullmatch(format(value, "x"))),
                    low <= value <= high,
                    (low, high, value),
                )

    def test_ipv4_prefixes_and_adjacent_addresses(self):
        """Проверяет IPv4-префиксы, соседей и якоря, запрещающие совпадение с IP внутри имени."""
        randomizer = random.Random(827)
        for prefix in range(1, 33):
            network = ipaddress.ip_network(f"81.92.173.219/{prefix}", strict=False)
            pattern = re.compile(ip_rules.network_pattern(network))
            values = [int(network.network_address), int(network.broadcast_address)]
            values.extend(randomizer.randrange(2**32) for _ in range(30))
            values.extend(v for v in [values[0] - 1, values[1] + 1] if 0 <= v < 2**32)
            for value in values:
                address = ipaddress.IPv4Address(value)
                self.assertEqual(
                    bool(pattern.fullmatch(str(address))), address in network, (network, address)
                )
            self.assertFalse(pattern.search(str(network.network_address) + ".example.org"))
            self.assertFalse(pattern.search("prefix-" + str(network.network_address)))

    def test_ipv6_all_prefixes_compression_and_boundaries(self):
        """Проверяет IPv6-префиксы и :: на границах и выборке адресов, ограничивает размер regex."""
        randomizer = random.Random(891)
        for base in ["2a00:1234:8000::ff", "2001:0:12::3", "::1"]:
            for prefix in range(1, 129):
                network = ipaddress.ip_network(f"{base}/{prefix}", strict=False)
                expression = ip_rules.network_pattern(network)
                self.assertLess(len(expression), 64000)
                pattern = re.compile(expression)
                lo, hi = int(network.network_address), int(network.broadcast_address)
                values = [lo, hi, (lo + hi) // 2]
                values.extend(randomizer.randint(lo, hi) for _ in range(8))
                values.extend(randomizer.randrange(2**128) for _ in range(8))
                values.extend(v for v in [lo - 1, hi + 1] if 0 <= v < 2**128)
                for value in values:
                    address = ipaddress.IPv6Address(value)
                    self.assertEqual(
                        bool(pattern.fullmatch(str(address))),
                        address in network,
                        (network, address),
                    )

    def test_compiled_lines_do_not_expand_networks_to_addresses(self):
        """Три сети дают три правила, одиночный IP имеет |якоря|, непубличная сеть отвергается."""
        lines = ip_rules.compile_networks(["8.8.8.8/32", "81.92.0.0/16", "2a03:1230::/29"])
        self.assertEqual(len(lines), 3)
        self.assertIn("|8.8.8.8|", lines)
        self.assertTrue(any(line.startswith("/^") for line in lines))
        with self.assertRaises(ValueError):
            ip_rules.compile_networks(["10.0.0.0/8"])


if __name__ == "__main__":
    unittest.main()
