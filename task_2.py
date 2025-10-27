import json
import time
import math
import mmh3
import os
from tabulate import tabulate
from hyperloglog import HyperLogLog


class CustomHyperLogLog:
    """
    Реалізація алгоритму HyperLogLog взята із конспекту
    """

    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2  # Поріг для малих значень

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def load_ip_addresses(file_path):
    """
    Завантажує IP-адреси з лог-файлу, ігноруючи некоректні рядки.
    """
    ip_addresses = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line.strip())
                ip = record.get("remote_addr")
                if ip:
                    ip_addresses.append(ip)
            except json.JSONDecodeError:
                continue
    return ip_addresses


def count_unique_exact(ip_list):
    """Точний підрахунок за допомогою set."""
    start = time.time()
    unique_ips = set(ip_list)
    duration = time.time() - start
    return len(unique_ips), duration


def count_unique_custom_hll(ip_list, p=10):
    """Наближений підрахунок за допомогою реалізації HyperLogLog."""
    start = time.time()
    hll = CustomHyperLogLog(p=p)
    for ip in ip_list:
        hll.add(ip)
    duration = time.time() - start
    return round(hll.count()), duration


def count_unique_lib_hll(ip_list):
    """Підрахунок унікальних IP бібліотечною реалізацією HyperLogLog."""
    start = time.time()
    hll = HyperLogLog(0.01)  # похибка ~1%
    for ip in ip_list:
        hll.add(ip)
    duration = time.time() - start
    return len(hll), duration


def compare_methods(log_filename="lms-stage-access.log"):
    """Порівняння точного та наближеного методів."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, log_filename)

    if not os.path.exists(file_path):
        print(f" Файл {log_filename} не знайдено у директорії: {script_dir}")
        return

    print(f" Використовується файл: {file_path}")

    ip_list = load_ip_addresses(file_path)
    print(f"Загальна кількість рядків у файлі: {len(ip_list)}")

    # Порівняння методів
    exact_count, exact_time = count_unique_exact(ip_list)
    custom_hll_count, custom_hll_time = count_unique_custom_hll(ip_list, p=10)
    lib_hll_count, lib_hll_time = count_unique_lib_hll(ip_list)

    # Обчислення похибок
    custom_error = (
        abs(exact_count - custom_hll_count) / exact_count * 100 if exact_count else 0
    )
    lib_error = (
        abs(exact_count - lib_hll_count) / exact_count * 100 if exact_count else 0
    )

    # Форматований результат
    results_table = [
        ["Унікальні елементи", exact_count, custom_hll_count, lib_hll_count],
        [
            "Час виконання (сек.)",
            round(exact_time, 4),
            round(custom_hll_time, 4),
            round(lib_hll_time, 4),
        ],
        ["Похибка (%)", "-", f"{custom_error:.2f}%", f"{lib_error:.2f}%"],
    ]

    print("\n Результати порівняння:")
    print(
        tabulate(
            results_table,
            headers=[
                "Метрика",
                "Точний (set)",
                "Custom HyperLogLog",
                "Library HyperLogLog",
            ],
            tablefmt="pretty",
        )
    )


if __name__ == "__main__":
    compare_methods()