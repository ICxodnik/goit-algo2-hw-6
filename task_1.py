class BloomFilter:
    def __init__(self, size=1000, num_hashes=3):
        """Фільтр Блума з використанням одного цілого числа як бітового поля (для виконання пункту 4 про використання мінімуму пам'яті)."""
        self.size = size
        self.num_hashes = num_hashes
        self.bit_field = 0  # Усі біти спочатку 0 альтернатива із більшим використанням пам'яті [0] * size

    def _simple_hash(self, item, seed):
        """Проста детермінована хеш-функція (без криптографії, як зазначено у пункті 3). При використанні хешування я б застосував mmh3, як в конспекті, або hashlib"""
        result = 0
        for char in item:
            result = (result * seed + ord(char)) % self.size
        return result

    def _get_hashes(self, item):
        return [self._simple_hash(item, seed) for seed in range(3, 3 + self.num_hashes)]

    def add(self, item):
        """Додає елемент до фільтра."""
        if not isinstance(item, str) or not item:
            return
        for h in self._get_hashes(item):
            self.bit_field |= 1 << h  # Встановлюємо відповідний біт у 1

    def contains(self, item):
        """Перевіряє, чи може елемент бути у фільтрі."""
        if not isinstance(item, str) or not item:
            return False
        return all((self.bit_field >> h) & 1 for h in self._get_hashes(item))


def check_password_uniqueness(bloom_filter, passwords):
    results = {}
    for password in passwords:
        if not isinstance(password, str) or not password.strip():
            results[password] = "некоректний"
            continue

        if bloom_filter.contains(password):
            results[password] = "вже використаний"
        else:
            bloom_filter.add(password)
            results[password] = "унікальний"
    return results


# === Приклад використання ===
if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = [
        "password123",
        "newpassword",
        "admin123",
        "guest",
        "",
        None,
    ]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")