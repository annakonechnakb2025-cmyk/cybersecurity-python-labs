import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "Compli4nc3@Check",
    "weak",
    "Risk@Ass3ssment",
    "guest",
    "Vulner4bility@Scan",
    "temp",
    "P3netration@Test",
    "demo",
    "S3curity@Audit",
    "trial",
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"weak", "guest", "temp", "demo", "trial", "password"}

random_indices = random.sample(range(len(passwords)), 3)

for index in random_indices:
    passwords.append(passwords[index])


def analyze_password(password):
    min_length = criteria["min_length"]

    if password in forbidden_passwords or len(password) < min_length:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_special = any(not char.isalnum() for char in password)
    has_lower = any(char.islower() for char in password)

    conditions = [has_digit, has_upper, has_special, has_lower]
    passed = sum(conditions)

    if passed == 4:
        if len(password) >= min_length + 4 and passwords.count(password) == 1:
            return "Дуже сильний"
        return "Сильний"

    if passed > 1:
        return "Середній"

    return "Слабкий"


def run():
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print()

    print("-" * 45)
    print(f"{'№':<4} {'Пароль':<25} {'Результат':<15}")
    print("-" * 45)
    for number, password in enumerate(passwords, start=1):
        result = analyze_password(password)
        print(f"{number:<4} {password:<25} {result:<15}")
