import json
import math
import sqlite3
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

BASE_DIR = Path(__file__).resolve().parent
SEED_PATH = BASE_DIR / "data" / "seed.json"

VALID_STATUSES = {"new", "in_progress", "done"}


def load_seed_data() -> dict:
    """Зчитати та перевірити початкові дані з JSON."""
    with SEED_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise TypeError("JSON повинен містити об'єкт.")

    if set(data) != {"categories", "records"}:
        raise ValueError("JSON повинен містити categories та records.")

    categories = data["categories"]
    records = data["records"]

    if not isinstance(categories, list) or len(categories) != 3:
        raise ValueError("Потрібно вказати рівно три категорії.")

    if not isinstance(records, list) or len(records) != 8:
        raise ValueError("Потрібно вказати рівно вісім записів.")

    category_ids = set()
    category_names = set()

    for category in categories:
        if not isinstance(category, dict):
            raise TypeError("Дані категорії мають бути об'єктом.")

        if set(category) != {"id", "name"}:
            raise ValueError("Категорія повинна містити id та name.")

        category_id = category["id"]
        name = category["name"]

        if (
            not isinstance(category_id, int)
            or isinstance(category_id, bool)
            or category_id <= 0
        ):
            raise ValueError("ID категорії має бути додатним цілим числом.")

        if not isinstance(name, str) or not 2 <= len(name.strip()) <= 40:
            raise ValueError("Назва категорії має містити від 2 до 40 символів.")

        if category_id in category_ids:
            raise ValueError(f"ID категорії повторюється: {category_id}")

        if name in category_names:
            raise ValueError(f"Назва категорії повторюється: {name}")

        category_ids.add(category_id)
        category_names.add(name)

    codes = set()

    for record in records:
        if not isinstance(record, dict):
            raise TypeError("Дані запису мають бути об'єктом.")

        required_fields = {
            "code",
            "title",
            "category_id",
            "value",
            "status",
        }

        if set(record) != required_fields:
            raise ValueError(
                "Кожен запис повинен містити code, title, category_id, value та status."
            )

        code = record["code"]
        title = record["title"]
        category_id = record["category_id"]
        value = record["value"]
        record_status = record["status"]

        if not isinstance(code, str) or not 3 <= len(code.strip()) <= 40:
            raise ValueError("Код запису має містити від 3 до 40 символів.")

        if code in codes:
            raise ValueError(f"Код запису повторюється: {code}")

        codes.add(code)

        if not isinstance(title, str) or not 3 <= len(title.strip()) <= 120:
            raise ValueError(f"Некоректна назва запису: {code}")

        if (
            not isinstance(category_id, int)
            or isinstance(category_id, bool)
            or category_id not in category_ids
        ):
            raise ValueError(f"Некоректна категорія запису: {code}")

        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or not 0 <= value <= 10
        ):
            raise ValueError(f"Оцінка запису {code} має бути від 0 до 10.")

        if not isinstance(record_status, str) or record_status not in VALID_STATUSES:
            raise ValueError(f"Некоректний статус запису: {code}")

    return data


def seed_database() -> None:
    """Заповнити порожню базу даних початковими даними."""
    data = load_seed_data()
    initialize_database()

    with closing(get_connection()) as connection:
        categories_count = connection.execute(
            "SELECT COUNT(*) FROM categories;"
        ).fetchone()[0]

        records_count = connection.execute("SELECT COUNT(*) FROM records;").fetchone()[
            0
        ]

        if categories_count > 0 or records_count > 0:
            print("База вже містить дані. Повторне заповнення пропущено.")
            return

        try:
            connection.execute("BEGIN")

            for category in data["categories"]:
                connection.execute(
                    """
                    INSERT INTO categories (id, name)
                    VALUES (?, ?);
                    """,
                    (category["id"], category["name"]),
                )

            for record in data["records"]:
                connection.execute(
                    """
                    INSERT INTO records
                        (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (
                        record["code"],
                        record["title"],
                        record["category_id"],
                        record["value"],
                        record["status"],
                    ),
                )

            connection.commit()
            print("Базу успішно заповнено: 3 категорії та 8 записів.")

        except sqlite3.Error:
            connection.rollback()
            raise


if __name__ == "__main__":
    try:
        seed_database()
    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        sqlite3.Error,
    ) as error:
        print(f"Помилка початкового заповнення: {error}")
