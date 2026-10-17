import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection


def get_all_categories() -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name FROM categories ORDER BY id ASC;"
        ).fetchall()
        return [dict(row) for row in rows]


def create_category(name: str) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute("INSERT INTO categories (name) VALUES (?);", (name,))
            cat_id = cursor.lastrowid
        row = conn.execute(
            "SELECT id, name FROM categories WHERE id = ?;", (cat_id,)
        ).fetchone()
        return {"id": row[0], "name": row[1]}


def delete_category(category_id: int) -> bool:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM categories WHERE id = ?;", (category_id,))
        return cursor.rowcount > 0


def get_record_by_id(record_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name AS category_name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?;
            """,
            (record_id,),
        ).fetchone()
        return dict(row) if row else None


def get_records_filtered(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        query = """
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name AS category_name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE 1=1
        """
        params: list[Any] = []

        if category_id is not None:
            query += " AND r.category_id = ?"
            params.append(category_id)
        if status is not None:
            query += " AND r.status = ?"
            params.append(status)
        if min_value is not None:
            query += " AND r.value >= ?"
            params.append(min_value)
        if q is not None:
            query += " AND instr(r.title, ?) > 0"
            params.append(q)

        query += " ORDER BY r.id ASC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def create_record(data: dict) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO records (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    data["code"],
                    data["title"],
                    data["category_id"],
                    data["value"],
                    data["status"],
                ),
            )
            rec_id = cursor.lastrowid
        return get_record_by_id(rec_id)  # type: ignore


def update_record(record_id: int, data: dict) -> dict[str, Any] | None:
    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute(
                """
                UPDATE records
                SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                WHERE id = ?;
                """,
                (
                    data["code"],
                    data["title"],
                    data["category_id"],
                    data["value"],
                    data["status"],
                    record_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
        return get_record_by_id(record_id)


def delete_record(record_id: int) -> bool:
    with closing(get_connection()) as conn, conn:
        cursor = conn.execute("DELETE FROM records WHERE id = ?;", (record_id,))
        return cursor.rowcount > 0


def create_records_bulk(records_data: list[dict]) -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        with conn:
            created_ids = []
            for data in records_data:
                cursor = conn.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (
                        data["code"],
                        data["title"],
                        data["category_id"],
                        data["value"],
                        data["status"],
                    ),
                )
                created_ids.append(cursor.lastrowid)

        result = []
        for rid in created_ids:
            rec = get_record_by_id(rid)
            if rec:
                result.append(rec)
        return result
