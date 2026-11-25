"""轻量 SQLite 数据库初始化。"""

import os
import sqlite3


DB_PATH = os.environ.get(
    "ECOM_DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "ecommerce.db"),
)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount REAL,
            title TEXT
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL
        );
        """
    )
    conn.commit()
    conn.close()

    seed_data()


def seed_data() -> None:
    """写入固定的演示数据，保证 SQL 布尔注入可对比。"""
    conn = get_connection()
    existing = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    if existing == 0:
        conn.executescript(
            """
            INSERT INTO users (id, username, password, role) VALUES
                (1, 'admin', 'e10adc3949ba59abbe56e057f20f883e', 'admin'),
                (2, 'alice', '25f9e794323b453885f5181f1b624d0b', 'user');
            INSERT INTO orders (id, user_id, amount, title) VALUES
                (1, 1, 100.0, 'admin order 1'),
                (2, 2, 200.0, 'alice order 2');
            INSERT INTO products (id, name, price) VALUES
                (1, 'security scanner', 99.0),
                (2, 'web proxy', 199.0);
            """
        )
        conn.commit()
    conn.close()
