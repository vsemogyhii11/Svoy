"""
Асинхронный слой базы данных (SQLite).

Таблицы:
- reports: жалобы на мошеннические номера
- checks: история проверок
- users: статистика пользователей
- votes: голосования за/против номеров
"""

import aiosqlite
import json
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger("svoy_bot.db")

DB_PATH = Path(__file__).parent / "data" / "svoy.db"

# ─── SQL-схема ───

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    type TEXT DEFAULT 'scam',
    description TEXT,
    reports_count INTEGER DEFAULT 1,
    reported_by INTEGER,
    first_report TEXT,
    last_report TEXT,
    UNIQUE(phone)
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message_text TEXT,
    risk_score REAL,
    risk_level TEXT,
    links_found INTEGER DEFAULT 0,
    phones_found INTEGER DEFAULT 0,
    has_threat INTEGER DEFAULT 0,
    checked_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    checks_count INTEGER DEFAULT 0,
    reports_count INTEGER DEFAULT 0,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    language TEXT DEFAULT 'ru'
);

CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    vote TEXT NOT NULL CHECK(vote IN ('scam', 'legit')),
    voted_at TEXT DEFAULT (datetime('now')),
    UNIQUE(phone, user_id)
);

CREATE TABLE IF NOT EXISTS reported_users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    risk_level TEXT DEFAULT 'suspicious',
    reports INTEGER DEFAULT 1,
    reported_by INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_reports_phone ON reports(phone);
CREATE INDEX IF NOT EXISTS idx_checks_user ON checks(user_id);
CREATE INDEX IF NOT EXISTS idx_reviews_phone ON votes(phone);

CREATE TABLE IF NOT EXISTS visited_urls (
    url TEXT PRIMARY KEY,
    visited_at TEXT DEFAULT (datetime('now'))
);
"""


class Database:
    """Асинхронный менеджер базы данных."""

    def __init__(self, db_path: str | Path = DB_PATH):
        self.db_path = str(db_path)
        self._db: aiosqlite.Connection | None = None

    async def connect(self):
        """Подключение и создание таблиц."""
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.executescript(SCHEMA)
        await self._db.commit()
        log.info(f"Database connected: {self.db_path} (WAL mode enabled)")

    async def close(self):
        """Закрытие соединения."""
        if self._db:
            await self._db.close()
            log.info("Database closed")

    # ─── Reports (мошеннические номера) ───

    async def get_phone_report(self, phone: str) -> dict | None:
        """Найти номер в базе жалоб."""
        async with self._db.execute(
            "SELECT * FROM reports WHERE phone = ?", (phone,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def add_phone_report(
        self, phone: str, type_: str, description: str, reported_by: int
    ) -> bool:
        """Добавить или обновить жалобу на номер."""
        now = datetime.now().isoformat()
        existing = await self.get_phone_report(phone)

        if existing:
            await self._db.execute(
                """UPDATE reports 
                   SET reports_count = reports_count + 1, 
                       last_report = ?
                   WHERE phone = ?""",
                (now, phone),
            )
        else:
            await self._db.execute(
                """INSERT INTO reports (phone, type, description, reported_by, 
                                       first_report, last_report)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (phone, type_, description, reported_by, now, now),
            )
        await self._db.commit()
        return True

    async def get_all_reports(self) -> list[dict]:
        """Все номера в базе жалоб."""
        async with self._db.execute(
            "SELECT * FROM reports ORDER BY reports_count DESC"
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_reports_count(self) -> int:
        """Количество номеров в базе."""
        async with self._db.execute("SELECT COUNT(*) FROM reports") as cursor:
            row = await cursor.fetchone()
            return row[0]

    # ─── Checks (история проверок) ───

    async def log_check(
        self,
        user_id: int,
        message_text: str,
        risk_score: float,
        risk_level: str,
        links_found: int = 0,
        phones_found: int = 0,
        has_threat: bool = False,
    ):
        """Записать проверку в историю."""
        await self._db.execute(
            """INSERT INTO checks 
               (user_id, message_text, risk_score, risk_level, 
                links_found, phones_found, has_threat)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                message_text[:500],  # ограничиваем длину
                risk_score,
                risk_level,
                links_found,
                phones_found,
                int(has_threat),
            ),
        )
        await self._db.commit()

    async def get_stats(self) -> dict:
        """Общая статистика."""
        stats = {}
        async with self._db.execute("SELECT COUNT(*) FROM checks") as c:
            stats["total_checks"] = (await c.fetchone())[0]
        async with self._db.execute(
            "SELECT COUNT(*) FROM checks WHERE has_threat = 1"
        ) as c:
            stats["threats_found"] = (await c.fetchone())[0]
        async with self._db.execute("SELECT COUNT(*) FROM reports") as c:
            stats["phones_in_db"] = (await c.fetchone())[0]
        async with self._db.execute("SELECT COUNT(DISTINCT user_id) FROM users") as c:
            stats["unique_users"] = (await c.fetchone())[0]
        return stats

    # ─── Users ───

    async def upsert_user(
        self, user_id: int, username: str = None, first_name: str = None
    ):
        """Создать/обновить пользователя."""
        now = datetime.now().isoformat()
        await self._db.execute(
            """INSERT INTO users (user_id, username, first_name, last_seen)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                   username = excluded.username,
                   first_name = excluded.first_name,
                   last_seen = excluded.last_seen,
                   checks_count = checks_count + 1""",
            (user_id, username, first_name, now),
        )
        await self._db.commit()

    # ─── Votes (голосования) ───

    async def add_vote(self, phone: str, user_id: int, vote: str) -> bool:
        """Добавить голос. Возвращает False если уже голосовал."""
        try:
            await self._db.execute(
                "INSERT INTO votes (phone, user_id, vote) VALUES (?, ?, ?)",
                (phone, user_id, vote),
            )
            await self._db.commit()

            # Автодобавление в reports при 3+ голосах "scam"
            async with self._db.execute(
                "SELECT COUNT(*) FROM votes WHERE phone = ? AND vote = 'scam'",
                (phone,),
            ) as c:
                scam_votes = (await c.fetchone())[0]

            if scam_votes >= 3:
                existing = await self.get_phone_report(phone)
                if not existing:
                    await self.add_phone_report(
                        phone, "scam", 
                        f"Автодобавлен: {scam_votes} голосов от пользователей",
                        0
                    )
                    log.info(f"Phone {phone} auto-added to reports ({scam_votes} votes)")

            return True
        except aiosqlite.IntegrityError:
            return False  # уже голосовал

    async def get_vote_counts(self, phone: str) -> dict:
        """Количество голосов за номер."""
        result = {"scam": 0, "legit": 0}
        async with self._db.execute(
            "SELECT vote, COUNT(*) FROM votes WHERE phone = ? GROUP BY vote",
            (phone,),
        ) as c:
            async for row in c:
                result[row[0]] = row[1]
        return result

    # ─── OSINT Кэш ───

    async def is_url_visited(self, url: str) -> bool:
        """Проверить, был ли URL уже обработан."""
        async with self._db.execute("SELECT 1 FROM visited_urls WHERE url = ?", (url,)) as cursor:
            return await cursor.fetchone() is not None

    async def mark_url_visited(self, url: str):
        """Отметить URL как обработанный."""
        try:
            await self._db.execute("INSERT OR IGNORE INTO visited_urls (url) VALUES (?)", (url,))
            await self._db.commit()
        except Exception as e:
            log.warning(f"Failed to mark url visited: {e}")

    # ─── Миграция из JSON ───

    async def migrate_from_json(self, json_path: str = "data/scam_phones.json"):
        """Импорт данных из старого JSON-файла."""
        p = Path(json_path)
        if not p.exists():
            p = Path(__file__).parent / json_path
        if not p.exists():
            log.info("No JSON file to migrate")
            return

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        numbers = data.get("numbers", {})
        migrated = 0
        for phone, info in numbers.items():
            existing = await self.get_phone_report(phone)
            if not existing:
                await self._db.execute(
                    """INSERT INTO reports (phone, type, description, reports_count, 
                                           reported_by, first_report, last_report)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        phone,
                        info.get("type", "scam"),
                        info.get("description", "Импортировано из JSON"),
                        info.get("reports", 1),
                        info.get("reported_by", 0),
                        info.get("first_report", datetime.now().isoformat()),
                        info.get("last_report", datetime.now().isoformat()),
                    ),
                )
                migrated += 1

        await self._db.commit()
        log.info(f"Migrated {migrated} phone records from JSON to SQLite")
