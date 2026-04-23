"""Tool description hash registry backed by SQLite for rug pull detection."""

from __future__ import annotations

import json
import time
from pathlib import Path

import aiosqlite

from .models import ToolSignature

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tool_registry (
    server_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    description_hash TEXT NOT NULL,
    description TEXT NOT NULL,
    parameters TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    authorized INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (server_id, tool_name)
);

CREATE TABLE IF NOT EXISTS hash_history (
    server_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    recorded_at REAL NOT NULL
);
"""


class ToolRegistry:
    """Persistent store for tool signatures, enabling rug pull detection."""

    def __init__(self, db_path: str | Path = "shieldmcp_registry.db") -> None:
        self.db_path = str(db_path)
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db = await aiosqlite.connect(self.db_path)
        await self._db.executescript(SCHEMA_SQL)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def check_tool(
        self, sig: ToolSignature
    ) -> tuple[bool, bool, str | None]:
        """Check a tool against the registry.

        Returns (is_known, has_changed, previous_hash).
        - is_known=False: tool never seen before
        - is_known=True, has_changed=False: tool unchanged
        - is_known=True, has_changed=True: RUG PULL detected
        """
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT content_hash, authorized FROM tool_registry WHERE server_id=? AND tool_name=?",
            (sig.server_id, sig.name),
        )
        row = await cursor.fetchone()

        now = time.time()
        current_hash = sig.content_hash

        if row is None:
            await self._db.execute(
                """INSERT INTO tool_registry
                   (server_id, tool_name, content_hash, description_hash, description, parameters, first_seen, last_seen, authorized)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    sig.server_id,
                    sig.name,
                    current_hash,
                    sig.description_hash,
                    sig.description,
                    json.dumps(sig.parameters),
                    now,
                    now,
                ),
            )
            await self._db.execute(
                "INSERT INTO hash_history (server_id, tool_name, content_hash, recorded_at) VALUES (?, ?, ?, ?)",
                (sig.server_id, sig.name, current_hash, now),
            )
            await self._db.commit()
            return False, False, None

        stored_hash, authorized = row

        if current_hash == stored_hash:
            await self._db.execute(
                "UPDATE tool_registry SET last_seen=? WHERE server_id=? AND tool_name=?",
                (now, sig.server_id, sig.name),
            )
            await self._db.commit()
            return True, False, stored_hash

        # Hash changed — rug pull detected
        await self._db.execute(
            "INSERT INTO hash_history (server_id, tool_name, content_hash, recorded_at) VALUES (?, ?, ?, ?)",
            (sig.server_id, sig.name, current_hash, now),
        )
        await self._db.execute(
            """UPDATE tool_registry
               SET content_hash=?, description_hash=?, description=?, parameters=?, last_seen=?, authorized=0
               WHERE server_id=? AND tool_name=?""",
            (
                current_hash,
                sig.description_hash,
                sig.description,
                json.dumps(sig.parameters),
                now,
                sig.server_id,
                sig.name,
            ),
        )
        await self._db.commit()
        return True, True, stored_hash

    async def authorize_tool(self, server_id: str, tool_name: str) -> None:
        assert self._db is not None
        await self._db.execute(
            "UPDATE tool_registry SET authorized=1 WHERE server_id=? AND tool_name=?",
            (server_id, tool_name),
        )
        await self._db.commit()

    async def is_authorized(self, server_id: str, tool_name: str) -> bool:
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT authorized FROM tool_registry WHERE server_id=? AND tool_name=?",
            (server_id, tool_name),
        )
        row = await cursor.fetchone()
        if row is None:
            return False
        return bool(row[0])

    async def get_all_tools(self, server_id: str | None = None) -> list[dict]:
        assert self._db is not None
        if server_id:
            cursor = await self._db.execute(
                "SELECT * FROM tool_registry WHERE server_id=?", (server_id,)
            )
        else:
            cursor = await self._db.execute("SELECT * FROM tool_registry")
        rows = await cursor.fetchall()
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    async def get_hash_history(self, server_id: str, tool_name: str) -> list[dict]:
        assert self._db is not None
        cursor = await self._db.execute(
            "SELECT * FROM hash_history WHERE server_id=? AND tool_name=? ORDER BY recorded_at",
            (server_id, tool_name),
        )
        rows = await cursor.fetchall()
        columns = [d[0] for d in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
