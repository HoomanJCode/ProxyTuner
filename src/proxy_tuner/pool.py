"""Connection pool for outbound proxy connections.

Maintains a pool of reusable connections to outbound proxies,
reducing connection overhead for repeated requests.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import NamedTuple

logger = logging.getLogger("proxy_tuner.pool")


class PooledConnection(NamedTuple):
    """A connection stored in the pool."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    created_at: float
    last_used: float


@dataclass
class ConnectionPool:
    """Pool of reusable connections to a specific outbound.

    Connections are keyed by (target_host, target_port).
    Idle connections are cleaned up after a timeout.
    """

    max_size: int = 32
    max_idle_seconds: float = 60.0
    _pools: dict[str, list[PooledConnection]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _cleanup_task: asyncio.Task | None = None

    @property
    def total_connections(self) -> int:
        return sum(len(conns) for conns in self._pools.values())

    def _key(self, target_host: str, target_port: int) -> str:
        return f"{target_host}:{target_port}"

    async def acquire(self, target_host: str, target_port: int) -> PooledConnection | None:
        """Try to acquire a pooled connection.

        Returns a PooledConnection if one is available, None otherwise.
        The caller should use the connection or close it and create a new one.
        """
        key = self._key(target_host, target_port)

        async with self._lock:
            conns = self._pools.get(key, [])
            # Return the most recently used connection
            while conns:
                conn = conns.pop()
                # Check if connection is still alive
                if self._is_alive(conn):
                    logger.debug("Reusing pooled connection to %s", key)
                    return conn
                # Connection is dead, close it
                try:
                    conn.writer.close()
                    await conn.writer.wait_closed()
                except Exception:
                    pass

            return None

    async def release(
        self,
        target_host: str,
        target_port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Return a connection to the pool for reuse."""
        key = self._key(target_host, target_port)
        now = time.time()

        async with self._lock:
            conns = self._pools.setdefault(key, [])

            # Don't exceed max pool size per target
            if len(conns) >= self.max_size:
                # Drop oldest
                old = conns.pop(0)
                try:
                    old.writer.close()
                    await old.writer.wait_closed()
                except Exception:
                    pass

            conns.append(PooledConnection(
                reader=reader,
                writer=writer,
                created_at=now,
                last_used=now,
            ))
            logger.debug("Released connection to pool %s (%d total)", key, len(conns))

    def _is_alive(self, conn: PooledConnection) -> bool:
        """Check if a connection is still alive."""
        try:
            if conn.writer.is_closing():
                return False
        except (NotImplementedError, AttributeError):
            pass  # Mock transports
        # Check idle timeout
        if time.time() - conn.last_used > self.max_idle_seconds:
            return False
        return True

    async def close_all(self) -> None:
        """Close all pooled connections."""
        async with self._lock:
            for key, conns in self._pools.items():
                for conn in conns:
                    try:
                        conn.writer.close()
                        await conn.writer.wait_closed()
                    except Exception:
                        pass
            self._pools.clear()
        logger.info("All pooled connections closed")

    async def cleanup_loop(self) -> None:
        """Background task to clean up stale connections."""
        while True:
            await asyncio.sleep(30)
            async with self._lock:
                for key in list(self._pools.keys()):
                    conns = self._pools[key]
                    alive = []
                    for conn in conns:
                        if self._is_alive(conn):
                            alive.append(conn)
                        else:
                            try:
                                conn.writer.close()
                            except Exception:
                                pass
                    if alive:
                        self._pools[key] = alive
                    else:
                        del self._pools[key]

    def start_cleanup(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self.cleanup_loop())

    def stop_cleanup(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
