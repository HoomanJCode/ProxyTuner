"""Unit tests for connection pool."""

from __future__ import annotations

import asyncio
import time

import pytest

from proxy_tuner.pool import ConnectionPool


class TestConnectionPool:
    def test_initial_state(self) -> None:
        pool = ConnectionPool()
        assert pool.total_connections == 0

    def test_acquire_empty_pool(self) -> None:
        async def _test() -> None:
            pool = ConnectionPool()
            conn = await pool.acquire("example.com", 80)
            assert conn is None

        asyncio.run(_test())

    def test_release_and_acquire(self) -> None:
        async def _test() -> None:
            pool = ConnectionPool()

            # Create mock reader/writer
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            transport = asyncio.Transport()
            writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_event_loop())

            await pool.release("example.com", 80, reader, writer)
            assert pool.total_connections == 1

            # Acquire should return the same connection
            conn = await pool.acquire("example.com", 80)
            assert conn is not None
            assert conn.reader is reader

            # Pool should be empty now
            assert pool.total_connections == 0

        asyncio.run(_test())

    def test_different_targets_separate_pools(self) -> None:
        async def _test() -> None:
            pool = ConnectionPool()

            reader1 = asyncio.StreamReader()
            protocol1 = asyncio.StreamReaderProtocol(reader1)
            transport1 = asyncio.Transport()
            writer1 = asyncio.StreamWriter(transport1, protocol1, reader1, asyncio.get_event_loop())

            reader2 = asyncio.StreamReader()
            protocol2 = asyncio.StreamReaderProtocol(reader2)
            transport2 = asyncio.Transport()
            writer2 = asyncio.StreamWriter(transport2, protocol2, reader2, asyncio.get_event_loop())

            await pool.release("host1.com", 80, reader1, writer1)
            await pool.release("host2.com", 80, reader2, writer2)
            assert pool.total_connections == 2

            conn1 = await pool.acquire("host1.com", 80)
            assert conn1 is not None
            assert conn1.reader is reader1
            assert pool.total_connections == 1

        asyncio.run(_test())

    def test_close_all(self) -> None:
        async def _test() -> None:
            pool = ConnectionPool()

            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            transport = asyncio.Transport()
            writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_event_loop())

            await pool.release("example.com", 80, reader, writer)
            assert pool.total_connections == 1

            await pool.close_all()
            assert pool.total_connections == 0

        asyncio.run(_test())

    def test_expired_connections_removed(self) -> None:
        async def _test() -> None:
            pool = ConnectionPool(max_idle_seconds=0)
            now = time.time()
            from proxy_tuner.pool import PooledConnection

            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            transport = asyncio.Transport()
            writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_event_loop())

            conn = PooledConnection(reader=reader, writer=writer, created_at=now - 100, last_used=now - 100)
            assert pool._is_alive(conn) is False

        asyncio.run(_test())

    def test_max_size_enforced(self) -> None:
        async def _test() -> None:
            pool = ConnectionPool(max_size=2)

            for i in range(4):
                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                transport = asyncio.Transport()
                writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_event_loop())
                await pool.release("example.com", 80, reader, writer)

            # Should only keep max_size connections
            assert pool.total_connections <= 2

        asyncio.run(_test())
