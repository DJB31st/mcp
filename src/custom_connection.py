"""
Custom asyncmy Connection and Pool classes that disable MULTI_STATEMENTS capability
and add connection validation to prevent "packet sequence number wrong" errors.

asyncmy hardcodes MULTI_STATEMENTS in Connection.__init__, but we need to disable it
for security reasons (to prevent SQL injection via multiple statements).

Additionally, we add connection health checking to prevent reusing stale connections
that have been closed by the server.
"""

import asyncio
import logging
from asyncmy.connection import Connection
from asyncmy.constants.CLIENT import MULTI_STATEMENTS, LOCAL_FILES
from asyncmy.pool import Pool
from asyncmy.contexts import _PoolContextManager, _PoolAcquireContextManager

from config import MCP_READ_ONLY

logger = logging.getLogger(__name__)


class SafeConnection(Connection):
    """
    A Connection subclass that removes the MULTI_STATEMENTS client flag.
    
    asyncmy automatically sets MULTI_STATEMENTS in __init__,
    but MariaDB's default behavior is to NOT allow multiple statements. 
    This class restores that safer default by clearing bit 16 before authentication.
    """
    
    async def connect(self):
        """
        Override connect to clear MULTI_STATEMENTS flag before authentication.
        
        The parent __init__ sets: client_flag |= MULTI_STATEMENTS
        We need to clear it before _request_authentication() is called.
        """
        # Clear the MULTI_STATEMENTS bit (bit 16 = 0x10000 = 65536) before connecting
        self._client_flag = self._client_flag & ~MULTI_STATEMENTS

        if MCP_READ_ONLY:
            self._client_flag = self._client_flag & ~LOCAL_FILES
        
        # Now proceed with normal connection
        return await super().connect()


async def safe_connect(**kwargs) -> SafeConnection:
    """
    Create a SafeConnection instead of a regular Connection.
    
    This is a drop-in replacement for asyncmy.connect() that uses SafeConnection.
    """
    conn = SafeConnection(**kwargs)
    await conn.connect()
    return conn


class SafePool(Pool):
    """
    A Pool subclass that uses SafeConnection instead of Connection
    and validates connections before serving them from the pool.
    
    This ensures all connections from the pool have MULTI_STATEMENTS disabled
    and are still alive before being used.
    """
    
    def __init__(self, minsize: int, maxsize: int, pool_recycle: int = 3600, echo: bool = False, **kwargs):
        """Initialize SafePool by calling parent Pool.__init__."""
        super().__init__(minsize=minsize, maxsize=maxsize, pool_recycle=pool_recycle, echo=echo, **kwargs)
    
    async def fill_free_pool(self, override_min: bool = False):
        """
        Override fill_free_pool to use safe_connect instead of connect.
        
        This is the method that creates new connections for the pool.
        """
        # iterate over free connections and remove timeouted ones
        free_size = len(self._free)
        n = 0
        while n < free_size:
            conn = self._free[-1]
            if conn._reader.at_eof() or conn._reader.exception():
                self._free.pop()
                conn.close()
            elif self._recycle > -1 and self._loop.time() - conn.last_usage > self._recycle:
                self._free.pop()
                conn.close()
            else:
                self._free.rotate()
            n += 1

        while self.size < self.minsize:
            self._acquiring += 1
            try:
                conn = await safe_connect(**self._conn_kwargs)
                self._free.append(conn)
                self._cond.notify()
            finally:
                self._acquiring -= 1
        if self._free:
            return

        if override_min and self.size < self.maxsize:
            self._acquiring += 1
            try:
                conn = await safe_connect(**self._conn_kwargs)
                self._free.append(conn)
                self._cond.notify()
            finally:
                self._acquiring -= 1
    
    async def _validate_connection(self, conn: Connection) -> bool:
        """
        Validate a connection by pinging it.
        
        Returns True if the connection is still alive, False otherwise.
        """
        try:
            await conn.ping()
            return True
        except Exception as e:
            logger.warning(f"Connection validation failed: {e}")
            return False
    
    def acquire(self):
        """
        Override acquire to return a context manager that validates connections.
        
        This ensures that connections from the pool are validated before use.
        """
        return _SafePoolAcquireContextManager(self, self._loop)


class _SafePoolAcquireContextManager(_PoolAcquireContextManager):
    """
    Context manager for acquiring connections from the pool with validation.
    
    This validates connections before serving them and creates new ones if validation fails.
    """
    
    async def __aenter__(self):
        """
        Acquire a connection from the pool and validate it.
        
        If validation fails, the connection is closed and a new one is created.
        """
        # Get a connection from the pool using parent logic
        pool = self._pool
        
        while True:
            async with pool.cond:
                while True:
                    await pool.fill_free_pool(True)
                    if pool._free:
                        conn = pool._free.popleft()
                        # Validate the connection
                        if await pool._validate_connection(conn):
                            # Connection is valid, use it
                            self._conn = conn
                            return conn
                        else:
                            # Connection is dead, close it and try again
                            logger.info("Discarding stale connection from pool, acquiring fresh connection")
                            conn.close()
                            # Continue the loop to get another connection
                    else:
                        # No free connections available, wait
                        await pool.cond.wait()


def create_safe_pool(
        minsize: int = 1, 
        maxsize: int = 10, 
        echo: bool = False, 
        pool_recycle: int = 3600, 
        **kwargs
):
    """
    Create a SafePool instead of a regular Pool.
    
    This is a drop-in replacement for asyncmy.create_pool() that uses SafeConnection
    and validates connections before serving them.
    """
    coro = _create_safe_pool(
        minsize=minsize, 
        maxsize=maxsize, 
        echo=echo, 
        pool_recycle=pool_recycle, 
        **kwargs
    )
    return _PoolContextManager(coro)


async def _create_safe_pool(
        minsize: int = 1, 
        maxsize: int = 10, 
        echo: bool = False, 
        pool_recycle: int = 3600, 
        **kwargs
):
    """Internal coroutine to create and initialize a SafePool."""
    pool = SafePool(
        minsize=minsize, 
        maxsize=maxsize, 
        echo=echo, 
        pool_recycle=pool_recycle, 
        **kwargs
    )
    if minsize > 0:
        async with pool.cond:
            await pool.fill_free_pool(False)
    return pool
