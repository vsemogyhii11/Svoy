"""
Redis Cache для СВОЙ

Персистентное кэширование с поддержкой:
- Строк, чисел, списков, хэшей
- TTL (время жизни)
- Pub/Sub для уведомлений
- Блокировок (distributed locks)
"""

import json
import logging
import asyncio
from typing import Any, Optional, List, Dict
from contextlib import asynccontextmanager

try:
    import redis.asyncio as redis
except ImportError:
    import aioredis as redis

logger = logging.getLogger("svoy_bot.redis_cache")


class RedisCache:
    """Асинхронный Redis кэш."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        decode_responses: bool = True
    ):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self._redis: Optional[redis.Redis] = None
    
    async def connect(self):
        """Подключение к Redis."""
        if not self._redis:
            self._redis = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=decode_responses
            )
            logger.info(f"✅ Redis connected: {self.host}:{self.port}")
    
    async def close(self):
        """Закрытие соединения."""
        if self._redis:
            await self._redis.close()
            logger.info("Redis connection closed")
    
    async def get(self, key: str) -> Optional[Any]:
        """Получить значение."""
        await self.connect()
        value = await self._redis.get(key)
        if value:
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
        return None
    
    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None
    ) -> bool:
        """
        Установить значение.
        
        Args:
            key: Ключ
            value: Значение (сериализуется в JSON)
            expire: TTL в секундах
        
        Returns:
            True если успешно
        """
        await self.connect()
        serialized = json.dumps(value) if not isinstance(value, str) else value
        if expire:
            return await self._redis.setex(key, expire, serialized)
        else:
            return await self._redis.set(key, serialized)
    
    async def delete(self, *keys: str) -> int:
        """Удалить ключи."""
        await self.connect()
        return await self._redis.delete(*keys)
    
    async def exists(self, *keys: str) -> bool:
        """Проверить существование ключей."""
        await self.connect()
        return await self._redis.exists(*keys) > 0
    
    async def expire(self, key: str, seconds: int) -> bool:
        """Установить TTL для ключа."""
        await self.connect()
        return await self._redis.expire(key, seconds)
    
    # Списки
    async def lpush(self, key: str, *values: Any) -> int:
        """Добавить в начало списка."""
        await self.connect()
        serialized = [json.dumps(v) for v in values]
        return await self._redis.lpush(key, *serialized)
    
    async def rpush(self, key: str, *values: Any) -> int:
        """Добавить в конец списка."""
        await self.connect()
        serialized = [json.dumps(v) for v in values]
        return await self._redis.rpush(key, *serialized)
    
    async def lrange(self, key: str, start: int, end: int) -> List[Any]:
        """Получить диапазон списка."""
        await self.connect()
        items = await self._redis.lrange(key, start, end)
        return [json.loads(i) if i.startswith('{') or i.startswith('[') else i for i in items]
    
    # Хэши
    async def hset(self, name: str, key: str, value: Any) -> int:
        """Установить поле хэша."""
        await self.connect()
        serialized = json.dumps(value) if not isinstance(value, str) else value
        return await self._redis.hset(name, key, serialized)
    
    async def hget(self, name: str, key: str) -> Optional[Any]:
        """Получить поле хэша."""
        await self.connect()
        value = await self._redis.hget(name, key)
        if value:
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
        return None
    
    async def hgetall(self, name: str) -> Dict[str, Any]:
        """Получить весь хэш."""
        await self.connect()
        data = await self._redis.hgetall(name)
        return {
            k: json.loads(v) if v.startswith('{') or v.startswith('[') else v
            for k, v in data.items()
        }
    
    # Pub/Sub
    @asynccontextmanager
    async def pubsub(self):
        """Контекстный менеджер для Pub/Sub."""
        await self.connect()
        ps = self._redis.pubsub()
        try:
            yield ps
        finally:
            await ps.unsubscribe()
    
    async def publish(self, channel: str, message: Any) -> int:
        """Опубликовать сообщение."""
        await self.connect()
        serialized = json.dumps(message) if not isinstance(message, str) else message
        return await self._redis.publish(channel, serialized)
    
    # Блокировки
    @asynccontextmanager
    async def lock(self, name: str, timeout: int = 10, blocking: bool = True):
        """
        Контекстный менеджер для распределённой блокировки.
        
        Args:
            name: Имя блокировки
            timeout: Таймаут блокировки (сек)
            blocking: Блокироваться если занято
        
        Usage:
            async with cache.lock("my_lock"):
                # Критическая секция
                ...
        """
        await self.connect()
        lock = self._redis.lock(name, timeout=timeout, blocking=blocking)
        acquired = await lock.acquire()
        try:
            yield acquired
        finally:
            if acquired:
                await lock.release()
    
    # Статистика
    async def get_stats(self) -> Dict[str, Any]:
        """Получить статистику Redis."""
        await self.connect()
        info = await self._redis.info()
        return {
            'connected_clients': info.get('connected_clients', 0),
            'used_memory': info.get('used_memory_human', 'unknown'),
            'total_keys': await self._redis.dbsize(),
            'uptime_days': info.get('uptime_in_days', 0)
        }
    
    # Утилиты
    async def flushdb(self):
        """Очистить текущую базу данных."""
        await self.connect()
        return await self._redis.flushdb()
    
    async def keys(self, pattern: str = "*") -> List[str]:
        """Получить ключи по паттерну."""
        await self.connect()
        return await self._redis.keys(pattern)


# Глобальный экземпляр
_cache: Optional[RedisCache] = None


def get_redis_cache() -> RedisCache:
    """Получить глобальный Redis кэш."""
    global _cache
    if _cache is None:
        _cache = RedisCache()
    return _cache


def init_redis_cache(
    host: str = "redis",
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None
) -> RedisCache:
    """Инициализировать глобальный Redis кэш."""
    global _cache
    _cache = RedisCache(host, port, db, password)
    return _cache
