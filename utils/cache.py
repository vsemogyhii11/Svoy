"""
In-memory кэширование для API-запросов.

Используется для кэширования результатов внешних API-запросов:
- VirusTotal
- Google Safe Browsing
- WHOIS
- Другие внешние сервисы
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from collections import OrderedDict
import logging

log = logging.getLogger("svoy_bot.cache")


@dataclass
class CacheEntry:
    """Запись в кэше."""
    value: Any
    expires_at: float
    
    def is_expired(self) -> bool:
        """Проверка истечения срока действия."""
        return time.time() > self.expires_at


@dataclass
class CacheStats:
    """Статистика кэша."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Коэффициент попаданий в кэш."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total


class InMemoryCache:
    """
    Асинхронный in-memory кэш с TTL и LRU- eviction.
    
    Пример использования:
        cache = InMemoryCache(max_size=1000, default_ttl=3600)
        
        # Запись в кэш
        await cache.set("key", value, ttl=1800)
        
        # Чтение из кэша
        value = await cache.get("key")
        
        # Проверка наличия
        exists = await cache.exists("key")
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        """
        Инициализация кэша.
        
        Args:
            max_size: Максимальное количество записей в кэше
            default_ttl: Время жизни записи по умолчанию (секунды)
        """
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._stats = CacheStats()
        self._lock = asyncio.Lock()
        
    async def get(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Получить значение из кэша.
        
        Args:
            key: Ключ
            default: Значение по умолчанию если ключ не найден
            
        Returns:
            Значение из кэша или default
        """
        async with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats.misses += 1
                return default
            
            if entry.is_expired():
                # Удаляем истёкшую запись
                del self._cache[key]
                self._stats.evictions += 1
                self._stats.misses += 1
                log.debug(f"Cache miss (expired): {key}")
                return default
            
            # Перемещаем в конец (LRU)
            self._cache.move_to_end(key)
            self._stats.hits += 1
            log.debug(f"Cache hit: {key}")
            return entry.value
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """
        Записать значение в кэш.
        
        Args:
            key: Ключ
            value: Значение
            ttl: Время жизни в секундах (по умолчанию default_ttl)
        """
        if ttl is None:
            ttl = self._default_ttl
            
        async with self._lock:
            # Если ключ уже есть, обновляем
            if key in self._cache:
                self._cache.move_to_end(key)
            
            # Проверяем лимит размера
            while len(self._cache) >= self._max_size:
                # Удаляем oldest запись (LRU)
                self._cache.popitem(last=False)
                self._stats.evictions += 1
            
            self._cache[key] = CacheEntry(
                value=value,
                expires_at=time.time() + ttl
            )
            log.debug(f"Cache set: {key} (TTL={ttl}s)")
    
    async def delete(self, key: str) -> bool:
        """
        Удалить запись из кэша.
        
        Args:
            key: Ключ
            
        Returns:
            True если запись была удалена
        """
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    async def exists(self, key: str) -> bool:
        """
        Проверить наличие ключа в кэше (без учёта TTL).
        
        Args:
            key: Ключ
            
        Returns:
            True если ключ существует
        """
        async with self._lock:
            return key in self._cache
    
    async def clear(self) -> None:
        """Очистить весь кэш."""
        async with self._lock:
            self._cache.clear()
            log.info("Cache cleared")
    
    async def cleanup_expired(self) -> int:
        """
        Удалить все истёкшие записи.
        
        Returns:
            Количество удалённых записей
        """
        async with self._lock:
            now = time.time()
            expired_keys = [
                k for k, v in self._cache.items()
                if v.expires_at < now
            ]
            
            for key in expired_keys:
                del self._cache[key]
                self._stats.evictions += 1
            
            if expired_keys:
                log.debug(f"Cleaned up {len(expired_keys)} expired entries")
            
            return len(expired_keys)
    
    async def get_stats(self) -> CacheStats:
        """
        Получить статистику кэша.
        
        Returns:
            Статистика кэша
        """
        async with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions
            )
    
    def __len__(self) -> int:
        """Текущее количество записей в кэше."""
        return len(self._cache)
    
    async def __repr__(self) -> str:
        """Строковое представление кэша."""
        stats = await self.get_stats()
        return (
            f"InMemoryCache(size={len(self)}/{self._max_size}, "
            f"hit_rate={stats.hit_rate:.2%}, "
            f"evictions={stats.evictions})"
        )


# Глобальный экземпляр кэша для использования в приложении
_api_cache: Optional[InMemoryCache] = None


def get_cache() -> InMemoryCache:
    """
    Получить глобальный экземпляр кэша.
    
    Returns:
        Экземпляр кэша
    """
    global _api_cache
    if _api_cache is None:
        _api_cache = InMemoryCache(max_size=1000, default_ttl=3600)
    return _api_cache


def init_cache(max_size: int = 1000, default_ttl: int = 3600) -> InMemoryCache:
    """
    Инициализировать глобальный кэш.
    
    Args:
        max_size: Максимальное количество записей
        default_ttl: Время жизни по умолчанию (секунды)
        
    Returns:
        Инициализированный экземпляр кэша
    """
    global _api_cache
    _api_cache = InMemoryCache(max_size=max_size, default_ttl=default_ttl)
    log.info(f"Cache initialized (max_size={max_size}, default_ttl={default_ttl}s)")
    return _api_cache


async def cached_api_call(
    key: str,
    func: callable,
    ttl: Optional[int] = None,
    force_refresh: bool = False
) -> Any:
    """
    Декоратор-обёртка для кэширования результатов API-вызовов.
    
    Пример использования:
        result = await cached_api_call(
            "virustotal:url:abc123",
            lambda: virustotal_api.scan_url("abc123"),
            ttl=1800
        )
    
    Args:
        key: Уникальный ключ кэша
        func: Асинхронная функция для вызова
        ttl: Время жизни кэша (секунды)
        force_refresh: Игнорировать кэш, обновить принудительно
        
    Returns:
        Результат вызова функции
    """
    cache = get_cache()
    
    if not force_refresh:
        cached = await cache.get(key)
        if cached is not None:
            return cached
    
    # Вызываем функцию
    if asyncio.iscoroutinefunction(func):
        result = await func()
    else:
        result = func()
    
    # Сохраняем в кэш
    await cache.set(key, result, ttl=ttl)
    
    return result
