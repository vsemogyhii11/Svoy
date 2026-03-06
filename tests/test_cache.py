"""
Тесты для utils/cache.py
"""
import pytest
import asyncio
import time
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.cache import InMemoryCache, CacheEntry, CacheStats, get_cache, init_cache, cached_api_call


@pytest.fixture
def cache():
    """Фикстура с новым кэшем."""
    return InMemoryCache(max_size=100, default_ttl=60)


@pytest.fixture
def small_cache():
    """Фикстура с маленьким кэшем для тестов eviction."""
    return InMemoryCache(max_size=3, default_ttl=60)


class TestCacheEntry:
    """Тесты записи в кэше."""

    def test_entry_not_expired(self):
        """Запись не истекла."""
        entry = CacheEntry(value="test", expires_at=time.time() + 100)
        assert entry.is_expired() is False

    def test_entry_expired(self):
        """Запись истекла."""
        entry = CacheEntry(value="test", expires_at=time.time() - 10)
        assert entry.is_expired() is True


class TestInMemoryCache:
    """Тесты InMemoryCache."""

    @pytest.mark.asyncio
    async def test_set_and_get(self, cache):
        """Базовая запись и чтение."""
        await cache.set("key1", "value1")
        result = await cache.get("key1")
        assert result == "value1"

    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, cache):
        """Чтение несуществующего ключа."""
        result = await cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_with_default(self, cache):
        """Чтение с значением по умолчанию."""
        result = await cache.get("nonexistent", default="default_value")
        assert result == "default_value"

    @pytest.mark.asyncio
    async def test_ttl_expiration(self):
        """Истечение TTL."""
        cache = InMemoryCache(max_size=10, default_ttl=1)
        await cache.set("key", "value")
        
        # Сразу должно работать
        assert await cache.get("key") == "value"
        
        # Ждём истечения TTL
        await asyncio.sleep(1.1)
        
        # Должно вернуть None
        assert await cache.get("key") is None

    @pytest.mark.asyncio
    async def test_custom_ttl(self, cache):
        """Кастомный TTL."""
        await cache.set("key", "value", ttl=1)
        assert await cache.get("key") == "value"
        
        await asyncio.sleep(1.1)
        assert await cache.get("key") is None

    @pytest.mark.asyncio
    async def test_lru_eviction(self, small_cache):
        """LRU eviction при переполнении."""
        # Заполняем кэш
        await small_cache.set("key1", "value1")
        await small_cache.set("key2", "value2")
        await small_cache.set("key3", "value3")
        
        # Добавляем ещё один, должен вытесниться первый
        await small_cache.set("key4", "value4")
        
        # Первый ключ должен быть удалён
        assert await small_cache.get("key1") is None
        assert await small_cache.get("key4") == "value4"

    @pytest.mark.asyncio
    async def test_lru_order_update(self, small_cache):
        """LRU порядок обновляется при доступе."""
        await small_cache.set("key1", "value1")
        await small_cache.set("key2", "value2")
        await small_cache.set("key3", "value3")
        
        # Обращаемся к key1, он перемещается в конец
        await small_cache.get("key1")
        
        # Добавляем key4, должен вытесниться key2 (самый старый)
        await small_cache.set("key4", "value4")
        
        assert await small_cache.get("key1") == "value1"
        assert await small_cache.get("key2") is None

    @pytest.mark.asyncio
    async def test_delete(self, cache):
        """Удаление ключа."""
        await cache.set("key", "value")
        assert await cache.delete("key") is True
        assert await cache.get("key") is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, cache):
        """Удаление несуществующего ключа."""
        assert await cache.delete("nonexistent") is False

    @pytest.mark.asyncio
    async def test_exists(self, cache):
        """Проверка существования ключа."""
        await cache.set("key", "value")
        assert await cache.exists("key") is True
        assert await cache.exists("nonexistent") is False

    @pytest.mark.asyncio
    async def test_clear(self, cache):
        """Очистка кэша."""
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        
        await cache.clear()
        
        assert await cache.get("key1") is None
        assert await cache.get("key2") is None

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        """Очистка истёкших записей."""
        cache = InMemoryCache(max_size=10, default_ttl=1)
        
        await cache.set("key1", "value1")
        await cache.set("key2", "value2", ttl=100)
        
        await asyncio.sleep(1.1)
        
        removed = await cache.cleanup_expired()
        assert removed == 1
        assert await cache.get("key1") is None
        assert await cache.get("key2") == "value2"

    @pytest.mark.asyncio
    async def test_stats(self, cache):
        """Статистика кэша."""
        await cache.set("key1", "value1")
        
        # Hit
        await cache.get("key1")
        # Miss
        await cache.get("nonexistent")
        
        stats = await cache.get_stats()
        assert stats.hits == 1
        assert stats.misses == 1
        assert stats.hit_rate == 0.5

    @pytest.mark.asyncio
    async def test_len(self, cache):
        """Длина кэша."""
        assert len(cache) == 0
        
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        
        assert len(cache) == 2

    @pytest.mark.asyncio
    async def test_update_existing_key(self, cache):
        """Обновление существующего ключа."""
        await cache.set("key", "value1")
        await cache.set("key", "value2")
        
        result = await cache.get("key")
        assert result == "value2"

    @pytest.mark.asyncio
    async def test_repr(self, cache):
        """Строковое представление."""
        await cache.set("key", "value")
        repr_str = await cache.__repr__()
        assert "InMemoryCache" in repr_str


class TestGlobalCache:
    """Тесты глобального кэша."""

    def test_get_cache_creates_new(self):
        """get_cache создаёт новый кэш если нет."""
        # Сбрасываем глобальный кэш
        import utils.cache
        utils.cache._api_cache = None
        
        cache = get_cache()
        assert isinstance(cache, InMemoryCache)

    def test_init_cache(self):
        """init_cache инициализирует глобальный кэш."""
        import utils.cache
        utils.cache._api_cache = None
        
        cache = init_cache(max_size=500, default_ttl=120)
        assert cache._max_size == 500
        assert cache._default_ttl == 120
        
        # get_cache должен вернуть тот же экземпляр
        assert get_cache() is cache


class TestCachedApiCall:
    """Тесты cached_api_call."""

    @pytest.mark.asyncio
    async def test_caches_result(self):
        """Кэширование результата."""
        import utils.cache
        utils.cache._api_cache = InMemoryCache(max_size=100, default_ttl=60)
        
        call_count = 0
        
        async def api_func():
            nonlocal call_count
            call_count += 1
            return "result"
        
        # Первый вызов
        result1 = await cached_api_call("test_key", api_func, ttl=60)
        assert result1 == "result"
        assert call_count == 1
        
        # Второй вызов (должен вернуть из кэша)
        result2 = await cached_api_call("test_key", api_func, ttl=60)
        assert result2 == "result"
        assert call_count == 1  # функция не вызывалась снова

    @pytest.mark.asyncio
    async def test_force_refresh(self):
        """Принудительное обновление."""
        import utils.cache
        utils.cache._api_cache = InMemoryCache(max_size=100, default_ttl=60)
        
        call_count = 0
        
        async def api_func():
            nonlocal call_count
            call_count += 1
            return f"result_{call_count}"
        
        result1 = await cached_api_call("test_key", api_func, ttl=60)
        result2 = await cached_api_call("test_key", api_func, ttl=60, force_refresh=True)
        
        assert result1 != result2
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_sync_function(self):
        """Кэширование синхронной функции."""
        import utils.cache
        utils.cache._api_cache = InMemoryCache(max_size=100, default_ttl=60)
        
        call_count = 0
        
        def sync_func():
            nonlocal call_count
            call_count += 1
            return "sync_result"
        
        result1 = await cached_api_call("sync_key", sync_func, ttl=60)
        result2 = await cached_api_call("sync_key", sync_func, ttl=60)
        
        assert result1 == "sync_result"
        assert result2 == "sync_result"
        assert call_count == 1
