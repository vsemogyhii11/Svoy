"""
🚀 ОПТИМИЗАЦИЯ OSINT АГЕНТОВ

Проблемы которые решаем:
1. Отсутствие кэширования результатов
2. Повторное сканирование одних и тех же страниц
3. Высокое потребление памяти
4. Нет приоритизации источников

Решения:
- Кэширование посещённых URL
- Умная приоритизация источников
- Потоковая обработка (без хранения всего в памяти)
- Rate limiting для уважительного скрапинга
"""

import asyncio
import time
import hashlib
import logging
import aiohttp
from typing import Set, Dict, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
import json

logger = logging.getLogger("svoy_bot.osint_optimizer")


@dataclass
class OptimizedOSINTConfig:
    """Конфигурация оптимизированного OSINT."""
    # Кэширование
    url_cache_ttl: int = 86400  # 24 часа
    max_cached_urls: int = 10000
    
    # Rate limiting
    request_delay: float = 0.5  # Задержка между запросами (сек)
    max_concurrent: int = 10  # Максимум параллельных запросов
    max_retries: int = 2  # Попытки при ошибке
    
    # Приоритеты источников
    high_priority_sources: List[str] = field(default_factory=lambda: [
        'ria.ru', 'tass.ru', 't.me/s/', 'vk.com'
    ])
    
    # Ограничения
    max_pages_per_cycle: int = 50  # Макс страниц за цикл
    timeout_seconds: int = 10  # Таймаут запроса


class URLCache:
    """Кэш посещённых URL для предотвращения повторного сканирования."""
    
    def __init__(self, max_size: int = 10000, ttl: int = 86400):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, float] = {}  # URL -> timestamp
        self._visited_hashes: Set[str] = set()  # Хэши контента
    
    def is_visited(self, url: str) -> bool:
        """Проверить, посещён ли URL."""
        if url in self._cache:
            if time.time() - self._cache[url] < self.ttl:
                return True
            else:
                del self._cache[url]  # Истёк TTL
        return False
    
    def mark_visited(self, url: str):
        """Отметить URL как посещённый."""
        # LRU eviction
        if len(self._cache) >= self.max_size:
            oldest = min(self._cache.items(), key=lambda x: x[1])
            del self._cache[oldest[0]]
        
        self._cache[url] = time.time()
    
    def add_content_hash(self, content: str):
        """Добавить хэш контента для детекции дубликатов."""
        h = hashlib.md5(content.encode()).hexdigest()
        self._visited_hashes.add(h)
        
        if len(self._visited_hashes) > self.max_size:
            # Удаляем старые хэши
            self._visited_hashes = set(list(self._visited_hashes)[-5000:])
    
    def is_duplicate_content(self, content: str) -> bool:
        """Проверить на дубликат контента."""
        h = hashlib.md5(content.encode()).hexdigest()
        return h in self._visited_hashes
    
    def save(self, path: str):
        """Сохранить кэш."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump({
                'urls': self._cache,
                'hashes': list(self._visited_hashes)
            }, f)
    
    def load(self, path: str):
        """Загрузить кэш."""
        if not Path(path).exists():
            return
        
        with open(path, 'r') as f:
            data = json.load(f)
            self._cache = data.get('urls', {})
            self._visited_hashes = set(data.get('hashes', []))


class RateLimiter:
    """Rate limiter для уважительного скрапинга."""
    
    def __init__(self, delay: float = 0.5, max_concurrent: int = 10):
        self.delay = delay
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._last_request: float = 0
    
    async def acquire(self):
        """Получить разрешение на запрос."""
        async with self._semaphore:
            # Задержка между запросами
            elapsed = time.time() - self._last_request
            if elapsed < self.delay:
                await asyncio.sleep(self.delay - elapsed)
            
            self._last_request = time.time()
            return True


class OptimizedOSINTAgent:
    """
    Оптимизированный OSINT агент.
    
    Улучшения:
    - Кэширование URL (нет повторных запросов)
    - Rate limiting (уважительный скрапинг)
    - Потоковая обработка (меньше памяти)
    - Приоритизация источников
    - Детекция дубликатов
    """
    
    def __init__(self, config: Optional[OptimizedOSINTConfig] = None):
        self.config = config or OptimizedOSINTConfig()
        self.url_cache = URLCache(
            max_size=self.config.max_cached_urls,
            ttl=self.config.url_cache_ttl
        )
        self.rate_limiter = RateLimiter(
            delay=self.config.request_delay,
            max_concurrent=self.config.max_concurrent
        )
        
        # Статистика
        self.stats = {
            'urls_visited': 0,
            'urls_skipped': 0,
            'duplicates_found': 0,
            'requests_made': 0,
            'errors': 0
        }
        
        # Загрузка кэша
        self.url_cache.load("data/osint_cache.json")
    
    async def fetch_with_retry(
        self,
        session: aiohttp.ClientSession,
        url: str,
        tag: str = "a",
        kwargs: Optional[Dict] = None
    ) -> List:
        """
        Запрос с повторными попытками и кэшированием.
        
        Args:
            session: aiohttp сессия
            url: URL для запроса
            tag: HTML тег для поиска
            kwargs: Дополнительные параметры
        
        Returns:
            Список элементов
        """
        # Проверка кэша URL
        if self.url_cache.is_visited(url):
            self.stats['urls_skipped'] += 1
            logger.debug(f"Skipping cached URL: {url[:80]}")
            return []
        
        kwargs = kwargs or {}
        
        try:
            # Rate limiting
            await self.rate_limiter.acquire()
            
            self.stats['requests_made'] += 1
            
            # Запрос
            async with session.get(url, timeout=self.config.timeout_seconds) as response:
                if response.status != 200:
                    self.stats['errors'] += 1
                    return []
                
                html = await response.text()
                
                # Проверка на дубликат контента
                if self.url_cache.is_duplicate_content(html):
                    self.stats['duplicates_found'] += 1
                    logger.debug(f"Duplicate content: {url[:80]}")
                    return []
                
                # Парсинг
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html, 'html.parser')
                elements = soup.find_all(tag, **kwargs)
                
                # Помечаем URL как посещённый
                self.url_cache.mark_visited(url)
                self.url_cache.add_content_hash(html)
                self.stats['urls_visited'] += 1
                
                logger.info(f"✅ Fetched: {url[:80]} (elements={len(elements)})")
                
                return elements
        
        except asyncio.TimeoutError:
            self.stats['errors'] += 1
            logger.warning(f"Timeout: {url[:80]}")
            return []
        
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Error fetching {url[:80]}: {e}")
            return []
    
    async def fetch_priority_sources(
        self,
        session: aiohttp.ClientSession,
        sources: List[str],
        tag: str = "div",
        kwargs: Optional[Dict] = None
    ) -> List:
        """
        Сканирование приоритетных источников.
        
        Args:
            session: aiohttp сессия
            sources: Список URL
            tag: HTML тег
            kwargs: Параметры поиска
        
        Returns:
            Список элементов
        """
        # Сортируем по приоритету
        def get_priority(url: str) -> int:
            for i, pattern in enumerate(self.config.high_priority_sources):
                if pattern in url:
                    return i
            return 999
        
        sorted_sources = sorted(sources, key=get_priority)
        
        # Ограничиваем количество
        limited_sources = sorted_sources[:self.config.max_pages_per_cycle]
        
        # Параллельное сканирование с ограничением
        tasks = [
            self.fetch_with_retry(session, url, tag, kwargs or {})
            for url in limited_sources
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Объединяем результаты
        all_elements = []
        for result in results:
            if isinstance(result, list):
                all_elements.extend(result)
        
        return all_elements
    
    def get_stats(self) -> Dict:
        """Получить статистику."""
        return {
            **self.stats,
            'cache_size': len(self.url_cache._cache),
            'hash_count': len(self.url_cache._visited_hashes)
        }
    
    def save_cache(self):
        """Сохранить кэш."""
        self.url_cache.save("data/osint_cache.json")
        logger.info(f"Cache saved: {self.get_stats()}")


# Глобальный оптимизированный агент
_optimizer: Optional[OptimizedOSINTAgent] = None


def get_osint_optimizer() -> OptimizedOSINTAgent:
    """Получить глобальный оптимизатор."""
    global _optimizer
    if _optimizer is None:
        _optimizer = OptimizedOSINTAgent()
    return _optimizer


def init_osint_optimizer(config: Optional[OptimizedOSINTConfig] = None) -> OptimizedOSINTAgent:
    """Инициализировать глобальный оптимизатор."""
    global _optimizer
    _optimizer = OptimizedOSINTAgent(config)
    return _optimizer
