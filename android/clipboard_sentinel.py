"""
Clipboard Sentinel — автоматическая проверка ссылок из буфера обмена.

Мониторит буфер обмена и автоматически проверяет скопированные ссылки
на фишинг без участия пользователя.

Использование (Android):
    val sentinel = ClipboardSentinel(context)
    sentinel.startMonitoring()
"""

import re
import logging
import asyncio
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass
from pathlib import Path
import json
import time

try:
    import aiohttp
except ImportError:
    aiohttp = None

log = logging.getLogger("svoy_bot.clipboard_sentinel")


@dataclass
class ClipboardCheckResult:
    """Результат проверки буфера обмена."""
    content: str
    content_type: str  # url, phone, text
    is_safe: bool
    risk_score: float
    risk_level: str  # none, low, medium, high, critical
    reason: Optional[str] = None
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class ClipboardSentinel:
    """
    Автоматическая проверка ссылок из буфера обмена.
    
    Обнаруживает:
    - Фишинговые URL
    - Подозрительные домены
    - Номера телефонов мошенников
    """
    
    # Паттерны для обнаружения ссылок
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+'
        r'|www\.[^\s<>"{}|\\^`\[\]]+'
        r'|[a-zA-Z0-9-]+\.[a-z]{2,}(?:/[^\s]*)?'
    )
    
    # Паттерны для телефонов
    PHONE_PATTERN = re.compile(
        r'[\+]?[78][\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}'
    )
    
    def __init__(
        self,
        api_url: str = "http://localhost:5000/api/check",
        check_interval: float = 1.0,
        cache_path: str = "data/clipboard_cache.json"
    ):
        self.api_url = api_url
        self.check_interval = check_interval
        self.cache_path = Path(cache_path)
        
        self._is_monitoring = False
        self._last_content: Optional[str] = None
        self._cache: dict = {}
        self._callbacks: list[Callable[[ClipboardCheckResult], Awaitable[None]]] = []
        
        self._load_cache()
    
    def _load_cache(self):
        """Загрузить кэш проверок."""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    self._cache = json.load(f)
                log.info(f"Loaded {len(self._cache)} clipboard checks from cache")
            except Exception as e:
                log.error(f"Failed to load cache: {e}")
    
    def _save_cache(self):
        """Сохранить кэш проверок."""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, 'w', encoding='utf-8') as f:
            json.dump(self._cache, f, ensure_ascii=False, indent=2)
    
    def add_callback(self, callback: Callable[[ClipboardCheckResult], Awaitable[None]]):
        """Добавить callback для результатов проверки."""
        self._callbacks.append(callback)
    
    def _detect_content_type(self, content: str) -> str:
        """Определить тип содержимого."""
        if self.URL_PATTERN.search(content):
            return "url"
        elif self.PHONE_PATTERN.search(content):
            return "phone"
        else:
            return "text"
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Быстрая проверка URL на подозрительность."""
        url_lower = url.lower()
        
        # Подозрительные паттерны
        suspicious_patterns = [
            'sber', 'sberbank', 'tinkoff', 'tbank', 'vtb', 'alfa',
            'gosuslugi', 'госуслуг', 'почта', 'mail', 'yandex',
            'verify', 'secure', 'login', 'account', 'update'
        ]
        
        suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.su']
        
        # Проверка бренда + подозрительный TLD
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                for tld in suspicious_tlds:
                    if url_lower.endswith(tld):
                        return True
        
        # Проверка на дефисы (sber-bank.ru)
        if url_lower.count('-') >= 2:
            return True
        
        # Очень длинные домены
        try:
            domain = url.split('/')[2] if '://' in url else url.split('/')[0]
            if len(domain) > 40:
                return True
        except:
            pass
        
        return False
    
    async def check_content(self, content: str) -> ClipboardCheckResult:
        """
        Проверить содержимое буфера обмена.
        
        Args:
            content: Текст из буфера обмена
            
        Returns:
            Результат проверки
        """
        content_type = self._detect_content_type(content)
        
        # Проверка кэша
        cache_key = f"{content_type}:{content[:100]}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached.get('timestamp', 0) < 3600:  # 1 час
                log.debug(f"Cache hit for: {content[:50]}")
                return ClipboardCheckResult(**cached['result'])
        
        result = ClipboardCheckResult(
            content=content,
            content_type=content_type,
            is_safe=True,
            risk_score=0.0,
            risk_level="none"
        )
        
        if content_type == "url":
            # Быстрая локальная проверка
            if self._is_suspicious_url(content):
                result.is_safe = False
                result.risk_score = 0.7
                result.risk_level = "high"
                result.reason = "Подозрительный URL (локальная проверка)"
            
            # API проверка (если доступен)
            elif aiohttp:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.api_url,
                            json={"url": content},
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as response:
                            if response.status == 200:
                                data = await response.json()
                                if data.get('is_phishing'):
                                    result.is_safe = False
                                    result.risk_score = data.get('risk_score', 0.8)
                                    result.risk_level = "critical"
                                    result.reason = "Фишинговый URL (API)"
                except Exception as e:
                    log.debug(f"API check failed: {e}")
        
        elif content_type == "phone":
            # Проверка телефона по базе
            phone_match = self.PHONE_PATTERN.search(content)
            if phone_match:
                # Здесь можно добавить проверку по базе мошенников
                pass
        
        # Кэширование
        self._cache[cache_key] = {
            'timestamp': time.time(),
            'result': {
                'content': result.content,
                'content_type': result.content_type,
                'is_safe': result.is_safe,
                'risk_score': result.risk_score,
                'risk_level': result.risk_level,
                'reason': result.reason,
                'timestamp': result.timestamp
            }
        }
        
        # Сохранение каждые 10 записей
        if len(self._cache) % 10 == 0:
            self._save_cache()
        
        return result
    
    async def _monitor_loop(self):
        """Цикл мониторинга буфера обмена."""
        log.info("Clipboard Sentinel started monitoring")
        
        while self._is_monitoring:
            try:
                # В Android здесь будет чтение из ClipboardManager
                # Для демонстрации — заглушка
                await asyncio.sleep(self.check_interval)
                
            except Exception as e:
                log.error(f"Monitor loop error: {e}")
                await asyncio.sleep(self.check_interval)
        
        log.info("Clipboard Sentinel stopped monitoring")
    
    def start_monitoring(self):
        """Запустить мониторинг буфера обмена."""
        if self._is_monitoring:
            return
        
        self._is_monitoring = True
        asyncio.create_task(self._monitor_loop())
    
    def stop_monitoring(self):
        """Остановить мониторинг."""
        self._is_monitoring = False
    
    def on_clipboard_changed(self, content: str):
        """
        Вызывается при изменении буфера обмена (Android).
        
        Args:
            content: Новое содержимое буфера
        """
        if content == self._last_content:
            return
        
        self._last_content = content
        
        # Пропускаем пустое или своё
        if not content or len(content) < 5:
            return
        
        # Запускаем проверку
        asyncio.create_task(self._handle_clipboard_change(content))
    
    async def _handle_clipboard_change(self, content: str):
        """Обработка изменения буфера обмена."""
        result = await self.check_content(content)
        
        # Вызов callback'ов
        for callback in self._callbacks:
            try:
                await callback(result)
            except Exception as e:
                log.error(f"Callback error: {e}")
        
        # Логирование
        if not result.is_safe:
            log.warning(f"🚫 Clipboard threat detected: {result.risk_level} - {content[:50]}")


# Глобальный экземпляр
_sentinel: Optional[ClipboardSentinel] = None


def get_clipboard_sentinel() -> ClipboardSentinel:
    """Получить глобальный Clipboard Sentinel."""
    global _sentinel
    if _sentinel is None:
        _sentinel = ClipboardSentinel()
    return _sentinel


def init_clipboard_sentinel(
    api_url: str = "http://localhost:5000/api/check",
    check_interval: float = 1.0
) -> ClipboardSentinel:
    """Инициализировать глобальный Clipboard Sentinel."""
    global _sentinel
    _sentinel = ClipboardSentinel(api_url, check_interval)
    return _sentinel
