"""
🛡 RATE LIMITING для админ-панели

Защита от:
- Brute force атак на логин
- DDoS запросов
- Злоупотребления API
"""

import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from functools import wraps
import asyncio

logger = logging.getLogger("svoy_bot.rate_limit")


@dataclass
class RateLimitConfig:
    """Конфигурация rate limiting."""
    # Максимум запросов
    max_requests: int = 100
    # Окно времени (сек)
    window_seconds: int = 60
    # Длительность бана (сек)
    ban_duration: int = 300
    # Блокировка после N неудачных попыток
    max_failed_attempts: int = 5


class RateLimiter:
    """
    Rate limiter с поддержкой банов.
    
    Использование:
        limiter = RateLimiter()
        
        @limiter.limit("login", max_requests=5, window_seconds=60)
        async def login(request):
            ...
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        
        # Хранилища
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._bans: Dict[str, float] = {}  # key -> ban expiry
        self._failed_attempts: Dict[str, int] = defaultdict(int)
        
        # Блокировка по IP
        self._ip_blacklist: set = set()
        
        # Статистика
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'banned_ips': 0
        }
    
    def _get_key(self, request) -> str:
        """Получить ключ для rate limiting (IP + user agent)."""
        # Для Quart/Flask запросов
        if hasattr(request, 'remote_addr'):
            ip = request.remote_addr or 'unknown'
        else:
            ip = 'unknown'
        
        return f"ip:{ip}"
    
    def _is_banned(self, key: str) -> bool:
        """Проверить бан."""
        if key in self._ip_blacklist:
            return True
        
        if key in self._bans:
            if time.time() < self._bans[key]:
                return True
            else:
                del self._bans[key]  # Бан истёк
        
        return False
    
    def _ban(self, key: str, duration: Optional[int] = None):
        """Забанить ключ."""
        duration = duration or self.config.ban_duration
        self._bans[key] = time.time() + duration
        self.stats['banned_ips'] += 1
        
        logger.warning(f"🚫 Banned {key} for {duration}s")
    
    def _record_request(self, key: str) -> bool:
        """
        Записать запрос и проверить лимит.
        
        Returns:
            True если запрос разрешён
        """
        now = time.time()
        window_start = now - self.config.window_seconds
        
        # Очищаем старые запросы
        self._requests[key] = [
            t for t in self._requests[key] if t > window_start
        ]
        
        # Проверка лимита
        if len(self._requests[key]) >= self.config.max_requests:
            self._ban(key)
            return False
        
        # Запись запроса
        self._requests[key].append(now)
        self.stats['total_requests'] += 1
        
        return True
    
    def record_failed_attempt(self, key: str):
        """Записать неудачную попытку (например, неправильный пароль)."""
        self._failed_attempts[key] += 1
        
        if self._failed_attempts[key] >= self.config.max_failed_attempts:
            self._ban(key, duration=3600)  # Бан на 1 час
            self._failed_attempts[key] = 0  # Сброс
    
    def record_success(self, key: str):
        """Записать успешную попытку (сброс failed attempts)."""
        self._failed_attempts[key] = 0
    
    def is_allowed(self, request) -> bool:
        """
        Проверить, разрешён ли запрос.
        
        Args:
            request: Запрос
        
        Returns:
            True если разрешён
        """
        key = self._get_key(request)
        
        # Проверка бана
        if self._is_banned(key):
            self.stats['blocked_requests'] += 1
            return False
        
        # Проверка rate limit
        return self._record_request(key)
    
    def get_remaining(self, request) -> int:
        """Получить оставшееся количество запросов."""
        key = self._get_key(request)
        now = time.time()
        window_start = now - self.config.window_seconds
        
        current_requests = len([
            t for t in self._requests[key] if t > window_start
        ])
        
        return max(0, self.config.max_requests - current_requests)
    
    def get_retry_after(self, request) -> int:
        """Получить время до следующего разрешённого запроса."""
        key = self._get_key(request)
        
        if not self._requests[key]:
            return 0
        
        oldest = min(self._requests[key])
        window_start = time.time() - self.config.window_seconds
        
        if oldest > window_start:
            return int(oldest - window_start)
        
        return 0
    
    def blacklist_ip(self, ip: str):
        """Добавить IP в чёрный список."""
        self._ip_blacklist.add(ip)
        logger.warning(f"🚫 IP blacklisted: {ip}")
    
    def remove_from_blacklist(self, ip: str):
        """Удалить IP из чёрного списка."""
        self._ip_blacklist.discard(ip)
        logger.info(f"✅ IP removed from blacklist: {ip}")
    
    def get_stats(self) -> dict:
        """Получить статистику."""
        return {
            **self.stats,
            'active_bans': len(self._bans),
            'blacklisted_ips': len(self._ip_blacklist)
        }


# Глобальный rate limiter
_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Получить глобальный rate limiter."""
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


def init_rate_limiter(config: Optional[RateLimitConfig] = None) -> RateLimiter:
    """Инициализировать глобальный rate limiter."""
    global _limiter
    _limiter = RateLimiter(config)
    return _limiter


# Декоратор для Quart routes
def rate_limit(max_requests: int = 100, window_seconds: int = 60):
    """
    Декоратор rate limiting для Quart routes.
    
    Пример:
        @app.route('/api/data')
        @rate_limit(max_requests=10, window_seconds=60)
        async def get_data():
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            from quart import request, jsonify
            
            limiter = get_rate_limiter()
            
            # Проверка rate limit
            if not limiter.is_allowed(request):
                retry_after = limiter.get_retry_after(request)
                
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': retry_after
                }), 429
            
            # Вызов функции
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Middleware для Quart
class RateLimitMiddleware:
    """
    Middleware для автоматического rate limiting.
    
    Использование:
        app = Quart(__name__)
        app.before_request(RateLimitMiddleware())
    """
    
    def __init__(self, limiter: Optional[RateLimiter] = None):
        self.limiter = limiter or get_rate_limiter()
    
    async def __call__(self):
        from quart import request, jsonify, g
        
        # Проверка rate limit
        if not self.limiter.is_allowed(request):
            retry_after = self.limiter.get_retry_after(request)
            
            return jsonify({
                'error': 'Rate limit exceeded',
                'retry_after': retry_after
            }), 429
        
        # Сохраняем оставшееся количество в g
        g.rate_limit_remaining = self.limiter.get_remaining(request)
        
        return None
