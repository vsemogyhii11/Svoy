"""
IP Rate Limiting Middleware — ограничение запросов по IP.

Защита от спам-атак и ботов:
- Лимит: 100 запросов/мин с одного IP
- Бан на 10 минут при превышении
- Игнорирование localhost для тестов

Использование:
    from middleware.ip_rate_limit import IPRateLimitMiddleware
    dp.message.middleware(IPRateateLimitMiddleware())
"""

import logging
import time
from collections import defaultdict
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

log = logging.getLogger("svoy_bot.middleware.ip_rate_limit")


class IPRateLimitMiddleware(BaseMiddleware):
    """
    Ограничение частоты запросов по IP.
    
    Работает в связке с Telegram API через webhook,
    где доступен IP через X-Forwarded-For.
    Для polling режима используется IP Telegram серверов.
    """
    
    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        ban_duration: int = 600
    ):
        """
        Инициализация middleware.
        
        Args:
            max_requests: Максимум запросов за окно
            window_seconds: Размер окна в секундах
            ban_duration: Длительность бана при превышении (секунды)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.ban_duration = ban_duration
        
        # Хранилища
        self._requests: Dict[str, list[float]] = defaultdict(list)
        self._bans: Dict[str, float] = {}  # IP -> время разбана
        
        # Игнорируемые IP (localhost, Telegram servers)
        self._whitelist = {
            '127.0.0.1',
            '::1',
            '149.154.160.0/20',  # Telegram IP range
            '91.108.4.0/22',
        }
        
        super().__init__()
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Проверка IP из whitelist."""
        # Простая проверка (для production нужен IPNetwork)
        for allowed in self._whitelist:
            if '/' in allowed:
                # CIDR notation — упрощённая проверка
                prefix = allowed.split('/')[0]
                if ip.startswith(prefix.rsplit('.', 1)[0]):
                    return True
            elif ip == allowed:
                return True
        return False
    
    def _cleanup(self, ip: str):
        """Удалить старые записи."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._requests[ip] = [
            t for t in self._requests[ip] if t > cutoff
        ]
    
    def _is_banned(self, ip: str) -> bool:
        """Проверка на бан."""
        if ip not in self._bans:
            return False
        
        if time.time() > self._bans[ip]:
            # Бан истёк
            del self._bans[ip]
            return False
        
        return True
    
    def _ban_ip(self, ip: str):
        """Забанить IP."""
        self._bans[ip] = time.time() + self.ban_duration
        log.warning(f"🚫 IP banned: {ip} for {self.ban_duration}s")
    
    def _get_ip_from_message(self, event: TelegramObject) -> str:
        """
        Извлечь IP из события.
        
        В Telegram Bot API через webhook IP доступен в
        X-Forwarded-For заголовке webhook request.
        Для polling — используем заглушку.
        """
        # В реальном webhook режиме IP передаётся в контексте
        # Здесь упрощённая версия для примера
        return "unknown"
    
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not isinstance(event, Message) or not event.from_user:
            return await handler(event, data)
        
        # Получаем IP (в webhook режиме)
        ip = self._get_ip_from_message(event)
        
        # Whitelist
        if self._is_whitelisted(ip):
            return await handler(event, data)
        
        # Проверка бана
        if self._is_banned(ip):
            remaining = int(self._bans[ip] - time.time())
            log.warning(f"🚫 Banned IP tried to access: {ip}")
            
            # Отправляем предупреждение (если бот ещё отвечает)
            try:
                await event.answer(
                    f"🚫 Ваш IP заблокирован на {remaining} сек. "
                    f"Превышен лимит запросов."
                )
            except Exception:
                pass
            
            return None
        
        # Очистка и проверка лимита
        self._cleanup(ip)
        
        if len(self._requests[ip]) >= self.max_requests:
            log.warning(f"⚠️ Rate limit exceeded for IP: {ip}")
            self._ban_ip(ip)
            
            await event.answer(
                "⏳ Слишком много запросов с вашего IP. "
                f"Подождите {self.ban_duration // 60} мин."
            )
            return None
        
        # Запись запроса
        self._requests[ip].append(time.time())
        
        return await handler(event, data)
    
    def get_stats(self) -> dict:
        """Получить статистику."""
        return {
            "tracked_ips": len(self._requests),
            "banned_ips": len(self._bans),
            "window_seconds": self.window_seconds,
            "max_requests": self.max_requests
        }


class SimpleIPRateLimitMiddleware(BaseMiddleware):
    """
    Упрощённая версия для polling режима.
    
    Считает запросы от одного user_id как прокси для IP,
    так как в polling режиме IP недоступен.
    """
    
    def __init__(self, max_requests: int = 50, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[int, list[float]] = defaultdict(list)
        super().__init__()
    
    def _cleanup(self, user_id: int):
        now = time.time()
        cutoff = now - self.window_seconds
        self._requests[user_id] = [
            t for t in self._requests[user_id] if t > cutoff
        ]
    
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if not isinstance(event, Message) or not event.from_user:
            return await handler(event, data)
        
        user_id = event.from_user.id
        self._cleanup(user_id)
        
        if len(self._requests[user_id]) >= self.max_requests:
            log.warning(f"⚠️ Rate limit exceeded for user: {user_id}")
            
            await event.answer(
                "⏳ Слишком много запросов. Подождите немного."
            )
            return None
        
        self._requests[user_id].append(time.time())
        return await handler(event, data)
