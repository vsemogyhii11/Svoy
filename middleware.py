"""
Middleware для aiogram 3:
- Rate limiting (защита от спама)
- Логирование запросов
- Обработка ошибок
"""

import logging
import time
from collections import defaultdict
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

log = logging.getLogger("svoy_bot.middleware")


class RateLimitMiddleware(BaseMiddleware):
    """
    Ограничение частоты запросов.
    Не более `max_requests` за `window_seconds` секунд на пользователя.
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[int, list[float]] = defaultdict(list)
        super().__init__()

    def _cleanup(self, user_id: int):
        """Удалить старые записи."""
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
            log.warning(f"Rate limit exceeded for user {user_id}")
            await event.answer(
                "⏳ Слишком много запросов. Подождите минуту и попробуйте снова."
            )
            return None

        self._requests[user_id].append(time.time())
        return await handler(event, data)


class LoggingMiddleware(BaseMiddleware):
    """Логирование всех входящих сообщений."""

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if isinstance(event, Message) and event.from_user:
            log.info(
                f"[MSG] user={event.from_user.id} "
                f"name={event.from_user.first_name} "
                f"text_len={len(event.text or '')} "
                f"chat={event.chat.type}"
            )

        start = time.time()
        try:
            result = await handler(event, data)
            elapsed = (time.time() - start) * 1000
            log.debug(f"Handler completed in {elapsed:.0f}ms")
            return result
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            log.error(
                f"Handler error after {elapsed:.0f}ms: {type(e).__name__}: {e}",
                exc_info=True,
            )
            if isinstance(event, Message):
                await event.answer(
                    "😔 Произошла ошибка при обработке вашего сообщения. "
                    "Попробуйте позже или обратитесь к администратору."
                )
            return None
