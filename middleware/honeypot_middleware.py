"""
Invisible Honeypot Middleware — невидимые ловушки для ботов.

Принцип работы:
1. В WebApp добавляются невидимые поля/кнопки
2. Люди их не видят и не нажимают
3. Боты сканируют DOM и нажимают
4. Любое взаимодействие = бот

Использование в WebApp (frontend):
    <script src="/static/honeypot.js"></script>
    
    // Добавить невидимые ловушки
    addHoneypotTraps();

Использование в боте (backend):
    from middleware.honeypot_middleware import HoneypotMiddleware
    
    dp.message.middleware(HoneypotMiddleware())
"""

import logging
import time
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from datetime import datetime

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

log = logging.getLogger("svoy_bot.honeypot_middleware")


@dataclass
class HoneypotResult:
    """Результат проверки honeypot."""
    triggered: bool = False
    trigger_type: Optional[str] = None
    confidence: float = 0.0
    user_agent_data: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    
    @property
    def is_bot(self) -> bool:
        return self.triggered


class HoneypotMiddleware(BaseMiddleware):
    """
    Middleware для детекции ботов через honeypot.
    
    Проверяет:
    - Невидимые поля в сообщениях
    - Скрытые команды
    - Timing взаимодействия
    """
    
    def __init__(self, db_path: str = "data/honeypot_traps.json"):
        self.db_path = Path(db_path)
        self._traps: Dict[str, dict] = {}
        self._triggered: Dict[int, list] = {}  # user_id -> [triggers]
        self._load_traps()
    
    def _load_traps(self):
        """Загрузить ловушки."""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self._traps = json.load(f)
                log.info(f"Honeypot traps loaded: {len(self._traps)}")
            except Exception as e:
                log.error(f"Failed to load honeypot traps: {e}")
    
    def _save_traps(self):
        """Сохранить ловушки."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self._traps, f, ensure_ascii=False, indent=2)
    
    def create_trap(self, user_id: int) -> str:
        """
        Создать ловушку для пользователя.
        
        Returns:
            Токен ловушки
        """
        import uuid
        token = str(uuid.uuid4())[:16]
        
        self._traps[token] = {
            'user_id': user_id,
            'created_at': time.time(),
            'triggered': False,
            'trigger_count': 0
        }
        
        if len(self._traps) % 10 == 0:
            self._save_traps()
        
        return token
    
    def check_trap(self, token: str, user_id: int) -> HoneypotResult:
        """
        Проверить, сработала ли ловушка.
        
        Args:
            token: Токен ловушки
            user_id: ID пользователя
            
        Returns:
            Результат проверки
        """
        result = HoneypotResult()
        
        if token not in self._traps:
            return result
        
        trap = self._traps[token]
        
        # Ловушка уже сработала
        if trap['triggered']:
            result.triggered = True
            result.trigger_type = "repeat_trap"
            result.confidence = 0.95
            return result
        
        # Помечаем как сработавшую
        trap['triggered'] = True
        trap['trigger_count'] += 1
        trap['triggered_at'] = time.time()
        trap['triggered_by'] = user_id
        
        self._save_traps()
        
        # Записываем триггер
        if user_id not in self._triggered:
            self._triggered[user_id] = []
        
        self._triggered[user_id].append({
            'token': token,
            'timestamp': time.time(),
            'type': 'honeypot_trap'
        })
        
        result.triggered = True
        result.trigger_type = "invisible_trap"
        result.confidence = 0.98
        
        log.warning(f"🎯 Honeypot triggered by user {user_id}")
        
        return result
    
    async def __call__(
        self,
        handler,
        event: TelegramObject,
        data: dict,
    ):
        """Проверка сообщений на honeypot."""
        if not isinstance(event, Message) or not event.from_user:
            return await handler(event, data)
        
        user_id = event.from_user.id
        text = event.text or ""
        
        # Проверка на активацию ловушки
        if text.startswith('/trap_') or text.startswith('/honeypot_'):
            # Это попытка активировать скрытую команду
            result = HoneypotResult(
                triggered=True,
                trigger_type="hidden_command",
                confidence=0.99
            )
            
            log.warning(f"🎯 Hidden command triggered by user {user_id}: {text}")
            
            # Записываем триггер
            if user_id not in self._triggered:
                self._triggered[user_id] = []
            
            self._triggered[user_id].append({
                'command': text,
                'timestamp': time.time(),
                'type': 'hidden_command'
            })
            
            # Не передаём обработчику
            return None
        
        # Проверка на наличие токенов ловушек в сообщении
        for token in self._traps:
            if token in text:
                result = self.check_trap(token, user_id)
                if result.triggered:
                    # Бот попался
                    log.warning(f"🎯 Bot detected via honeypot: user={user_id}")
                    return None
        
        return await handler(event, data)
    
    def get_user_triggers(self, user_id: int) -> List[dict]:
        """Получить все триггеры пользователя."""
        return self._triggered.get(user_id, [])
    
    def is_confirmed_bot(self, user_id: int, threshold: int = 2) -> bool:
        """
        Проверить, является ли пользователь ботом.
        
        Args:
            user_id: ID пользователя
            threshold: Количество триггеров для подтверждения
            
        Returns:
            True если это бот
        """
        triggers = self.get_user_triggers(user_id)
        return len(triggers) >= threshold
    
    def cleanup_old(self, days: int = 7):
        """Удалить старые ловушки."""
        cutoff = time.time() - (days * 86400)
        
        to_remove = []
        for token, trap in self._traps.items():
            if trap.get('created_at', 0) < cutoff:
                to_remove.append(token)
        
        for token in to_remove:
            del self._traps[token]
        
        if to_remove:
            self._save_traps()
            log.info(f"Cleaned up {len(to_remove)} old honeypot traps")


# Глобальный экземпляр
_middleware: Optional[HoneypotMiddleware] = None


def get_honeypot_middleware() -> HoneypotMiddleware:
    """Получить глобальный middleware."""
    global _middleware
    if _middleware is None:
        _middleware = HoneypotMiddleware()
    return _middleware


def init_honeypot_middleware(db_path: str = "data/honeypot_traps.json") -> HoneypotMiddleware:
    """Инициализировать глобальный middleware."""
    global _middleware
    _middleware = HoneypotMiddleware(db_path)
    return _middleware
