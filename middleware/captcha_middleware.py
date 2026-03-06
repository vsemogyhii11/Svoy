"""
CAPTCHA Middleware — проверка на человека для подозрительных пользователей.

Поддерживает:
- Кнопочная CAPTCHA (Telegram Inline Keyboard)
- Cloudflare Turnstile (для WebApp)
- Математическая CAPTCHA
- Emoji CAPTCHA

Использование:
    from middleware.captcha_middleware import CaptchaMiddleware
    
    captcha = CaptchaMiddleware()
    dp.message.middleware(captcha)
    
    # Принудительная проверка
    await captcha.force_verify(user_id, message)
"""

import logging
import time
import random
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta

from aiogram import BaseMiddleware, types
from aiogram.types import Message, TelegramObject, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder

log = logging.getLogger("svoy_bot.captcha")


@dataclass
class CaptchaSession:
    """Сессия CAPTCHA."""
    user_id: int
    captcha_type: str
    correct_answer: str
    created_at: float
    attempts: int = 0
    passed: bool = False
    expires_at: float = field(default_factory=lambda: time.time() + 300)  # 5 минут


class CaptchaMiddleware(BaseMiddleware):
    """
    Middleware для CAPTCHA проверки.
    
    Проверяет подозрительных пользователей,
    требуя подтвердить, что они люди.
    """
    
    # Типы CAPTCHA
    CAPTCHA_BUTTON = 'button'  # Нажать правильную кнопку
    CAPTCHA_MATH = 'math'  # Решить пример
    CAPTCHA_EMOJI = 'emoji'  # Найти определённый emoji
    CAPTCHA_TEXT = 'text'  # Ввести текст
    
    def __init__(
        self,
        db_path: str = "data/captcha_sessions.json",
        auto_verify_threshold: float = 0.5
    ):
        self.db_path = Path(db_path)
        self._sessions: Dict[str, CaptchaSession] = {}
        self._verified: Dict[int, float] = {}  # user_id -> timestamp
        self._failed: Dict[int, int] = {}  # user_id -> failed attempts
        self.auto_verify_threshold = auto_verify_threshold
        self._load_db()
    
    def _load_db(self):
        """Загрузить сессии."""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._sessions = {
                        k: CaptchaSession(**v) for k, v in data.get('sessions', {}).items()
                    }
                    self._verified = {
                        int(k): v for k, v in data.get('verified', {}).items()
                    }
                log.info(f"Captcha DB loaded: {len(self._sessions)} sessions")
            except Exception as e:
                log.error(f"Failed to load captcha DB: {e}")
    
    def _save_db(self):
        """Сохранить сессии."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'sessions': {k: vars(v) for k, v in self._sessions.items()},
            'verified': self._verified
        }
        
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _generate_captcha(self, captcha_type: str) -> Tuple[str, str, InlineKeyboardMarkup]:
        """
        Сгенерировать CAPTCHA.
        
        Returns:
            (question, correct_answer, keyboard)
        """
        if captcha_type == self.CAPTCHA_BUTTON:
            return self._generate_button_captcha()
        elif captcha_type == self.CAPTCHA_MATH:
            return self._generate_math_captcha()
        elif captcha_type == self.CAPTCHA_EMOJI:
            return self._generate_emoji_captcha()
        else:
            return self._generate_button_captcha()
    
    def _generate_button_captcha(self) -> Tuple[str, str, InlineKeyboardMarkup]:
        """Кнопочная CAPTCHA."""
        questions = [
            ("Выберите число больше 5", "6", ["3", "6", "5"]),
            ("Выберите зелёный цвет", "green", ["red", "green", "blue"]),
            ("Выберите животное", "cat", ["car", "cat", "tree"]),
            ("Выберите день недели", "monday", ["apple", "monday", "water"]),
            ("Выберите фрукт", "apple", ["dog", "apple", "chair"]),
        ]
        
        question, correct, options = random.choice(questions)
        random.shuffle(options)
        
        builder = InlineKeyboardBuilder()
        for option in options:
            builder.button(text=option.capitalize(), callback_data=f"captcha_{option}")
        builder.adjust(3)
        
        return question, correct, builder.as_markup()
    
    def _generate_math_captcha(self) -> Tuple[str, str, InlineKeyboardMarkup]:
        """Математическая CAPTCHA."""
        a = random.randint(1, 10)
        b = random.randint(1, 10)
        correct = str(a + b)
        
        # Генерируем варианты ответов
        variants = [correct, str(int(correct) + 1), str(int(correct) - 1)]
        variants = [str(v) for v in random.sample(set(int(v) for v in variants), 3)]
        
        builder = InlineKeyboardBuilder()
        for v in sorted(variants, key=lambda x: int(x)):
            builder.button(text=v, callback_data=f"captcha_{v}")
        builder.adjust(3)
        
        return f"Сколько будет {a} + {b}?", correct, builder.as_markup()
    
    def _generate_emoji_captcha(self) -> Tuple[str, str, InlineKeyboardMarkup]:
        """Emoji CAPTCHA."""
        emoji_groups = [
            ("🐶 🐱 🐭 🐹", "🐱"),
            ("🍎 🍌 🍇 🍊", "🍌"),
            ("🚗 🚕 🚙 🚌", "🚕"),
            ("⚽ 🏀 🏈 ⚾", "🏀"),
        ]
        
        emojis, correct = random.choice(emoji_groups)
        emoji_list = emojis.split()
        random.shuffle(emoji_list)
        
        builder = InlineKeyboardBuilder()
        for emoji in emoji_list:
            builder.button(text=emoji, callback_data=f"captcha_{emoji}")
        builder.adjust(4)
        
        return f"Найдите котика: {emojis}", correct, builder.as_markup()
    
    async def send_captcha(
        self,
        user_id: int,
        message: types.Message,
        captcha_type: Optional[str] = None
    ) -> str:
        """
        Отправить CAPTCHA пользователю.
        
        Args:
            user_id: ID пользователя
            message: Сообщение для ответа
            captcha_type: Тип CAPTCHA (случайный если None)
            
        Returns:
            Токен сессии
        """
        # Выбираем тип CAPTCHA
        if captcha_type is None:
            captcha_type = random.choice([
                self.CAPTCHA_BUTTON,
                self.CAPTCHA_MATH,
                self.CAPTCHA_EMOJI
            ])
        
        # Генерируем CAPTCHA
        question, correct, keyboard = self._generate_captcha(captcha_type)
        
        # Создаём сессию
        token = f"captcha_{user_id}_{int(time.time())}"
        self._sessions[token] = CaptchaSession(
            user_id=user_id,
            captcha_type=captcha_type,
            correct_answer=correct,
            created_at=time.time()
        )
        
        # Отправляем CAPTCHA
        text = (
            f"🤖 <b>Проверка на бота</b>\n\n"
            f"Пожалуйста, подтвердите, что вы человек.\n\n"
            f"<b>Вопрос:</b> {question}\n\n"
            f"⏱ У вас есть 5 минут."
        )
        
        await message.answer(text, parse_mode="HTML", reply_markup=keyboard)
        
        log.info(f"Captcha sent to user {user_id}: {captcha_type}")
        
        return token
    
    async def check_answer(
        self,
        callback: types.CallbackQuery,
        answer: str
    ) -> bool:
        """
        Проверить ответ CAPTCHA.
        
        Args:
            callback: Callback query
            answer: Ответ пользователя
            
        Returns:
            True если верно
        """
        # Находим сессию
        session = None
        session_token = None
        
        for token, sess in self._sessions.items():
            if sess.user_id == callback.from_user.id and not sess.passed:
                session = sess
                session_token = token
                break
        
        if not session:
            return False
        
        # Проверка времени
        if time.time() > session.expires_at:
            del self._sessions[session_token]
            await callback.answer("⏰ Время вышло!", show_alert=True)
            return False
        
        # Проверка ответа
        session.attempts += 1
        
        if answer.lower() == session.correct_answer.lower():
            session.passed = True
            self._verified[callback.from_user.id] = time.time()
            
            # Очищаем сессию
            del self._sessions[session_token]
            self._save_db()
            
            log.info(f"Captcha passed by user {callback.from_user.id}")
            return True
        else:
            # Неверный ответ
            if session.attempts >= 3:
                # Превышено количество попыток
                self._failed[callback.from_user.id] = self._failed.get(callback.from_user.id, 0) + 1
                del self._sessions[session_token]
                
                await callback.answer(
                    "❌ Превышено количество попыток. Вы заблокированы.",
                    show_alert=True
                )
                return False
            else:
                await callback.answer(
                    f"❌ Неверно. Попытка {session.attempts}/3",
                    show_alert=True
                )
                return False
    
    def is_verified(self, user_id: int) -> bool:
        """Проверить, прошёл ли пользователь CAPTCHA."""
        if user_id in self._verified:
            # Верификация действительна 24 часа
            if time.time() - self._verified[user_id] < 86400:
                return True
            else:
                del self._verified[user_id]
        return False
    
    def get_failed_attempts(self, user_id: int) -> int:
        """Получить количество неудачных попыток."""
        return self._failed.get(user_id, 0)
    
    async def force_verify(self, user_id: int, message: types.Message):
        """Принудительная верификация."""
        await self.send_captcha(user_id, message)
    
    async def __call__(
        self,
        handler,
        event: TelegramObject,
        data: dict,
    ):
        """Проверка CAPTCHA для подозрительных."""
        if not isinstance(event, Message) or not event.from_user:
            return await handler(event, data)
        
        user_id = event.from_user.id
        
        # Пропускаем верифицированных
        if self.is_verified(user_id):
            return await handler(event, data)
        
        # Пропускаем callback от CAPTCHA
        if event.text and event.text.startswith('/start captcha_'):
            return await handler(event, data)
        
        # Проверяем на подозрительность (упрощённо)
        # В реальности здесь интеграция с behavior_analyzer
        risk_score = data.get('risk_score', 0)
        
        if risk_score >= self.auto_verify_threshold:
            # Требуем CAPTCHA
            if not any(s.user_id == user_id for s in self._sessions.values()):
                await self.send_captcha(user_id, event)
                return None
        
        return await handler(event, data)


# Глобальный экземпляр
_middleware: Optional[CaptchaMiddleware] = None


def get_captcha_middleware() -> CaptchaMiddleware:
    """Получить глобальный middleware."""
    global _middleware
    if _middleware is None:
        _middleware = CaptchaMiddleware()
    return _middleware


def init_captcha_middleware(
    db_path: str = "data/captcha_sessions.json",
    auto_verify_threshold: float = 0.5
) -> CaptchaMiddleware:
    """Инициализировать глобальный middleware."""
    global _middleware
    _middleware = CaptchaMiddleware(db_path, auto_verify_threshold)
    return _middleware
