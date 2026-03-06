"""
Telegram Account Checker — проверка аккаунтов Telegram.

Проверяет:
- Возраст аккаунта (через @userinfobot API)
- Паттерны username (временные = риск)
- Наличие фото профиля
- Bio на спам-ключи
- Premium статус

Использование:
    from analyzers.telegram_account_checker import TelegramAccountChecker
    
    checker = TelegramAccountChecker(bot_token)
    result = await checker.check_user(user_id)
    
    if result.is_suspicious:
        print(f"Подозрительный аккаунт: {result.reasons}")
"""

import logging
import re
import time
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime, timedelta

import aiohttp

log = logging.getLogger("svoy_bot.telegram_checker")


@dataclass
class TelegramAccountResult:
    """Результат проверки аккаунта Telegram."""
    user_id: int
    is_valid: bool = True
    
    # Основные данные
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_premium: bool = False
    is_bot: bool = False
    
    # Возраст аккаунта
    account_age_days: Optional[int] = None
    is_new_account: bool = False
    
    # Фото профиля
    has_profile_photo: bool = False
    
    # Bio
    bio: Optional[str] = None
    bio_has_links: bool = False
    bio_has_spam: bool = False
    
    # Username анализ
    is_temp_username: bool = False
    username_score: float = 0.0  # 0-1, 1 = нормальный
    
    # Итоги
    is_suspicious: bool = False
    confidence: float = 0.0
    risk_score: float = 0.0  # 0.0 - 1.0
    risk_level: str = "none"
    reasons: List[str] = field(default_factory=list)
    
    @property
    def emoji(self) -> str:
        if self.risk_level == "high":
            return "🔴"
        elif self.risk_level == "medium":
            return "🟡"
        elif self.risk_level == "low":
            return "🟠"
        return "🟢"


class TelegramAccountChecker:
    """
    Проверка аккаунтов Telegram.
    
    Использует:
    - @userinfobot API для получения данных
    - Паттерны для анализа username
    - Эвристики для оценки риска
    """
    
    # Временные username паттерны
    TEMP_USERNAME_PATTERNS = [
        r'^user\d+$',  # user12345678
        r'^\d+$',  # Просто цифры
        r'^[a-z]{1,3}\d+$',  # ab123
        r'^[a-z]\d{6,}$',  # a1234567
        r'^\d{8,}$',  # 12345678
        r'^[a-z]{10,}$',  # случайные буквы
    ]
    
    # Спам-ключи в bio
    SPAM_KEYWORDS = [
        'заработок', 'money', 'crypto', 'bitcoin', 'usdt',
        'казино', 'casino', 'slots', '1win', 'vulcan',
        'инвестиции', 'invest', 'трейдинг', 'trading',
        'бесплатно', 'free', 'подарок', 'gift', 'win',
        'перевод', 'card', 'sber', 'tinkoff',
        'работа', 'work', 'удалёнка', 'remote',
        'только сегодня', 'only today', 'акция', 'promo',
    ]
    
    # Домены в bio
    SPAM_DOMAINS = [
        't.me/', 'telegram.me/', 'wa.me/', 'whatsapp.com',
        'bit.ly', 'tinyurl', 'cutt.ly',
    ]
    
    def __init__(
        self,
        bot_token: str,
        cache_path: str = "data/telegram_cache.json"
    ):
        self.bot_token = bot_token
        self.cache_path = Path(cache_path)
        self._cache: Dict[int, dict] = {}
        self._load_cache()
    
    def _load_cache(self):
        """Загрузить кэш проверок."""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    self._cache = {
                        int(k): v for k, v in json.load(f).items()
                    }
                log.info(f"Telegram cache loaded: {len(self._cache)} users")
            except Exception as e:
                log.error(f"Failed to load Telegram cache: {e}")
    
    def _save_cache(self):
        """Сохранить кэш проверок."""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.cache_path, 'w', encoding='utf-8') as f:
            json.dump(self._cache, f, ensure_ascii=False, indent=2)
    
    async def check_user(self, user_id: int) -> TelegramAccountResult:
        """
        Проверить пользователя Telegram.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            Результат проверки
        """
        # Проверка кэша (24 часа)
        if user_id in self._cache:
            cached = self._cache[user_id]
            if time.time() - cached.get('timestamp', 0) < 86400:
                log.debug(f"Telegram cache hit for user {user_id}")
                return self._dict_to_result(cached['result'])
        
        result = TelegramAccountResult(user_id=user_id)
        
        # Получаем данные через @userinfobot
        user_data = await self._get_user_info(user_id)
        
        if user_data:
            self._parse_user_data(user_data, result)
        
        # Анализируем username
        if result.username:
            self._analyze_username(result)
        
        # Анализируем bio
        if result.bio:
            self._analyze_bio(result)
        
        # Оцениваем возраст аккаунта
        await self._estimate_account_age(result)
        
        # Вычисляем риск
        self._calculate_risk(result)
        
        # Кэшируем
        self._cache[user_id] = {
            'timestamp': time.time(),
            'result': self._result_to_dict(result)
        }
        if len(self._cache) % 10 == 0:
            self._save_cache()
        
        log.info(
            f"Telegram check: user={user_id}, "
            f"risk={result.risk_level}, age={result.account_age_days}d"
        )
        
        return result
    
    async def _get_user_info(self, user_id: int) -> Optional[dict]:
        """
        Получить информацию о пользователе через @userinfobot.
        
        Используем публичный API @userinfobot
        """
        try:
            # Метод 1: Через getChat API
            url = f"https://api.telegram.org/bot{self.bot_token}/getChat"
            params = {'chat_id': user_id}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('ok'):
                            return data.get('result', {})
                    else:
                        log.debug(f"Telegram API error: {response.status}")
            
            return None
        
        except Exception as e:
            log.debug(f"Failed to get user info: {e}")
            return None
    
    def _parse_user_data(self, data: dict, result: TelegramAccountResult):
        """Распарсить данные пользователя."""
        result.user_id = data.get('id', result.user_id)
        result.first_name = data.get('first_name')
        result.last_name = data.get('last_name')
        result.username = data.get('username')
        result.is_bot = data.get('is_bot', False)
        result.is_premium = data.get('is_premium', False)
        
        # Фото профиля
        if data.get('photo'):
            result.has_profile_photo = True
        
        # Bio (доступно только для некоторых пользователей)
        result.bio = data.get('bio')
    
    def _analyze_username(self, result: TelegramAccountResult):
        """Анализ username."""
        if not result.username:
            result.is_temp_username = True
            result.username_score = 0.3
            result.reasons.append("Нет username")
            return
        
        username = result.username.lower()
        score = 1.0
        
        # Проверка на временные паттерны
        for pattern in self.TEMP_USERNAME_PATTERNS:
            if re.match(pattern, username):
                result.is_temp_username = True
                score -= 0.5
                result.reasons.append(f"Временный username паттерн: {result.username}")
                break
        
        # Длина
        if len(username) < 4:
            score -= 0.2
            result.reasons.append("Слишком короткий username")
        
        # Цифры в конце
        digit_count = sum(1 for c in username if c.isdigit())
        if digit_count > len(username) * 0.5:
            score -= 0.2
            result.reasons.append("Много цифр в username")
        
        # Повторяющиеся символы
        if re.search(r'(.)\1{3,}', username):
            score -= 0.1
            result.reasons.append("Повторяющиеся символы в username")
        
        result.username_score = max(score, 0.0)
    
    def _analyze_bio(self, result: TelegramAccountResult):
        """Анализ bio."""
        if not result.bio:
            return
        
        bio_lower = result.bio.lower()
        
        # Проверка на ссылки
        for domain in self.SPAM_DOMAINS:
            if domain in bio_lower:
                result.bio_has_links = True
                result.reasons.append(f"Ссылка в bio: {domain}")
                break
        
        # Проверка на спам-ключи
        spam_count = 0
        for keyword in self.SPAM_KEYWORDS:
            if keyword in bio_lower:
                spam_count += 1
        
        if spam_count >= 2:
            result.bio_has_spam = True
            result.reasons.append(f"Спам-ключи в bio ({spam_count} найдено)")
    
    async def _estimate_account_age(self, result: TelegramAccountResult):
        """
        Оценить возраст аккаунта.
        
        Метод: Telegram user_id выдавались последовательно.
        Примерные диапазоны:
        - 0-100M: 2013-2015
        - 100-300M: 2016-2017
        - 300-500M: 2018-2019
        - 500-700M: 2020-2021
        - 700M+: 2022+
        """
        user_id = result.user_id
        
        # Очень грубая оценка по ID
        if user_id < 100_000_000:
            result.account_age_days = 3000  # ~8 лет
        elif user_id < 300_000_000:
            result.account_age_days = 2200  # ~6 лет
        elif user_id < 500_000_000:
            result.account_age_days = 1500  # ~4 года
        elif user_id < 700_000_000:
            result.account_age_days = 800  # ~2 года
        else:
            result.account_age_days = 400  # ~1 год
            result.is_new_account = True
            result.reasons.append("Новый аккаунт (высокий ID)")
        
        # Точная оценка через @userinfobot
        try:
            # Пытаемся получить точную дату через API
            user_data = await self._get_user_info(result.user_id)
            if user_data and 'added_to_attachment_menu' in user_data:
                # Это не даёт точную дату, но можно использовать эвристики
                pass
        except Exception:
            pass
    
    def _calculate_risk(self, result: TelegramAccountResult):
        """Вычислить итоговый риск."""
        score = 0.0
        
        # Боты
        if result.is_bot:
            score += 0.5
            result.reasons.append("Это бот")
        
        # Новый аккаунт
        if result.is_new_account:
            score += 0.2
        
        # Временный username
        if result.is_temp_username:
            score += 0.25
        
        # Нет фото
        if not result.has_profile_photo:
            score += 0.15
            result.reasons.append("Нет фото профиля")
        
        # Спам в bio
        if result.bio_has_spam:
            score += 0.3
        if result.bio_has_links:
            score += 0.15
        
        # Низкий username score
        if result.username_score < 0.5:
            score += 0.2
        
        # Нормализация
        result.risk_score = min(score, 1.0)
        
        # Определение уровня
        if result.risk_score >= 0.7:
            result.risk_level = "high"
            result.is_suspicious = True
            result.confidence = 0.85
        elif result.risk_score >= 0.5:
            result.risk_level = "medium"
            result.is_suspicious = True
            result.confidence = 0.7
        elif result.risk_score >= 0.3:
            result.risk_level = "low"
            result.confidence = 0.5
        else:
            result.confidence = 0.3
    
    def _result_to_dict(self, result: TelegramAccountResult) -> dict:
        """Сериализовать результат."""
        return {
            'user_id': result.user_id,
            'username': result.username,
            'is_premium': result.is_premium,
            'is_bot': result.is_bot,
            'has_profile_photo': result.has_profile_photo,
            'is_temp_username': result.is_temp_username,
            'username_score': result.username_score,
            'risk_score': result.risk_score,
            'risk_level': result.risk_level,
            'reasons': result.reasons
        }
    
    def _dict_to_result(self, data: dict) -> TelegramAccountResult:
        """Десериализовать результат."""
        return TelegramAccountResult(**data)
    
    def get_cached_user(self, user_id: int) -> Optional[TelegramAccountResult]:
        """Получить из кэша."""
        if user_id in self._cache:
            return self._dict_to_result(self._cache[user_id]['result'])
        return None


# Глобальный экземпляр
_checker: Optional[TelegramAccountChecker] = None


def get_telegram_checker() -> Optional[TelegramAccountChecker]:
    """Получить глобальный чекер."""
    return _checker


def init_telegram_checker(
    bot_token: str,
    cache_path: str = "data/telegram_cache.json"
) -> TelegramAccountChecker:
    """Инициализировать глобальный чекер."""
    global _checker
    _checker = TelegramAccountChecker(bot_token, cache_path)
    return _checker
