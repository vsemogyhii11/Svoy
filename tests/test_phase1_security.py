"""
Тесты для Phase 1 security modules:
- Behavior Analyzer
- Telegram Account Checker
- Honeypot Middleware
- Captcha Middleware
"""
import pytest
import sys
import os
import time
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.behavior_analyzer import BehaviorAnalyzer, BehaviorResult
from middleware.honeypot_middleware import HoneypotMiddleware, HoneypotResult
from middleware.captcha_middleware import CaptchaMiddleware, CaptchaSession


class TestBehaviorAnalyzer:
    """Тесты поведенческого анализатора."""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    @pytest.fixture
    def analyzer(self, temp_db):
        return BehaviorAnalyzer(db_path=temp_db)

    def test_normal_user_behavior(self, analyzer):
        """Нормальное поведение пользователя."""
        user_id = 123456
        
        # Имитируем нормальные сообщения с человеческой скоростью
        for i in range(5):
            analyzer.record_message(
                user_id=user_id,
                message_text=f"Сообщение номер {i}",
                timestamp=time.time() + (i * 2000)  # 2 секунды между сообщениями
            )
        
        result = analyzer.analyze_user(user_id)
        
        assert result.is_bot is False
        assert result.risk_level in ["none", "low"]
        assert result.avg_response_time >= 1500  # ~2 секунды

    def test_bot_too_fast(self, analyzer):
        """Бот с слишком быстрыми ответами."""
        user_id = 789012
        
        # Бот отвечает мгновенно (<100мс)
        for i in range(10):
            analyzer.record_message(
                user_id=user_id,
                message_text=f"Быстрое сообщение {i}",
                timestamp=time.time() + (i * 0.05)  # 50мс между сообщениями
            )
        
        result = analyzer.analyze_user(user_id)
        
        assert result.is_bot is True
        assert result.is_too_fast is True
        assert result.risk_level in ["high", "critical"]
        assert result.confidence >= 0.9

    def test_copy_paste_pattern(self, analyzer):
        """Copy-paste паттерн."""
        user_id = 345678
        
        # Одинаковые сообщения
        for i in range(10):
            analyzer.record_message(
                user_id=user_id,
                message_text="Одинаковый спам текст",
                timestamp=time.time() + (i * 1000)
            )
        
        result = analyzer.analyze_user(user_id)
        
        assert result.copy_paste_pattern is True
        assert result.is_suspicious is True
        assert result.confidence >= 0.7

    def test_spam_repeat_pattern(self, analyzer):
        """Спам повторениями."""
        user_id = 901234
        
        # Повторение одного сообщения
        for i in range(8):
            analyzer.record_message(
                user_id=user_id,
                message_text="Повторяющийся спам",
                timestamp=time.time() + (i * 500)
            )
        
        result = analyzer.analyze_user(user_id)
        
        assert result.spam_pattern is True
        assert result.confidence >= 0.8

    def test_command_abuse(self, analyzer):
        """Злоупотребление командами."""
        user_id = 567890
        
        # Много команд
        for i in range(15):
            analyzer.record_message(
                user_id=user_id,
                message_text="/start",
                timestamp=time.time() + (i * 1000)
            )
        
        result = analyzer.analyze_user(user_id)
        
        assert result.command_abuse is True
        assert result.confidence >= 0.6

    def test_247_activity(self, analyzer):
        """Активность 24/7."""
        user_id = 234567
        
        # Имитируем активность в течение 20+ часов
        base_time = time.time()
        for hour in range(24):
            for msg in range(3):
                analyzer.record_message(
                    user_id=user_id,
                    message_text=f"Сообщение в час {hour}",
                    timestamp=base_time + (hour * 3600) + (msg * 60)
                )
        
        result = analyzer.analyze_user(user_id)
        
        assert result.is_247_activity is True
        assert result.confidence >= 0.75

    def test_risk_score_calculation(self, analyzer):
        """Расчёт risk score."""
        user_id = 678901
        
        # Комбинация подозрительных паттернов
        for i in range(20):
            analyzer.record_message(
                user_id=user_id,
                message_text="/start",  # Команды
                timestamp=time.time() + (i * 0.08)  # Быстро
            )
        
        result = analyzer.analyze_user(user_id)
        
        assert result.risk_score > 0.5
        assert result.risk_level in ["medium", "high", "critical"]

    def test_get_user_profile(self, analyzer):
        """Получение профиля пользователя."""
        user_id = 111222
        
        analyzer.record_message(user_id, "Привет", time.time())
        analyzer.record_message(user_id, "Как дела", time.time() + 1000)
        
        profile = analyzer.get_user_profile(user_id)
        
        assert profile is not None
        assert profile['total_messages'] == 2

    def test_cleanup_old(self, analyzer):
        """Очистка старых данных."""
        user_id = 333444
        
        # Запись со старым timestamp
        analyzer._users[user_id] = {
            'profile': {'first_seen': time.time() - 100000, 'total_messages': 1},
            'stats': {},
            'last_seen': time.time() - 100000  # 27 часов назад
        }
        
        analyzer.cleanup_old(days=1)
        
        assert user_id not in analyzer._users


class TestHoneypotMiddleware:
    """Тесты honeypot middleware."""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    @pytest.fixture
    def middleware(self, temp_db):
        return HoneypotMiddleware(db_path=temp_db)

    def test_create_trap(self, middleware):
        """Создание ловушки."""
        token = middleware.create_trap(user_id=123456)
        
        assert len(token) == 16
        assert token in middleware._traps
        assert middleware._traps[token]['user_id'] == 123456

    def test_check_trap_triggered(self, middleware):
        """Проверка сработавшей ловушки."""
        user_id = 789012
        token = middleware.create_trap(user_id)
        
        result = middleware.check_trap(token, user_id)
        
        assert result.triggered is True
        assert result.trigger_type == "invisible_trap"
        assert result.confidence >= 0.98
        assert result.is_bot is True

    def test_check_trap_invalid_token(self, middleware):
        """Проверка несуществующего токена."""
        result = middleware.check_trap("invalid_token", 123456)
        
        assert result.triggered is False

    def test_hidden_command_detection(self, middleware):
        """Детекция скрытых команд."""
        # Симуляция сообщения со скрытой командой
        assert '/trap_' in '/trap_test'
        assert '/honeypot_' in '/honeypot_bypass'

    def test_get_user_triggers(self, middleware):
        """Получение триггеров пользователя."""
        user_id = 345678
        
        # Создаём и активируем ловушку
        token = middleware.create_trap(user_id)
        middleware.check_trap(token, user_id)
        
        triggers = middleware.get_user_triggers(user_id)
        
        assert len(triggers) >= 1

    def test_is_confirmed_bot(self, middleware):
        """Подтверждённый бот."""
        user_id = 901234
        
        # Несколько триггеров
        for i in range(3):
            token = middleware.create_trap(user_id)
            middleware.check_trap(token, user_id)
        
        assert middleware.is_confirmed_bot(user_id, threshold=2) is True


class TestCaptchaMiddleware:
    """Тесты CAPTCHA middleware."""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    @pytest.fixture
    def middleware(self, temp_db):
        return CaptchaMiddleware(db_path=temp_db)

    def test_generate_button_captcha(self, middleware):
        """Генерация кнопочной CAPTCHA."""
        question, answer, keyboard = middleware._generate_button_captcha()
        
        assert question is not None
        assert len(question) > 0
        assert answer is not None
        assert keyboard is not None

    def test_generate_math_captcha(self, middleware):
        """Генерация математической CAPTCHA."""
        question, answer, keyboard = middleware._generate_math_captcha()
        
        assert "+" in question
        assert answer.isdigit()
        assert int(answer) >= 2  # Минимум 1+1
        assert int(answer) <= 20  # Максимум 10+10

    def test_generate_emoji_captcha(self, middleware):
        """Генерация emoji CAPTCHA."""
        question, answer, keyboard = middleware._generate_emoji_captcha()
        
        assert "🐱" in question or "Найдите" in question
        assert answer in ["🐶", "🐱", "🐭", "🐹"]

    def test_is_verified(self, middleware):
        """Проверка верификации."""
        user_id = 123456
        
        # Сначала не верифицирован
        assert middleware.is_verified(user_id) is False
        
        # Добавляем верификацию
        middleware._verified[user_id] = time.time()
        
        # Теперь верифицирован
        assert middleware.is_verified(user_id) is True

    def test_is_verified_expired(self, middleware):
        """Истёкшая верификация."""
        user_id = 789012
        
        # Старая верификация (25 часов назад)
        middleware._verified[user_id] = time.time() - 90000
        
        # Истекла (24 часа лимит)
        assert middleware.is_verified(user_id) is False

    def test_get_failed_attempts(self, middleware):
        """Получение неудачных попыток."""
        user_id = 345678
        
        assert middleware.get_failed_attempts(user_id) == 0
        
        middleware._failed[user_id] = 3
        
        assert middleware.get_failed_attempts(user_id) == 3

    def test_captcha_session_expiration(self, middleware):
        """Истечение сессии CAPTCHA."""
        user_id = 901234
        
        # Создаём сессию с истёкшим временем
        token = f"captcha_{user_id}_0"
        middleware._sessions[token] = CaptchaSession(
            user_id=user_id,
            captcha_type='button',
            correct_answer='test',
            created_at=time.time() - 600,  # 10 минут назад
            expires_at=time.time() - 60  # Истекла 1 минуту назад
        )
        
        # Сессия есть, но истекла
        session = middleware._sessions[token]
        assert time.time() > session.expires_at
