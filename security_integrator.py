"""
Security Integrator — единая система защиты от мошенников.

Объединяет все модули защиты:
1. Поведенческий анализ
2. Telegram аккаунт проверка
3. IP проверка (reputation, geo, rate limit)
4. User-Agent анализ
5. Fingerprint анализ
6. Honeypot детекция
7. CAPTCHA верификация
8. ML классификатор
9. Graph анализ (бот-сети)

Использование:
    from security_integrator import SecurityIntegrator
    
    security = SecurityIntegrator()
    
    # При сообщении
    result = await security.check_user(message)
    
    if result.is_blocked:
        await message.answer("🚫 Доступ заблокирован")
    elif result.requires_captcha:
        await security.send_captcha(message)
    else:
        # Обработка сообщения
        ...
"""

import logging
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any

from aiogram import types

log = logging.getLogger("svoy_bot.security")


@dataclass
class SecurityResult:
    """Результат проверки безопасности."""
    user_id: int
    
    # Общий статус
    is_blocked: bool = False
    is_suspicious: bool = False
    requires_captcha: bool = False
    requires_verification: bool = False
    
    # Scores от различных систем
    behavior_score: float = 0.0
    telegram_score: float = 0.0
    ip_score: float = 0.0
    ua_score: float = 0.0
    fingerprint_score: float = 0.0
    honeypot_score: float = 0.0
    ml_score: float = 0.0
    graph_score: float = 0.0
    
    # Итоговый score
    total_risk_score: float = 0.0
    risk_level: str = "none"  # none, low, medium, high, critical
    
    # Детали
    blocked_reason: Optional[str] = None
    risk_factors: List[str] = field(default_factory=list)
    
    # Рекомендации
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def emoji(self) -> str:
        if self.risk_level == "critical":
            return "🔴"
        elif self.risk_level == "high":
            return "🟠"
        elif self.risk_level == "medium":
            return "🟡"
        elif self.risk_level == "low":
            return "🟠"
        return "🟢"


class SecurityIntegrator:
    """
    Интегратор всех систем защиты.
    
    Вычисляет общий риск на основе всех модулей.
    """
    
    # Веса систем (важность)
    SYSTEM_WEIGHTS = {
        'behavior': 0.15,
        'telegram': 0.10,
        'ip': 0.15,
        'ua': 0.10,
        'fingerprint': 0.10,
        'honeypot': 0.15,
        'ml': 0.15,
        'graph': 0.10
    }
    
    # Пороги
    BLOCK_THRESHOLD = 0.8
    CAPTCHA_THRESHOLD = 0.5
    SUSPICIOUS_THRESHOLD = 0.3
    
    def __init__(self):
        self._initialized = False
        self._cache: Dict[int, tuple] = {}  # user_id -> (result, timestamp)
        self._cache_ttl = 300  # 5 минут
    
    def _init_modules(self):
        """Инициализировать модули."""
        if self._initialized:
            return
        
        try:
            # Импорты с обработкой ошибок
            from analyzers.behavior_analyzer import get_behavior_analyzer
            from analyzers.telegram_account_checker import get_telegram_checker
            from analyzers.user_agent_analyzer import get_ua_analyzer
            from analyzers.fingerprint import get_fingerprint_analyzer
            from analyzers.ml_fraud_classifier import get_ml_classifier
            from analyzers.graph_analyzer import get_graph_analyzer
            from middleware.honeypot_middleware import get_honeypot_middleware
            from middleware.captcha_middleware import get_captcha_middleware
            from integrations.ip_reputation import get_ip_checker
            
            self.behavior = get_behavior_analyzer()
            self.telegram = get_telegram_checker()
            self.ua = get_ua_analyzer()
            self.fingerprint = get_fingerprint_analyzer()
            self.ml = get_ml_classifier()
            self.graph = get_graph_analyzer()
            self.honeypot = get_honeypot_middleware()
            self.captcha = get_captcha_middleware()
            self.ip = get_ip_checker()
            
            self._initialized = True
            log.info("Security modules initialized")
        
        except ImportError as e:
            log.warning(f"Some security modules not available: {e}")
            self._initialized = False
    
    async def check_user(
        self,
        message: types.Message,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        fingerprint_data: Optional[dict] = None
    ) -> SecurityResult:
        """
        Полная проверка пользователя.
        
        Args:
            message: Сообщение от пользователя
            user_agent: User-Agent (если доступен)
            ip_address: IP адрес (если доступен)
            fingerprint_data: Fingerprint данные (если доступны)
            
        Returns:
            Результат проверки
        """
        self._init_modules()
        
        user_id = message.from_user.id
        
        # Проверка кэша
        if user_id in self._cache:
            result, timestamp = self._cache[user_id]
            if time.time() - timestamp < self._cache_ttl:
                return result
        
        result = SecurityResult(user_id=user_id)
        
        # 1. Поведенческий анализ
        if self._initialized and self.behavior:
            behavior_result = self.behavior.record_message(
                user_id=user_id,
                message_text=message.text or "",
                timestamp=time.time()
            )
            result.behavior_score = behavior_result.risk_score
            
            if behavior_result.risk_level in ["high", "critical"]:
                result.risk_factors.append(f"Behavior: {behavior_result.risk_level}")
        
        # 2. Telegram аккаунт проверка
        if self._initialized and self.telegram:
            tg_result = await self.telegram.check_user(user_id)
            result.telegram_score = tg_result.risk_score
            
            if tg_result.is_suspicious:
                result.risk_factors.extend(tg_result.reasons[:2])
        
        # 3. IP проверка
        if self._initialized and self.ip and ip_address:
            ip_result = await self.ip.check_ip(ip_address)
            result.ip_score = ip_result.abuse_score / 100
            
            if ip_result.is_malicious:
                result.risk_factors.append(f"Malicious IP: {ip_result.abuse_score}%")
        
        # 4. User-Agent анализ
        if self._initialized and self.ua and user_agent:
            ua_result = self.ua.analyze(user_agent)
            result.ua_score = ua_result.confidence if ua_result.is_bot else 0.0
            
            if ua_result.is_bot:
                result.risk_factors.append(f"Bot UA: {ua_result.bot_type}")
        
        # 5. Fingerprint анализ
        if self._initialized and self.fingerprint and fingerprint_data:
            fp_result = self.fingerprint.analyze(fingerprint_data, user_id)
            result.fingerprint_score = fp_result.confidence if fp_result.is_suspicious else 0.0
            
            if fp_result.is_suspicious:
                result.risk_factors.extend(fp_result.reasons[:2])
        
        # 6. Honeypot проверка
        if self._initialized and self.honeypot:
            triggers = self.honeypot.get_user_triggers(user_id)
            result.honeypot_score = min(1.0, len(triggers) / 3)
            
            if triggers:
                result.risk_factors.append(f"Honeypot triggers: {len(triggers)}")
        
        # 7. ML классификатор
        if self._initialized and self.ml:
            # Собираем признаки
            from analyzers.ml_fraud_classifier import UserFeatures
            
            features = UserFeatures(
                user_id=user_id,
                # Заполняем из результатов
                min_response_time_ms=getattr(self, '_last_response_time', 1000),
                # ... остальные признаки
            )
            
            ml_result = self.ml.predict(features)
            result.ml_score = ml_result.probability
            
            if ml_result.is_fraud:
                result.risk_factors.extend(ml_result.risk_factors[:3])
        
        # 8. Graph анализ
        if self._initialized and self.graph:
            graph_result = self.graph.analyze_user(user_id)
            result.graph_score = graph_result.risk_score
            
            if graph_result.is_suspicious:
                result.risk_factors.extend(graph_result.reasons[:2])
        
        # Вычисление общего score
        self._calculate_total_score(result)
        
        # Определение статуса
        self._determine_status(result)
        
        # Кэширование
        self._cache[user_id] = (result, time.time())
        
        log.info(
            f"Security check: user={user_id}, "
            f"risk={result.risk_level}, score={result.total_risk_score:.2f}"
        )
        
        return result
    
    def _calculate_total_score(self, result: SecurityResult):
        """Вычислить общий risk score."""
        total = 0.0
        
        total += result.behavior_score * self.SYSTEM_WEIGHTS['behavior']
        total += result.telegram_score * self.SYSTEM_WEIGHTS['telegram']
        total += result.ip_score * self.SYSTEM_WEIGHTS['ip']
        total += result.ua_score * self.SYSTEM_WEIGHTS['ua']
        total += result.fingerprint_score * self.SYSTEM_WEIGHTS['fingerprint']
        total += result.honeypot_score * self.SYSTEM_WEIGHTS['honeypot']
        total += result.ml_score * self.SYSTEM_WEIGHTS['ml']
        total += result.graph_score * self.SYSTEM_WEIGHTS['graph']
        
        result.total_risk_score = min(total, 1.0)
        
        # Определение уровня риска
        if total >= self.BLOCK_THRESHOLD:
            result.risk_level = "critical"
        elif total >= 0.6:
            result.risk_level = "high"
        elif total >= self.CAPTCHA_THRESHOLD:
            result.risk_level = "medium"
        elif total >= self.SUSPICIOUS_THRESHOLD:
            result.risk_level = "low"
        else:
            result.risk_level = "none"
    
    def _determine_status(self, result: SecurityResult):
        """Определить статус пользователя."""
        # Блокировка
        if result.risk_level == "critical":
            result.is_blocked = True
            result.blocked_reason = "Высокий уровень риска"
        
        # Подозрительный
        if result.risk_level in ["medium", "high"]:
            result.is_suspicious = True
        
        # Требуется CAPTCHA
        if result.total_risk_score >= self.CAPTCHA_THRESHOLD:
            result.requires_captcha = True
        
        # Требуется верификация
        if result.total_risk_score >= self.BLOCK_THRESHOLD:
            result.requires_verification = True
    
    async def send_captcha(self, message: types.Message):
        """Отправить CAPTCHA."""
        if self._initialized and self.captcha:
            await self.captcha.send_captcha(message.from_user.id, message)
    
    def is_verified(self, user_id: int) -> bool:
        """Проверить верификацию."""
        if self._initialized and self.captcha:
            return self.captcha.is_verified(user_id)
        return False
    
    def get_risk_report(self, user_id: int) -> dict:
        """Получить подробный отчёт о рисках."""
        if user_id in self._cache:
            result, _ = self._cache[user_id]
            
            return {
                'user_id': user_id,
                'risk_level': result.risk_level,
                'total_score': result.total_risk_score,
                'scores': {
                    'behavior': result.behavior_score,
                    'telegram': result.telegram_score,
                    'ip': result.ip_score,
                    'ua': result.ua_score,
                    'fingerprint': result.fingerprint_score,
                    'honeypot': result.honeypot_score,
                    'ml': result.ml_score,
                    'graph': result.graph_score
                },
                'risk_factors': result.risk_factors,
                'is_blocked': result.is_blocked,
                'requires_captcha': result.requires_captcha
            }
        
        return {'error': 'User not in cache'}


# Глобальный экземпляр
_integrator: Optional[SecurityIntegrator] = None


def get_security_integrator() -> SecurityIntegrator:
    """Получить глобальный интегратор."""
    global _integrator
    if _integrator is None:
        _integrator = SecurityIntegrator()
    return _integrator


def init_security_integrator() -> SecurityIntegrator:
    """Инициализировать глобальный интегратор."""
    global _integrator
    _integrator = SecurityIntegrator()
    return _integrator
