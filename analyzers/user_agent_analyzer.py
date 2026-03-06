"""
User-Agent Analyzer — детекция ботов по User-Agent.

Анализирует User-Agent строку на признаки:
- Автоматизации (боты, скраперы, headless браузеры)
- Подозрительных паттернов
- Несовместимостей

Использование:
    from analyzers.user_agent_analyzer import UserAgentAnalyzer
    
    analyzer = UserAgentAnalyzer()
    result = analyzer.analyze("Mozilla/5.0 ...")
    
    if result.is_bot:
        print(f"Бот обнаружен: {result.confidence}")
"""

import re
import logging
from dataclasses import dataclass
from typing import List, Optional

log = logging.getLogger("svoy_bot.ua_analyzer")


@dataclass
class UserAgentResult:
    """Результат анализа User-Agent."""
    user_agent: str
    is_bot: bool = False
    confidence: float = 0.0  # 0.0 - 1.0
    bot_type: Optional[str] = None
    browser: Optional[str] = None
    os: Optional[str] = None
    device: Optional[str] = None
    is_headless: bool = False
    is_suspicious: bool = False
    reasons: List[str] = None
    
    def __post_init__(self):
        if self.reasons is None:
            self.reasons = []
    
    @property
    def risk_level(self) -> str:
        if self.confidence >= 0.8:
            return "high"
        elif self.confidence >= 0.5:
            return "medium"
        elif self.confidence >= 0.3:
            return "low"
        return "none"


class UserAgentAnalyzer:
    """
    Анализатор User-Agent строк.
    
    Обнаруживает:
    - Известные бот-фреймворки (Selenium, Puppeteer, Playwright)
    - Headless браузеры
    - Скраперы и парсеры
    - Подозрительные паттерны
    """
    
    # Паттерны известных ботов
    BOT_PATTERNS = [
        # Автоматизация
        (r'selenium', 'selenium', 0.95),
        (r'puppeteer', 'puppeteer', 0.95),
        (r'playwright', 'playwright', 0.95),
        (r'phantomjs', 'phantomjs', 0.90),
        (r'headlesschrome', 'headless_chrome', 0.90),
        
        # Скраперы
        (r'scrapy', 'scrapy', 0.95),
        (r'curl', 'curl', 0.80),
        (r'wget', 'wget', 0.80),
        (r'python-requests', 'python_requests', 0.85),
        (r'python-urllib', 'python_urllib', 0.85),
        (r'httpx', 'httpx', 0.80),
        (r'http.client', 'http_client', 0.80),
        
        # Боты общего назначения
        (r'bot', 'generic_bot', 0.60),
        (r'spider', 'spider', 0.70),
        (r'crawler', 'crawler', 0.70),
        (r'scraper', 'scraper', 0.75),
        
        # Headless индикаторы
        (r'headless', 'headless', 0.85),
        
        # Специфичные боты
        (r'googlebot', 'googlebot', 0.99),
        (r'bingbot', 'bingbot', 0.99),
        (r'yandexbot', 'yandexbot', 0.99),
        (r'slackbot', 'slackbot', 0.95),
        (r'telegrambot', 'telegrambot', 0.99),
    ]
    
    # Подозрительные паттерны
    SUSPICIOUS_PATTERNS = [
        # Пустой или очень короткий UA
        (lambda ua: len(ua) < 20, "Very short User-Agent", 0.70),
        
        # Отсутствие версий браузеров
        (lambda ua: 'Mozilla' in ua and 'Chrome' in ua and 'Safari' in ua and len(ua) < 50,
         "Suspiciously short Chrome UA", 0.60),
        
        # Несовместимости
        (lambda ua: 'Chrome' in ua and 'Firefox' in ua,
         "Chrome + Firefox in same UA (incompatible)", 0.80),
        
        (lambda ua: 'MSIE' in ua and 'Chrome' in ua,
         "IE + Chrome in same UA (incompatible)", 0.85),
        
        # Старые версии
        (lambda ua: re.search(r'MSIE\s[4-6]', ua),
         "Very old IE version", 0.70),
        
        # Отсутствие стандартных полей
        (lambda ua: 'Mozilla' not in ua and len(ua) > 20,
         "Missing Mozilla prefix", 0.50),
    ]
    
    # Паттерны headless браузеров
    HEADLESS_PATTERNS = [
        r'headless',
        r'phantomjs',
        r'selenium',
        r'puppeteer',
        r'playwright',
        r'webdriver',
    ]
    
    # Нормальные браузеры
    BROWSER_PATTERNS = [
        (r'Chrome/[\d.]+', 'Chrome'),
        (r'Firefox/[\d.]+', 'Firefox'),
        (r'Safari/[\d.]+', 'Safari'),
        (r'Edg/[\d.]+', 'Edge'),
        (r'Opera[\d./]+', 'Opera'),
        (r'MSIE\s[\d.]+', 'Internet Explorer'),
        (r'Trident/[\d.]+', 'Internet Explorer'),
    ]
    
    # Операционные системы
    OS_PATTERNS = [
        (r'Windows NT [\d.]+', 'Windows'),
        (r'Mac OS X [\d_]+', 'macOS'),
        (r'Linux', 'Linux'),
        (r'Android [\d.]+', 'Android'),
        (r'iPhone OS [\d_]+', 'iOS'),
        (r'iPad.*OS [\d_]+', 'iPadOS'),
    ]
    
    # Устройства
    DEVICE_PATTERNS = [
        (r'Mobile', 'mobile'),
        (r'Tablet', 'tablet'),
        (r'iPad', 'tablet'),
        (r'Android.*Mobile', 'mobile'),
    ]
    
    def analyze(self, user_agent: str) -> UserAgentResult:
        """
        Проанализировать User-Agent.
        
        Args:
            user_agent: User-Agent строка
            
        Returns:
            Результат анализа
        """
        if not user_agent:
            return UserAgentResult(
                user_agent="",
                is_bot=True,
                confidence=0.90,
                bot_type="empty_ua",
                reasons=["Empty User-Agent"]
            )
        
        result = UserAgentResult(user_agent=user_agent)
        
        # Проверка на бот-паттерны
        for pattern, bot_type, confidence in self.BOT_PATTERNS:
            if re.search(pattern, user_agent, re.IGNORECASE):
                result.is_bot = True
                result.bot_type = bot_type
                result.confidence = max(result.confidence, confidence)
                result.reasons.append(f"Bot pattern detected: {bot_type}")
                break
        
        # Проверка на headless
        for pattern in self.HEADLESS_PATTERNS:
            if re.search(pattern, user_agent, re.IGNORECASE):
                result.is_headless = True
                result.reasons.append("Headless browser detected")
                break
        
        # Проверка на подозрительные паттерны
        for check, reason, confidence in self.SUSPICIOUS_PATTERNS:
            try:
                if check(user_agent):
                    result.is_suspicious = True
                    result.confidence = max(result.confidence, confidence)
                    result.reasons.append(reason)
            except Exception:
                pass
        
        # Определение браузера
        for pattern, browser in self.BROWSER_PATTERNS:
            if re.search(pattern, user_agent):
                result.browser = browser
                break
        
        # Определение ОС
        for pattern, os_name in self.OS_PATTERNS:
            if re.search(pattern, user_agent):
                result.os = os_name
                break
        
        # Определение устройства
        for pattern, device in self.DEVICE_PATTERNS:
            if re.search(pattern, user_agent):
                result.device = device
                break
        
        # Telegram-клиенты (нормальные)
        if 'Telegram' in user_agent and 'bot' not in user_agent.lower():
            result.is_bot = False
            result.confidence = 0.0
            result.reasons = ["Legitimate Telegram client"]
        
        log.debug(
            f"UA analysis: bot={result.is_bot}, "
            f"confidence={result.confidence}, "
            f"type={result.bot_type}"
        )
        
        return result
    
    def is_legitimate_telegram(self, user_agent: str) -> bool:
        """
        Проверка на легитимный Telegram клиент.
        
        Telegram клиенты имеют специфичные UA:
        - Telegram Android
        - Telegram iOS
        - Telegram Desktop
        """
        if not user_agent:
            return False
        
        # Паттерны легитимных клиентов
        legitimate_patterns = [
            r'TelegramAndroid',
            r'TelegramiOS',
            r'TelegramDesktop',
            r'TelegramMac',
        ]
        
        for pattern in legitimate_patterns:
            if re.search(pattern, user_agent):
                return True
        
        return False


# Глобальный экземпляр
_analyzer: Optional[UserAgentAnalyzer] = None


def get_ua_analyzer() -> UserAgentAnalyzer:
    """Получить глобальный анализатор."""
    global _analyzer
    if _analyzer is None:
        _analyzer = UserAgentAnalyzer()
    return _analyzer
