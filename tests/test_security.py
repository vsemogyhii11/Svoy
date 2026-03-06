"""
Тесты для модулей безопасности:
- User-Agent Analyzer
- Fingerprint Analyzer
- IP Tracker
"""
import pytest
import sys
import os
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.user_agent_analyzer import UserAgentAnalyzer, UserAgentResult
from analyzers.fingerprint import FingerprintAnalyzer, FingerprintResult


class TestUserAgentAnalyzer:
    """Тесты анализатора User-Agent."""

    @pytest.fixture
    def analyzer(self):
        return UserAgentAnalyzer()

    def test_empty_user_agent(self, analyzer):
        """Пустой User-Agent."""
        result = analyzer.analyze("")
        assert result.is_bot is True
        assert result.confidence >= 0.9
        assert result.bot_type == "empty_ua"

    def test_selenium_detected(self, analyzer):
        """Обнаружение Selenium."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Selenium/4.0.0"
        result = analyzer.analyze(ua)
        assert result.is_bot is True
        assert result.bot_type == "selenium"
        assert result.confidence >= 0.9

    def test_puppeteer_detected(self, analyzer):
        """Обнаружение Puppeteer."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.124 Safari/537.36 Puppeteer/10.0.0"
        result = analyzer.analyze(ua)
        assert result.is_bot is True
        assert result.is_headless is True
        assert result.confidence >= 0.9

    def test_playwright_detected(self, analyzer):
        """Обнаружение Playwright."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Playwright/1.15.0"
        result = analyzer.analyze(ua)
        assert result.is_bot is True
        assert result.bot_type == "playwright"

    def test_scrapy_detected(self, analyzer):
        """Обнаружение Scrapy."""
        ua = "Scrapy/2.5.0 (+https://scrapy.org)"
        result = analyzer.analyze(ua)
        assert result.is_bot is True
        assert result.bot_type == "scrapy"

    def test_curl_detected(self, analyzer):
        """Обнаружение curl."""
        ua = "curl/7.68.0"
        result = analyzer.analyze(ua)
        assert result.is_bot is True
        assert result.bot_type == "curl"

    def test_python_requests_detected(self, analyzer):
        """Обнаружение python-requests."""
        ua = "python-requests/2.26.0"
        result = analyzer.analyze(ua)
        assert result.is_bot is True
        assert result.bot_type == "python_requests"

    def test_legitimate_chrome(self, analyzer):
        """Легитимный Chrome."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        result = analyzer.analyze(ua)
        assert result.is_bot is False
        assert result.browser == "Chrome"
        assert result.os == "Windows"

    def test_legitimate_firefox(self, analyzer):
        """Легитимный Firefox."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        result = analyzer.analyze(ua)
        assert result.is_bot is False
        assert result.browser == "Firefox"

    def test_telegram_android(self, analyzer):
        """Легитимный Telegram Android."""
        ua = "TelegramAndroid/7.8.0 (Android 11; SDK 30; arm64-v8a; ru; Pixel 5)"
        result = analyzer.analyze(ua)
        assert result.is_bot is False
        assert analyzer.is_legitimate_telegram(ua) is True

    def test_telegram_ios(self, analyzer):
        """Легитимный Telegram iOS."""
        ua = "TelegramiOS/7.8.0 (iPhone; iOS 14.6; ru; iPhone12,1)"
        result = analyzer.analyze(ua)
        assert result.is_bot is False
        assert analyzer.is_legitimate_telegram(ua) is True

    def test_suspicious_incompatible(self, analyzer):
        """Подозрительная несовместимая конфигурация."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0 Firefox/89.0"
        result = analyzer.analyze(ua)
        assert result.is_suspicious is True
        assert any("incompatible" in r.lower() for r in result.reasons)

    def test_googlebot_detected(self, analyzer):
        """Googlebot."""
        ua = "Googlebot/2.1 (+http://www.google.com/bot.html)"
        result = analyzer.analyze(ua)
        assert result.is_bot is True
        assert result.bot_type == "googlebot"
        assert result.confidence >= 0.99

    def test_risk_levels(self, analyzer):
        """Уровни риска."""
        # Высокий риск
        result_high = analyzer.analyze("Scrapy/2.5.0")
        assert result_high.risk_level == "high"

        # Низкий риск (легитимный)
        result_low = analyzer.analyze("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0")
        assert result_low.risk_level == "none"


class TestFingerprintAnalyzer:
    """Тесты анализатора fingerprint."""

    @pytest.fixture
    def temp_db(self):
        """Временная база fingerprint."""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = f.name
        
        yield temp_path
        
        os.unlink(temp_path)

    @pytest.fixture
    def analyzer(self, temp_db):
        return FingerprintAnalyzer(db_path=temp_db)

    def test_normal_device(self, analyzer):
        """Нормальное устройство."""
        fp_data = {
            'screen': '1920x1080',
            'timezone': 'Europe/Moscow',
            'language': 'ru-RU',
            'platform': 'Win32',
            'browser': 'Chrome 91.0',
            'os': 'Windows 10',
            'cpu': 'Intel Core i7',
            'gpu': 'NVIDIA GeForce GTX 1060',
            'fonts': ['Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Tahoma'],
            'user_agent': 'Mozilla/5.0 ...'
        }
        
        result = analyzer.analyze(fp_data, user_id=123456)
        
        assert result.is_suspicious is False
        assert result.is_emulator is False
        assert result.is_vm is False
        assert len(result.fingerprint_hash) == 16

    def test_emulator_detected(self, analyzer):
        """Обнаружение эмулятора."""
        fp_data = {
            'screen': '1024x768',
            'timezone': 'UTC',
            'language': 'en-US',
            'platform': 'Linux x86_64',
            'browser': 'Chrome 91.0',
            'os': 'Android',
            'cpu': '',
            'gpu': 'SwiftShader',
            'fonts': ['Arial'],
            'user_agent': 'Mozilla/5.0 ... BlueStacks'
        }
        
        result = analyzer.analyze(fp_data, user_id=123456)
        
        assert result.is_emulator is True
        assert result.confidence >= 0.8

    def test_vm_detected(self, analyzer):
        """Обнаружение VM."""
        fp_data = {
            'screen': '1920x1080',
            'timezone': 'UTC',
            'language': 'en-US',
            'platform': 'Linux x86_64',
            'browser': 'Firefox 89.0',
            'os': 'Linux',
            'cpu': 'QEMU Virtual CPU',
            'gpu': 'VMware SVGA',
            'fonts': [],
            'user_agent': 'Mozilla/5.0 ...'
        }
        
        result = analyzer.analyze(fp_data, user_id=123456)
        
        assert result.is_vm is True
        assert result.confidence >= 0.7

    def test_linked_accounts(self, analyzer):
        """Связанные аккаунты."""
        # Один и тот же fingerprint для разных пользователей
        fp_data = {
            'screen': '1920x1080',
            'timezone': 'Europe/Moscow',
            'language': 'ru-RU',
            'platform': 'Win32',
            'browser': 'Chrome 91.0',
            'os': 'Windows 10',
            'cpu': 'Intel',
            'gpu': 'NVIDIA',
            'fonts': ['Arial', 'Times'],
            'user_agent': 'Mozilla/5.0 ...'
        }
        
        # Первый пользователь
        result1 = analyzer.analyze(fp_data, user_id=111)
        assert len(result1.linked_accounts) == 0
        
        # Второй пользователь (связанный)
        result2 = analyzer.analyze(fp_data, user_id=222)
        assert 111 in result2.linked_accounts
        
        # Третий пользователь (подозрительно много)
        result3 = analyzer.analyze(fp_data, user_id=333)
        assert result3.is_suspicious is True
        assert len(result3.linked_accounts) >= 2

    def test_fingerprint_hash_consistency(self, analyzer):
        """Консистентность хэша."""
        fp_data = {
            'screen': '1920x1080',
            'timezone': 'Europe/Moscow',
            'language': 'ru-RU',
            'platform': 'Win32',
            'browser': 'Chrome 91.0',
            'os': 'Windows 10',
            'cpu': 'Intel',
            'gpu': 'NVIDIA',
            'fonts': ['Arial', 'Times'],
            'user_agent': 'Mozilla/5.0 ...'
        }
        
        result1 = analyzer.analyze(fp_data, user_id=111)
        result2 = analyzer.analyze(fp_data, user_id=111)
        
        assert result1.fingerprint_hash == result2.fingerprint_hash

    def test_rooted_device(self, analyzer):
        """Root устройство."""
        fp_data = {
            'screen': '2400x1080',
            'timezone': 'Europe/Moscow',
            'language': 'ru-RU',
            'platform': 'Linux aarch64',
            'browser': 'Chrome 91.0',
            'os': 'Android 11',
            'cpu': 'Snapdragon',
            'gpu': 'Adreno',
            'fonts': ['Roboto', 'Noto'],
            'user_agent': 'Mozilla/5.0 ...',
            'is_rooted': True
        }
        
        result = analyzer.analyze(fp_data, user_id=123456)
        
        assert result.is_rooted is True
        assert result.confidence >= 0.5

    def test_get_linked_accounts(self, analyzer):
        """Получение связанных аккаунтов."""
        fp_data = {
            'screen': '1920x1080',
            'timezone': 'UTC',
            'language': 'en',
            'platform': 'Win32',
            'browser': 'Chrome',
            'os': 'Windows',
            'cpu': 'Intel',
            'gpu': 'NVIDIA',
            'fonts': ['Arial'],
            'user_agent': 'Mozilla/5.0 ...'
        }
        
        analyzer.analyze(fp_data, user_id=100)
        analyzer.analyze(fp_data, user_id=200)
        analyzer.analyze(fp_data, user_id=300)
        
        linked = analyzer.get_linked_accounts(200)
        assert set(linked) == {100, 300}

    def test_risk_levels(self, analyzer):
        """Уровни риска."""
        # Высокий риск (эмулятор + много аккаунтов)
        fp_emulator = {
            'screen': '1024x768',
            'timezone': 'UTC',
            'language': 'en',
            'platform': 'Linux',
            'browser': 'Chrome',
            'os': 'Android',
            'cpu': '',
            'gpu': 'SwiftShader',
            'fonts': ['Arial'],
            'user_agent': '... BlueStacks ...'
        }
        
        result = analyzer.analyze(fp_emulator, user_id=999)
        assert result.risk_level == "high"
