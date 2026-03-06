"""
Тесты для link_checker.py
"""
import pytest
import sys
import os
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.link_checker import LinkChecker, LinkCheckResult


@pytest.fixture
def temp_trusted_domains():
    """Создаёт временный файл с доверенными доменами."""
    test_data = {
        "trusted": [
            "sberbank.ru",
            "tinkoff.ru",
            "gosuslugi.ru",
            "yandex.ru"
        ],
        "brand_keywords": [
            "sber", "sberbank", "tinkoff", "tbank",
            "gosuslugi", "vtb", "alfa"
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_data, f, ensure_ascii=False, indent=2)
        temp_path = f.name
    
    yield temp_path
    
    os.unlink(temp_path)


@pytest.fixture
def checker(temp_trusted_domains):
    """Фикстура LinkChecker с тестовыми данными."""
    return LinkChecker(trusted_path=temp_trusted_domains)


class TestExtractUrls:
    """Тесты извлечения URL из текста."""

    def test_extract_single_url(self, checker):
        """Извлечение одной ссылки."""
        text = "Перейдите по ссылке https://example.com"
        urls = checker.extract_urls(text)
        assert len(urls) == 1
        assert "https://example.com" in urls

    def test_extract_multiple_urls(self, checker):
        """Извлечение нескольких ссылок."""
        text = "Посетите https://site1.com и http://site2.ru/page"
        urls = checker.extract_urls(text)
        assert len(urls) == 2

    def test_extract_www_url(self, checker):
        """Извлечение www-ссылки."""
        text = "Зайдите на www.example.com"
        urls = checker.extract_urls(text)
        assert len(urls) == 1
        # Должна добавиться схема
        assert urls[0].startswith("http://")

    def test_extract_no_urls(self, checker):
        """Текст без ссылок."""
        text = "Просто текст без ссылок"
        urls = checker.extract_urls(text)
        assert len(urls) == 0

    def test_extract_url_with_trailing_punctuation(self, checker):
        """URL с конечной пунктуацией."""
        text = "Смотрите https://example.com."
        urls = checker.extract_urls(text)
        assert len(urls) == 1
        # Точка должна быть убрана
        assert urls[0].endswith("com")
        assert not urls[0].endswith("com.")


@pytest.mark.asyncio
class TestCheckUrl:
    """Тесты проверки URL."""

    async def test_trusted_domain(self, checker):
        """Домен в белом списке."""
        result = await checker.check_url("https://sberbank.ru")
        assert result.risk_level == "safe"
        assert result.risk_score == 0.0
        assert result.is_trusted is True

    async def test_suspicious_tld(self, checker):
        """Подозрительная доменная зона."""
        result = await checker.check_url("https://example.xyz")
        assert result.risk_score >= 0.3
        assert any("TLD" in r or "доменная зона" in r for r in result.reasons)

    async def test_typosquatting(self, checker):
        """Домен с бренд-ключевым словом."""
        result = await checker.check_url("https://sber-fake.com")
        assert result.risk_score >= 0.4
        assert any("бренд" in r.lower() or "sber" in r for r in result.reasons)

    async def test_suspicious_pattern_login(self, checker):
        """Подозрительный паттерн login."""
        result = await checker.check_url("https://login123.com")
        assert result.risk_score >= 0.2

    async def test_suspicious_pattern_ip(self, checker):
        """Прямой IP-адрес в URL."""
        result = await checker.check_url("http://192.168.1.1/login")
        assert result.risk_score >= 0.2

    async def test_long_domain(self, checker):
        """Длинный домен."""
        long_domain = "very-long-suspicious-domain-name-that-is-too-long.com"
        result = await checker.check_url(f"https://{long_domain}")
        assert any("длинн" in r.lower() for r in result.reasons)

    async def test_many_subdomains(self, checker):
        """Много уровней поддоменов."""
        result = await checker.check_url("https://sub1.sub2.sub3.example.com")
        assert any("поддомен" in r.lower() for r in result.reasons)

    async def test_safe_url(self, checker):
        """Безопасная ссылка."""
        result = await checker.check_url("https://normal-site.ru")
        assert result.risk_level == "safe"
        assert result.risk_score < 0.25


@pytest.mark.asyncio
class TestCheckAll:
    """Тесты массовой проверки ссылок."""

    async def test_check_all_multiple_urls(self, checker):
        """Проверка всех ссылок в тексте."""
        text = """
            Перейдите на https://sberbank.ru (официальный)
            или на https://fake-sber.xyz (подозрительно)
        """
        results = await checker.check_all(text)
        assert len(results) == 2
        
        risk_levels = [r.risk_level for r in results]
        assert "safe" in risk_levels

    async def test_check_all_no_urls(self, checker):
        """Текст без ссылок."""
        results = await checker.check_all("Просто текст")
        assert len(results) == 0


class TestLinkCheckResult:
    """Тесты dataclass результата."""

    def test_emoji_danger(self):
        """Emoji для danger уровня."""
        result = LinkCheckResult(
            url="https://evil.com",
            domain="evil.com",
            risk_score=0.8,
            risk_level="danger",
            reasons=["Плохой сайт"]
        )
        assert result.emoji == "🔴"

    def test_emoji_suspicious(self):
        """Emoji для suspicious уровня."""
        result = LinkCheckResult(
            url="https://maybe-evil.com",
            domain="maybe-evil.com",
            risk_score=0.4,
            risk_level="suspicious",
            reasons=["Подозрительно"]
        )
        assert result.emoji == "🟡"

    def test_emoji_safe(self):
        """Emoji для safe уровня."""
        result = LinkCheckResult(
            url="https://good-site.ru",
            domain="good-site.ru",
            risk_score=0.1,
            risk_level="safe",
            reasons=["Всё хорошо"]
        )
        assert result.emoji == "🟢"

    def test_is_trusted_flag(self):
        """Флаг is_trusted для доверенного домена."""
        result = LinkCheckResult(
            url="https://sberbank.ru",
            domain="sberbank.ru",
            risk_score=0.0,
            risk_level="safe",
            is_trusted=True
        )
        assert result.is_trusted is True
