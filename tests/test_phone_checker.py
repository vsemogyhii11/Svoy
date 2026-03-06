"""
Тесты для phone_checker.py
"""
import pytest
import sys
import os
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.phone_checker import PhoneChecker, PhoneCheckResult


@pytest.fixture
def temp_phone_db():
    """Создаёт временную базу телефонов для тестов."""
    test_data = {
        "numbers": {
            "+79991234567": {
                "type": "danger",
                "description": "Известный мошенник",
                "reports": 5
            },
            "+74951234567": {
                "type": "spam",
                "description": "Спам-рассылка",
                "reports": 2
            }
        },
        "prefixes_warning": ["+7843", "+7812"]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_data, f, ensure_ascii=False, indent=2)
        temp_path = f.name
    
    yield temp_path
    
    os.unlink(temp_path)


@pytest.fixture
def checker(temp_phone_db):
    """Фикстура PhoneChecker с тестовой базой."""
    return PhoneChecker(phones_path=temp_phone_db)


class TestNormalizePhone:
    """Тесты нормализации номеров."""

    def test_normalize_plus7_format(self, checker):
        """Нормализация +7XXXXXXXXXX."""
        result = checker.normalize_phone("+79991234567")
        assert result == "+79991234567"

    def test_normalize_8_format(self, checker):
        """Конвертация 8XXXXXXXXXX → +7XXXXXXXXXX."""
        result = checker.normalize_phone("89991234567")
        assert result == "+79991234567"

    def test_normalize_7_format(self, checker):
        """Конвертация 7XXXXXXXXXX → +7XXXXXXXXXX."""
        result = checker.normalize_phone("79991234567")
        assert result == "+79991234567"

    def test_normalize_with_spaces(self, checker):
        """Нормализация номера с пробелами."""
        result = checker.normalize_phone("+7 999 123-45-67")
        assert result == "+79991234567"

    def test_normalize_with_parens(self, checker):
        """Нормализация номера со скобками."""
        result = checker.normalize_phone("8(999)123-45-67")
        assert result == "+79991234567"

    def test_normalize_with_dashes(self, checker):
        """Нормализация номера с дефисами."""
        result = checker.normalize_phone("8-999-123-45-67")
        assert result == "+79991234567"


class TestExtractPhones:
    """Тесты извлечения номеров из текста."""

    def test_extract_single_phone(self, checker):
        """Извлечение одного номера."""
        text = "Позвоните мне на +79991234567"
        phones = checker.extract_phones(text)
        assert len(phones) == 1
        assert "+79991234567" in phones

    def test_extract_multiple_phones(self, checker):
        """Извлечение нескольких номеров."""
        text = "Звоните на +79991234567 или 84951234567"
        phones = checker.extract_phones(text)
        assert len(phones) == 2

    def test_extract_no_phones(self, checker):
        """Текст без номеров."""
        text = "Привет, как дела?"
        phones = checker.extract_phones(text)
        assert len(phones) == 0

    def test_extract_different_formats(self, checker):
        """Извлечение номеров в разных форматах."""
        text = """
            +79991234567
            8(999)123-45-67
            8-999-123-45-67
            +7 999 123 45 67
        """
        phones = checker.extract_phones(text)
        # Все должны нормализоваться до одного формата
        assert len(phones) >= 1


class TestCheckPhone:
    """Тесты проверки номеров."""

    def test_check_danger_number(self, checker):
        """Проверка номера из чёрного списка."""
        result = checker.check_phone("+79991234567")
        assert result.risk_level == "danger"
        assert result.reports == 5
        assert "Известный мошенник" in result.description

    def test_check_spam_number(self, checker):
        """Проверка спам-номера."""
        result = checker.check_phone("+74951234567")
        assert result.risk_level == "spam"
        assert result.reports == 2

    def test_check_prefix_warning(self, checker):
        """Предупреждение о городском коде."""
        result = checker.check_phone("+78431234567")
        assert result.risk_level == "safe"
        assert "Городской код" in result.description

    def test_check_clean_number(self, checker):
        """Проверка чистого номера."""
        result = checker.check_phone("+79001112233")
        assert result.risk_level == "safe"
        assert "не найден в базе" in result.description.lower()


class TestCheckAll:
    """Тесты массовой проверки."""

    def test_check_all_in_text(self, checker):
        """Проверка всех номеров в тексте."""
        text = "Мошенники звонят с +79991234567 и +74951234567"
        results = checker.check_all(text)
        assert len(results) == 2
        
        risk_levels = [r.risk_level for r in results]
        assert "danger" in risk_levels
        assert "spam" in risk_levels

    def test_check_all_empty_text(self, checker):
        """Пустой текст."""
        results = checker.check_all("")
        assert len(results) == 0


class TestAddNumber:
    """Тесты добавления номеров."""

    def test_add_new_number(self, temp_phone_db):
        """Добавление нового номера."""
        checker = PhoneChecker(phones_path=temp_phone_db)
        checker.add_number("+79001112233", "danger", "Тестовый мошенник")
        
        # Пересоздаём checker для загрузки обновлённых данных
        checker2 = PhoneChecker(phones_path=temp_phone_db)
        result = checker2.check_phone("+79001112233")
        
        assert result.risk_level == "danger"
        assert result.reports == 1

    def test_add_existing_number_increments_reports(self, temp_phone_db):
        """Добавление существующего номера увеличивает счётчик."""
        checker = PhoneChecker(phones_path=temp_phone_db)
        checker.add_number("+79991234567", "danger", "Повторная жалоба")
        
        checker2 = PhoneChecker(phones_path=temp_phone_db)
        result = checker2.check_phone("+79991234567")
        
        assert result.reports == 6  # было 5 + 1


class TestPhoneCheckResult:
    """Тесты dataclass результата."""

    def test_emoji_danger(self):
        """Emoji для danger уровня."""
        result = PhoneCheckResult(
            phone="+79991234567",
            risk_level="danger",
            description="Тест"
        )
        assert result.emoji == "🔴"

    def test_emoji_suspicious(self):
        """Emoji для suspicious уровня."""
        result = PhoneCheckResult(
            phone="+79991234567",
            risk_level="suspicious",
            description="Тест"
        )
        assert result.emoji == "🟡"

    def test_emoji_spam(self):
        """Emoji для spam уровня."""
        result = PhoneCheckResult(
            phone="+79991234567",
            risk_level="spam",
            description="Тест"
        )
        assert result.emoji == "🟡"

    def test_emoji_safe(self):
        """Emoji для safe уровня."""
        result = PhoneCheckResult(
            phone="+79991234567",
            risk_level="safe",
            description="Тест"
        )
        assert result.emoji == "🟢"
