import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analyzers.text_analyzer import TextAnalyzer

@pytest.fixture
def analyzer():
    return TextAnalyzer()

def test_safe_message(analyzer):
    result = analyzer.analyze("Привет, как дела? Пойдем сегодня в кино?")
    assert result.risk_level == "safe"
    assert result.risk_score < 0.25

def test_obvious_scam_message(analyzer):
    # Фразы, типичные для мошенников (важно: паттерны зависят от scam_patterns.json)
    msg = "Срочно! Ваша карта заблокирована, продиктуйте код из СМС для отмены перевода."
    result = analyzer.analyze(msg)
    assert result.risk_level in ["suspicious", "danger"]
    assert result.risk_score >= 0.25

def test_empty_message(analyzer):
    result = analyzer.analyze("")
    assert result.risk_level == "safe"
    assert result.risk_score == 0.0

def test_crypto_wallet_message(analyzer):
    msg = "Переведите USDT на кошелек bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh срочно"
    result = analyzer.analyze(msg)
    assert result.risk_score >= 0.25 # У нас есть crypto_wallet и urgency
    assert any(t["category"] == "Запрос перевода в криптовалюте" for t in result.triggers)
