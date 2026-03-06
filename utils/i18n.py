"""
Мультиязычность (i18n).

Определяет язык пользователя и возвращает строки из словарей.
Поддержка: ru (по умолчанию), kz, en.
"""

import json
import logging
from pathlib import Path

log = logging.getLogger("svoy_bot.i18n")

_strings: dict[str, dict] = {}
DEFAULT_LANG = "ru"


def load_locales(locales_dir: str = "locales"):
    """Загрузить все языковые файлы."""
    global _strings
    p = Path(locales_dir)
    if not p.exists():
        p = Path(__file__).parent.parent / locales_dir
    if not p.exists():
        log.warning(f"Locales dir not found: {p}")
        return

    for lang_file in p.glob("*.json"):
        lang = lang_file.stem  # "ru", "kz", "en"
        with open(lang_file, "r", encoding="utf-8") as f:
            _strings[lang] = json.load(f)
        log.info(f"Loaded locale: {lang} ({len(_strings[lang])} strings)")


def t(key: str, lang: str = DEFAULT_LANG, **kwargs) -> str:
    """
    Получить перевод по ключу.
    
    Использование:
        t("welcome_message", lang="kz")
        t("risk_score", lang="en", score=75)
    """
    # Сначала ищем в запрошенном языке
    if lang in _strings and key in _strings[lang]:
        template = _strings[lang][key]
    # Fallback на русский
    elif DEFAULT_LANG in _strings and key in _strings[DEFAULT_LANG]:
        template = _strings[DEFAULT_LANG][key]
    else:
        return key  # ключ как есть

    # Подставляем параметры
    if kwargs:
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError):
            return template
    return template


def get_user_lang(language_code: str | None) -> str:
    """Определить язык по Telegram language_code."""
    if not language_code:
        return DEFAULT_LANG

    code = language_code.lower()[:2]
    if code in _strings:
        return code
    # Маппинг
    mapping = {"kk": "kz", "uz": "uz"}
    return mapping.get(code, DEFAULT_LANG)
