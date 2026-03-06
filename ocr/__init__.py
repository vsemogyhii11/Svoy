"""
OCR-модуль: распознавание текста с изображений (скриншотов SMS).

Пользователь присылает фото → бот извлекает текст → анализирует на мошенничество.
Использует pytesseract (offline) с fallback-сообщением при отсутствии.
"""

import logging
import tempfile
from pathlib import Path

log = logging.getLogger("svoy_bot.ocr")

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    log.info("pytesseract/Pillow not installed — OCR disabled")


async def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Распознать текст с изображения.
    Возвращает распознанный текст или пустую строку.
    """
    if not OCR_AVAILABLE:
        return ""

    try:
        # Сохраняем во временный файл
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(image_bytes)
            tmp_path = f.name

        img = Image.open(tmp_path)
        # Русский + английский
        text = pytesseract.image_to_string(img, lang="rus+eng")

        # Чистим результат
        text = text.strip()
        Path(tmp_path).unlink(missing_ok=True)

        if text:
            log.info(f"OCR recognized {len(text)} chars")
        return text

    except Exception as e:
        log.error(f"OCR error: {e}")
        return ""


def is_ocr_available() -> bool:
    """Проверка доступности OCR."""
    return OCR_AVAILABLE
