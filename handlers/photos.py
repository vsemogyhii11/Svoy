"""
Обработчик фото-сообщений (OCR → анализ текста).
"""

import logging

from aiogram import Router, F
from aiogram.types import Message

from ocr import extract_text_from_image, is_ocr_available
from analyzers import TextAnalyzer

log = logging.getLogger("svoy_bot.photos")
router = Router()

# Инжектируются из bot.py
text_analyzer: TextAnalyzer | None = None


@router.message(F.photo)
async def handle_photo(message: Message):
    """Обработка фотографий: OCR → анализ текста."""
    if not is_ocr_available():
        await message.answer(
            "📷 Я вижу фото, но OCR-модуль не установлен.\n"
            "Пока что скопируйте текст с изображения и отправьте мне.\n\n"
            "💡 Для включения OCR: pip install pytesseract Pillow"
        )
        return

    await message.answer("🔍 Распознаю текст с изображения...")
    await message.answer_chat_action("typing")

    # Скачиваем фото (максимальное качество)
    photo = message.photo[-1]  # последнее = самое большое
    file = await message.bot.get_file(photo.file_id)
    file_bytes = await message.bot.download_file(file.file_path)
    image_data = file_bytes.read()

    # OCR
    text = await extract_text_from_image(image_data)

    if not text or len(text.strip()) < 5:
        await message.answer(
            "😕 Не удалось распознать текст с изображения.\n"
            "Попробуйте отправить более чёткое фото или скопируйте текст вручную."
        )
        return

    await message.answer(
        f"📝 <b>Распознанный текст:</b>\n<i>{text[:500]}</i>\n\n"
        f"Анализирую...",
        parse_mode="HTML",
    )

    # Анализируем распознанный текст
    if text_analyzer:
        result = text_analyzer.analyze(text)
        await message.answer(result.summary)
    else:
        await message.answer("⚠️ Анализатор текста недоступен.")
