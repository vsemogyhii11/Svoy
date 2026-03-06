import logging

from aiogram import Router, F
from aiogram.types import Message

from analyzers import TextAnalyzer
from integrations import LLMAnalyzer

log = logging.getLogger("svoy_bot.voice")
router = Router()

text_analyzer: TextAnalyzer | None = None
llm_analyzer: LLMAnalyzer | None = None

@router.message(F.voice | F.audio)
async def handle_voice(message: Message):
    """Обработка голосовых сообщений: Whisper -> Анализ текста."""
    if not llm_analyzer or not llm_analyzer.enabled:
        await message.answer(
            "🎙 Я вижу голосовое сообщение, но модуль распознавания речи "
            "(Whisper) сейчас отключен."
        )
        return

    await message.answer("🎙 Слушаю и расшифровываю...")
    await message.answer_chat_action("typing")

    file_id = message.voice.file_id if message.voice else message.audio.file_id
    file = await message.bot.get_file(file_id)
    file_bytes = await message.bot.download_file(file.file_path)
    audio_data = file_bytes.read()

    text = await llm_analyzer.transcribe_audio(audio_data)

    if not text or len(text.strip()) < 5:
        await message.answer("😕 Не удалось разобрать речь, или сообщение слишком короткое.")
        return

    await message.answer(
        f"🎙 <b>Расшифровка:</b>\n<i>{text}</i>\n\nАнализирую...",
        parse_mode="HTML"
    )

    if text_analyzer:
        result = text_analyzer.analyze(text)
        await message.answer(result.summary)
    else:
        await message.answer("⚠️ Анализатор текста недоступен.")
