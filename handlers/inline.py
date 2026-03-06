"""
Inline-режим бота: проверка ссылок/текста прямо из любого чата.
Пользователь набирает @svoy_bot <текст> и получает результат.
"""

import logging
import hashlib

from aiogram import Router
from aiogram.types import (
    InlineQuery,
    InlineQueryResultArticle,
    InputTextMessageContent,
)

from analyzers import TextAnalyzer, LinkChecker, PhoneChecker

log = logging.getLogger("svoy_bot.inline")
router = Router()

# Инжектируются из bot.py
text_analyzer: TextAnalyzer | None = None
link_checker: LinkChecker | None = None
phone_checker: PhoneChecker | None = None


@router.inline_query()
async def handle_inline_query(query: InlineQuery):
    """Обработка inline-запроса."""
    text = query.query.strip()
    if len(text) < 5:
        return

    results = []

    # Анализ текста
    if text_analyzer:
        ta_result = text_analyzer.analyze(text)
        if ta_result.risk_score > 0:
            result_id = hashlib.md5(f"text_{text}".encode()).hexdigest()
            results.append(
                InlineQueryResultArticle(
                    id=result_id,
                    title=f"{ta_result.emoji} Анализ текста — риск {int(ta_result.risk_score * 100)}%",
                    description=ta_result.summary[:100],
                    input_message_content=InputTextMessageContent(
                        message_text=(
                            f"🛡 <b>Проверка СВОЙ</b>\n\n"
                            f"{ta_result.summary}\n\n"
                            f"— 🛡 СВОЙ | Защита от мошенников"
                        ),
                        parse_mode="HTML",
                    ),
                )
            )

    # Проверка ссылок
    if link_checker:
        link_results = await link_checker.check_all(text)
        for lr in link_results:
            result_id = hashlib.md5(f"link_{lr.url}".encode()).hexdigest()
            results.append(
                InlineQueryResultArticle(
                    id=result_id,
                    title=f"{lr.emoji} Ссылка: {lr.domain} — риск {int(lr.risk_score * 100)}%",
                    description=", ".join(lr.reasons[:2]),
                    input_message_content=InputTextMessageContent(
                        message_text=(
                            f"🛡 <b>Проверка ссылки</b>\n\n"
                            f"🔗 {lr.domain}\n"
                            f"{lr.emoji} Риск: {int(lr.risk_score * 100)}%\n"
                            + "\n".join(f"  • {r}" for r in lr.reasons)
                            + "\n\n— 🛡 СВОЙ | Защита от мошенников"
                        ),
                        parse_mode="HTML",
                    ),
                )
            )

    # Проверка номеров
    if phone_checker:
        phones = phone_checker.check_all(text)
        for pr in phones:
            result_id = hashlib.md5(f"phone_{pr.phone}".encode()).hexdigest()
            results.append(
                InlineQueryResultArticle(
                    id=result_id,
                    title=f"{pr.emoji} Номер: {pr.phone}",
                    description=pr.description[:100],
                    input_message_content=InputTextMessageContent(
                        message_text=(
                            f"🛡 <b>Проверка номера</b>\n\n"
                            f"📞 {pr.phone}\n"
                            f"{pr.emoji} {pr.description}\n\n"
                            f"— 🛡 СВОЙ | Защита от мошенников"
                        ),
                        parse_mode="HTML",
                    ),
                )
            )

    if not results:
        result_id = hashlib.md5(f"safe_{text}".encode()).hexdigest()
        results.append(
            InlineQueryResultArticle(
                id=result_id,
                title="🟢 Явных признаков мошенничества нет",
                description="Всё выглядит безопасным",
                input_message_content=InputTextMessageContent(
                    message_text=(
                        "🛡 <b>Проверка СВОЙ</b>\n\n"
                        "✅ Явных признаков мошенничества не обнаружено.\n"
                        "Но всегда будьте внимательны!\n\n"
                        "— 🛡 СВОЙ | Защита от мошенников"
                    ),
                    parse_mode="HTML",
                ),
            )
        )

    await query.answer(results[:10], cache_time=60)
