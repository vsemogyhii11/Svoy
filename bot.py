"""
🛡 СВОЙ — Telegram-бот защиты от мошенников.

Точка входа. Инициализация компонентов, подключение роутеров и middleware.

Запуск: python bot.py
"""

import asyncio
import logging
import sys

from aiogram import Bot, Dispatcher

from config import (
    BOT_TOKEN, RATE_LIMIT, RATE_WINDOW,
    VIRUSTOTAL_KEY, GOOGLE_SAFE_BROWSING_KEY, OPENAI_API_KEY,
)
from database import Database
from middleware import RateLimitMiddleware, LoggingMiddleware
from analyzers import TextAnalyzer, LinkChecker, PhoneChecker
from integrations import VirusTotalChecker, SafeBrowsingChecker, LLMAnalyzer, CASChecker
from utils.i18n import load_locales

from handlers.commands import router as commands_router
from handlers.messages import router as messages_router
from handlers.callbacks import router as callbacks_router
from handlers.inline import router as inline_router
from handlers.photos import router as photos_router
from handlers.voice import router as voice_router
from handlers.group_events import router as group_events_router

# ─── Логирование ───
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("svoy_bot")


async def main():
    if not BOT_TOKEN:
        log.error(
            "BOT_TOKEN не задан! "
            "Создай файл .env с токеном (см. .env.example)"
        )
        sys.exit(1)

    # ─── Инициализация ───
    db = Database()
    await db.connect()
    await db.migrate_from_json()

    # Мультиязычность
    load_locales()

    # Интеграции (активируются при наличии API-ключей)
    vt_checker = VirusTotalChecker(VIRUSTOTAL_KEY)
    gsb_checker = SafeBrowsingChecker(GOOGLE_SAFE_BROWSING_KEY)
    llm_analyzer = LLMAnalyzer(OPENAI_API_KEY)
    cas_checker = CASChecker()

    # OSINT Agents (if enabled)
    from integrations.osint_agents import OSINTAgent
    from analyzers.osint_inspector import OSINTInspector
    from analyzers.trust_score import TrustScoringSystem
    osint_agent = OSINTAgent(db=db, llm=llm_analyzer)
    osint_inspector = OSINTInspector(osint_agent=osint_agent)
    trust_scoring = TrustScoringSystem()

    if vt_checker.enabled:
        log.info("✅ VirusTotal integration enabled")
    if gsb_checker.enabled:
        log.info("✅ Google Safe Browsing integration enabled")
    if llm_analyzer.enabled:
        log.info("✅ LLM analysis integration enabled")
    if cas_checker.enabled:
        log.info("✅ CAS integration enabled")

    # Анализаторы
    text_analyzer = TextAnalyzer(llm_analyzer=llm_analyzer)
    link_checker = LinkChecker()
    phone_checker = PhoneChecker()

    # Фоновые агенты (OSINT)
    from integrations.osint_agents import OSINTAgent
    osint_agent = OSINTAgent(db, llm_analyzer)
    if llm_analyzer.enabled:
        # Запускаем основной цикл мониторинга
        asyncio.create_task(osint_agent.start())
        # Разовая глубокая загрузка данных за 3 месяца (фоном)
        asyncio.create_task(osint_agent.run_historical_scan(months=3))
        log.info("🤖 OSINT Agents background task started (+ Historical Backfill)")

    # ─── Инжекция зависимостей ───
    from handlers import commands as cmd_module
    from handlers import messages as msg_module
    from handlers import inline as inline_module
    from handlers import photos as photos_module
    from handlers import voice as voice_module

    cmd_module.db = db
    cmd_module.phone_checker = phone_checker

    msg_module.db = db
    msg_module.text_analyzer = text_analyzer
    msg_module.link_checker = link_checker
    msg_module.phone_checker = phone_checker
    msg_module.vt_checker = vt_checker
    msg_module.gsb_checker = gsb_checker
    msg_module.cas_checker = cas_checker
    msg_module.osint_inspector = osint_inspector
    msg_module.trust_scoring = trust_scoring

    inline_module.text_analyzer = text_analyzer
    inline_module.link_checker = link_checker
    inline_module.phone_checker = phone_checker

    photos_module.text_analyzer = text_analyzer

    voice_module.text_analyzer = text_analyzer
    voice_module.llm_analyzer = llm_analyzer

    # ─── Dispatcher ───
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    # Middleware
    dp.message.middleware(RateLimitMiddleware(RATE_LIMIT, RATE_WINDOW))
    dp.message.middleware(LoggingMiddleware())

    # Routers (порядок важен)
    from handlers import honeypot
    dp.include_router(cmd_module.router)    # /start, /help, /stats, /report
    dp.include_router(honeypot.router)      # /bait
    dp.include_router(photos_module.router) # фото (OCR)
    dp.include_router(voice_module.router)  # гс (Whisper)
    dp.include_router(inline_module.router) # inline-режим @svoy_bot
    dp.include_router(msg_module.router)    # текстовые сообщения (последний!)

    log.info("🛡 СВОЙ v2.0 запущен. Ожидание сообщений...")

    try:
        await dp.start_polling(bot)
    finally:
        await db.close()
        log.info("🛡 СВОЙ остановлен.")


if __name__ == "__main__":
    asyncio.run(main())
