"""
Хендлер для ловушек (Honeypots). Генерирует ссылки для отслеживания IP.
"""

import logging
from aiogram import Router, types
from aiogram.filters import Command
import uuid

log = logging.getLogger("svoy_bot.honeypot")
router = Router()

# В реальности здесь должен быть внешний сервис или мини-вебсервер.
# Для демонстрации мы просто генерируем "магическую" ссылку.
BASE_HONEY_URL = "https://trax.svoy.app/verify/"

@router.message(Command("bait"))
async def cmd_bait(message: types.Message):
    """Генерирует ссылку-ловушку."""
    token = str(uuid.uuid4())[:8]
    honey_url = f"{BASE_HONEY_URL}{token}"
    
    text = (
        f"🎣 <b>Ловушка создана!</b>\n\n"
        f"Отправьте эту ссылку мошеннику под любым предлогом (например, 'вот скриншот чека' или 'подтверди тут').\n\n"
        f"🔗 <code>{honey_url}</code>\n\n"
        f"Как только он кликнет, я пришлю вам его IP-адрес и данные об устройстве."
    )
    await message.answer(text, parse_mode="HTML")
