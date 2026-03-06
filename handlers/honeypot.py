"""
Хендлер для ловушек (Honeypots). Генерирует ссылки для отслеживания IP.

Использование:
    /bait — создать ссылку-ловушку
    /bait_status — проверить статус ловушки
"""

import logging
from aiogram import Router, types
from aiogram.filters import Command
from datetime import datetime

from integrations.ip_tracker import get_tracker

log = logging.getLogger("svoy_bot.honeypot")
router = Router()

# Базовый URL для ловушек (заменить на свой домен)
BASE_HONEY_URL = "https://trax.svoy.app/verify/"


@router.message(Command("bait"))
async def cmd_bait(message: types.Message):
    """Генерирует ссылку-ловушку."""
    tracker = get_tracker()
    
    # Создаём токен
    token = tracker.create_token(
        user_id=message.from_user.id,
        username=message.from_user.username or ""
    )
    
    honey_url = f"{BASE_HONEY_URL}{token}"
    
    text = (
        f"🎣 <b>Ловушка создана!</b>\n\n"
        f"<b>Как использовать:</b>\n"
        f"1. Отправьте эту ссылку мошеннику\n"
        f"2. Подойдёт любой предлог:\n"
        f"   • 'Вот скриншот чека'\n"
        f"   • 'Подтверди тут'\n"
        f"   • 'Перейди и посмотри'\n\n"
        f"🔗 <code>{honey_url}</code>\n\n"
        f"📊 <b>Что вы получите:</b>\n"
        f"• IP-адрес мошенника\n"
        f"• Данные об устройстве\n"
        f"• Время клика\n"
        f"• Реферер (откуда перешёл)\n\n"
        f"⚠️ <b>Важно:</b>\n"
        f"Ссылка действительна 7 дней. "
        f"Как только мошенник кликнет — вы получите уведомление."
    )
    
    await message.answer(text, parse_mode="HTML")
    
    log.info(f"Honeypot created by user {message.from_user.id}: {token}")


@router.message(Command("bait_status"))
async def cmd_bait_status(message: types.Message):
    """Показывает статус всех ловушек пользователя."""
    tracker = get_tracker()
    user_id = message.from_user.id
    
    # Находим все токены пользователя
    user_tokens = []
    for token, data in tracker._tokens.items():
        if data.get('user_id') == user_id:
            user_tokens.append((token, data))
    
    if not user_tokens:
        await message.answer(
            "📭 У вас нет активных ловушек.\n\n"
            f"Создайте новую командой /bait"
        )
        return
    
    text = f"🎯 <b>Ваши ловушки ({len(user_tokens)} шт.)</b>\n\n"
    
    for token, data in sorted(user_tokens, key=lambda x: x[1]['created_at'], reverse=True)[:5]:
        created = datetime.fromisoformat(data['created_at']).strftime('%d.%m.%Y %H:%M')
        clicks = data.get('clicks', 0)
        last_click = data.get('last_click', '')
        
        status_emoji = "✅" if clicks > 0 else "⏳"
        
        text += f"{status_emoji} <code>{token}</code>\n"
        text += f"   Создана: {created}\n"
        text += f"   Кликов: {clicks}\n"
        
        if last_click:
            last_time = datetime.fromisoformat(last_click).strftime('%d.%m.%Y %H:%M')
            text += f"   Последний клик: {last_time}\n"
        
        # Получаем данные о кликах
        clicks_data = tracker.get_clicks_for_token(token)
        if clicks_data:
            for click in clicks_data[-3:]:  # Последние 3 клика
                ip = click.get('ip_address', 'unknown')
                ua = click.get('user_agent', 'unknown')[:50]
                text += f"   📍 {ip} — {ua}...\n"
        
        text += "\n"
    
    if len(user_tokens) > 5:
        text += f"... и ещё {len(user_tokens) - 5} ловушек\n"
    
    await message.answer(text, parse_mode="HTML")


@router.message(Command("bait_delete"))
async def cmd_bait_delete(message: types.Message):
    """Удаляет ловушку по токену."""
    args = message.text.split()
    
    if len(args) < 2:
        await message.answer(
            "❌ <b>Использование:</b>\n"
            f"/bait_delete <token>\n\n"
            f"Пример: /bait_delete abc123xyz"
        )
        return
    
    token = args[1]
    tracker = get_tracker()
    
    if token in tracker._tokens:
        del tracker._tokens[token]
        tracker._save_tokens()
        await message.answer(f"✅ Ловушка <code>{token}</code> удалена")
        log.info(f"Honeypot deleted by user {message.from_user.id}: {token}")
    else:
        await message.answer(f"❌ Ловушка <code>{token}</code> не найдена")
