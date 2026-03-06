"""
Обработка событий групп: новые участники, CAPTCHA, автоудаление.
"""

import logging

from aiogram import Router, F
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, ChatPermissions
from aiogram.filters import IS_MEMBER, IS_NOT_MEMBER, ChatMemberUpdatedFilter
from aiogram.types import ChatMemberUpdated

log = logging.getLogger("svoy_bot.group_events")
router = Router()

@router.chat_member(ChatMemberUpdatedFilter(IS_NOT_MEMBER >> IS_MEMBER))
async def on_user_join(event: ChatMemberUpdated):
    """Когда новый пользователь заходит в группу."""
    if event.chat.type not in ("group", "supergroup"):
        return
        
    user = event.new_chat_member.user
    
    # Игнорируем ботов
    if user.is_bot:
        return
        
    try:
        # Ограничиваем права (только чтение)
        await event.bot.restrict_chat_member(
            chat_id=event.chat.id,
            user_id=user.id,
            permissions=ChatPermissions(
                can_send_messages=False,
                can_send_audios=False,
                can_send_documents=False,
                can_send_photos=False,
                can_send_videos=False,
                can_send_video_notes=False,
                can_send_voice_notes=False,
                can_send_polls=False,
                can_send_other_messages=False,
                can_add_web_page_previews=False,
                can_change_info=False,
                can_invite_users=False,
                can_pin_messages=False,
            )
        )
        
        # Отправляем капчу
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Я не робот", callback_data=f"captcha_{user.id}")]
        ])
        
        await event.bot.send_message(
            chat_id=event.chat.id,
            text=f"Привет, <a href='tg://user?id={user.id}'>{user.first_name}</a>! "
                 f"Пожалуйста, подтвердите, что вы не бот, чтобы писать сообщения в эту группу.",
            reply_markup=keyboard,
            parse_mode="HTML"
        )
        log.info(f"User {user.id} joined {event.chat.id}, sent CAPTCHA.")
    except Exception as e:
        log.warning(f"Failed to restrict or send CAPTCHA to user {user.id} in {event.chat.id}: {e}")
