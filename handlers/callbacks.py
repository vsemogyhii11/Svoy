"""
Обработчики callback-запросов от inline-кнопок.
"""

import logging

from aiogram import Router
from aiogram.types import CallbackQuery

log = logging.getLogger("svoy_bot.callbacks")
router = Router()


@router.callback_query(lambda c: c.data == "check_more")
async def cb_check_more(callback: CallbackQuery):
    """Кнопка 'Проверить ещё'."""
    await callback.answer()
    await callback.message.answer(
        "📝 Отправьте мне подозрительный текст, ссылку или номер телефона — "
        "я проверю. 🛡"
    )


@router.callback_query(lambda c: c.data == "report_prompt")
async def cb_report_prompt(callback: CallbackQuery):
    """Кнопка 'Пожаловаться'."""
    await callback.answer()
    await callback.message.answer(
        "📝 <b>Как сообщить о мошеннике:</b>\n\n"
        "/report +79991234567 Описание ситуации\n\n"
        "Укажите номер и краткое описание.",
        parse_mode="HTML",
    )


@router.callback_query(lambda c: c.data.startswith("captcha_"))
async def cb_captcha(callback: CallbackQuery):
    """Обработка кнопки 'Я не робот'."""
    user_id_str = callback.data.split("_")[1]
    
    if str(callback.from_user.id) != user_id_str:
        await callback.answer("Это кнопка не для вас!", show_alert=True)
        return
        
    try:
        from aiogram.types import ChatPermissions
        # Разблокируем
        await callback.bot.restrict_chat_member(
            chat_id=callback.message.chat.id,
            user_id=callback.from_user.id,
            permissions=ChatPermissions(
                can_send_messages=True,
                can_send_audios=True,
                can_send_documents=True,
                can_send_photos=True,
                can_send_videos=True,
                can_send_video_notes=True,
                can_send_voice_notes=True,
                can_send_polls=True,
                can_send_other_messages=True,
                can_add_web_page_previews=True,
            )
        )
        await callback.message.delete()
        await callback.answer("Успешно! Теперь вы можете писать в группу.", show_alert=True)
        log.info(f"User {callback.from_user.id} passed CAPTCHA in {callback.message.chat.id}")
    except Exception as e:
        log.warning(f"Failed to unrestrict user {callback.from_user.id}: {e}")
        await callback.answer("Произошла ошибка. Свяжитесь с админом.", show_alert=True)

