"""
Обработчики команд: /start, /help, /stats, /report.
"""

import logging

from aiogram import Router
from aiogram.filters import CommandStart, Command
from aiogram.types import Message

from database import Database
from analyzers import PhoneChecker

log = logging.getLogger("svoy_bot.commands")
router = Router()

# Ссылки на общие объекты (инжектируются из bot.py)
db: Database | None = None
phone_checker: PhoneChecker | None = None

# ─── Тексты ───

WELCOME_TEXT = """🛡 <b>СВОЙ</b> — защита от мошенников

Я помогу проверить подозрительные сообщения, ссылки и номера телефонов.

<b>Как пользоваться:</b>
• Перешлите мне подозрительное сообщение
• Или отправьте текст / ссылку / номер телефона
• Я проанализирую и скажу, есть ли риск

<b>Команды:</b>
/check — проверить текст (можно просто отправить сообщение)
/report — сообщить о мошенническом номере
/stats — статистика бота
/help — помощь

Свой не обманет. Начинайте! 👇"""

HELP_TEXT = """🛡 <b>Помощь — СВОЙ</b>

<b>Что я проверяю:</b>
• <b>Текст</b> — анализирую на маркеры манипуляции (срочность, страх, давление, просьбы о деньгах/кодах)
• <b>Ссылки</b> — проверяю домен (возраст, подмена бренда, подозрительные зоны)
• <b>Номера</b> — ищу в базе известных мошенников

<b>Как использовать:</b>
1. Просто перешлите сюда подозрительное SMS или сообщение
2. Или скопируйте текст и отправьте мне
3. Я сразу покажу результат

<b>Пример:</b>
<i>«Ваша карта заблокирована. Срочно позвоните по номеру +7-999-123-45-67 или перейдите по ссылке http://sberbank-secure.xyz для разблокировки»</i>

<b>Помните:</b>
• Банки НИКОГДА не просят коды из SMS
• Полиция не звонит и не просит переводить деньги
• Если сомневаетесь — позвоните родственникам

/report — сообщить о новом мошенническом номере
/stats — статистика"""


# ─── Обработчики команд ───

@router.message(CommandStart())
async def cmd_start(message: Message):
    if db:
        await db.upsert_user(
            message.from_user.id,
            message.from_user.username,
            message.from_user.first_name,
        )
    await message.answer(WELCOME_TEXT, parse_mode="HTML")


@router.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(HELP_TEXT, parse_mode="HTML")


@router.message(Command("stats"))
async def cmd_stats(message: Message):
    if db:
        stats = await db.get_stats()
        text = (
            f"📊 <b>Статистика СВОЙ</b>\n\n"
            f"Проверок: {stats['total_checks']}\n"
            f"Угроз найдено: {stats['threats_found']}\n"
            f"Номеров в базе: {stats['phones_in_db']}\n"
            f"Пользователей: {stats['unique_users']}"
        )
    else:
        text = "📊 Статистика временно недоступна."
    await message.answer(text, parse_mode="HTML")


@router.message(Command("report"))
async def cmd_report(message: Message):
    """Пользователь сообщает о мошеннике (номер или пересланное сообщение)."""
    
    # Сценарий 1: Реплай на сообщение мошенника
    if message.reply_to_message:
        target_msg = message.reply_to_message
        from aiogram.types import MessageOriginUser
        
        scammer_id = None
        scammer_name = None
        scammer_username = None
        
        # Если это пересланное сообщение
        if target_msg.forward_origin and isinstance(target_msg.forward_origin, MessageOriginUser):
            spammer_user = target_msg.forward_origin.sender_user
            if not spammer_user.is_bot:
                scammer_id = spammer_user.id
                scammer_name = spammer_user.first_name
                scammer_username = spammer_user.username
        # Если это прямое сообщение (например бот добавлен в группу)
        elif target_msg.from_user and not target_msg.from_user.is_bot:
            scammer_id = target_msg.from_user.id
            scammer_name = target_msg.from_user.first_name
            scammer_username = target_msg.from_user.username
            
        if scammer_id:
            if db:
                await db.add_user_report(scammer_id, scammer_username, scammer_name, message.from_user.id)
            
            identifier = f"@{scammer_username}" if scammer_username else scammer_name
            await message.answer(
                f"✅ Жалоба на пользователя {identifier} (ID: <code>{scammer_id}</code>) принята!\n"
                f"Мы занесли его в локальную базу подозрительных контактов.",
                parse_mode="HTML"
            )
            log.info(f"User {message.from_user.id} reported scammer ID: {scammer_id}")
            return
        else:
            await message.answer("❌ Не удалось определить ID пользователя. Возможно, он скрыл свой профиль.")
            return

    # Сценарий 2: Репорт номера телефона через текст команды
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "📝 <b>Как сообщить о мошеннике:</b>\n\n"
            "1️⃣ <b>По номеру:</b>\n"
            "/report +79991234567 Звонили от имени банка\n\n"
            "2️⃣ <b>По аккаунту:</b>\n"
            "Сделайте <b>Reply (Ответить)</b> на сообщение мошенника текстом <code>/report</code>.",
            parse_mode="HTML",
        )
        return

    raw = parts[1]
    if not phone_checker:
        await message.answer("❌ Сервис временно недоступен.")
        return

    phones = phone_checker.extract_phones(raw)
    if not phones:
        await message.answer(
            "❌ Не удалось найти номер телефона в вашем сообщении.\n"
            "Формат: /report +79991234567 описание"
        )
        return

    phone = phones[0]
    desc = raw.replace(phone, "").strip()
    if not desc:
        desc = "Пользователь отметил как мошеннический"

    if db:
        await db.add_phone_report(phone, "scam", desc, message.from_user.id)
    phone_checker.add_number(phone, "scam", desc)

    await message.answer(
        f"✅ Номер {phone} добавлен в базу.\n"
        f"Описание: {desc}\n\n"
        f"Спасибо! Вы помогаете защитить других людей. 🛡"
    )
    log.info(f"User {message.from_user.id} reported phone: {phone}")
