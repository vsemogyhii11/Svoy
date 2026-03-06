"""
Обработчик текстовых сообщений (основная проверка).
Интегрирует rule-based анализ, LLM, VirusTotal и Google Safe Browsing.
"""

import logging

from aiogram import Router, F
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton

from analyzers import TextAnalyzer, LinkChecker, PhoneChecker
from database import Database
from utils import format_full_report

log = logging.getLogger("svoy_bot.messages")
router = Router()

# Ссылки на общие объекты (инжектируются из bot.py)
db: Database | None = None
text_analyzer: TextAnalyzer | None = None
link_checker: LinkChecker | None = None
phone_checker: PhoneChecker | None = None
vt_checker = None   # VirusTotalChecker
gsb_checker = None  # SafeBrowsingChecker


def _result_keyboard() -> InlineKeyboardMarkup:
    """Inline-кнопки после анализа."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="🔍 Проверить ещё", callback_data="check_more"),
            InlineKeyboardButton(text="⚠️ Пожаловаться", callback_data="report_prompt"),
        ],
        [
            InlineKeyboardButton(text="📢 Поделиться результатом", switch_inline_query=""),
        ],
    ])


@router.message(F.text)
async def handle_message(message: Message):
    """Анализирует любое текстовое сообщение."""
    text = message.text or ""

    # Пропускаем короткие сообщения
    if len(text) < 5:
        await message.answer(
            "Отправьте подозрительное сообщение, ссылку или номер "
            "телефона — я проверю. 🛡"
        )
        return

    # Обновляем пользователя в БД
    if db:
        await db.upsert_user(
            message.from_user.id,
            message.from_user.username,
            message.from_user.first_name,
        )

    # Отправляем "печатает..."
    await message.bot.send_chat_action(chat_id=message.chat.id, action="typing")

    # --- 0. Проверка пересланных сообщений по CAS ---
    cas_report = ""
    cas_was_found = False
    from aiogram.types import MessageOriginUser
    
    if message.forward_origin and isinstance(message.forward_origin, MessageOriginUser):
        spammer_user = message.forward_origin.sender_user
        if not spammer_user.is_bot:
            spammer_id = spammer_user.id
            spammer_name = spammer_user.first_name
            username_str = f" (@{spammer_user.username})" if spammer_user.username else ""
            
            if cas_checker and cas_checker.enabled:
                cas_res = await cas_checker.check_user_id(spammer_id)
                if cas_res.get("ok"):
                    cas_was_found = True
                    # Человек в базе CAS!
                    cas_report = (
                        f"🚨 <b>ВНИМАНИЕ: ОТПРАВИТЕЛЬ В ГЛОБАЛЬНОЙ БАЗЕ СПАМЕРОВ!</b>\n"
                        f"Пользователь: {spammer_name}{username_str}\n"
                        f"База: Combot Anti-Spam (CAS)\n"
                        f"Жалоб: {cas_res.get('result', {}).get('offenses', 'N/A')}\n\n"
                        f"⚠️ <b>НЕ ВСТУПАЙТЕ В ДИАЛОГ С ЭТИМ ПОЛЬЗОВАТЕЛЕМ.</b>\n"
                    )
            
            # --- 0.1 Глубокий OSINT по аккаунту ---
            if osint_inspector:
                osint_data = await osint_inspector.analyze_user(spammer_id, spammer_user.username)
                age_info = osint_data.get("age", {})
                web_info = osint_data.get("web_search", {})
                
                age_text = f"📅 <b>Аккаунт:</b> {age_info.get('period')} ({age_info.get('status')})\n"
                web_text = ""
                if web_info:
                    web_text = f"🌐 <b>Web OSINT:</b> {web_info.get('summary')}\n"
                
                # Если в CAS не нашли, шлем аккуратный инфо-блок
                if not cas_was_found:
                    cas_report = (
                        f"🕵️‍♂️ <b>Глубокий анализ аккаунта:</b>\n"
                        f"Пользователь: {spammer_name}{username_str}\n"
                        f"{age_text}{web_text}"
                        f"ID: <code>{spammer_id}</code>\n\n"
                    )
            elif not cas_was_found:
                cas_report = f"ℹ️ <b>Отправитель:</b> {spammer_name}{username_str} (ID: <code>{spammer_id}</code>)\n\n"
    elif message.forward_origin:
        cas_report = "<i>⚠️ Отправитель скрыл свой профиль (настройки приватности). Не могу получить ID для точной проверки.</i>\n\n"

    # 1. Анализ текста (гибридный: rule-based + LLM при неоднозначных случаях)
    text_result = None
    if text_analyzer:
        if text_analyzer.llm and text_analyzer.llm.enabled:
            text_result = await text_analyzer.analyze_with_llm(text)
        else:
            text_result = text_analyzer.analyze(text)

    # 2. Проверка ссылок (WHOIS + паттерны)
    link_results = await link_checker.check_all(text) if link_checker else []

    # 3. Обогащение ссылок через внешние API
    if link_results:
        urls = [lr.url for lr in link_results]

        # VirusTotal
        if vt_checker and vt_checker.enabled:
            for lr in link_results:
                try:
                    vt_result = await vt_checker.check_url(lr.url)
                    vt_score = vt_result.get("risk_score", 0.0)
                    if vt_score > 0.3:
                        lr.risk_score = min(lr.risk_score + vt_score * 0.35, 1.0)
                        lr.reasons.append(
                            f"🦠 VirusTotal: {vt_result['malicious']} антивирусов "
                            f"считают вредоносным"
                        )
                        if lr.risk_score >= 0.5:
                            lr.risk_level = "danger"
                except Exception as e:
                    log.warning(f"VT check failed for {lr.url}: {e}")

        # Google Safe Browsing
        if gsb_checker and gsb_checker.enabled:
            try:
                gsb_results = await gsb_checker.check_urls(urls)
                for lr in link_results:
                    gsb = gsb_results.get(lr.url, {})
                    if gsb.get("is_threat"):
                        lr.risk_score = min(lr.risk_score + 0.5, 1.0)
                        lr.risk_level = "danger"
                        lr.reasons.append(
                            f"🚨 Google Safe Browsing: {gsb.get('threat_type', 'угроза')}"
                        )
            except Exception as e:
                log.warning(f"GSB check failed: {e}")

        # Screenshot capture and detailed link report
        for lr in link_results:
            url = lr.url
            # Анализ внешними API (Phase 2 & 4)
            vt_results_str = "N/A"
            if vt_checker and vt_checker.enabled:
                try:
                    vt_result = await vt_checker.check_url(url)
                    vt_results_str = f"{vt_result.get('malicious', 0)} malicious"
                except Exception as e:
                    log.warning(f"VT check for screenshot failed for {url}: {e}")
                    vt_results_str = "Error"

            gsb_results_str = "N/A"
            if gsb_checker and gsb_checker.enabled:
                try:
                    gsb_check = await gsb_checker.check_urls([url])
                    gsb_info = gsb_check.get(url, {})
                    if gsb_info.get("is_threat"):
                        gsb_results_str = f"Threat: {gsb_info.get('threat_type', 'unknown')}"
                    else:
                        gsb_results_str = "No threat detected"
                except Exception as e:
                    log.warning(f"GSB check for screenshot failed for {url}: {e}")
                    gsb_results_str = "Error"

            # Скриншот (Phase 4)
            st = ScreenshotTaker()
            screenshot_path = None
            try:
                screenshot_path = await st.take_screenshot(url)
            except Exception as e:
                log.warning(f"Screenshot failed for {url}: {e}")

            response = (
                f"🔗 **Результаты проверки ссылки:**\n`{url}`\n\n"
                f"🛡 **VirusTotal:** {vt_results_str}\n"
                f"🚫 **Safe Browsing:** {gsb_results_str}\n"
            )

            if screenshot_path and os.path.exists(screenshot_path):
                await message.answer_photo(
                    FSInputFile(screenshot_path),
                    caption=response,
                    parse_mode="Markdown"
                )
                os.remove(screenshot_path) # Clean up the screenshot file
            else:
                await message.answer(response, parse_mode="Markdown")


    # 4. Проверка номеров
    phone_results = phone_checker.check_all(text) if phone_checker else []

    # Считаем угрозы
    has_threat = False
    risk_score = 0.0

    if text_result:
        risk_score = text_result.risk_score
        if text_result.risk_level in ("danger", "suspicious"):
            has_threat = True

    if any(lr.risk_level == "danger" for lr in link_results):
        has_threat = True
    if any(pr.risk_level in ("danger", "scam") for pr in phone_results):
        has_threat = True

    # Логируем проверку в БД
    if db:
        await db.log_check(
            user_id=message.from_user.id,
            message_text=text,
            risk_score=risk_score,
            risk_level=text_result.risk_level if text_result else "unknown",
            links_found=len(link_results),
            phones_found=len(phone_results),
            has_threat=has_threat,
        )

    # Групповая модерация: если это спам, удаляем сразу
    if message.chat.type in ("group", "supergroup"):
        if has_threat:
            log.info(f"Spam detected in group {message.chat.id}, trying to delete message {message.message_id}")
            try:
                await message.delete()
                # Можно отправить предупреждение
                # await message.answer(f"Сообщение от пользователя было удалено (подозрение на спам/фишинг).")
            except Exception as e:
                log.warning(f"Could not delete spam message in {message.chat.id}: {e}")
        return # Не шлем полный репорт в группу, чтобы не флудить

    # Формируем ответ (только для личных сообщений)
    report = format_full_report(text_result, link_results, phone_results)
    
    # --- 4. Финальный балл доверия (Phase 6) ---
    trust_text = ""
    if trust_scoring:
        text_risk_val = text_result.risk_score if text_result else 0.0
        links_risk_val = max([lr.risk_score for lr in link_results] or [0.0])
        cas_banned = cas_was_found
        trust_val = trust_scoring.calculate_score(text_risk_val, links_risk_val, cas_banned, 0)
        trust_emoji = trust_scoring.get_color_emoji(trust_val)
        trust_text = f"🛡 <b>ИНДЕКС ДОВЕРИЯ СВОЙ: {trust_val}/100</b> {trust_emoji}\n\n"

    if trust_text:
        report = trust_text + report
        
    if cas_report:
        report = cas_report + "\n" + report
        
    await message.answer(report, reply_markup=_result_keyboard(), parse_mode="HTML")

    log.info(
        f"Check by user {message.from_user.id}: "
        f"risk={risk_score:.2f}, "
        f"links={len(link_results)}, "
        f"phones={len(phone_results)}, "
        f"threat={has_threat}"
    )
