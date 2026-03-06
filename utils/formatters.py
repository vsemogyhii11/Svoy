"""
Форматирование ответов бота для Telegram.
"""


def format_full_report(
    text_result=None,
    link_results: list | None = None,
    phone_results: list | None = None,
) -> str:
    """Собирает полный отчёт из всех анализаторов."""
    sections = []

    # --- Анализ текста ---
    if text_result and text_result.risk_score > 0:
        sections.append(text_result.summary)

    # --- Ссылки ---
    if link_results:
        for lr in link_results:
            lines = [f"\n🔗 Ссылка: {lr.domain}"]
            lines.append(f"{lr.emoji} Риск: {int(lr.risk_score * 100)}%")
            for reason in lr.reasons:
                lines.append(f"  • {reason}")
            if lr.risk_level == "danger":
                lines.append("🛑 НЕ переходите по этой ссылке!")
            sections.append("\n".join(lines))

    # --- Телефоны ---
    if phone_results:
        for pr in phone_results:
            lines = [f"\n📞 Номер: {pr.phone}"]
            lines.append(f"{pr.emoji} {pr.description}")
            if pr.reports > 0:
                lines.append(f"  Жалоб: {pr.reports}")
            sections.append("\n".join(lines))

    # --- Итог ---
    if not sections:
        return (
            "✅ Анализ завершён.\n"
            "Явных признаков мошенничества не обнаружено.\n\n"
            "Но всегда будьте внимательны:\n"
            "• Не сообщайте коды из SMS\n"
            "• Не устанавливайте приложения по просьбе незнакомцев\n"
            "• При сомнениях — позвоните родственникам"
        )

    report = "\n\n".join(sections)

    # Подпись
    report += "\n\n— 🛡 СВОЙ | Защита от мошенников"

    return report
