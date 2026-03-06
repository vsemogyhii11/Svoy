"""
Анализатор текста на признаки мошенничества.

Использует паттерны социальной инженерии (принципы Чалдини):
- Срочность (давление временем)
- Страх (запугивание последствиями)
- Авторитет (подмена ролей)
- Секретность (требование молчания)
- Запрос данных/денег
- Эмоциональный крючок
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AnalysisResult:
    """Результат анализа текста."""
    risk_score: float                       # 0.0 - 1.0
    risk_level: str                         # safe / suspicious / danger
    triggers: list[dict] = field(default_factory=list)  # сработавшие паттерны
    summary: str = ""                       # человекочитаемый вывод

    @property
    def emoji(self) -> str:
        if self.risk_level == "danger":
            return "🔴"
        elif self.risk_level == "suspicious":
            return "🟡"
        return "🟢"


class TextAnalyzer:
    """Анализатор текста на маркеры мошенничества."""

    def __init__(self, patterns_path: str = "data/scam_patterns.json", llm_analyzer=None):
        self.patterns = self._load_patterns(patterns_path)
        self.llm = llm_analyzer  # интеграция с LLM (Phase 2)

    def _load_patterns(self, path: str) -> dict:
        p = Path(path)
        if not p.exists():
            p = Path(__file__).parent.parent / path
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def analyze(self, text: str) -> AnalysisResult:
        """Анализирует текст (rule-based) и возвращает оценку риска."""
        if not text or not text.strip():
            return AnalysisResult(
                risk_score=0.0,
                risk_level="safe",
                summary="Пустое сообщение."
            )

        text_lower = text.lower().strip()
        triggers = []
        total_score = 0.0
        max_possible = 0.0

        for category_key, category_data in self.patterns.items():
            if category_key.startswith("_"):
                continue

            weight = category_data.get("weight", 0.1)
            description = category_data.get("description", category_key)
            patterns = category_data.get("patterns", [])
            max_possible += weight

            matched_patterns = []
            for pattern in patterns:
                try:
                    if re.search(pattern, text_lower):
                        matched_patterns.append(pattern)
                except re.error:
                    # Если регулярка некорректна — пробуем как подстроку
                    if pattern in text_lower:
                        matched_patterns.append(pattern)

            if matched_patterns:
                # Чем больше паттернов совпало в одной категории,
                # тем увереннее мы в этой категории (до 100%)
                category_confidence = min(len(matched_patterns) / 2, 1.0)
                category_score = weight * category_confidence
                total_score += category_score

                triggers.append({
                    "category": description,
                    "score": round(category_score, 3),
                    "matched": matched_patterns[:3]  # показываем макс 3
                })

        # Нормализуем скор
        risk_score = min(total_score / max(max_possible, 0.01), 1.0)

        # Бонус: если сработало 3+ категорий — это почти наверняка скам
        if len(triggers) >= 3:
            risk_score = min(risk_score * 1.3, 1.0)

        # Определяем уровень
        if risk_score >= 0.5:
            risk_level = "danger"
        elif risk_score >= 0.25:
            risk_level = "suspicious"
        else:
            risk_level = "safe"

        summary = self._build_summary(risk_level, risk_score, triggers)

        return AnalysisResult(
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            triggers=triggers,
            summary=summary
        )

    async def analyze_with_llm(self, text: str) -> AnalysisResult:
        """
        Гибридный анализ: rule-based + LLM.
        LLM используется при неоднозначных результатах (0.25–0.5).
        """
        # Сначала rule-based
        result = self.analyze(text)

        # Если LLM доступен и результат неоднозначный — уточняем
        if self.llm and self.llm.enabled and 0.2 <= result.risk_score <= 0.55:
            try:
                llm_result = await self.llm.analyze(text)
                if "error" not in llm_result:
                    llm_score = llm_result.get("risk_score", 0.0)
                    # Взвешенный blend: 40% rule-based + 60% LLM
                    blended = result.risk_score * 0.4 + llm_score * 0.6
                    blended = round(min(blended, 1.0), 2)

                    # Обновляем уровень
                    if blended >= 0.5:
                        risk_level = "danger"
                    elif blended >= 0.25:
                        risk_level = "suspicious"
                    else:
                        risk_level = "safe"

                    # Добавляем LLM-анализ в summary
                    llm_analysis = llm_result.get("analysis", "")
                    llm_recommendation = llm_result.get("recommendation", "")
                    
                    extra_lines = []
                    if llm_analysis:
                        extra_lines.append(f"\n🤖 AI-анализ: {llm_analysis}")
                    if llm_recommendation:
                        extra_lines.append(f"💡 {llm_recommendation}")

                    summary = self._build_summary(risk_level, blended, result.triggers)
                    if extra_lines:
                        summary += "\n" + "\n".join(extra_lines)

                    return AnalysisResult(
                        risk_score=blended,
                        risk_level=risk_level,
                        triggers=result.triggers,
                        summary=summary,
                    )
            except Exception as e:
                import logging
                logging.getLogger("svoy_bot.text").warning(f"LLM fallback: {e}")

        return result

    def _build_summary(self, level: str, score: float, triggers: list[dict]) -> str:
        """Формирует понятный текст для пользователя."""
        if level == "danger":
            header = "⚠️ ВЫСОКИЙ РИСК МОШЕННИЧЕСТВА"
        elif level == "suspicious":
            header = "⚡ ПОДОЗРИТЕЛЬНОЕ СООБЩЕНИЕ"
        else:
            header = "✅ Сообщение выглядит безопасным"

        lines = [header, f"Уровень риска: {int(score * 100)}%", ""]

        if triggers:
            lines.append("Обнаруженные признаки:")
            for t in triggers:
                lines.append(f"  • {t['category']}")

        if level == "danger":
            lines.append("")
            lines.append("🛑 Рекомендация: НЕ выполняйте требования!")
            lines.append("Не сообщайте коды из SMS, не переводите деньги.")
            lines.append("Позвоните родственнику или в банк по номеру с карты.")
        elif level == "suspicious":
            lines.append("")
            lines.append("⚡ Рекомендация: будьте осторожны.")
            lines.append("Перепроверьте информацию самостоятельно.")

        return "\n".join(lines)

