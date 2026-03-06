"""
Система вычисления балла доверия (Trust Score) на основе всех данных.
"""

class TrustScoringSystem:
    def __init__(self):
        # Веса различных факторов (в сумме 1.0)
        self.weights = {
            "text": 0.3,
            "links": 0.3,
            "cas": 0.2,
            "reports": 0.2
        }

    def calculate_score(self, text_risk: float, links_risk: float, cas_banned: bool, report_count: int) -> int:
        """
        Вычисляет балл от 0 до 100.
        0 - Абсолютный скам.
        100 - Полное доверие.
        """
        # Инвертируем риски в баллы доверия (1.0 risk = 0 trust)
        text_trust = 1.0 - text_risk
        links_trust = 1.0 - links_risk
        
        cas_trust = 0.0 if cas_banned else 1.0
        
        # Репорты: 0 репортов = 1.0 trust, 5+ репортов = 0 trust
        reports_trust = max(0.0, 1.0 - (report_count / 5.0))
        
        final_trust_score = (
            text_trust * self.weights["text"] +
            links_trust * self.weights["links"] +
            cas_trust * self.weights["cas"] +
            reports_trust * self.weights["reports"]
        )
        
        # Приводим к 0-100
        return int(final_trust_score * 100)

    @staticmethod
    def get_color_emoji(score: int) -> str:
        if score > 80: return "🟢 (Высокое)"
        if score > 50: return "🟡 (Среднее)"
        if score > 20: return "🟠 (Низкое)"
        return "🔴 (КРИТИЧЕСКИЙ РИСК)"
