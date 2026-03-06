"""
Анализатор возраста аккаунта по User ID и поиск по никнейму.
"""

import logging
import datetime

log = logging.getLogger("svoy_bot.osint_inspector")

class AccountAgeInspector:
    """Оценка возраста аккаунта Telegram по ID."""
    
    # Приблизительные границы ID по годам (очень грубо)
    ID_RANGES = [
        (0, 100_000_000, "2013-2015", "Trustworthy (Old-timer)"),
        (100_000_001, 400_000_000, "2016-2017", "Stable"),
        (400_000_001, 800_000_000, "2018-2019", "Standard"),
        (800_000_001, 1_500_000_000, "2020-2021", "Standard"),
        (1_500_000_001, 4_000_000_000, "2021-2022", "Recent"),
        (4_000_000_001, 6_000_000_000, "2023", "New (Risk)"),
        (6_000_000_001, 10_000_000_000, "2024+", "Fresh (High Risk)")
    ]

    @classmethod
    def estimate_age(cls, user_id: int) -> dict:
        """Возвращает примерный год регистрации и уровень риска."""
        period = "Unknown"
        status = "Unknown"
        risk_score = 0.0
        
        for start, end, year, desc in cls.ID_RANGES:
            if start <= user_id <= end:
                period = year
                status = desc
                if "Risk" in desc:
                    risk_score = 0.4 if "High" in desc else 0.2
                break
        else:
            if user_id > 10_000_000_000:
                period = "2024+"
                status = "Fresh (High Risk)"
                risk_score = 0.5

        return {
            "period": period,
            "status": status,
            "risk_score": risk_score,
            "is_new": risk_score > 0
        }

class OSINTInspector:
    """Комплексный OSINT-инспектор."""
    
    def __init__(self, osint_agent=None):
        self.age_inspector = AccountAgeInspector()
        self.osint_agent = osint_agent
        
    async def analyze_user(self, user_id: int, username: str = None) -> dict:
        """Полный анализ пользователя."""
        result = {
            "age": self.age_inspector.estimate_age(user_id),
            "web_search": None
        }
        
        if username and self.osint_agent:
            query = f'"{username}" мошенник кидала отзывы'
            search_results = await self.osint_agent.search(query)
            # Очень грубый анализ наличия негатива
            total_hits = search_results.get("total_results", 0)
            result["web_search"] = {
                "found_hits": total_hits,
                "summary": "Найдено упоминание в негативном контексте" if total_hits > 0 else "Прямых улик не найдено"
            }
            
        return result
