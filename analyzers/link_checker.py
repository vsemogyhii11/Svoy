"""
Проверка ссылок и доменов.

Что проверяем:
- Возраст домена (WHOIS) — молодой домен = подозрительно
- Похожесть на известные бренды (typosquatting)
- Наличие в белом списке
- Подозрительные паттерны в URL
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import socket
import logging
log = logging.getLogger("svoy_bot.link_checker")

try:
    import whois

    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


@dataclass
class LinkCheckResult:
    """Результат проверки ссылки."""
    url: str
    domain: str
    risk_score: float
    risk_level: str  # safe / suspicious / danger
    reasons: list[str] = field(default_factory=list)
    domain_age_days: int | None = None
    is_trusted: bool = False

    @property
    def emoji(self) -> str:
        if self.risk_level == "danger":
            return "🔴"
        elif self.risk_level == "suspicious":
            return "🟡"
        return "🟢"


class LinkChecker:
    """Проверка ссылок на фишинг."""

    # Подозрительные TLD
    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".click", ".link", ".buzz",
        ".icu", ".monster", ".tk", ".ml", ".ga", ".cf",
        ".gq", ".pw", ".cc", ".su"
    }

    # Подозрительные паттерны в URL
    SUSPICIOUS_URL_PATTERNS = [
        r"login.*\d{3,}",           # login с числами
        r"secure.*bank",            # secure + bank
        r"(sber|tink|vtb).*\.(com|net|org|xyz)",  # РФ банки на нетипичных TLD
        r"gosuslugi.*\.(com|net|org|xyz|top)",     # госуслуги на нетипичных TLD
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # прямой IP в URL
        r"bit\.ly|tinyurl|goo\.gl|t\.co",          # сокращалки (подозрительно в контексте банка)
    ]

    def __init__(self, trusted_path: str = "data/trusted_domains.json"):
        data = self._load_data(trusted_path)
        self.trusted_domains = set(data.get("trusted", []))
        self.brand_keywords = data.get("brand_keywords", [])

    def _load_data(self, path: str) -> dict:
        p = Path(path)
        if not p.exists():
            p = Path(__file__).parent.parent / path
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def extract_urls(self, text: str) -> list[str]:
        """Извлекает URL из текста."""
        url_pattern = r'https?://[^\s<>\"\')\]]+|www\.[^\s<>\"\')\]]+'
        urls = re.findall(url_pattern, text)
        # Убираем висящие знаки пунктуации
        cleaned = []
        for u in urls:
            u = u.rstrip(".,;:!?)")
            if not u.startswith("http"):
                u = "http://" + u
            cleaned.append(u)
        return cleaned

    async def check_url(self, url: str) -> LinkCheckResult:
        """Проверяет одну ссылку (асинхронно)."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().lstrip("www.")
        except Exception:
            return LinkCheckResult(
                url=url, domain="???",
                risk_score=0.5, risk_level="suspicious",
                reasons=["Не удалось разобрать URL"]
            )

        reasons = []
        score = 0.0

        # 1. Белый список
        if domain in self.trusted_domains:
            return LinkCheckResult(
                url=url, domain=domain,
                risk_score=0.0, risk_level="safe",
                is_trusted=True,
                reasons=["Домен в белом списке"]
            )

        # 2. Подозрительный TLD
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 0.3
                reasons.append(f"Подозрительная доменная зона: {tld}")
                break

        # 3. Typosquatting — похожесть на бренды
        for keyword in self.brand_keywords:
            if keyword in domain and domain not in self.trusted_domains:
                score += 0.4
                reasons.append(
                    f"Домен содержит '{keyword}', но не является "
                    f"официальным сайтом"
                )
                break

        # 4. Подозрительные паттерны
        for pattern in self.SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url.lower()):
                score += 0.2
                reasons.append("Подозрительный паттерн в URL")
                break

        # 5. Длинный домен (часто признак фишинга)
        if len(domain) > 30:
            score += 0.1
            reasons.append("Необычно длинный домен")

        # 6. Много поддоменов
        if domain.count(".") > 2:
            score += 0.15
            reasons.append("Много уровней поддоменов")

        # 7. WHOIS — возраст домена (асинхронно)
        domain_age = await self._check_whois(domain)
        if domain_age is not None:
            if domain_age < 30:
                score += 0.4
                reasons.append(
                    f"Домен создан недавно ({domain_age} дн. назад)"
                )
            elif domain_age < 180:
                score += 0.15
                reasons.append(
                    f"Домен относительно молодой ({domain_age} дн.)"
                )

        # 8. Инфраструктурный анализ (IP Reputation)
        try:
            ip_addr = await asyncio.to_thread(socket.gethostbyname, domain)
            # Здесь в будущем будет проверка по базе "плохих IP"
            if ip_addr.startswith("127."): # Placeholder logic
                pass 
        except Exception:
            pass


        # Финальный скор
        risk_score = min(score, 1.0)
        if risk_score >= 0.5:
            risk_level = "danger"
        elif risk_score >= 0.25:
            risk_level = "suspicious"
        else:
            risk_level = "safe"

        if not reasons:
            reasons.append("Явных признаков фишинга не обнаружено")

        return LinkCheckResult(
            url=url,
            domain=domain,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            reasons=reasons,
            domain_age_days=domain_age
        )

    async def _check_whois(self, domain: str) -> int | None:
        """Возвращает возраст домена в днях (асинхронно)."""
        if not WHOIS_AVAILABLE:
            return None
        
        try:
            # Выполняем блокирующий вызов в отдельном потоке
            w = await asyncio.to_thread(whois.whois, domain)
            
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                now = datetime.now(timezone.utc)
                if creation.tzinfo is None:
                    from datetime import timezone as tz
                    creation = creation.replace(tzinfo=tz.utc)
                age = (now - creation).days
                return max(age, 0)
        except Exception:
            pass
        return None

    async def check_all(self, text: str) -> list[LinkCheckResult]:
        """Проверяет все ссылки в тексте асинхронно."""
        urls = self.extract_urls(text)
        tasks = [self.check_url(u) for u in urls]
        return await asyncio.gather(*tasks)
