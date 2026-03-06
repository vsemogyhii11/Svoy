"""
Интеграция с Google Safe Browsing Lookup API v4.

Проверяет URL по базе фишинга и вредоносных сайтов Google.
Документация: https://developers.google.com/safe-browsing/v4/lookup-api
"""

import logging
from datetime import datetime, timedelta

import aiohttp

log = logging.getLogger("svoy_bot.safe_browsing")


class SafeBrowsingChecker:
    """Асинхронная проверка URL через Google Safe Browsing."""

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    # Типы угроз для проверки
    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self._cache: dict[str, dict] = {}
        self._cache_ttl = timedelta(hours=1)
        self.enabled = bool(api_key)

    async def check_urls(self, urls: list[str]) -> dict[str, dict]:
        """
        Проверить список URL через Google Safe Browsing.
        
        Возвращает словарь {url: result} для каждого URL.
        result: {
            "is_threat": bool,
            "threat_type": str | None,
            "platform": str | None,
            "risk_score": float,
            "source": "google_safe_browsing"
        }
        """
        if not self.enabled or not urls:
            return {url: self._safe_result() for url in urls}

        # Фильтруем кэшированные
        to_check = []
        results = {}
        for url in urls:
            if url in self._cache:
                cached = self._cache[url]
                if datetime.now() - cached["_cached_at"] < self._cache_ttl:
                    results[url] = cached
                    continue
            to_check.append(url)

        if not to_check:
            return results

        try:
            body = {
                "client": {
                    "clientId": "svoy_bot",
                    "clientVersion": "2.0",
                },
                "threatInfo": {
                    "threatTypes": self.THREAT_TYPES,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": u} for u in to_check],
                },
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.API_URL}?key={self.api_key}",
                    json=body,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        matches = data.get("matches", [])

                        # Помечаем найденные угрозы
                        threat_urls = set()
                        for match in matches:
                            threat_url = match.get("threat", {}).get("url")
                            if threat_url:
                                threat_urls.add(threat_url)
                                result = {
                                    "is_threat": True,
                                    "threat_type": match.get("threatType"),
                                    "platform": match.get("platformType"),
                                    "risk_score": 0.95,
                                    "source": "google_safe_browsing",
                                    "_cached_at": datetime.now(),
                                }
                                results[threat_url] = result
                                self._cache[threat_url] = result

                        # URL, не найденные в угрозах — безопасны
                        for url in to_check:
                            if url not in threat_urls:
                                result = self._safe_result()
                                result["_cached_at"] = datetime.now()
                                results[url] = result
                                self._cache[url] = result

                    else:
                        log.warning(f"GSB API returned {resp.status}")
                        for url in to_check:
                            results[url] = self._safe_result()

        except Exception as e:
            log.error(f"GSB API error: {e}")
            for url in to_check:
                results[url] = self._safe_result()

        return results

    async def check_url(self, url: str) -> dict:
        """Проверить один URL."""
        results = await self.check_urls([url])
        return results.get(url, self._safe_result())

    def _safe_result(self) -> dict:
        return {
            "is_threat": False,
            "threat_type": None,
            "platform": None,
            "risk_score": 0.0,
            "source": "google_safe_browsing",
        }
