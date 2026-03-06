"""
Интеграция с VirusTotal API v3.

Проверяет URL на вредоносность через базу VirusTotal.
Документация: https://docs.virustotal.com/reference/url-info
"""

import asyncio
import base64
import logging
from datetime import datetime, timedelta

import aiohttp

log = logging.getLogger("svoy_bot.virustotal")


class VirusTotalChecker:
    """Асинхронная проверка URL через VirusTotal."""

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self._cache: dict[str, dict] = {}
        self._cache_ttl = timedelta(hours=1)
        self.enabled = bool(api_key)

    def _get_url_id(self, url: str) -> str:
        """VirusTotal URL ID = base64(url) без padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    async def check_url(self, url: str) -> dict:
        """
        Проверить URL через VirusTotal.
        
        Возвращает:
        {
            "malicious": int,       # количество антивирусов, считающих URL вредоносным
            "suspicious": int,      
            "harmless": int,
            "undetected": int,
            "risk_score": float,    # 0.0 - 1.0
            "categories": list,     # категории сайта
            "source": "virustotal"
        }
        """
        if not self.enabled:
            return self._empty_result("API key not configured")

        # Проверяем кэш
        if url in self._cache:
            cached = self._cache[url]
            if datetime.now() - cached["_cached_at"] < self._cache_ttl:
                return cached

        try:
            url_id = self._get_url_id(url)
            headers = {"x-apikey": self.api_key}

            async with aiohttp.ClientSession() as session:
                # Сначала пробуем получить существующий анализ
                async with session.get(
                    f"{self.API_BASE}/urls/{url_id}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = self._parse_response(data)
                        result["_cached_at"] = datetime.now()
                        self._cache[url] = result
                        return result

                    elif resp.status == 404:
                        # URL ещё не в базе — отправляем на сканирование
                        return await self._submit_url(session, url, headers)

                    else:
                        log.warning(f"VT API returned {resp.status} for {url}")
                        return self._empty_result(f"API error: {resp.status}")

        except asyncio.TimeoutError:
            log.warning(f"VT API timeout for {url}")
            return self._empty_result("API timeout")
        except Exception as e:
            log.error(f"VT API error: {e}")
            return self._empty_result(str(e))

    async def _submit_url(
        self, session: aiohttp.ClientSession, url: str, headers: dict
    ) -> dict:
        """Отправить URL на сканирование."""
        try:
            async with session.post(
                f"{self.API_BASE}/urls",
                headers=headers,
                data={"url": url},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    analysis_id = data.get("data", {}).get("id")
                    if analysis_id:
                        # Ждём пару секунд и проверяем результат
                        await asyncio.sleep(3)
                        return await self._get_analysis(session, analysis_id, headers)
                return self._empty_result("Submitted for scanning")
        except Exception as e:
            log.error(f"VT submit error: {e}")
            return self._empty_result(str(e))

    async def _get_analysis(
        self, session: aiohttp.ClientSession, analysis_id: str, headers: dict
    ) -> dict:
        """Получить результат анализа."""
        try:
            async with session.get(
                f"{self.API_BASE}/analyses/{analysis_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                    return self._stats_to_result(stats)
        except Exception as e:
            log.error(f"VT analysis error: {e}")
        return self._empty_result("Analysis pending")

    def _parse_response(self, data: dict) -> dict:
        """Парсим ответ VT."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        categories = list(attrs.get("categories", {}).values())
        result = self._stats_to_result(stats)
        result["categories"] = categories
        return result

    def _stats_to_result(self, stats: dict) -> dict:
        """Преобразуем статистику VT в наш формат."""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected
        risk_score = 0.0
        if total > 0:
            risk_score = min((malicious * 1.0 + suspicious * 0.5) / total * 5, 1.0)

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "risk_score": round(risk_score, 2),
            "categories": [],
            "source": "virustotal",
        }

    def _empty_result(self, reason: str = "") -> dict:
        return {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "risk_score": 0.0,
            "categories": [],
            "source": "virustotal",
            "error": reason,
        }
