"""
IP Reputation Checker — проверка IP по чёрным спискам.

Интеграция с сервисами:
- AbuseIPDB (бесплатно, до 1000 запросов/день)
- IPQualityScore (платно, есть бесплатный tier)
- TOR Exit Nodes список
- Proxy/VPN детектор

Использование:
    from integrations.ip_reputation import IPReputationChecker
    
    checker = IPReputationChecker(api_key="...")
    result = await checker.check_ip("1.2.3.4")
    
    if result.is_malicious:
        print(f"IP опасен: {result.threat_types}")
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from pathlib import Path

import aiohttp

log = logging.getLogger("svoy_bot.ip_reputation")


@dataclass
class IPReputationResult:
    """Результат проверки IP."""
    ip: str
    is_malicious: bool = False
    abuse_score: int = 0  # 0-100
    threat_types: List[str] = field(default_factory=list)
    is_tor: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_hosting: bool = False
    country: Optional[str] = None
    isp: Optional[str] = None
    last_reported: Optional[str] = None
    total_reports: int = 0
    source: str = "unknown"
    
    @property
    def risk_level(self) -> str:
        """Уровень риска."""
        if self.is_malicious or self.abuse_score >= 75:
            return "high"
        elif self.abuse_score >= 40 or self.is_tor or self.is_proxy:
            return "medium"
        elif self.abuse_score >= 20:
            return "low"
        return "none"
    
    @property
    def emoji(self) -> str:
        """Emoji для уровня риска."""
        if self.risk_level == "high":
            return "🔴"
        elif self.risk_level == "medium":
            return "🟡"
        elif self.risk_level == "low":
            return "🟠"
        return "🟢"


class AbuseIPDBChecker:
    """
    Проверка IP через AbuseIPDB API.
    
    API: https://docs.abuseipdb.com/
    Лимит: 1000 запросов/день (бесплатно)
    """
    
    API_URL = "https://api.abuseipdb.com/api/v2/check"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._cache: Dict[str, tuple] = {}  # IP -> (result, timestamp)
        self._cache_ttl = 3600  # 1 час
    
    async def check(self, ip: str) -> Optional[IPReputationResult]:
        """Проверить IP."""
        # Проверка кэша
        if ip in self._cache:
            result, timestamp = self._cache[ip]
            if time.time() - timestamp < self._cache_ttl:
                log.debug(f"AbuseIPDB cache hit: {ip}")
                return result
        
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.API_URL,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_response(ip, data)
                    elif response.status == 429:
                        log.warning("AbuseIPDB rate limit exceeded")
                        return None
                    else:
                        log.warning(f"AbuseIPDB API error: {response.status}")
                        return None
        
        except Exception as e:
            log.debug(f"AbuseIPDB check error: {e}")
            return None
    
    def _parse_response(self, ip: str, data: dict) -> IPReputationResult:
        """Парсинг ответа API."""
        try:
            report = data.get('data', {})
            
            result = IPReputationResult(
                ip=ip,
                abuse_score=report.get('abuseConfidenceScore', 0),
                country=report.get('countryCode'),
                isp=report.get('isp'),
                last_reported=report.get('lastReportedAt'),
                total_reports=report.get('totalReports', 0),
                is_malicious=report.get('abuseConfidenceScore', 0) >= 50,
                source="abuseipdb"
            )
            
            # Определение типов угроз из отчётов
            threat_types = set()
            for report_item in report.get('reports', []):
                categories = report_item.get('categories', {})
                for cat_id, cat_name in categories.items():
                    threat_types.add(cat_name.lower())
            
            result.threat_types = list(threat_types)
            
            # Кэширование
            self._cache[ip] = (result, time.time())
            
            return result
        
        except Exception as e:
            log.debug(f"Error parsing AbuseIPDB response: {e}")
            return self._empty_result(ip)
    
    def _empty_result(self, ip: str) -> IPReputationResult:
        """Пустой результат при ошибке."""
        return IPReputationResult(ip=ip, source="abuseipdb")


class TORExitNodeChecker:
    """
    Проверка на TOR exit node.
    
    Использует публичный список exit nodes от Tor Project.
    Обновляется каждые 24 часа.
    """
    
    TOR_LIST_URL = "https://check.torproject.org/exit-addresses"
    
    def __init__(self):
        self._exit_nodes: set = set()
        self._last_update = 0
        self._update_interval = 86400  # 24 часа
    
    async def _update_list(self):
        """Обновить список exit nodes."""
        if time.time() - self._last_update < self._update_interval:
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.TOR_LIST_URL,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        self._exit_nodes.clear()
                        
                        for line in text.split('\n'):
                            if line.startswith('ExitAddress '):
                                parts = line.split()
                                if len(parts) >= 2:
                                    self._exit_nodes.add(parts[1])
                        
                        self._last_update = time.time()
                        log.info(f"TOR exit nodes updated: {len(self._exit_nodes)} nodes")
        
        except Exception as e:
            log.debug(f"Failed to update TOR list: {e}")
    
    async def is_tor(self, ip: str) -> bool:
        """Проверить IP на TOR exit node."""
        await self._update_list()
        return ip in self._exit_nodes


class IPReputationChecker:
    """
    Основной класс для проверки репутации IP.
    
    Объединяет несколько источников:
    - AbuseIPDB
    - TOR Exit Nodes
    - Proxy/VPN детекция
    """
    
    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        ipqualityscore_key: Optional[str] = None
    ):
        self.abuseipdb = AbuseIPDBChecker(abuseipdb_key) if abuseipdb_key else None
        self.tor_checker = TORExitNodeChecker()
        self.ipqualityscore = ipqualityscore_key  # Для будущего расширения
        
        # Кэш результатов
        self._cache: Dict[str, tuple] = {}
        self._cache_ttl = 3600
    
    async def check_ip(self, ip: str) -> IPReputationResult:
        """
        Полная проверка IP.
        
        Args:
            ip: IP адрес для проверки
            
        Returns:
            Результат проверки
        """
        # Проверка кэша
        if ip in self._cache:
            result, timestamp = self._cache[ip]
            if time.time() - timestamp < self._cache_ttl:
                return result
        
        results = []
        
        # AbuseIPDB
        if self.abuseipdb:
            result = await self.abuseipdb.check(ip)
            if result:
                results.append(result)
        
        # TOR
        is_tor = await self.tor_checker.is_tor(ip)
        
        # Объединение результатов
        final_result = IPReputationResult(ip=ip)
        
        if results:
            # Берём наиболее полный результат
            best_result = max(results, key=lambda r: r.total_reports)
            final_result = best_result
        
        final_result.is_tor = is_tor
        
        # TOR = автоматически medium риск
        if is_tor:
            final_result.threat_types.append("tor_exit_node")
            if final_result.risk_level == "none":
                final_result.abuse_score = 50
        
        # Определение hosting/proxy (упрощённо)
        if final_result.isp and any(
            keyword in final_result.isp.lower()
            for keyword in ['hosting', 'datacenter', 'cloud', 'digitalocean', 'aws', 'google cloud']
        ):
            final_result.is_hosting = True
        
        # Кэширование
        self._cache[ip] = (final_result, time.time())
        
        log.info(
            f"IP check: {ip} -> "
            f"risk={final_result.risk_level}, "
            f"score={final_result.abuse_score}, "
            f"tor={is_tor}"
        )
        
        return final_result
    
    async def is_safe(self, ip: str, threshold: int = 50) -> bool:
        """
        Быстрая проверка на безопасность.
        
        Args:
            ip: IP адрес
            threshold: Порог abuse score для блокировки
            
        Returns:
            True если IP безопасен
        """
        result = await self.check_ip(ip)
        return result.abuse_score < threshold and not result.is_tor


# Глобальный экземпляр
_checker: Optional[IPReputationChecker] = None


def get_ip_checker() -> Optional[IPReputationChecker]:
    """Получить глобальный чекер."""
    return _checker


def init_ip_checker(
    abuseipdb_key: Optional[str] = None,
    ipqualityscore_key: Optional[str] = None
) -> IPReputationChecker:
    """Инициализировать глобальный чекер."""
    global _checker
    _checker = IPReputationChecker(
        abuseipdb_key=abuseipdb_key,
        ipqualityscore_key=ipqualityscore_key
    )
    return _checker
