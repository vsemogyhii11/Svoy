"""
GeoIP Blocking — блокировка запросов по географическому расположению.

Использует базу MaxMind GeoIP2 для определения страны по IP.

Настройка в .env:
    GEOIP_LICENSE_KEY=your_license_key
    ALLOWED_COUNTRIES=RU,BY,KZ
    BLOCKED_COUNTRIES=KP,IR,SY

Использование:
    from middleware.geo_block import GeoBlockMiddleware
    dp.message.middleware(GeoBlockMiddleware())
"""

import logging
import os
import socket
import struct
from pathlib import Path
from typing import Optional, Set, List

from aiogram import BaseMiddleware
from aiogram.types import Message, TelegramObject

log = logging.getLogger("svoy_bot.middleware.geo_block")


class GeoIPDatabase:
    """
    Локальная GeoIP база (без внешних API).
    
    Использует бесплатную базу GeoLite2 от MaxMind.
    Скачать: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    """
    
    def __init__(self, db_path: str = "data/GeoLite2-Country.mmdb"):
        self.db_path = Path(db_path)
        self._reader = None
        self._load_db()
    
    def _load_db(self):
        """Загрузить GeoIP базу."""
        if not self.db_path.exists():
            log.warning(f"GeoIP database not found: {self.db_path}")
            log.warning("Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            return
        
        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(str(self.db_path))
            log.info(f"GeoIP database loaded: {self.db_path}")
        except ImportError:
            log.warning("geoip2 package not installed. Run: pip install geoip2")
        except Exception as e:
            log.error(f"Failed to load GeoIP database: {e}")
    
    def get_country(self, ip_address: str) -> Optional[str]:
        """
        Получить код страны по IP.
        
        Args:
            ip_address: IP адрес
            
        Returns:
            Код страны (RU, US, etc.) или None
        """
        if not self._reader:
            return None
        
        try:
            response = self._reader.country(ip_address)
            return response.country.iso_code
        except Exception:
            return None
    
    def close(self):
        """Закрыть соединение с базой."""
        if self._reader:
            self._reader.close()


class IP2CountryAPI:
    """
    Бесплатный API для определения страны по IP.
    
    Альтернатива локальной базе GeoIP.
    """
    
    _cache = {}  # Простой кэш
    
    @classmethod
    async def get_country(cls, ip_address: str) -> Optional[str]:
        """Получить страну по IP через API."""
        if ip_address in cls._cache:
            return cls._cache[ip_address]
        
        try:
            import aiohttp
            
            # Бесплатные API (без ключа)
            apis = [
                f"http://ip-api.com/json/{ip_address}",
                f"https://ipapi.co/{ip_address}/json/",
            ]
            
            for url in apis:
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                        async with session.get(url) as response:
                            if response.status == 200:
                                data = await response.json()
                                country = data.get('country_code') or data.get('countryCode')
                                if country:
                                    cls._cache[ip_address] = country
                                    return country
                except Exception:
                    continue
            
            return None
        
        except Exception as e:
            log.debug(f"IP2Country API error: {e}")
            return None


class GeoBlockMiddleware(BaseMiddleware):
    """
    Middleware для блокировки по странам.
    """
    
    # Страны по умолчанию для блокировки (угрозы)
    DEFAULT_BLOCKED = {'KP', 'IR', 'SY', 'CU'}
    
    # Страны для разрешения (если задано)
    DEFAULT_ALLOWED = None  # Все разрешены кроме blocked
    
    def __init__(
        self,
        allowed_countries: Optional[Set[str]] = None,
        blocked_countries: Optional[Set[str]] = None,
        use_local_db: bool = True
    ):
        """
        Инициализация.
        
        Args:
            allowed_countries: Разрешённые страны (None = все кроме blocked)
            blocked_countries: Заблокированные страны
            use_local_db: Использовать локальную GeoIP базу
        """
        self.allowed_countries = allowed_countries or self.DEFAULT_ALLOWED
        self.blocked_countries = blocked_countries or self.DEFAULT_BLOCKED
        
        # GeoIP база
        self.geo_db = GeoIPDatabase() if use_local_db else None
        
        # Статистика
        self._blocked_count = 0
        self._allowed_count = 0
        
        super().__init__()
    
    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Проверка на whitelist IP."""
        # Telegram IP диапазоны
        telegram_ranges = [
            '149.154.',
            '91.108.',
            '5.28.',
        ]
        return any(ip.startswith(prefix) for prefix in telegram_ranges)
    
    async def _get_country(self, ip: str) -> Optional[str]:
        """Получить страну по IP."""
        # Локальная база
        if self.geo_db:
            country = self.geo_db.get_country(ip)
            if country:
                return country
        
        # API fallback
        country = await IP2CountryAPI.get_country(ip)
        return country
    
    async def __call__(
        self,
        handler,
        event: TelegramObject,
        data: dict,
    ):
        if not isinstance(event, Message) or not event.from_user:
            return await handler(event, data)
        
        # В webhook режиме можно получить IP из заголовков
        # Для polling — пропускаем гео-блокировку
        ip = "unknown"  # В polling режиме IP недоступен
        
        # Пропускаем whitelist IP
        if self._is_whitelisted_ip(ip):
            return await handler(event, data)
        
        # Определяем страну
        country = await self._get_country(ip)
        
        if country:
            # Проверка на блокировку
            if self.blocked_countries and country in self.blocked_countries:
                self._blocked_count += 1
                log.warning(f"🚫 Blocked user from {country}: {event.from_user.id}")
                
                await event.answer(
                    f"🚫 Доступ из вашей страны ({country}) ограничен.",
                    show_alert=True
                )
                return None
            
            # Проверка на разрешение
            if self.allowed_countries and country not in self.allowed_countries:
                self._blocked_count += 1
                log.warning(f"🚫 Blocked user from {country}: {event.from_user.id}")
                
                await event.answer(
                    f"🚫 Доступ из вашей страны ({country}) ограничен.",
                    show_alert=True
                )
                return None
            
            self._allowed_count += 1
        
        return await handler(event, data)
    
    def get_stats(self) -> dict:
        """Статистика блокировок."""
        return {
            "blocked_count": self._blocked_count,
            "allowed_count": self._allowed_count,
            "blocked_countries": list(self.blocked_countries),
            "allowed_countries": list(self.allowed_countries) if self.allowed_countries else "all"
        }


def load_geo_config_from_env() -> dict:
    """Загрузить конфигурацию GeoIP из .env."""
    from dotenv import load_dotenv
    load_dotenv()
    
    config = {
        "allowed_countries": None,
        "blocked_countries": None,
        "use_local_db": True
    }
    
    # Загруженные страны
    allowed = os.getenv("ALLOWED_COUNTRIES", "")
    if allowed:
        config["allowed_countries"] = set(allowed.split(','))
    
    # Заблокированные страны
    blocked = os.getenv("BLOCKED_COUNTRIES", "")
    if blocked:
        config["blocked_countries"] = set(blocked.split(','))
    
    # Использовать локальную базу
    config["use_local_db"] = os.getenv("GEOIP_USE_LOCAL", "true").lower() == "true"
    
    return config
