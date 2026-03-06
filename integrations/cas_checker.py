"""
Интеграция с базой данных спамеров CAS (Combot Anti-Spam API).
Проверяет user_id глобально по всем чатам.
"""

import logging
import aiohttp

log = logging.getLogger("svoy_bot.cas")

class CASChecker:
    """Асинхронная проверка User ID по базе CAS."""
    
    def __init__(self, api_base: str = "https://api.cas.chat/check"):
        self.api_base = api_base
        self.enabled = True # Public API, no key required
        
    async def check_user_id(self, user_id: int) -> dict:
        """
        Проверяет user_id. 
        Возвращает:
        {
            "ok": bool,     # True если юзер найден в спам-базе (ЗАБАНЕН)
            "result": str,  # "User is banned"
            "offenses": int,# количество спам-репортов
            "time_added": int # timestamp банов
        }
        Важно: ok=True значит что пользователь В ЧЕРНОМ СПИСКЕ.
        """
        if not self.enabled:
            return {"ok": False, "result": "CAS is disabled"}
            
        try:
            async with aiohttp.ClientSession() as session:
                # url = https://api.cas.chat/check?user_id=...
                async with session.get(
                    self.api_base, 
                    params={"user_id": str(user_id)},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        # Пример ответа: {"ok":true,"result":{"offenses":1,"time_added":1616...}}
                        # Или если чист: {"ok":false,"description":"User not found"}
                        data = await resp.json()
                        return data
                    else:
                        log.warning(f"CAS API returned status {resp.status}")
                        return {"ok": False, "error": f"HTTP {resp.status}"}
        except Exception as e:
            log.error(f"CAS API error for {user_id}: {e}")
            return {"ok": False, "error": str(e)}
