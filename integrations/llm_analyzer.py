"""
LLM-анализ текста на мошенничество.

Использует OpenAI API для интеллектуального анализа текста,
когда rule-based анализ даёт неоднозначный результат (0.3–0.6).
Fallback на rule-based при отсутствии ключа или ошибке API.
"""

import json
import logging

import aiohttp

log = logging.getLogger("svoy_bot.llm")

# Системный промпт для анализа
SYSTEM_PROMPT = """Ты — эксперт по кибербезопасности и социальной инженерии. 
Проанализируй сообщение на признаки мошенничества.

Отвечай ТОЛЬКО в формате JSON:
{
    "risk_score": <число от 0.0 до 1.0>,
    "risk_level": "<safe|suspicious|danger>",
    "analysis": "<краткий анализ на русском, 1-2 предложения>",
    "manipulation_techniques": ["<техника1>", "<техника2>"],
    "recommendation": "<совет пользователю на русском>"
}

Учитывай:
- Давление временем (срочность)
- Запугивание (блокировка карт, арест)
- Подмена авторитета (банк, полиция, ФСБ)
- Просьбы о деньгах, кодах, установке ПО
- Ложные выигрыши и компенсации
- Требование секретности

Будь строгим: лучше ложноположительный результат, чем пропущенное мошенничество."""


class LLMAnalyzer:
    """Анализ текста через LLM (OpenAI-совместимый API)."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "openai/gpt-4o-mini",
        api_base: str = "https://openrouter.ai/api/v1",
    ):
        self.api_key = api_key
        self.model = model
        self.api_base = api_base
        self.enabled = bool(api_key)

    async def analyze(self, text: str, custom_prompt: str | None = None) -> dict:
        """
        Анализ текста через LLM.
        """
        if not self.enabled:
            return self._empty_result("API key not configured")

        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }

            system_content = custom_prompt if custom_prompt else SYSTEM_PROMPT

            body = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": f"Данные для анализа:\n\n{text[:3000]}"},
                ],
                "temperature": 0.1,
                "max_tokens": 800,
                "response_format": {"type": "json_object"},
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=body,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content = (
                            data.get("choices", [{}])[0]
                            .get("message", {})
                            .get("content", "{}")
                        )
                        result = json.loads(content)
                        result["source"] = "llm"
                        return result
                    else:
                        error_text = await resp.text()
                        log.warning(f"LLM API {resp.status}: {error_text[:200]}")
                        return self._empty_result(f"API error: {resp.status}")

        except json.JSONDecodeError as e:
            log.error(f"LLM response parse error: {e}")
            return self._empty_result("Invalid JSON response")
        except Exception as e:
            log.error(f"LLM API error: {e}")
            return self._empty_result(str(e))

    def _empty_result(self, reason: str = "") -> dict:
        return {
            "risk_score": 0.0,
            "risk_level": "unknown",
            "analysis": "",
            "manipulation_techniques": [],
            "recommendation": "",
            "source": "llm",
            "error": reason,
        }

    async def transcribe_audio(self, audio_bytes: bytes) -> str:
        """Расшифровка голосовых сообщений через OpenAI Audio API (Whisper)."""
        if not self.enabled:
            return ""
            
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
            }
            
            data = aiohttp.FormData()
            data.add_field("file", audio_bytes, filename="audio.ogg", content_type="audio/ogg")
            data.add_field("model", "whisper-1")
            
            # Мы жестко используем API OpenAI для транскрибации, так как OpenRouter не поддерживает audio endpoints
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.openai.com/v1/audio/transcriptions",
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=45)
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        return result.get("text", "")
                    else:
                        error_text = await resp.text()
                        log.error(f"Whisper API error {resp.status}: {error_text}")
                        return ""
        except Exception as e:
            log.error(f"Whisper API exception: {e}")
            return ""
