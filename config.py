import os
from dotenv import load_dotenv

load_dotenv()

# ─── Обязательные ───
BOT_TOKEN = os.getenv("BOT_TOKEN")

# ─── API-ключи (опционально) ───
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ─── Админы (Telegram user IDs через запятую) ───
_admin_ids = os.getenv("ADMIN_IDS", "")
ADMIN_IDS = [int(x.strip()) for x in _admin_ids.split(",") if x.strip()]

# ─── Webhook (опционально, для продакшена) ───
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "/webhook")
WEBAPP_HOST = os.getenv("WEBAPP_HOST", "0.0.0.0")
WEBAPP_PORT = int(os.getenv("WEBAPP_PORT", "8443"))

# ─── Rate Limiting ───
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "30"))         # запросов в минуту
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))        # окно в секундах

# ─── Пороги риска (0.0 - 1.0) ───
RISK_LOW = 0.3       # ниже — безопасно
RISK_MEDIUM = 0.6    # ниже — подозрительно
                     # выше — опасно
