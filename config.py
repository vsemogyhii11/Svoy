"""
Конфигурация проекта СВОЙ
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Загружаем .env
load_dotenv()

# ============================================
# TELEGRAM
# ============================================
BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# ============================================
# API КЛЮЧИ
# ============================================
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

# ============================================
# АДМИН-ПАНЕЛЬ
# ============================================
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "super-secret-key")

# ============================================
# БАЗА ДАННЫХ
# ============================================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///data/svoy.db")
DB_PATH = Path("data/svoy.db")

# ============================================
# RATE LIMITING
# ============================================
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "30"))
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))

# ============================================
# КЭШИРОВАНИЕ
# ============================================
API_CACHE_TTL = int(os.getenv("API_CACHE_TTL", "3600"))
WHOIS_CACHE_TTL = int(os.getenv("WHOIS_CACHE_TTL", "86400"))

# ============================================
# OSINT АГЕНТЫ
# ============================================
OSINT_CYCLE_INTERVAL = int(os.getenv("OSINT_CYCLE_INTERVAL", "180"))
OSINT_SCAN_DEPTH = int(os.getenv("OSINT_SCAN_DEPTH", "5"))
OSINT_MAX_CONCURRENT = int(os.getenv("OSINT_MAX_CONCURRENT", "20"))

# ============================================
# ЛОГИРОВАНИЕ
# ============================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/svoy_bot.log")
LOG_MAX_SIZE_MB = int(os.getenv("LOG_MAX_SIZE_MB", "10"))
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))

# ============================================
# МОНИТОРИНГ
# ============================================
ENABLE_HEALTH_CHECK = os.getenv("ENABLE_HEALTH_CHECK", "true").lower() == "true"
HEALTH_CHECK_PORT = int(os.getenv("HEALTH_CHECK_PORT", "5005"))
ENABLE_METRICS = os.getenv("ENABLE_METRICS", "true").lower() == "true"

# ============================================
# БЕЗОПАСНОСТЬ
# ============================================
BLOCKED_COUNTRIES = set(os.getenv("BLOCKED_COUNTRIES", "KP,IR,SY").split(","))
ALLOWED_COUNTRIES = os.getenv("ALLOWED_COUNTRIES", None)
if ALLOWED_COUNTRIES:
    ALLOWED_COUNTRIES = set(ALLOWED_COUNTRIES.split(","))
CAPTCHA_THRESHOLD = float(os.getenv("CAPTCHA_THRESHOLD", "0.5"))

# ============================================
# ПУТИ
# ============================================
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Создаём директории
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ============================================
# ВЕРСИЯ
# ============================================
VERSION = "2.0.0"
PROJECT_NAME = "СВОЙ"
