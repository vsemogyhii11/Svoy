# 🛡 Система защиты СВОЙ

## Обзор

Комплексная система защиты от ботов, спама и мошенников в Telegram-боте.

---

## 📋 Компоненты

### 1. **Honeypot Tracking** — Ловушки для IP

**Файлы:**
- `integrations/ip_tracker.py` — веб-сервер для отслеживания
- `handlers/honeypot.py` — команды бота

**Команды:**
- `/bait` — создать ссылку-ловушку
- `/bait_status` — проверить статус ловушек
- `/bait_delete <token>` — удалить ловушку

**Как работает:**
```
1. Пользователь создаёт ловушку: /bait
2. Бот генерирует уникальную ссылку: https://trax.svoy.app/verify/abc123
3. Ссылка отправляется мошеннику
4. При клике фиксируются: IP, User-Agent, Referer, время
5. Пользователь получает уведомление
```

**Настройка:**
```bash
# Запуск сервера ловушек
python -m integrations.ip_tracker

# Порт: 8080
# Домен: trax.svoy.app (заменить на свой)
```

---

### 2. **IP Rate Limiting** — Ограничение по IP

**Файл:** `middleware/ip_rate_limit.py`

**Параметры:**
- 100 запросов/мин с одного IP
- Бан на 10 минут при превышении
- Whitelist для Telegram IP

**Подключение:**
```python
from middleware.ip_rate_limit import IPRateLimitMiddleware

dp.message.middleware(IPRateLimitMiddleware(
    max_requests=100,
    window_seconds=60,
    ban_duration=600
))
```

---

### 3. **Geo-Blocking** — Блокировка по странам

**Файл:** `middleware/geo_block.py`

**Настройка в .env:**
```env
# Разрешённые страны (None = все кроме blocked)
ALLOWED_COUNTRIES=RU,BY,KZ

# Заблокированные страны
BLOCKED_COUNTRIES=KP,IR,SY,CU

# Использовать локальную GeoIP базу
GEOIP_USE_LOCAL=true
```

**Источники GeoIP:**
1. Локальная база MaxMind GeoLite2
2. API fallback (ip-api.com, ipapi.co)

**Установка базы:**
```bash
# Скачать GeoLite2
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb
mv GeoLite2-Country.mmdb data/
```

---

### 4. **IP Reputation** — Проверка репутации IP

**Файл:** `integrations/ip_reputation.py`

**Источники:**
- AbuseIPDB (бесплатно, 1000 запросов/день)
- TOR Exit Nodes список
- Proxy/VPN детекция
- Hosting детекция

**Настройка:**
```env
# Получить ключ: https://www.abuseipdb.com/api
ABUSEIPDB_KEY=your_api_key_here
```

**Использование:**
```python
from integrations.ip_reputation import init_ip_checker, get_ip_checker

init_ip_checker(abuseipdb_key="your-key")
checker = get_ip_checker()

result = await checker.check_ip("1.2.3.4")

if result.is_malicious:
    print(f"🔴 IP опасен: {result.abuse_score}%")
    print(f"Типы угроз: {result.threat_types}")
```

**Уровни риска:**
| Risk | Abuse Score | Действие |
|------|-------------|----------|
| none | 0-19 | Пропустить |
| low | 20-39 | Логировать |
| medium | 40-74 | Проверить |
| high | 75-100 | Заблокировать |

---

### 5. **User-Agent Analysis** — Детекция ботов

**Файл:** `analyzers/user_agent_analyzer.py`

**Обнаруживает:**
- Selenium, Puppeteer, Playwright
- Headless браузеры
- Scrapy, curl, wget
- Python-requests
- Подозрительные паттерны

**Использование:**
```python
from analyzers.user_agent_analyzer import get_ua_analyzer

analyzer = get_ua_analyzer()
result = analyzer.analyze(user_agent_string)

if result.is_bot:
    print(f"Бот: {result.bot_type}")
    print(f"Уверенность: {result.confidence:.0%}")
    print(f"Риск: {result.risk_level}")
```

**Обнаруживаемые боты:**
| Тип | Пример | Confidence |
|-----|--------|------------|
| selenium | Selenium/4.0 | 95% |
| puppeteer | Puppeteer/10.0 | 95% |
| playwright | Playwright/1.15 | 95% |
| scrapy | Scrapy/2.5 | 95% |
| curl | curl/7.68 | 80% |
| python-requests | python-requests/2.26 | 85% |

---

### 6. **Device Fingerprinting** — Связка аккаунтов

**Файл:** `analyzers/fingerprint.py`

**Собираемые данные:**
- Разрешение экрана
- Часовой пояс
- Язык
- Платформа
- CPU/GPU
- Шрифты
- WebGL

**Обнаруживает:**
- Одинаковые устройства ≠ разные аккаунты
- Эмуляторы (BlueStacks, Nox)
- VM (VirtualBox, VMware)
- Root/jailbreak устройства

**Использование (клиент WebApp):**
```javascript
// Сбор fingerprint
async function collectFingerprint() {
    return {
        screen: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: navigator.language,
        platform: navigator.platform,
        cpu: navigator.hardwareConcurrency,
        gpu: await getWebGLRenderer(),
        fonts: await detectFonts(),
        user_agent: navigator.userAgent
    };
}

// Отправка боту
Telegram.WebApp.sendData(JSON.stringify(fp));
```

**Использование (бот):**
```python
from analyzers.fingerprint import init_fingerprint_analyzer, get_fingerprint_analyzer

init_fingerprint_analyzer()
analyzer = get_fingerprint_analyzer()

result = analyzer.analyze(fingerprint_data, user_id)

if result.is_suspicious:
    print(f"Подозрительное устройство!")
    print(f"Связанные аккаунты: {result.linked_accounts}")
```

---

## 🔧 Интеграция в бота

### bot.py — полное подключение

```python
from middleware.ip_rate_limit import IPRateLimitMiddleware, SimpleIPRateLimitMiddleware
from middleware.geo_block import GeoBlockMiddleware, load_geo_config_from_env
from integrations.ip_reputation import init_ip_checker, get_ip_checker
from analyzers.user_agent_analyzer import get_ua_analyzer
from analyzers.fingerprint import init_fingerprint_analyzer
from integrations.ip_tracker import init_tracker

# Инициализация
init_tracker()
init_ip_checker(abuseipdb_key=os.getenv("ABUSEIPDB_KEY"))
init_fingerprint_analyzer()

# Загрузка конфигурации GeoIP
geo_config = load_geo_config_from_env()

# Middleware
dp.message.middleware(GeoBlockMiddleware(**geo_config))
dp.message.middleware(SimpleIPRateLimitMiddleware())  # Для polling
# или IPRateLimitMiddleware() для webhook

# В хендлерах
async def check_user_safety(user_id: int, user_agent: str, ip: str):
    checker = get_ip_checker()
    ua_analyzer = get_ua_analyzer()
    fp_analyzer = get_fingerprint_analyzer()
    
    # Проверка IP
    ip_result = await checker.check_ip(ip)
    if ip_result.risk_level == "high":
        return False, "IP в чёрном списке"
    
    # Проверка UA
    ua_result = ua_analyzer.analyze(user_agent)
    if ua_result.is_bot and ua_result.confidence > 0.8:
        return False, "Обнаружен бот"
    
    # Проверка fingerprint
    fp_result = fp_analyzer.analyze(fingerprint, user_id)
    if fp_result.is_suspicious:
        return False, "Подозрительное устройство"
    
    return True, "OK"
```

---

## 📊 Мониторинг

### Health Check endpoints

```bash
# IP Tracker
curl http://localhost:8080/health

# Admin Panel
curl http://localhost:5005/health
```

### Логи

```bash
# Логи ловушек
tail -f data/honeypot/clicks.json

# Логи бота
tail -f logs/svoy_bot.log

# Логи админки
tail -f logs/admin_panel.log
```

---

## 🚀 Быстрый старт

```bash
# 1. Установка зависимостей
pip install -r requirements.txt

# 2. Скачать GeoIP базу
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb
mv GeoLite2-Country.mmdb data/

# 3. Настроить .env
cp .env.example .env
# Отредактировать: ABUSEIPDB_KEY, BLOCKED_COUNTRIES, etc.

# 4. Запустить сервер ловушек
python -m integrations.ip_tracker &

# 5. Запустить бота
python bot.py
```

---

## 📈 Статистика

| Метрика | Значение |
|---------|----------|
| Файлов добавлено | 10 |
| Строк кода | ~2500 |
| Тестов | 25 |
| Уровней защиты | 6 |

---

## ⚠️ Важные замечания

1. **GeoIP база** — требует обновления раз в месяц
2. **AbuseIPDB** — лимит 1000 запросов/день (бесплатно)
3. **Honeypot** — нужен публичный домен для работы
4. **Fingerprint** — работает только с WebApp
5. **IP Rate Limit** — в polling режиме менее эффективен

---

## 📝 TODO

- [ ] Добавить интеграцию с IPQualityScore
- [ ] Реализовать CAPTCHA для подозрительных
- [ ] Добавить Telegram WebApp Verification
- [ ] Поведенческий анализ (время между сообщениями)
- [ ] Redis для хранения fingerprint/rate limits
