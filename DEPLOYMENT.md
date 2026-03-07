# 🚀 DEPLOYMENT GUIDE — СВОЙ

## БЫСТРЫЙ СТАРТ

### Вариант 1: Docker Compose (Рекомендуется)

```bash
# Клонировать репозиторий
git clone https://github.com/vsemogyhii11/Svoy.git
cd Svoy

# Скопировать .env.example в .env
cp .env.example .env

# Отредактировать .env (добавить BOT_TOKEN и ключи API)
nano .env

# Запустить всё одной командой
docker-compose up -d

# Проверить статус
docker-compose ps

# Посмотреть логи
docker-compose logs -f bot
docker-compose logs -f admin

# Остановить
docker-compose down
```

**Сервисы:**
- 🤖 Бот: `svoy_bot`
- 🖥 Админка: http://localhost:5005
- 🗄 Redis: `svoy_redis`
- 📊 Redis GUI (dev): http://localhost:8081

---

### Вариант 2: Локальный запуск

```bash
# Установка Python 3.11+
python3 --version

# Установка зависимостей
pip3 install -r requirements.txt

# Настройка .env
cp .env.example .env
nano .env

# Запуск бота
python3 bot.py

# Запуск админки (в другом терминале)
python3 admin_panel.py
```

---

## НАСТРОЙКА .ENV

```env
# TELEGRAM
BOT_TOKEN=your_bot_token_from_botfather

# API КЛЮЧИ
VIRUSTOTAL_KEY=your_virustotal_key
GOOGLE_SAFE_BROWSING_KEY=your_google_key
OPENAI_API_KEY=your_openrouter_key

# АДМИНКА
ADMIN_PASSWORD=your_secure_password
ADMIN_SECRET_KEY=your_secret_key

# REDIS
REDIS_HOST=redis
REDIS_PORT=6379

# LOGGING
LOG_LEVEL=INFO
```

---

## DOCKER COMPOSE ПРОФИЛИ

### Production (по умолчанию)
```bash
docker-compose up -d
```

### Development (с Redis GUI)
```bash
docker-compose --profile dev up -d
```

Доступ к Redis GUI: http://localhost:8081

---

## HEALTH CHECKS

```bash
# Бот
curl http://localhost:8080/health

# Админка
curl http://localhost:5005/health

# Redis
docker exec svoy_redis redis-cli ping
```

---

## ЛОГИРОВАНИЕ

Логи сохраняются в:
- `logs/svoy_bot.log` — логи бота
- `logs/admin_panel.log` — логи админки

Просмотр:
```bash
tail -f logs/svoy_bot.log
docker-compose logs -f bot
```

---

## BACKUP ДАННЫХ

```bash
# Бэкап базы данных
docker cp svoy_bot:/app/data/svoy.db ./backup_svoy.db

# Бэкап Redis
docker exec svoy_redis redis-cli SAVE
docker cp svoy_redis:/data/dump.rdb ./backup_redis.rdb
```

---

## ОБНОВЛЕНИЕ

```bash
# Pull новых изменений
git pull

# Пересобрать и перезапустить
docker-compose up -d --build
```

---

## МОНИТОРИНГ

```bash
# Статус сервисов
docker-compose ps

# Использование ресурсов
docker stats

# Метрики Prometheus
curl http://localhost:5005/metrics
```

---

## ПРОБЛЕМЫ И РЕШЕНИЯ

### Бот не запускается
```bash
# Проверить токен
docker-compose logs bot | grep "BOT_TOKEN"

# Перезапустить
docker-compose restart bot
```

### Админка недоступна
```bash
# Проверить порт
netstat -tlnp | grep 5005

# Проверить логи
docker-compose logs admin
```

### Redis не подключается
```bash
# Проверить Redis
docker exec svoy_redis redis-cli ping

# Перезапустить Redis
docker-compose restart redis
```

---

## БЕЗОПАСНОСТЬ

1. **Смените пароль админки** по умолчанию
2. **Не коммитьте .env** в git
3. **Используйте HTTPS** в production
4. **Регулярно обновляйте** зависимости

---

**Версия:** 2.0  
**Дата:** 2026-03-06  
**Статус:** Production Ready ✅
