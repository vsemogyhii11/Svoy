"""
IP Tracker — веб-сервер для отслеживания кликов по ссылкам-ловушкам.

Использование:
    python -m integrations.ip_tracker
    
Сервер запускается на порту 8080 и логирует:
- IP адрес
- User-Agent
- Referer
- Timestamp
- Гео-данные (если доступна GeoIP база)
"""

import asyncio
import logging
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass, asdict

from quart import Quart, request, jsonify, render_template_string
import aiofiles

log = logging.getLogger("svoy_bot.ip_tracker")

# Шаблон страницы-ловушки (перенаправляет на Google с задержкой)
HONEY_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Проверка безопасности</title>
    <meta http-equiv="refresh" content="2;url=https://www.google.com">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 400px;
        }
        h1 { color: #333; margin-bottom: 15px; }
        p { color: #666; line-height: 1.6; }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Проверка безопасности</h1>
        <p>Пожалуйста, подождите... Вы будете перенаправлены через несколько секунд.</p>
        <div class="spinner"></div>
    </div>
    <script>
        // Отправка данных о клике
        fetch('/api/log', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                token: '{{ token }}',
                timestamp: new Date().toISOString()
            })
        });
    </script>
</body>
</html>
"""


@dataclass
class ClickLog:
    """Запись о клике по ловушке."""
    token: str
    ip_address: str
    user_agent: str
    referer: str
    timestamp: str
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None


class IPTracker:
    """Трекер кликов по IP."""
    
    def __init__(self, data_dir: str = "data/honeypot"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_file = self.data_dir / "clicks.json"
        self.tokens_file = self.data_dir / "tokens.json"
        self._tokens: Dict[str, dict] = {}
        self._load_tokens()
    
    def _load_tokens(self):
        """Загрузить активные токены."""
        if self.tokens_file.exists():
            with open(self.tokens_file, 'r', encoding='utf-8') as f:
                self._tokens = json.load(f)
    
    def _save_tokens(self):
        """Сохранить токены."""
        with open(self.tokens_file, 'w', encoding='utf-8') as f:
            json.dump(self._tokens, f, ensure_ascii=False, indent=2)
    
    def create_token(self, user_id: int, username: str = "") -> str:
        """Создать новый токен ловушки."""
        import uuid
        token = str(uuid.uuid4())[:12]
        
        self._tokens[token] = {
            "user_id": user_id,
            "username": username,
            "created_at": datetime.now().isoformat(),
            "clicks": 0
        }
        self._save_tokens()
        
        return token
    
    async def log_click(self, click_data: ClickLog):
        """Записать клик в лог."""
        # Обновляем счётчик кликов
        if click_data.token in self._tokens:
            self._tokens[click_data.token]["clicks"] += 1
            self._tokens[click_data.token]["last_click"] = datetime.now().isoformat()
            self._save_tokens()
        
        # Записываем в файл логов
        log_entry = asdict(click_data)
        
        async with aiofiles.open(self.logs_file, 'a', encoding='utf-8') as f:
            await f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
        
        log.info(f"🎯 Honeypot click: {click_data.ip_address} -> Token: {click_data.token}")
    
    def get_token_info(self, token: str) -> Optional[dict]:
        """Получить информацию о токене."""
        return self._tokens.get(token)
    
    def get_clicks_for_token(self, token: str) -> list:
        """Получить все клики для токена."""
        clicks = []
        if self.logs_file.exists():
            with open(self.logs_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if data.get('token') == token:
                            clicks.append(data)
                    except json.JSONDecodeError:
                        continue
        return clicks
    
    def cleanup_old_tokens(self, days: int = 7):
        """Удалить старые токены."""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=days)
        to_remove = []
        
        for token, data in self._tokens.items():
            created = datetime.fromisoformat(data["created_at"])
            if created < cutoff:
                to_remove.append(token)
        
        for token in to_remove:
            del self._tokens[token]
        
        if to_remove:
            self._save_tokens()
            log.info(f"Cleaned up {len(to_remove)} old honeypot tokens")


# Глобальный экземпляр
_tracker: Optional[IPTracker] = None


def get_tracker() -> IPTracker:
    """Получить глобальный экземпляр трекера."""
    global _tracker
    if _tracker is None:
        _tracker = IPTracker()
    return _tracker


def init_tracker(data_dir: str = "data/honeypot") -> IPTracker:
    """Инициализировать глобальный трекер."""
    global _tracker
    _tracker = IPTracker(data_dir)
    return _tracker


# Quart приложение для трекинга
app = Quart(__name__)
app.config['MAX_CONTENT_LENGTH'] = '1KB'  # Защита от больших запросов


@app.route('/verify/<token>')
async def verify_click(token: str):
    """Страница-ловушка для отлова IP."""
    tracker = get_tracker()
    token_info = tracker.get_token_info(token)
    
    if not token_info:
        return await render_template_string(
            "<h1>❌ Ссылка недействительна или истекла</h1>",
            status=404
        )
    
    return await render_template_string(
        HONEY_PAGE_TEMPLATE,
        token=token
    )


@app.route('/api/log', methods=['POST'])
async def log_click_api():
    """API для логирования клика."""
    try:
        data = await request.get_json()
        token = data.get('token', '')
        
        if not token:
            return jsonify({"error": "No token"}), 400
        
        tracker = get_tracker()
        
        # Получаем IP (с учётом прокси)
        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip_address = request.remote_addr or 'unknown'
        
        click_log = ClickLog(
            token=token,
            ip_address=ip_address,
            user_agent=request.headers.get('User-Agent', 'unknown'),
            referer=request.headers.get('Referer', 'unknown'),
            timestamp=datetime.now().isoformat()
        )
        
        await tracker.log_click(click_log)
        
        # Уведомляем пользователя (через Telegram бота)
        # Это будет вызвано из bot.py через callback
        token_info = tracker.get_token_info(token)
        if token_info:
            log.info(f"📩 Notify user {token_info['user_id']} about click from {ip_address}")
            # Здесь будет интеграция с ботом для отправки уведомления
        
        return jsonify({"status": "ok"})
    
    except Exception as e:
        log.error(f"Error logging click: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/health')
async def health():
    """Health check для трекера."""
    return jsonify({
        "status": "healthy",
        "service": "ip_tracker",
        "active_tokens": len(get_tracker()._tokens)
    })


def run_tracker_server(host: str = '0.0.0.0', port: int = 8080):
    """Запустить сервер трекера."""
    log.info(f"🎯 Starting IP Tracker server on {host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    # Инициализация
    init_tracker()
    
    # Запуск сервера
    run_tracker_server()
