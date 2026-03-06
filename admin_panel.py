from quart import Quart, render_template, request, redirect, url_for, session, jsonify
import os
import logging
import aiosqlite
from datetime import datetime

from utils.logger import setup_logging

# Настраиваем логирование
log = setup_logging(log_file="logs/admin_panel.log", level=logging.INFO)

app = Quart(__name__)
app.secret_key = os.getenv("ADMIN_SECRET_KEY", "super-secret-key")

# Путь к БД из конфига или окружения
DB_PATH = "data/svoy.db"


@app.route('/health')
async def health_check():
    """
    Health check endpoint для Docker и мониторинга.
    
    Returns:
        JSON со статусом сервиса и зависимостей
    """
    status = {
        "status": "healthy",
        "version": "0.1.0",
        "checks": {}
    }
    overall_status = "healthy"
    
    # Проверка БД
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT 1")
        status["checks"]["database"] = "ok"
    except Exception as e:
        status["checks"]["database"] = f"error: {str(e)}"
        overall_status = "unhealthy"
    
    # Проверка файлов данных
    data_files = [
        "data/scam_phones.json",
        "data/scam_patterns.json",
        "data/trusted_domains.json"
    ]
    missing_files = []
    for file_path in data_files:
        if not os.path.exists(file_path):
            # Проверяем относительно корня проекта
            root_path = os.path.join(os.path.dirname(__file__), file_path)
            if not os.path.exists(root_path):
                missing_files.append(file_path)
    
    if missing_files:
        status["checks"]["data_files"] = f"missing: {', '.join(missing_files)}"
        if overall_status == "healthy":
            overall_status = "degraded"
    else:
        status["checks"]["data_files"] = "ok"
    
    status["status"] = overall_status
    
    http_status = 200 if overall_status == "healthy" else 503
    return jsonify(status), http_status


@app.route('/ready')
async def readiness_check():
    """
    Readiness check endpoint для Kubernetes/Docker Swarm.
    
    Проверяет готовность сервиса принимать трафик.
    """
    try:
        # Быстрая проверка БД
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("SELECT COUNT(*) FROM users")
        return jsonify({"ready": True}), 200
    except Exception as e:
        log.error(f"Readiness check failed: {e}")
        return jsonify({"ready": False, "error": str(e)}), 503

async def get_dashboard_stats():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # Всего отчетов (номеров)
        async with db.execute("SELECT COUNT(*) FROM reports") as cursor:
            total_reports = (await cursor.fetchone())[0]
        # Всего пользователей
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            total_users = (await cursor.fetchone())[0]
        # Всего выявленных угроз (проверок с риском)
        async with db.execute("SELECT COUNT(*) FROM checks WHERE has_threat = 1") as cursor:
            scam_count = (await cursor.fetchone())[0]
        # Всего проверок
        async with db.execute("SELECT COUNT(*) FROM checks") as cursor:
            total_checks = (await cursor.fetchone())[0]

        # Последние 10 отчетов
        async with db.execute("SELECT * FROM reports ORDER BY last_report DESC LIMIT 10") as cursor:
            recent_reports = [dict(r) for r in await cursor.fetchall()]

        # Все уникальные описания схем (топ 20)
        async with db.execute("SELECT description, COUNT(*) as count FROM reports GROUP BY description ORDER BY count DESC LIMIT 20") as cursor:
            scam_schemes = [dict(r) for r in await cursor.fetchall()]

        return {
            "total_reports": total_reports,
            "total_users": total_users,
            "scam_count": scam_count,
            "total_checks": total_checks,
            "recent_reports": recent_reports,
            "scam_schemes": scam_schemes
        }

@app.route('/')
async def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    stats = await get_dashboard_stats()
    return await render_template('dashboard.html', stats=stats)

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        # В продакшене пароль должен быть в .env
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
        form = await request.form
        if form['password'] == admin_pass:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
    return await render_template('login.html')

@app.route('/logout')
async def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005)
