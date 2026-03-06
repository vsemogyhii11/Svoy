from quart import Quart, render_template, request, redirect, url_for, session
import os
import aiosqlite
from datetime import datetime

app = Quart(__name__)
app.secret_key = os.getenv("ADMIN_SECRET_KEY", "super-secret-key")

# Путь к БД из конфига или окружения
DB_PATH = "data/svoy.db"

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
