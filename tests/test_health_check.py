"""
Тесты для health check endpoints в admin_panel.py
"""
import pytest
import sys
import os
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from admin_panel import app, DB_PATH


@pytest.fixture
def test_client():
    """Фикстура тестового клиента Quart."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def temp_db():
    """Создаёт временную БД для тестов."""
    import aiosqlite
    
    # Создаём временный файл БД
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        temp_db_path = f.name
    
    async def setup_db():
        async with aiosqlite.connect(temp_db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    checks_count INTEGER DEFAULT 0,
                    reports_count INTEGER DEFAULT 0,
                    first_seen TEXT DEFAULT (datetime('now')),
                    last_seen TEXT DEFAULT (datetime('now')),
                    language TEXT DEFAULT 'ru'
                )
            """)
            await db.execute("INSERT INTO users (user_id) VALUES (1)")
            await db.commit()
    
    import asyncio
    asyncio.run(setup_db())
    
    # Сохраняем оригинальный путь и подменяем
    original_db_path = DB_PATH
    import admin_panel
    admin_panel.DB_PATH = temp_db_path
    
    yield temp_db_path
    
    # Восстанавливаем оригинальный путь
    admin_panel.DB_PATH = original_db_path
    os.unlink(temp_db_path)


class TestHealthCheck:
    """Тесты health check endpoint."""

    def test_health_endpoint_exists(self, test_client):
        """Health endpoint существует и возвращает JSON."""
        response = test_client.get('/health')
        assert response.status_code in [200, 503]
        assert response.content_type == 'application/json'

    def test_health_response_structure(self, test_client):
        """Структура ответа health check."""
        response = test_client.get('/health')
        data = response.get_json()
        
        assert "status" in data
        assert "checks" in data
        assert "version" in data
        
        assert data["version"] == "0.1.0"
        assert data["status"] in ["healthy", "unhealthy", "degraded"]

    def test_health_database_check(self, test_client, temp_db):
        """Проверка БД в health check."""
        response = test_client.get('/health')
        data = response.get_json()
        
        assert "database" in data["checks"]
        # С временной БД должен быть ok
        assert data["checks"]["database"] == "ok"

    def test_health_status_codes(self, test_client):
        """Проверка кодов статуса."""
        response = test_client.get('/health')
        
        # Должен вернуть 200 или 503
        assert response.status_code in [200, 503]
        
        # Если healthy - 200, иначе 503
        data = response.get_json()
        if data["status"] == "healthy":
            assert response.status_code == 200
        else:
            assert response.status_code == 503


class TestReadinessCheck:
    """Тесты readiness check endpoint."""

    def test_ready_endpoint_exists(self, test_client):
        """Readiness endpoint существует."""
        response = test_client.get('/ready')
        assert response.status_code in [200, 503]
        assert response.content_type == 'application/json'

    def test_ready_response_structure(self, test_client):
        """Структура ответа readiness check."""
        response = test_client.get('/ready')
        data = response.get_json()
        
        assert "ready" in data
        assert isinstance(data["ready"], bool)

    def test_ready_with_working_db(self, test_client, temp_db):
        """Readiness check с рабочей БД."""
        response = test_client.get('/ready')
        data = response.get_json()
        
        assert data["ready"] is True
        assert response.status_code == 200

    def test_ready_error_response(self, test_client):
        """Readiness check с ошибкой (БД не существует)."""
        # Временно подменяем путь на несуществующий
        import admin_panel
        original = admin_panel.DB_PATH
        admin_panel.DB_PATH = "/nonexistent/path/db.sqlite"
        
        try:
            response = test_client.get('/ready')
            data = response.get_json()
            
            assert data["ready"] is False
            assert "error" in data
            assert response.status_code == 503
        finally:
            admin_panel.DB_PATH = original
