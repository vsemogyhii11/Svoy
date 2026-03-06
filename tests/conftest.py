"""
Общая конфигурация pytest для всех тестов.
"""
import pytest


def pytest_configure(config):
    """Настройка конфигурации pytest."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as an asyncio test."
    )
