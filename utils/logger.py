"""
Настройка логирования в файл и консоль.

Использование:
    from utils.logger import setup_logging
    
    log = setup_logging(
        log_file="logs/svoy_bot.log",
        level=logging.INFO,
        max_bytes=10*1024*1024,  # 10 MB
        backup_count=5
    )
"""

import logging
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler


def setup_logging(
    log_file: str = "logs/svoy_bot.log",
    level: int = logging.INFO,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    format_string: str = None
) -> logging.Logger:
    """
    Настроить логирование в консоль и файл с ротацией.
    
    Args:
        log_file: Путь к файлу логов
        level: Уровень логирования
        max_bytes: Максимальный размер одного файла логов
        backup_count: Количество файлов для ротации
        format_string: Формат логов (по умолчанию стандартный)
        
    Returns:
        Настроенный логгер
    """
    if format_string is None:
        format_string = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    
    # Создаём директорию для логов
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Получаем корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Очищаем существующие обработчики
    root_logger.handlers.clear()
    
    # Форматтер
    formatter = logging.Formatter(format_string)
    
    # Консольный обработчик
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Файловый обработчик с ротацией
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Логгируем запуск
    root_logger.info(f"Logging initialized. Log file: {log_file}")
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Получить логгер с указанным именем.
    
    Args:
        name: Имя логгера (обычно __name__ модуля)
        
    Returns:
        Логгер
    """
    return logging.getLogger(name)
