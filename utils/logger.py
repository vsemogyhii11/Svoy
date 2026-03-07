"""
📝 УЛУЧШЕННАЯ СИСТЕМА ЛОГИРОВАНИЯ для СВОЙ

Функции:
- Ротация файлов по размеру и времени
- Разные уровни для разных модулей
- Логирование в файл и консоль
- JSON формат (опционально)
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from datetime import datetime
import json


class JSONFormatter(logging.Formatter):
    """JSON форматтер для структурированного логирования."""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, ensure_ascii=False)


def setup_logging(
    log_level: str = "INFO",
    log_file: str = "logs/svoy_bot.log",
    max_size_mb: int = 10,
    backup_count: int = 5
) -> logging.Logger:
    """
    Настроить логирование.
    
    Args:
        log_level: Уровень логирования
        log_file: Путь к файлу логов
        max_size_mb: Максимальный размер файла (MB)
        backup_count: Количество резервных файлов
    
    Returns:
        Настроенный логгер
    """
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    root_logger.handlers.clear()
    
    # Форматтер
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Консольный обработчик
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Файловый обработчик с ротацией по размеру
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Архивное логирование по времени
    archive_handler = TimedRotatingFileHandler(
        str(log_path).replace('.log', '_archive.log'),
        when='D',
        interval=1,
        backupCount=30,
        encoding='utf-8'
    )
    archive_handler.setLevel(logging.WARNING)
    archive_handler.setFormatter(formatter)
    root_logger.addHandler(archive_handler)
    
    logger = logging.getLogger("svoy_bot")
    logger.info(f"📝 Logging initialized (level={log_level})")
    logger.info(f"📁 Log file: {log_file}")
    logger.info(f"💾 Max size: {max_size_mb}MB, Backups: {backup_count}")
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Получить логгер с именем."""
    return logging.getLogger(f"svoy_bot.{name}")
