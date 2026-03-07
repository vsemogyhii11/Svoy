"""
📊 СИСТЕМА МОНИТОРИНГА И МЕТРИК для СВОЙ

Сбор и экспорт метрик для Prometheus/Grafana
"""

import time
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import asyncio

logger = logging.getLogger("svoy_bot.metrics")


@dataclass
class MetricsCollector:
    """Сборщик метрик."""
    
    # Счётчики
    counters: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Таймеры
    timers: Dict[str, list] = field(default_factory=lambda: defaultdict(list))
    
    # Гейджи (текущие значения)
    gauges: Dict[str, float] = field(default_factory=dict)
    
    # Временные метки
    start_time: float = field(default_factory=time.time)
    
    def inc(self, name: str, value: int = 1):
        """Увеличить счётчик."""
        self.counters[name] += value
    
    def dec(self, name: str, value: int = 1):
        """Уменьшить счётчик."""
        self.counters[name] -= value
    
    def set(self, name: str, value: float):
        """Установить гейдж."""
        self.gauges[name] = value
    
    def observe(self, name: str, value: float):
        """Записать наблюдение в таймер."""
        self.timers[name].append(value)
        # Храним только последние 1000 значений
        if len(self.timers[name]) > 1000:
            self.timers[name] = self.timers[name][-1000:]
    
    def timer(self, name: str):
        """Контекстный менеджер для замера времени."""
        return TimerContext(self, name)
    
    def get_uptime(self) -> float:
        """Получить время работы (сек)."""
        return time.time() - self.start_time
    
    def get_stats(self, name: str) -> Dict[str, float]:
        """Получить статистику по таймеру."""
        if name not in self.timers or not self.timers[name]:
            return {}
        
        values = self.timers[name]
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'avg': sum(values) / len(values),
            'sum': sum(values)
        }
    
    def export_prometheus(self) -> str:
        """Экспорт метрик в формате Prometheus."""
        lines = []
        
        # Счётчики
        for name, value in self.counters.items():
            lines.append(f"svoy_{name} {value}")
        
        # Гейджи
        for name, value in self.gauges.items():
            lines.append(f"svoy_{name} {value}")
        
        # Таймеры
        for name, stats in [(k, self.get_stats(k)) for k in self.timers]:
            if stats:
                lines.append(f"svoy_{name}_count {stats['count']}")
                lines.append(f"svoy_{name}_sum {stats['sum']}")
                lines.append(f"svoy_{name}_avg {stats['avg']}")
        
        # Аптайм
        lines.append(f"svoy_uptime_seconds {self.get_uptime()}")
        
        return "\n".join(lines)


class TimerContext:
    """Контекстный менеджер для замера времени."""
    
    def __init__(self, collector: MetricsCollector, name: str):
        self.collector = collector
        self.name = name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, *args):
        elapsed = (time.time() - self.start_time) * 1000  # мс
        self.collector.observe(self.name, elapsed)


# Глобальный сборщик метрик
_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """Получить глобальный сборщик метрик."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics


def init_metrics() -> MetricsCollector:
    """Инициализировать глобальный сборщик метрик."""
    global _metrics
    _metrics = MetricsCollector()
    return _metrics


# Декоратор для сбора метрик
def track_metrics(name: str):
    """
    Декоратор для сбора метрик функции.
    
    Пример:
        @track_metrics("check_url_duration")
        async def check_url(url):
            ...
    """
    def decorator(func):
        import functools
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            metrics = get_metrics()
            metrics.inc(f"{name}_calls")
            
            with metrics.timer(f"{name}_duration"):
                try:
                    result = await func(*args, **kwargs)
                    metrics.inc(f"{name}_success")
                    return result
                except Exception as e:
                    metrics.inc(f"{name}_errors")
                    logger.error(f"Error in {name}: {e}")
                    raise
        
        return wrapper
    return decorator
