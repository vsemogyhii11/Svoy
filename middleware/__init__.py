"""
Middleware для СВОЙ бота
"""
from .rate_limit import RateLimiter, RateLimitConfig, get_rate_limiter
from .ip_rate_limit import IPRateLimitMiddleware, SimpleIPRateLimitMiddleware
from .captcha_middleware import CaptchaMiddleware
from .honeypot_middleware import HoneypotMiddleware
from .geo_block import GeoBlockMiddleware

# Из старого middleware.py
import sys
from pathlib import Path
middleware_path = Path(__file__).parent.parent / 'middleware.py'
if middleware_path.exists():
    import importlib.util
    spec = importlib.util.spec_from_file_location("old_middleware", middleware_path)
    old_middleware = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old_middleware)
    LoggingMiddleware = old_middleware.LoggingMiddleware
else:
    LoggingMiddleware = None

# Для обратной совместимости
RateLimitMiddleware = IPRateLimitMiddleware

__all__ = [
    'RateLimiter',
    'RateLimitConfig', 
    'get_rate_limiter',
    'RateLimitMiddleware',
    'IPRateLimitMiddleware',
    'SimpleIPRateLimitMiddleware',
    'CaptchaMiddleware',
    'HoneypotMiddleware',
    'GeoBlockMiddleware',
    'LoggingMiddleware'
]
