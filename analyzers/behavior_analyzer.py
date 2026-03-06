"""
Behavioral Analyzer — поведенческий анализ пользователей.

Обнаруживает:
- Ботов по timing сообщений (слишком быстро)
- Спам-сессии (активность 24/7)
- Аномальные паттерны (длина, частота, команды)
- Клавиатурных ботов (реакция <100мс)

Использование:
    from analyzers.behavior_analyzer import BehaviorAnalyzer
    
    analyzer = BehaviorAnalyzer()
    
    # Перед сообщением
    analyzer.record_message(user_id, message_text, timestamp)
    
    # Анализ
    result = analyzer.analyze_user(user_id)
    if result.is_suspicious:
        print(f"Подозрительный: {result.reasons}")
"""

import logging
import time
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
import hashlib

log = logging.getLogger("svoy_bot.behavior_analyzer")


@dataclass
class MessageRecord:
    """Запись о сообщении."""
    text: str
    text_length: int
    timestamp: float
    has_command: bool
    has_links: bool
    has_phones: bool


@dataclass
class SessionData:
    """Данные сессии пользователя."""
    start_time: float
    last_activity: float
    message_count: int = 0
    commands_used: int = 0
    avg_response_time: float = 0.0
    message_lengths: List[int] = field(default_factory=list)


@dataclass
class BehaviorResult:
    """Результат поведенческого анализа."""
    user_id: int
    is_bot: bool = False
    is_suspicious: bool = False
    confidence: float = 0.0
    risk_score: float = 0.0  # 0.0 - 1.0
    risk_level: str = "none"  # none, low, medium, high, critical
    
    # Timing метрики
    avg_response_time: float = 0.0
    min_response_time: float = 0.0
    is_too_fast: bool = False
    
    # Сессионные метрики
    session_count: int = 0
    is_247_activity: bool = False
    avg_session_duration: float = 0.0
    
    # Контент метрики
    command_abuse: bool = False
    spam_pattern: bool = False
    copy_paste_pattern: bool = False
    
    reasons: List[str] = field(default_factory=list)
    
    @property
    def emoji(self) -> str:
        if self.risk_level == "critical":
            return "🔴"
        elif self.risk_level == "high":
            return "🟠"
        elif self.risk_level == "medium":
            return "🟡"
        elif self.risk_level == "low":
            return "🟠"
        return "🟢"


class BehaviorAnalyzer:
    """
    Анализатор поведения пользователей.
    
    Детектирует:
    - Слишком быстрые ответы (<100мс = бот)
    - Активность 24/7 (нет перерывов на сон)
    - Спам-паттерны (повторяющиеся сообщения)
    - Злоупотребление командами
    - Copy-paste паттерны
    """
    
    # Пороги детекции
    MIN_RESPONSE_TIME_MS = 100  # Минимальное время реакции человека
    SUSPICIOUS_RESPONSE_TIME_MS = 300  # Подозрительно быстро
    MAX_SESSION_HOURS = 20  # Максимальная длительность сессии в часах
    MIN_SLEEP_HOURS = 4  # Минимальный перерыв на "сон"
    COMMAND_ABUSE_THRESHOLD = 10  # Команд за сессию
    SPAM_REPEAT_THRESHOLD = 5  # Повторов одного сообщения
    
    def __init__(self, db_path: str = "data/behavior.json"):
        self.db_path = Path(db_path)
        self._users: Dict[int, dict] = {}
        self._sessions: Dict[int, SessionData] = {}
        self._message_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=100))
        self._load_db()
    
    def _load_db(self):
        """Загрузить базу поведений."""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._users = {int(k): v for k, v in data.get('users', {}).items()}
                log.info(f"Behavior DB loaded: {len(self._users)} users")
            except Exception as e:
                log.error(f"Failed to load behavior DB: {e}")
    
    def _save_db(self):
        """Сохранить базу поведений."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Сериализация с ограничением истории
        save_data = {
            'users': {
                uid: {
                    'profile': data['profile'],
                    'stats': data['stats'],
                    'last_seen': data['last_seen']
                }
                for uid, data in self._users.items()
            }
        }
        
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, ensure_ascii=False, indent=2)
    
    def record_message(
        self,
        user_id: int,
        message_text: str,
        timestamp: Optional[float] = None
    ) -> BehaviorResult:
        """
        Записать сообщение пользователя.
        
        Args:
            user_id: ID пользователя
            message_text: Текст сообщения
            timestamp: Время сообщения (default: now)
        """
        timestamp = timestamp or time.time()
        
        # Инициализация пользователя
        if user_id not in self._users:
            self._users[user_id] = {
                'profile': {
                    'first_seen': timestamp,
                    'total_messages': 0,
                    'total_sessions': 0
                },
                'stats': {
                    'response_times': [],
                    'session_durations': [],
                    'hourly_activity': defaultdict(int)
                },
                'last_seen': timestamp
            }
        
        user_data = self._users[user_id]
        user_data['profile']['total_messages'] += 1
        user_data['last_seen'] = timestamp
        
        # Парсинг сообщения
        has_command = message_text.startswith('/')
        has_links = 'http://' in message_text or 'https://' in message_text
        has_phones = any(c.isdigit() for c in message_text) and len(message_text) > 10
        
        record = MessageRecord(
            text=message_text[:500],  # Ограничиваем длину
            text_length=len(message_text),
            timestamp=timestamp,
            has_command=has_command,
            has_links=has_links,
            has_phones=has_phones
        )
        
        # Добавляем в историю
        history = self._message_history[user_id]
        
        # Вычисляем время ответа
        response_time = 0.0
        if history:
            last_message = history[-1]
            response_time = (timestamp - last_message.timestamp) * 1000  # мс
        
        history.append(record)
        
        # Обновляем сессию
        self._update_session(user_id, record, response_time)
        
        # Обновляем статистику
        hour = datetime.fromtimestamp(timestamp).hour
        user_data['stats']['hourly_activity'][str(hour)] += 1
        
        if response_time > 0:
            user_data['stats']['response_times'].append(response_time)
            # Ограничиваем размер
            if len(user_data['stats']['response_times']) > 1000:
                user_data['stats']['response_times'] = user_data['stats']['response_times'][-500:]
        
        # Сохраняем периодически
        if user_data['profile']['total_messages'] % 10 == 0:
            self._save_db()
        
        # Быстрый анализ
        return self.analyze_user(user_id)
    
    def _update_session(self, user_id: int, record: MessageRecord, response_time: float):
        """Обновить данные сессии."""
        now = record.timestamp
        
        if user_id not in self._sessions:
            self._sessions[user_id] = SessionData(
                start_time=now,
                last_activity=now
            )
            self._users[user_id]['profile']['total_sessions'] += 1
        
        session = self._sessions[user_id]
        
        # Проверка на новую сессию (перерыв > 30 мин)
        if now - session.last_activity > 1800:  # 30 минут
            # Сохраняем длительность предыдущей сессии
            duration = session.last_activity - session.start_time
            self._users[user_id]['stats']['session_durations'].append(duration)
            
            # Новая сессия
            self._sessions[user_id] = SessionData(
                start_time=now,
                last_activity=now,
                message_count=1,
                commands_used=1 if record.has_command else 0,
                message_lengths=[record.text_length]
            )
        else:
            session.last_activity = now
            session.message_count += 1
            if record.has_command:
                session.commands_used += 1
            session.message_lengths.append(record.text_length)
            
            # Обновляем среднее время ответа
            if response_time > 0:
                session.avg_response_time = (
                    session.avg_response_time * (session.message_count - 1) + response_time
                ) / session.message_count
    
    def analyze_user(self, user_id: int) -> BehaviorResult:
        """
        Проанализировать поведение пользователя.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            Результат анализа
        """
        result = BehaviorResult(user_id=user_id)
        
        if user_id not in self._users:
            return result
        
        user_data = self._users[user_id]
        history = self._message_history[user_id]
        session = self._sessions.get(user_id)
        
        # 1. Анализ timing (самый надёжный признак бота)
        self._analyze_timing(user_id, user_data, history, result)
        
        # 2. Анализ сессий
        self._analyze_sessions(user_id, user_data, session, result)
        
        # 3. Анализ контента
        self._analyze_content(history, result)
        
        # 4. Анализ активности по часам
        self._analyze_hourly_activity(user_data, result)
        
        # Вычисляем итоговый risk score
        self._calculate_risk_score(result)
        
        log.info(
            f"Behavior analysis: user={user_id}, "
            f"risk={result.risk_level}, score={result.risk_score:.2f}, "
            f"bot={result.is_bot}"
        )
        
        return result
    
    def _analyze_timing(
        self,
        user_id: int,
        user_data: dict,
        history: deque,
        result: BehaviorResult
    ):
        """Анализ timing сообщений."""
        response_times = user_data['stats'].get('response_times', [])
        
        if not response_times:
            return
        
        result.avg_response_time = sum(response_times) / len(response_times)
        result.min_response_time = min(response_times)
        
        # Слишком быстрые ответы
        if result.min_response_time < self.MIN_RESPONSE_TIME_MS:
            result.is_too_fast = True
            result.is_bot = True
            result.confidence = max(result.confidence, 0.95)
            result.reasons.append(
                f"Слишком быстрый ответ: {result.min_response_time:.0f}мс "
                f"(минимум для человека: {self.MIN_RESPONSE_TIME_MS}мс)"
            )
        elif result.avg_response_time < self.SUSPICIOUS_RESPONSE_TIME_MS:
            result.confidence = max(result.confidence, 0.7)
            result.reasons.append(
                f"Подозрительно средняя скорость: {result.avg_response_time:.0f}мс"
            )
        
        # Статистически аномальная скорость
        if len(response_times) >= 20:
            std_dev = (sum((t - result.avg_response_time) ** 2 for t in response_times) / len(response_times)) ** 0.5
            cv = std_dev / result.avg_response_time if result.avg_response_time > 0 else 0
            
            # У ботов CV очень низкий (слишком стабильно)
            if cv < 0.1 and result.avg_response_time < 500:
                result.is_bot = True
                result.confidence = max(result.confidence, 0.85)
                result.reasons.append(f"Слишком стабильная скорость (CV={cv:.2f})")
    
    def _analyze_sessions(
        self,
        user_id: int,
        user_data: dict,
        session: Optional[SessionData],
        result: BehaviorResult
    ):
        """Анализ сессий."""
        if not session:
            return
        
        result.session_count = user_data['profile'].get('total_sessions', 0)
        
        # Длительность текущей сессии
        duration_hours = (session.last_activity - session.start_time) / 3600
        
        if duration_hours > self.MAX_SESSION_HOURS:
            result.is_247_activity = True
            result.confidence = max(result.confidence, 0.8)
            result.reasons.append(f"Сессия {duration_hours:.1f}ч без перерыва")
        
        # Злоупотребление командами
        if session.commands_used > self.COMMAND_ABUSE_THRESHOLD:
            result.command_abuse = True
            result.confidence = max(result.confidence, 0.6)
            result.reasons.append(f"Злоупотребление командами: {session.commands_used}")
        
        # Анализ длительностей сессий
        session_durations = user_data['stats'].get('session_durations', [])
        if len(session_durations) >= 5:
            avg_duration = sum(session_durations) / len(session_durations)
            result.avg_session_duration = avg_duration / 3600  # часы
            
            # Очень длинные сессии
            if avg_duration > 15 * 3600:  # 15 часов
                result.is_247_activity = True
                result.confidence = max(result.confidence, 0.7)
    
    def _analyze_content(self, history: deque, result: BehaviorResult):
        """Анализ контента сообщений."""
        if len(history) < 5:
            return
        
        messages = [r.text for r in history]
        
        # Copy-paste паттерн (одинаковые сообщения)
        unique_messages = set(messages)
        if len(unique_messages) < len(messages) * 0.3:  # Менее 30% уникальных
            result.copy_paste_pattern = True
            result.confidence = max(result.confidence, 0.75)
            result.reasons.append("Copy-paste паттерн (мало уникальных сообщений)")
        
        # Spam паттерн (повторение одного сообщения)
        from collections import Counter
        message_counts = Counter(messages)
        most_common_count = message_counts.most_common(1)[0][1] if message_counts else 0
        
        if most_common_count >= self.SPAM_REPEAT_THRESHOLD:
            result.spam_pattern = True
            result.confidence = max(result.confidence, 0.8)
            result.reasons.append(f"Спам: одно сообщение повторено {most_common_count} раз")
        
        # Анализ длины
        lengths = [r.text_length for r in history[-10:]]
        if lengths:
            avg_length = sum(lengths) / len(lengths)
            length_variance = sum((l - avg_length) ** 2 for l in lengths) / len(lengths)
            
            # Подозрительно одинаковая длина
            if length_variance < 10 and avg_length > 50:
                result.confidence = max(result.confidence, 0.5)
                result.reasons.append("Подозрительно одинаковая длина сообщений")
    
    def _analyze_hourly_activity(self, user_data: dict, result: BehaviorResult):
        """Анализ активности по часам."""
        hourly = user_data['stats'].get('hourly_activity', {})
        
        if len(hourly) < 24:
            return
        
        # Проверка на активность 24/7
        hours_with_activity = sum(1 for v in hourly.values() if v > 0)
        
        if hours_with_activity >= 22:  # Активность в 22+ часах
            result.is_247_activity = True
            result.confidence = max(result.confidence, 0.75)
            result.reasons.append("Активность 24/7 (нет перерыва на сон)")
        
        # Проверка на ночную активность (3-5 утра)
        night_hours = ['3', '4', '5']
        night_activity = sum(hourly.get(h, 0) for h in night_hours)
        total_activity = sum(hourly.values())
        
        if total_activity > 0 and night_activity / total_activity > 0.3:
            result.confidence = max(result.confidence, 0.5)
            result.reasons.append("Высокая ночная активность")
    
    def _calculate_risk_score(self, result: BehaviorResult):
        """Вычислить итоговый risk score."""
        score = 0.0
        
        # Timing (самый важный фактор)
        if result.is_too_fast:
            score += 0.4
        elif result.avg_response_time < 500:
            score += 0.2
        
        # Сессии
        if result.is_247_activity:
            score += 0.25
        if result.command_abuse:
            score += 0.15
        
        # Контент
        if result.spam_pattern:
            score += 0.25
        if result.copy_paste_pattern:
            score += 0.2
        
        # Нормализация
        result.risk_score = min(score, 1.0)
        
        # Определение уровня риска
        if result.risk_score >= 0.8:
            result.risk_level = "critical"
            result.is_bot = True
        elif result.risk_score >= 0.6:
            result.risk_level = "high"
            result.is_bot = True
        elif result.risk_score >= 0.4:
            result.risk_level = "medium"
            result.is_suspicious = True
        elif result.risk_score >= 0.2:
            result.risk_level = "low"
            result.is_suspicious = True
    
    def get_user_profile(self, user_id: int) -> Optional[dict]:
        """Получить профиль пользователя."""
        if user_id not in self._users:
            return None
        
        return self._users[user_id]['profile']
    
    def get_risk_users(self, min_risk: str = "medium") -> List[int]:
        """Получить пользователей с риском."""
        risk_order = ["none", "low", "medium", "high", "critical"]
        min_index = risk_order.index(min_risk)
        
        risky_users = []
        for user_id in self._users:
            result = self.analyze_user(user_id)
            if risk_order.index(result.risk_level) >= min_index:
                risky_users.append(user_id)
        
        return risky_users
    
    def cleanup_old(self, days: int = 30):
        """Удалить старые данные."""
        cutoff = time.time() - (days * 86400)
        
        to_remove = []
        for user_id, data in self._users.items():
            if data.get('last_seen', 0) < cutoff:
                to_remove.append(user_id)
        
        for user_id in to_remove:
            del self._users[user_id]
            if user_id in self._sessions:
                del self._sessions[user_id]
            if user_id in self._message_history:
                del self._message_history[user_id]
        
        if to_remove:
            self._save_db()
            log.info(f"Cleaned up {len(to_remove)} old user behaviors")


# Глобальный экземпляр
_analyzer: Optional[BehaviorAnalyzer] = None


def get_behavior_analyzer() -> BehaviorAnalyzer:
    """Получить глобальный анализатор."""
    global _analyzer
    if _analyzer is None:
        _analyzer = BehaviorAnalyzer()
    return _analyzer


def init_behavior_analyzer(db_path: str = "data/behavior.json") -> BehaviorAnalyzer:
    """Инициализировать глобальный анализатор."""
    global _analyzer
    _analyzer = BehaviorAnalyzer(db_path)
    return _analyzer
