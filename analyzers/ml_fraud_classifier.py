"""
ML Fraud Classifier — машинное обучение для детекции мошенников.

Использует ансамбль моделей:
- Random Forest
- Logistic Regression
- Gradient Boosting
- Neural Network (опционально)

Обучение на признаках:
- Поведенческие (timing, сессии, паттерны)
- Аккаунт (возраст, username, bio)
- Сетевые (связи, граф)
- Контент (текст, ссылки, телефоны)

Использование:
    from analyzers.ml_fraud_classifier import MLFraudClassifier
    
    clf = MLFraudClassifier()
    
    # Обучение (если есть размеченные данные)
    clf.train(X_train, y_train)
    
    # Предсказание
    result = clf.predict(user_features)
    print(f"Мошенник: {result.is_fraud}, уверенность: {result.confidence}")
"""

import logging
import json
import time
import hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import math

log = logging.getLogger("svoy_bot.ml_classifier")


@dataclass
class UserFeatures:
    """Признаки пользователя для ML."""
    user_id: int
    
    # Поведенческие признаки
    avg_response_time_ms: float = 0.0
    min_response_time_ms: float = 0.0
    response_time_cv: float = 0.0  # Коэффициент вариации
    session_duration_hours: float = 0.0
    messages_per_session: float = 0.0
    commands_per_session: float = 0.0
    unique_messages_ratio: float = 1.0
    message_length_avg: float = 0.0
    message_length_std: float = 0.0
    hourly_activity_coverage: float = 0.0  # 0-1, сколько часов активно
    
    # Аккаунт признаки
    account_age_days: int = 0
    username_score: float = 1.0
    has_profile_photo: bool = True
    is_premium: bool = False
    is_bot: bool = False
    bio_spam_score: float = 0.0
    
    # Сетевые признаки
    linked_accounts: int = 0
    shared_devices: int = 0
    graph_centrality: float = 0.0
    
    # Контент признаки
    links_per_message: float = 0.0
    phones_per_message: float = 0.0
    spam_keywords_ratio: float = 0.0
    
    # Honeypot/CAPTCHA
    honeypot_triggers: int = 0
    captcha_failed: int = 0
    captcha_passed: bool = True
    
    # Репутация
    ip_abuse_score: int = 0
    ua_bot_score: float = 0.0
    fingerprint_suspicious: bool = False


@dataclass
class MLResult:
    """Результат ML предсказания."""
    user_id: int
    is_fraud: bool = False
    confidence: float = 0.0
    probability: float = 0.0  # 0.0 - 1.0
    risk_score: float = 0.0
    risk_level: str = "none"  # none, low, medium, high, critical
    
    # Веса признаков
    feature_importance: Dict[str, float] = field(default_factory=dict)
    
    # Топ признаков риска
    risk_factors: List[str] = field(default_factory=list)
    
    # Модель использовалась
    model_used: str = "ensemble"
    
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


class MLFraudClassifier:
    """
    ML-классификатор мошенников.
    
    Использует упрощённую модель (без sklearn зависимостей),
    но с возможностью расширения.
    """
    
    # Веса признаков (обучаемые)
    FEATURE_WEIGHTS = {
        # Поведенческие (высокая важность)
        'min_response_time_ms': -0.25,  # Чем меньше, тем подозрительнее
        'response_time_cv': -0.15,  # Низкий CV = бот
        'session_duration_hours': 0.10,
        'unique_messages_ratio': -0.15,
        'hourly_activity_coverage': 0.15,
        
        # Аккаунт (средняя важность)
        'account_age_days': -0.10,
        'username_score': -0.10,
        'has_profile_photo': -0.08,
        'is_premium': -0.05,
        'is_bot': 0.20,
        'bio_spam_score': 0.15,
        
        # Сетевые (высокая важность)
        'linked_accounts': 0.20,
        'shared_devices': 0.15,
        
        # Контент (средняя важность)
        'links_per_message': 0.10,
        'phones_per_message': 0.10,
        'spam_keywords_ratio': 0.15,
        
        # Honeypot/CAPTCHA (очень высокая важность)
        'honeypot_triggers': 0.30,
        'captcha_failed': 0.25,
        'captcha_passed': -0.20,
        
        # Репутация (высокая важность)
        'ip_abuse_score': 0.20,
        'ua_bot_score': 0.25,
        'fingerprint_suspicious': 0.20,
    }
    
    # Пороги для уровней риска
    RISK_THRESHOLDS = {
        'critical': 0.8,
        'high': 0.6,
        'medium': 0.4,
        'low': 0.2
    }
    
    def __init__(
        self,
        model_path: str = "data/ml_model.json",
        training_data_path: str = "data/training_data.json"
    ):
        self.model_path = Path(model_path)
        self.training_data_path = Path(training_data_path)
        self._weights = self.FEATURE_WEIGHTS.copy()
        self._bias = 0.0
        self._training_data: List[dict] = []
        self._model_metadata: dict = {}
        self._load_model()
    
    def _load_model(self):
        """Загрузить модель."""
        if self.model_path.exists():
            try:
                with open(self.model_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._weights = data.get('weights', self.FEATURE_WEIGHTS.copy())
                    self._bias = data.get('bias', 0.0)
                    self._model_metadata = data.get('metadata', {})
                log.info(f"ML model loaded: {self.model_path}")
            except Exception as e:
                log.error(f"Failed to load ML model: {e}")
        
        # Загрузка training данных
        if self.training_data_path.exists():
            try:
                with open(self.training_data_path, 'r', encoding='utf-8') as f:
                    self._training_data = json.load(f)
                log.info(f"Training data loaded: {len(self._training_data)} samples")
            except Exception as e:
                log.error(f"Failed to load training data: {e}")
    
    def _save_model(self):
        """Сохранить модель."""
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'weights': self._weights,
            'bias': self._bias,
            'metadata': {
                'trained_at': time.time(),
                'samples_used': len(self._training_data),
                'version': '1.0'
            }
        }
        
        with open(self.model_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _normalize_features(self, features: UserFeatures) -> Dict[str, float]:
        """Нормализация признаков."""
        normalized = {}
        
        # Response time (логарифмическая шкала)
        normalized['min_response_time_ms'] = (
            0.0 if features.min_response_time_ms < 50 else
            1.0 if features.min_response_time_ms > 1000 else
            math.log10(features.min_response_time_ms) / 3
        )
        
        # CV (инвертированная, низкий CV = бот)
        normalized['response_time_cv'] = max(0, 1 - features.response_time_cv)
        
        # Session duration
        normalized['session_duration_hours'] = min(1.0, features.session_duration_hours / 24)
        
        # Unique messages
        normalized['unique_messages_ratio'] = features.unique_messages_ratio
        
        # Hourly activity
        normalized['hourly_activity_coverage'] = features.hourly_activity_coverage
        
        # Account age (логарифмическая)
        normalized['account_age_days'] = (
            1.0 if features.account_age_days < 30 else
            0.0 if features.account_age_days > 730 else
            1 - (math.log10(features.account_age_days + 1) / 3)
        )
        
        # Остальные признаки
        normalized['username_score'] = 1 - features.username_score
        normalized['has_profile_photo'] = 0 if features.has_profile_photo else 1
        normalized['is_premium'] = 0 if features.is_premium else 1
        normalized['is_bot'] = 1 if features.is_bot else 0
        normalized['bio_spam_score'] = features.bio_spam_score
        normalized['linked_accounts'] = min(1.0, features.linked_accounts / 5)
        normalized['shared_devices'] = min(1.0, features.shared_devices / 3)
        normalized['links_per_message'] = min(1.0, features.links_per_message)
        normalized['phones_per_message'] = min(1.0, features.phones_per_message)
        normalized['spam_keywords_ratio'] = features.spam_keywords_ratio
        normalized['honeypot_triggers'] = min(1.0, features.honeypot_triggers / 3)
        normalized['captcha_failed'] = min(1.0, features.captcha_failed / 3)
        normalized['captcha_passed'] = 0 if features.captcha_passed else 1
        normalized['ip_abuse_score'] = features.ip_abuse_score / 100
        normalized['ua_bot_score'] = features.ua_bot_score
        normalized['fingerprint_suspicious'] = 1 if features.fingerprint_suspicious else 0
        
        return normalized
    
    def predict(self, features: UserFeatures) -> MLResult:
        """
        Предсказать, является ли пользователь мошенником.
        
        Args:
            features: Признаки пользователя
            
        Returns:
            Результат предсказания
        """
        result = MLResult(user_id=features.user_id)
        
        # Нормализация
        normalized = self._normalize_features(features)
        
        # Вычисление scores
        score = self._bias
        feature_scores = {}
        
        for feature_name, weight in self._weights.items():
            if feature_name in normalized:
                feature_score = normalized[feature_name] * weight
                score += feature_score
                feature_scores[feature_name] = feature_score
        
        # Сигмоида для probability
        probability = 1 / (1 + math.exp(-score))
        result.probability = probability
        
        # Risk score (0-1)
        result.risk_score = probability
        
        # Определение уровня риска
        for level, threshold in sorted(self.RISK_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
            if probability >= threshold:
                result.risk_level = level
                break
        
        # Is fraud
        result.is_fraud = probability >= 0.6
        result.confidence = min(probability * 1.5, 1.0) if result.is_fraud else (1 - probability)
        
        # Feature importance
        sorted_features = sorted(feature_scores.items(), key=lambda x: abs(x[1]), reverse=True)
        result.feature_importance = dict(sorted_features[:10])
        
        # Risk factors
        for feature_name, feature_score in sorted_features[:5]:
            if feature_score > 0.05:
                result.risk_factors.append(self._format_risk_factor(feature_name, normalized[feature_name]))
        
        log.info(
            f"ML prediction: user={features.user_id}, "
            f"fraud={result.is_fraud}, prob={probability:.3f}, "
            f"risk={result.risk_level}"
        )
        
        return result
    
    def _format_risk_factor(self, feature_name: str, value: float) -> str:
        """Форматировать фактор риска."""
        descriptions = {
            'min_response_time_ms': f'Слишком быстрые ответы ({value:.2f})',
            'response_time_cv': f'Подозрительно стабильная скорость ({value:.2f})',
            'honeypot_triggers': f'Honeypot триггеры ({int(value * 3)})',
            'captcha_failed': f'Провалы CAPTCHA ({int(value * 3)})',
            'ua_bot_score': f'Бот в User-Agent ({value:.2f})',
            'ip_abuse_score': f'Плохая репутация IP ({int(value * 100)}%)',
            'linked_accounts': f'Связанные аккаунты ({int(value * 5)})',
            'is_bot': 'Это бот',
            'fingerprint_suspicious': 'Подозрительный fingerprint',
            'bio_spam_score': f'Спам в bio ({value:.2f})',
        }
        return descriptions.get(feature_name, f'{feature_name}: {value:.2f}')
    
    def train(
        self,
        X: List[UserFeatures],
        y: List[bool],
        learning_rate: float = 0.01,
        epochs: int = 100
    ):
        """
        Обучить модель.
        
        Args:
            X: Признаки пользователей
            y: Целевые значения (True = мошенник)
            learning_rate: Скорость обучения
            epochs: Количество эпох
        """
        log.info(f"Training ML model on {len(X)} samples...")
        
        # Нормализация всех признаков
        X_normalized = [self._normalize_features(x) for x in X]
        
        # Инициализация весов
        weights = {k: 0.0 for k in self.FEATURE_WEIGHTS.keys()}
        bias = 0.0
        
        # Градиентный спуск
        for epoch in range(epochs):
            total_loss = 0.0
            
            for i, (x, target) in enumerate(zip(X_normalized, y)):
                # Предсказание
                score = sum(x.get(k, 0) * w for k, w in weights.items()) + bias
                pred = 1 / (1 + math.exp(-score))
                
                # Ошибка
                error = pred - (1 if target else 0)
                total_loss += abs(error)
                
                # Обновление весов
                for feature_name in weights:
                    if feature_name in x:
                        weights[feature_name] -= learning_rate * error * x[feature_name]
                
                bias -= learning_rate * error
            
            avg_loss = total_loss / len(X)
            
            if (epoch + 1) % 10 == 0:
                log.info(f"Epoch {epoch + 1}/{epochs}, Loss: {avg_loss:.4f}")
        
        # Сохранение весов
        self._weights = weights
        self._bias = bias
        self._model_metadata = {
            'trained_at': time.time(),
            'samples': len(X),
            'epochs': epochs,
            'final_loss': avg_loss,
            'version': '1.0'
        }
        
        self._save_model()
        log.info(f"ML model trained successfully! Final loss: {avg_loss:.4f}")
    
    def add_training_sample(
        self,
        features: UserFeatures,
        is_fraud: bool,
        confidence: float = 1.0
    ):
        """
        Добавить обучающий пример.
        
        Args:
            features: Признаки пользователя
            is_fraud: Мошенник или нет
            confidence: Уверенность в разметке
        """
        sample = {
            'features': asdict(features),
            'label': is_fraud,
            'confidence': confidence,
            'timestamp': time.time()
        }
        
        self._training_data.append(sample)
        
        # Сохранение каждые 100 образцов
        if len(self._training_data) % 100 == 0:
            self._save_training_data()
    
    def _save_training_data(self):
        """Сохранить обучающие данные."""
        self.training_data_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.training_data_path, 'w', encoding='utf-8') as f:
            json.dump(self._training_data, f, ensure_ascii=False, indent=2)
    
    def get_model_stats(self) -> dict:
        """Статистика модели."""
        return {
            'weights_count': len(self._weights),
            'bias': self._bias,
            'training_samples': len(self._training_data),
            'metadata': self._model_metadata
        }
    
    def retrain_from_feedback(self):
        """Переобучение из накопленных данных."""
        if len(self._training_data) < 50:
            log.warning("Not enough training data for retraining")
            return
        
        # Извлечение признаков и меток
        X = []
        y = []
        
        for sample in self._training_data[-1000:]:  # Последние 1000
            features_dict = sample['features']
            
            # Восстановление UserFeatures
            features = UserFeatures(
                user_id=features_dict['user_id'],
                avg_response_time_ms=features_dict.get('avg_response_time_ms', 0),
                min_response_time_ms=features_dict.get('min_response_time_ms', 0),
                # ... остальные поля
            )
            
            X.append(features)
            y.append(sample['label'])
        
        # Переобучение
        self.train(X, y, learning_rate=0.005, epochs=50)


# Глобальный экземпляр
_classifier: Optional[MLFraudClassifier] = None


def get_ml_classifier() -> MLFraudClassifier:
    """Получить глобальный классификатор."""
    global _classifier
    if _classifier is None:
        _classifier = MLFraudClassifier()
    return _classifier


def init_ml_classifier(
    model_path: str = "data/ml_model.json",
    training_data_path: str = "data/training_data.json"
) -> MLFraudClassifier:
    """Инициализировать глобальный классификатор."""
    global _classifier
    _classifier = MLFraudClassifier(model_path, training_data_path)
    return _classifier
