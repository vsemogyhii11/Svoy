"""
Device Fingerprinting — идентификация устройств по цифровому отпечатку.

Собирает данные из Telegram WebApp и определяет:
- Одно устройство = несколько аккаунтов (бот-ферма)
- Подозрительные паттерны (эмуляция, виртуалки)

Использование в WebApp:
    // Сбор данных на клиенте
    const fingerprint = collectFingerprint();
    await botApi.sendData(JSON.stringify(fingerprint));

Использование в боте:
    from analyzers.fingerprint import FingerprintAnalyzer
    
    analyzer = FingerprintAnalyzer()
    result = analyzer.analyze(fingerprint_data)
    
    if result.is_suspicious:
        print(f"Подозрительное устройство: {result.confidence}")
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from collections import defaultdict

log = logging.getLogger("svoy_bot.fingerprint")


@dataclass
class FingerprintResult:
    """Результат анализа fingerprint."""
    fingerprint_hash: str
    is_suspicious: bool = False
    confidence: float = 0.0
    device_id: Optional[str] = None
    is_emulator: bool = False
    is_vm: bool = False
    is_rooted: bool = False
    browser: Optional[str] = None
    os: Optional[str] = None
    screen: Optional[str] = None
    linked_accounts: List[int] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    
    @property
    def risk_level(self) -> str:
        if self.confidence >= 0.8:
            return "high"
        elif self.confidence >= 0.5:
            return "medium"
        elif self.confidence >= 0.3:
            return "low"
        return "none"


class FingerprintAnalyzer:
    """
    Анализатор цифровых отпечатков устройств.
    
    Обнаруживает:
    - Одинаковые устройства на разных аккаунтах
    - Эмуляторы и виртуальные машины
    - Root/jailbreak устройства
    - Подозрительные конфигурации
    """
    
    def __init__(self, db_path: str = "data/fingerprints.json"):
        self.db_path = db_path
        self._fingerprints: Dict[str, dict] = {}
        self._account_map: Dict[str, List[int]] = defaultdict(list)  # hash -> [user_ids]
        self._load_db()
    
    def _load_db(self):
        """Загрузить базу fingerprint."""
        import json
        from pathlib import Path
        
        if Path(self.db_path).exists():
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._fingerprints = data.get('fingerprints', {})
                    self._account_map = defaultdict(list, data.get('account_map', {}))
                log.info(f"Fingerprint DB loaded: {len(self._fingerprints)} prints")
            except Exception as e:
                log.error(f"Failed to load fingerprint DB: {e}")
    
    def _save_db(self):
        """Сохранить базу fingerprint."""
        import json
        from pathlib import Path
        
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump({
                'fingerprints': self._fingerprints,
                'account_map': dict(self._account_map)
            }, f, ensure_ascii=False, indent=2)
    
    def _compute_hash(self, data: dict) -> str:
        """Вычислить хэш fingerprint."""
        # Нормализация данных
        normalized = {
            'screen': data.get('screen', ''),
            'timezone': data.get('timezone', ''),
            'language': data.get('language', ''),
            'platform': data.get('platform', ''),
            'cpu': data.get('cpu', ''),
            'gpu': data.get('gpu', ''),
            'webgl': data.get('webgl', ''),
            'fonts': sorted(data.get('fonts', [])),
        }
        
        # Сериализация и хэширование
        serialized = json.dumps(normalized, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]
    
    def analyze(self, fingerprint_data: dict, user_id: int) -> FingerprintResult:
        """
        Проанализировать fingerprint устройства.
        
        Args:
            fingerprint_data: Данные fingerprint от клиента
            user_id: ID пользователя Telegram
            
        Returns:
            Результат анализа
        """
        # Вычисляем хэш
        fp_hash = self._compute_hash(fingerprint_data)
        
        result = FingerprintResult(
            fingerprint_hash=fp_hash,
            device_id=fingerprint_data.get('device_id'),
            browser=fingerprint_data.get('browser'),
            os=fingerprint_data.get('os'),
            screen=fingerprint_data.get('screen')
        )
        
        # Проверка на эмуляцию
        if self._is_emulator(fingerprint_data):
            result.is_emulator = True
            result.confidence = max(result.confidence, 0.8)
            result.reasons.append("Emulator detected")
        
        # Проверка на VM
        if self._is_virtual_machine(fingerprint_data):
            result.is_vm = True
            result.confidence = max(result.confidence, 0.7)
            result.reasons.append("Virtual machine detected")
        
        # Проверка на root/jailbreak
        if fingerprint_data.get('is_rooted') or fingerprint_data.get('is_jailbroken'):
            result.is_rooted = True
            result.confidence = max(result.confidence, 0.5)
            result.reasons.append("Rooted/jailbroken device")
        
        # Проверка на связанные аккаунты
        if fp_hash in self._account_map:
            linked = self._account_map[fp_hash]
            if user_id not in linked:
                result.linked_accounts = linked
                result.confidence = max(result.confidence, 0.6)
                result.reasons.append(f"Device shared with {len(linked)} other accounts")
                
                # Подозрительно если много аккаунтов
                if len(linked) >= 3:
                    result.is_suspicious = True
                    result.reasons.append(f"Too many accounts ({len(linked) + 1}) on one device")
        
        # Проверка на подозрительные конфигурации
        if self._is_suspicious_config(fingerprint_data):
            result.is_suspicious = True
            result.confidence = max(result.confidence, 0.7)
            result.reasons.append("Suspicious device configuration")
        
        # Сохраняем fingerprint
        self._update_fingerprint(fp_hash, user_id, fingerprint_data)
        
        log.info(
            f"Fingerprint: user={user_id}, hash={fp_hash}, "
            f"risk={result.risk_level}, linked={len(result.linked_accounts)}"
        )
        
        return result
    
    def _is_emulator(self, data: dict) -> bool:
        """Проверка на эмулятор."""
        indicators = 0
        
        # Специфичные строки
        suspicious_strings = [
            'bluestacks', 'nox', 'genymotion', 'android emulator',
            'virtualbox', 'vmware', 'qemu', 'virtualpc'
        ]
        
        ua = data.get('user_agent', '').lower()
        for s in suspicious_strings:
            if s in ua:
                indicators += 1
        
        # Специфичное железо
        gpu = data.get('gpu', '').lower()
        if 'swiftshader' in gpu or 'angle' in gpu:
            indicators += 1
        
        # Разрешения эмуляторов
        screen = data.get('screen', '')
        if screen in ['800x600', '1024x768', '1280x720']:
            indicators += 0.5
        
        return indicators >= 1
    
    def _is_virtual_machine(self, data: dict) -> bool:
        """Проверка на VM."""
        indicators = 0
        
        # VM в CPU/GPU
        cpu = data.get('cpu', '').lower()
        gpu = data.get('gpu', '').lower()
        
        vm_strings = ['virtualbox', 'vmware', 'qemu', 'kvm', 'xen', 'hyperv']
        
        for s in vm_strings:
            if s in cpu or s in gpu:
                indicators += 1
        
        # Недостаточно данных (часто в VM)
        if len(data.get('fonts', [])) < 5:
            indicators += 0.5
        
        return indicators >= 1
    
    def _is_suspicious_config(self, data: dict) -> bool:
        """Проверка на подозрительную конфигурацию."""
        # Слишком мало шрифтов
        if len(data.get('fonts', [])) < 3:
            return True
        
        # Несовместимые комбинации
        os_name = data.get('os', '').lower()
        browser = data.get('browser', '').lower()
        
        if 'iphone' in os_name and 'chrome' in browser and 'safari' not in data.get('user_agent', ''):
            return True
        
        # Очень старое ПО
        user_agent = data.get('user_agent', '')
        if 'MSIE 6' in user_agent or 'MSIE 7' in user_agent:
            return True
        
        return False
    
    def _update_fingerprint(self, fp_hash: str, user_id: int, data: dict):
        """Обновить базу fingerprint."""
        # Сохраняем fingerprint
        self._fingerprints[fp_hash] = {
            'data': data,
            'first_seen': self._fingerprints.get(fp_hash, {}).get('first_seen', time.time()),
            'last_seen': time.time(),
            'user_ids': list(set(
                self._fingerprints.get(fp_hash, {}).get('user_ids', []) + [user_id]
            ))
        }
        
        # Обновляем карту аккаунтов
        self._account_map[fp_hash] = self._fingerprints[fp_hash]['user_ids']
        
        # Сохраняем на диск (каждые 10 обновлений)
        if len(self._fingerprints) % 10 == 0:
            self._save_db()
    
    def get_linked_accounts(self, user_id: int) -> List[int]:
        """Получить связанные аккаунты для пользователя."""
        # Находим fingerprint пользователя
        for fp_hash, data in self._fingerprints.items():
            if user_id in data.get('user_ids', []):
                return [uid for uid in data['user_ids'] if uid != user_id]
        return []
    
    def get_device_stats(self, fp_hash: str) -> dict:
        """Получить статистику устройства."""
        if fp_hash not in self._fingerprints:
            return {}
        
        data = self._fingerprints[fp_hash]
        return {
            'hash': fp_hash,
            'account_count': len(data.get('user_ids', [])),
            'first_seen': data.get('first_seen'),
            'last_seen': data.get('last_seen'),
            'user_ids': data.get('user_ids', [])
        }
    
    def cleanup_old(self, days: int = 30):
        """Удалить старые fingerprint."""
        cutoff = time.time() - (days * 86400)
        
        to_remove = []
        for fp_hash, data in self._fingerprints.items():
            if data.get('last_seen', 0) < cutoff:
                to_remove.append(fp_hash)
        
        for fp_hash in to_remove:
            del self._fingerprints[fp_hash]
            if fp_hash in self._account_map:
                del self._account_map[fp_hash]
        
        if to_remove:
            self._save_db()
            log.info(f"Cleaned up {len(to_remove)} old fingerprints")


# Глобальный экземпляр
_analyzer: Optional[FingerprintAnalyzer] = None


def get_fingerprint_analyzer() -> FingerprintAnalyzer:
    """Получить глобальный анализатор."""
    global _analyzer
    if _analyzer is None:
        _analyzer = FingerprintAnalyzer()
    return _analyzer


def init_fingerprint_analyzer(db_path: str = "data/fingerprints.json") -> FingerprintAnalyzer:
    """Инициализировать глобальный анализатор."""
    global _analyzer
    _analyzer = FingerprintAnalyzer(db_path)
    return _analyzer
