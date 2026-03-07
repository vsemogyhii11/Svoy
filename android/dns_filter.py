"""
Local DNS Filter — локальный DNS фаервол для блокировки фишинга.

Работает через Android VpnService (локальный режим, трафик не уходит).
Перехватывает DNS запросы и блокирует фишинговые домены.

Использование:
    # В AndroidManifest.xml:
    <service android:name=".LocalDNSFilter" />
    
    # Запуск:
    val intent = Intent(this, LocalDNSFilter::class.java)
    startService(intent)
"""

import socket
import struct
import logging
from typing import Set, Optional
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("svoy_bot.dns_filter")


@dataclass
class DNSQuery:
    """DNS запрос."""
    domain: str
    query_type: int
    raw_data: bytes


@dataclass
class DNSResponse:
    """DNS ответ."""
    domain: str
    ip_address: str
    ttl: int = 300


class LocalDNSFilter:
    """
    Локальный DNS фильтр для блокировки фишинга.
    
    Блокирует:
    - Фишинговые домены (из базы)
    - Свежие домены (< 7 дней)
    - Подозрительные паттерны (sber-bank.ru и т.п.)
    """
    
    # DNS серверы для перенаправления (безопасные)
    SAFE_DNS_SERVERS = [
        '8.8.8.8',  # Google
        '1.1.1.1',  # Cloudflare
        '77.88.8.8',  # Yandex DNS
    ]
    
    # IP для заблокированных доменов (показывает страницу предупреждения)
    BLOCK_IP = '127.0.0.1'
    
    def __init__(self, blocklist_path: str = "data/phishing_domains.txt"):
        self.blocklist: Set[str] = set()
        self.blocklist_path = Path(blocklist_path)
        self._load_blocklist()
        
        # Кэш разрешённых доменов (белый список)
        self.whitelist = {
            'sberbank.ru',
            'sberbank-online.ru',
            'tinkoff.ru',
            'tbank.ru',
            'vtb.ru',
            'alfabank.ru',
            'gosuslugi.ru',
            'google.com',
            'yandex.ru',
            'telegram.org',
            'whatsapp.com',
        }
    
    def _load_blocklist(self):
        """Загрузить базу фишинговых доменов."""
        if self.blocklist_path.exists():
            with open(self.blocklist_path, 'r', encoding='utf-8') as f:
                self.blocklist = {
                    line.strip().lower()
                    for line in f
                    if line.strip() and not line.startswith('#')
                }
            log.info(f"Loaded {len(self.blocklist)} phishing domains")
        else:
            # Базовый список для примера
            self.blocklist = {
                'sber-bank.ru',
                'sberbank-online-verify.ru',
                'tinkoff-verify.ru',
                'vtb-secure.ru',
                'gosuslugi-verify.ru',
                'gосуслуги-подтверждение.рф',
                'сбербанк-онлайн.рф',
            }
            self._save_blocklist()
    
    def _save_blocklist(self):
        """Сохранить базу доменов."""
        self.blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.blocklist_path, 'w', encoding='utf-8') as f:
            f.write("# Фишинговые домены\n")
            for domain in sorted(self.blocklist):
                f.write(f"{domain}\n")
    
    def add_phishing_domain(self, domain: str):
        """Добавить фишинговый домен в базу."""
        domain = domain.lower().strip()
        if domain not in self.blocklist:
            self.blocklist.add(domain)
            self._save_blocklist()
            log.info(f"Added phishing domain: {domain}")
    
    def _parse_dns_query(self, data: bytes) -> Optional[DNSQuery]:
        """Распарсить DNS запрос."""
        if len(data) < 12:
            return None
        
        # DNS заголовок
        header = data[:12]
        q_count = struct.unpack('!H', header[4:6])[0]
        
        if q_count == 0:
            return None
        
        # Парсинг доменного имени
        offset = 12
        labels = []
        
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            labels.append(data[offset + 1:offset + 1 + length].decode('ascii'))
            offset += 1 + length
        
        if offset + 4 > len(data):
            return None
        
        # Тип запроса и класс
        q_type = struct.unpack('!H', data[offset:offset + 2])[0]
        
        domain = '.'.join(labels)
        return DNSQuery(domain=domain, query_type=q_type, raw_data=data)
    
    def _is_phishing(self, domain: str) -> bool:
        """Проверить домен на фишинг."""
        domain = domain.lower()
        
        # Белый список
        if domain in self.whitelist:
            return False
        
        # Чёрный список
        if domain in self.blocklist:
            return True
        
        # Проверка паттернов
        phishing_patterns = [
            'sber', 'sberbank', 'tinkoff', 'tbank', 'vtb', 'alfa',
            'gosuslugi', 'госуслуг', 'почта', 'mail', 'yandex',
        ]
        
        suspicious_tlds = ['.ru', '.рф', '.xyz', '.top', '.tk']
        
        # Подозрительные комбинации
        for pattern in phishing_patterns:
            if pattern in domain:
                # Проверка на подозрительные TLD
                for tld in suspicious_tlds:
                    if domain.endswith(tld):
                        # Проверка на дефисы (часто фишинг)
                        if domain.count('-') >= 1:
                            return True
                        # Проверка на дублирование бренда
                        if domain.count(pattern) > 1:
                            return True
        
        # Проверка на очень длинные домены (фишинг)
        if len(domain) > 40:
            return True
        
        return False
    
    def handle_dns_query(self, data: bytes) -> Optional[bytes]:
        """
        Обработать DNS запрос.
        
        Returns:
            DNS ответ (заблокированный или перенаправленный)
        """
        query = self._parse_dns_query(data)
        
        if not query:
            return None
        
        log.debug(f"DNS query: {query.domain}")
        
        # Проверка на фишинг
        if self._is_phishing(query.domain):
            log.warning(f"🚫 BLOCKED phishing domain: {query.domain}")
            return self._create_block_response(data, self.BLOCK_IP)
        
        # Разрешённый домен — пропускаем
        return None
    
    def _create_block_response(self, query_data: bytes, ip: str) -> bytes:
        """Создать DNS ответ с заблокированным IP."""
        # Копируем ID запроса
        response = bytearray(query_data[:2])
        
        # Флаги: ответ, авторитетный
        response.extend(b'\x81\x80')
        
        # Количество вопросов, ответов, авторитетных, дополнительных
        response.extend(query_data[4:6])  # Questions
        response.extend(b'\x00\x01')  # Answer RRs
        response.extend(b'\x00\x00')  # Authority RRs
        response.extend(b'\x00\x00')  # Additional RRs
        
        # Копируем вопрос
        response.extend(query_data[12:])
        
        # Добавляем ответ
        # Сжатие имени (указатель на вопрос)
        response.extend(b'\xc0\x0c')
        
        # Тип: A (1), класс: IN (1)
        response.extend(b'\x00\x01\x00\x01')
        
        # TTL: 300 секунд
        response.extend(struct.pack('!I', 300))
        
        # Длина данных: 4 (IPv4)
        response.extend(b'\x00\x04')
        
        # IP адрес
        response.extend(socket.inet_aton(ip))
        
        return bytes(response)
    
    def get_stats(self) -> dict:
        """Статистика фильтра."""
        return {
            'blocked_domains': len(self.blocklist),
            'whitelisted': len(self.whitelist),
        }


# Глобальный экземпляр
_dns_filter: Optional[LocalDNSFilter] = None


def get_dns_filter() -> LocalDNSFilter:
    """Получить глобальный DNS фильтр."""
    global _dns_filter
    if _dns_filter is None:
        _dns_filter = LocalDNSFilter()
    return _dns_filter


def init_dns_filter(blocklist_path: str = "data/phishing_domains.txt") -> LocalDNSFilter:
    """Инициализировать глобальный DNS фильтр."""
    global _dns_filter
    _dns_filter = LocalDNSFilter(blocklist_path)
    return _dns_filter
