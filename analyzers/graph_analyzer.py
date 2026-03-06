"""
Graph Analyzer — анализ графа связей для обнаружения бот-сетей.

Обнаруживает:
- Координированные группы (бот-фермы)
- Общие устройства/IP
- Реферральные цепи
- Кластеры подозрительных пользователей

Использование:
    from analyzers.graph_analyzer import GraphAnalyzer
    
    analyzer = GraphAnalyzer()
    
    # Добавление связей
    analyzer.add_edge(user1, user2, relation='shared_device')
    analyzer.add_edge(user2, user3, relation='same_ip')
    
    # Анализ
    clusters = analyzer.find_suspicious_clusters()
    central_users = analyzer.find_central_users()
    
    # Проверка пользователя
    result = analyzer.analyze_user(user_id)
"""

import logging
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict, deque

log = logging.getLogger("svoy_bot.graph_analyzer")


@dataclass
class GraphEdge:
    """Ребро графа."""
    user1: int
    user2: int
    relation: str  # shared_device, same_ip, referral, etc.
    weight: float = 1.0
    created_at: float = field(default_factory=time.time)


@dataclass
class GraphNode:
    """Узел графа (пользователь)."""
    user_id: int
    degree: int = 0  # Количество связей
    suspicious_relations: int = 0
    cluster_id: Optional[int] = None
    centrality: float = 0.0
    risk_score: float = 0.0


@dataclass
class Cluster:
    """Кластер связанных пользователей."""
    cluster_id: int
    members: List[int]
    edge_count: int
    suspicious_ratio: float
    avg_risk_score: float
    is_suspicious: bool


@dataclass
class GraphAnalysisResult:
    """Результат анализа пользователя."""
    user_id: int
    direct_connections: int = 0
    indirect_connections: int = 0
    cluster_size: int = 0
    centrality_score: float = 0.0
    is_hub: bool = False  # Центральный узел
    is_suspicious: bool = False
    risk_score: float = 0.0
    risk_level: str = "none"
    connected_users: List[int] = field(default_factory=list)
    shared_devices: List[str] = field(default_factory=list)
    shared_ips: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


class GraphAnalyzer:
    """
    Анализатор графа связей пользователей.
    
    Использует алгоритмы:
    - Connected Components (поиск кластеров)
    - PageRank (центральность узлов)
    - Community Detection (обнаружение сообществ)
    """
    
    # Типы отношений
    REL_SHARED_DEVICE = 'shared_device'
    REL_SHARED_IP = 'shared_ip'
    REL_REFERRAL = 'referral'
    REL_SAME_SESSION = 'same_session'
    REL_MESSAGE_INTERACTION = 'message_interaction'
    
    # Веса отношений (подозрительность)
    RELATION_WEIGHTS = {
        REL_SHARED_DEVICE: 1.0,
        REL_SHARED_IP: 0.8,
        REL_REFERRAL: 0.5,
        REL_SAME_SESSION: 0.6,
        REL_MESSAGE_INTERACTION: 0.2,
    }
    
    # Пороги
    SUSPICIOUS_CLUSTER_SIZE = 5  # Минимум участников
    SUSPICIOUS_RATIO = 0.6  # Минимум подозрительных связей
    HUB_CENTRALITY_THRESHOLD = 0.3  # Порог центральности
    
    def __init__(self, db_path: str = "data/graph.json"):
        self.db_path = Path(db_path)
        self._edges: List[GraphEdge] = []
        self._adjacency: Dict[int, Set[int]] = defaultdict(set)
        self._relations: Dict[Tuple[int, int], List[str]] = defaultdict(list)
        self._nodes: Dict[int, GraphNode] = {}
        self._device_map: Dict[str, List[int]] = defaultdict(list)  # device -> [users]
        self._ip_map: Dict[str, List[int]] = defaultdict(list)  # ip -> [users]
        self._load_graph()
    
    def _load_graph(self):
        """Загрузить граф."""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Восстановление рёбер
                    for edge_data in data.get('edges', []):
                        edge = GraphEdge(**edge_data)
                        self._edges.append(edge)
                        self._adjacency[edge.user1].add(edge.user2)
                        self._adjacency[edge.user2].add(edge.user1)
                        self._relations[(edge.user1, edge.user2)].append(edge.relation)
                    
                    # Восстановление мапов
                    self._device_map = defaultdict(list, data.get('device_map', {}))
                    self._ip_map = defaultdict(list, data.get('ip_map', {}))
                    
                    # Восстановление узлов
                    for uid, node_data in data.get('nodes', {}).items():
                        self._nodes[int(uid)] = GraphNode(**node_data)
                    
                log.info(f"Graph loaded: {len(self._edges)} edges, {len(self._nodes)} nodes")
            except Exception as e:
                log.error(f"Failed to load graph: {e}")
    
    def _save_graph(self):
        """Сохранить граф."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'edges': [asdict(e) for e in self._edges],
            'nodes': {str(k): asdict(v) for k, v in self._nodes.items()},
            'device_map': dict(self._device_map),
            'ip_map': dict(self._ip_map)
        }
        
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def add_edge(
        self,
        user1: int,
        user2: int,
        relation: str,
        weight: Optional[float] = None
    ):
        """
        Добавить связь между пользователями.
        
        Args:
            user1: ID первого пользователя
            user2: ID второго пользователя
            relation: Тип связи
            weight: Вес связи
        """
        if user1 == user2:
            return
        
        # Проверка на существующую связь
        existing = self._relations.get((min(user1, user2), max(user1, user2)), [])
        if relation in existing:
            return
        
        # Создание ребра
        edge = GraphEdge(
            user1=min(user1, user2),
            user2=max(user1, user2),
            relation=relation,
            weight=weight or self.RELATION_WEIGHTS.get(relation, 1.0)
        )
        
        self._edges.append(edge)
        self._adjacency[user1].add(user2)
        self._adjacency[user2].add(user1)
        self._relations[(edge.user1, edge.user2)].append(relation)
        
        # Обновление узлов
        self._ensure_node(user1)
        self._ensure_node(user2)
        self._nodes[user1].degree += 1
        self._nodes[user2].degree += 1
        
        if relation in [self.REL_SHARED_DEVICE, self.REL_SHARED_IP]:
            self._nodes[user1].suspicious_relations += 1
            self._nodes[user2].suspicious_relations += 1
        
        # Сохранение периодически
        if len(self._edges) % 100 == 0:
            self._save_graph()
    
    def add_shared_device(self, user_id: int, device_id: str):
        """Добавить общее устройство."""
        # Находим всех пользователей с этим device
        for other_user in self._device_map[device_id]:
            if other_user != user_id:
                self.add_edge(user_id, other_user, self.REL_SHARED_DEVICE)
        
        self._device_map[device_id].append(user_id)
    
    def add_shared_ip(self, user_id: int, ip_address: str):
        """Добавить общий IP."""
        # Находим всех пользователей с этим IP
        for other_user in self._ip_map[ip_address]:
            if other_user != user_id:
                self.add_edge(user_id, other_user, self.REL_SHARED_IP)
        
        self._ip_map[ip_address].append(user_id)
    
    def add_referral(self, referrer_id: int, referred_id: int):
        """Добавить реферральную связь."""
        self.add_edge(referrer_id, referred_id, self.REL_REFERRAL)
    
    def _ensure_node(self, user_id: int):
        """Убедиться, что узел существует."""
        if user_id not in self._nodes:
            self._nodes[user_id] = GraphNode(user_id=user_id)
    
    def find_connected_components(self) -> List[Set[int]]:
        """
        Найти все связные компоненты (кластеры).
        
        Returns:
            Список кластеров (множеств user_id)
        """
        visited = set()
        components = []
        
        for user_id in self._adjacency:
            if user_id not in visited:
                # BFS для поиска компоненты
                component = set()
                queue = deque([user_id])
                
                while queue:
                    current = queue.popleft()
                    if current in visited:
                        continue
                    
                    visited.add(current)
                    component.add(current)
                    
                    for neighbor in self._adjacency[current]:
                        if neighbor not in visited:
                            queue.append(neighbor)
                
                if len(component) > 1:
                    components.append(component)
        
        return components
    
    def find_suspicious_clusters(self) -> List[Cluster]:
        """
        Найти подозрительные кластеры.
        
        Returns:
            Список подозрительных кластеров
        """
        components = self.find_connected_components()
        clusters = []
        
        for i, component in enumerate(components):
            if len(component) < self.SUSPICIOUS_CLUSTER_SIZE:
                continue
            
            # Подсчёт подозрительных рёбер
            total_edges = 0
            suspicious_edges = 0
            
            for user_id in component:
                node = self._nodes.get(user_id)
                if node:
                    total_edges += node.degree
                    suspicious_edges += node.suspicious_relations
            
            suspicious_ratio = suspicious_edges / max(total_edges, 1)
            
            # Средняя оценка риска
            avg_risk = sum(
                self._nodes[uid].risk_score for uid in component
            ) / len(component)
            
            cluster = Cluster(
                cluster_id=i,
                members=list(component),
                edge_count=total_edges // 2,  # Каждое ребро считается дважды
                suspicious_ratio=suspicious_ratio,
                avg_risk_score=avg_risk,
                is_suspicious=suspicious_ratio >= self.SUSPICIOUS_RATIO
            )
            
            if cluster.is_suspicious:
                clusters.append(cluster)
                
                # Помечаем узлы
                for uid in component:
                    if uid in self._nodes:
                        self._nodes[uid].cluster_id = i
        
        return clusters
    
    def compute_pagerank(self, damping: float = 0.85, iterations: int = 20) -> Dict[int, float]:
        """
        Вычислить PageRank для всех узлов.
        
        Args:
            damping: Коэффициент затухания
            iterations: Количество итераций
            
        Returns:
            Словарь {user_id: pagerank_score}
        """
        # Инициализация
        nodes = list(self._adjacency.keys())
        n = len(nodes)
        
        if n == 0:
            return {}
        
        pagerank = {node: 1.0 / n for node in nodes}
        
        for _ in range(iterations):
            new_pagerank = {}
            
            for node in nodes:
                rank_sum = 0.0
                
                for neighbor in self._adjacency[node]:
                    if neighbor in pagerank:
                        degree = len(self._adjacency[neighbor])
                        if degree > 0:
                            rank_sum += pagerank[neighbor] / degree
                
                new_pagerank[node] = (1 - damping) / n + damping * rank_sum
            
            pagerank = new_pagerank
        
        # Нормализация
        max_pr = max(pagerank.values()) if pagerank else 1.0
        
        return {k: v / max_pr for k, v in pagerank.items()}
    
    def find_central_users(self, top_n: int = 10) -> List[Tuple[int, float]]:
        """
        Найти самых центральных пользователей.
        
        Args:
            top_n: Количество топ пользователей
            
        Returns:
            Список (user_id, centrality_score)
        """
        pagerank = self.compute_pagerank()
        
        # Сортировка
        sorted_users = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)
        
        # Обновление центральности в узлах
        for user_id, centrality in sorted_users:
            if user_id in self._nodes:
                self._nodes[user_id].centrality = centrality
        
        return sorted_users[:top_n]
    
    def analyze_user(self, user_id: int) -> GraphAnalysisResult:
        """
        Проанализировать пользователя в графе.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            Результат анализа
        """
        result = GraphAnalysisResult(user_id=user_id)
        
        if user_id not in self._adjacency:
            return result
        
        # Прямые связи
        direct = self._adjacency[user_id]
        result.direct_connections = len(direct)
        result.connected_users = list(direct)
        
        # Косвенные связи (2 уровня)
        indirect = set()
        for neighbor in direct:
            for second_neighbor in self._adjacency.get(neighbor, set()):
                if second_neighbor != user_id and second_neighbor not in direct:
                    indirect.add(second_neighbor)
        
        result.indirect_connections = len(indirect)
        
        # Размер кластера
        if user_id in self._nodes:
            node = self._nodes[user_id]
            result.cluster_size = len([
                uid for uid in self._nodes.values()
                if uid.cluster_id == node.cluster_id
            ]) if node.cluster_id is not None else 1
            
            result.centrality_score = node.centrality
            result.is_hub = node.centrality >= self.HUB_CENTRALITY_THRESHOLD
        
        # Подсчёт типов связей
        shared_devices = set()
        shared_ips = set()
        suspicious_count = 0
        
        for neighbor in direct:
            relations = self._relations.get((min(user_id, neighbor), max(user_id, neighbor)), [])
            
            if self.REL_SHARED_DEVICE in relations:
                suspicious_count += 1
                # Находим device_id
                for device_id, users in self._device_map.items():
                    if user_id in users and neighbor in users:
                        shared_devices.add(device_id)
            
            if self.REL_SHARED_IP in relations:
                suspicious_count += 1
                for ip, users in self._ip_map.items():
                    if user_id in users and neighbor in users:
                        shared_ips.add(ip)
        
        result.shared_devices = list(shared_devices)
        result.shared_ips = list(shared_ips)
        
        # Risk score
        risk_score = 0.0
        
        if suspicious_count >= 3:
            risk_score += 0.3
            result.reasons.append(f"Много общих устройств/IP: {suspicious_count}")
        
        if result.cluster_size >= self.SUSPICIOUS_CLUSTER_SIZE:
            risk_score += 0.25
            result.reasons.append(f"Большой кластер: {result.cluster_size} участников")
        
        if result.is_hub:
            risk_score += 0.2
            result.reasons.append(f"Центральный узел (centrality={result.centrality_score:.2f})")
        
        if result.direct_connections >= 10:
            risk_score += 0.15
            result.reasons.append(f"Много связей: {result.direct_connections}")
        
        result.risk_score = min(risk_score, 1.0)
        result.is_suspicious = result.risk_score >= 0.4
        
        # Risk level
        if result.risk_score >= 0.7:
            result.risk_level = "high"
        elif result.risk_score >= 0.4:
            result.risk_level = "medium"
        elif result.risk_score >= 0.2:
            result.risk_level = "low"
        
        return result
    
    def get_all_clusters(self) -> List[Cluster]:
        """Получить все кластеры."""
        return self.find_suspicious_clusters()
    
    def get_graph_stats(self) -> dict:
        """Статистика графа."""
        components = self.find_connected_components()
        
        return {
            'total_users': len(self._nodes),
            'total_edges': len(self._edges),
            'total_components': len(components),
            'largest_component': max(len(c) for c in components) if components else 0,
            'suspicious_clusters': len(self.find_suspicious_clusters()),
            'central_users': len([n for n in self._nodes.values() if n.centrality >= self.HUB_CENTRALITY_THRESHOLD])
        }
    
    def cleanup_old(self, days: int = 30):
        """Удалить старые связи."""
        cutoff = time.time() - (days * 86400)
        
        # Фильтрация рёбер
        new_edges = []
        for edge in self._edges:
            if edge.created_at > cutoff:
                new_edges.append(edge)
        
        removed = len(self._edges) - len(new_edges)
        self._edges = new_edges
        
        if removed > 0:
            # Перестройка adjacency
            self._adjacency.clear()
            self._relations.clear()
            
            for edge in self._edges:
                self._adjacency[edge.user1].add(edge.user2)
                self._adjacency[edge.user2].add(edge.user1)
                self._relations[(edge.user1, edge.user2)].append(edge.relation)
            
            self._save_graph()
            log.info(f"Cleaned up {removed} old edges from graph")


# Для сериализации dataclass
from dataclasses import asdict


# Глобальный экземпляр
_analyzer: Optional[GraphAnalyzer] = None


def get_graph_analyzer() -> GraphAnalyzer:
    """Получить глобальный анализатор."""
    global _analyzer
    if _analyzer is None:
        _analyzer = GraphAnalyzer()
    return _analyzer


def init_graph_analyzer(db_path: str = "data/graph.json") -> GraphAnalyzer:
    """Инициализировать глобальный анализатор."""
    global _analyzer
    _analyzer = GraphAnalyzer(db_path)
    return _analyzer
