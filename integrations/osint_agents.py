"""
Фоновые агенты для сбора данных о мошенниках (OSINT).

1. NewsAgent: собирает новости о новых схемах.
2. SearchAgent: ищет упоминания номеров на форумах.
3. LLMProcessor: структурирует найденную информацию.
"""

import asyncio
import logging
import re
from datetime import datetime
import aiohttp
from bs4 import BeautifulSoup

from database import Database
from integrations.llm_analyzer import LLMAnalyzer

log = logging.getLogger("svoy_bot.agents")

# Категории источников
NEWS_SOURCES = [
    "https://ria.ru/keyword_moshennichestvo/",
    "https://tass.ru/search?q=мошенничество",
    "https://www.rbc.ru/tags/?tag=мошенничество",
    "https://Lenta.ru/tags/moshennichestvo/",
]

# Телеграм-каналы (веб-превью)
TG_CHANNELS = [
    "https://t.me/s/infosec_scam",
    "https://t.me/s/bad_list_ru",
    "https://t.me/s/scambase_ru",
    "https://t.me/s/moscow_fraud",
]

# Соцсети и сообщества (публичные зеркала/теги)
SOCIAL_SOURCES = [
    "https://vk.com/wall-21144004?q=мошенничество", # Пример группы ВК
    "https://pikabu.ru/tag/Мошенничество/new",
    "https://www.banki.ru/services/responses/list/tag/moshennichestvo/",
    "https://otzovik.com/reviews/internet-moshennichestvo/",
]

# Специализированные сайты проверок и базы жалоб
PHONE_SITES = [
    "https://zvonili.com/",
    "https://кто-звонил.рф/comments/",
    "https://mysms.ru/reviews",
    "https://eto-razvod.ru/complaints/",
    "https://vshoke.net/antimoshennik/",
]

class OSINTAgent:
    """Глубокий OSINT-агент: новости + соцсети + форумы + отзывы."""

    def __init__(self, db: Database, llm: LLMAnalyzer):
        self.db = db
        self.llm = llm
        self._is_running = False
        self._semaphore = asyncio.Semaphore(10) # Лимит параллельных задач

    async def start(self):
        """Запуск цикла мониторинга."""
        if self._is_running: return
        self._is_running = True
        log.info("🚀 OSINT Agents started (Deep Discovery)")
        
        while self._is_running:
            try:
                await self.run_discovery_cycle()
            except Exception as e:
                log.error(f"Critical error in OSINT cycle: {e}")
            
            # Ждем 15 минут между циклами (быстрая реакция)
            await asyncio.sleep(900)

    async def run_discovery_cycle(self, max_pages_per_source=2):
        """Полный обход всех категорий с параллельной обработкой."""
        log.info(f"🚀 OSINT: Starting HIGH-SPEED discovery cycle (depth: {max_pages_per_source} pages)...")
        
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        
        async with aiohttp.ClientSession(headers=headers) as session:
            # 1. Поисковый доркинг (динамическое обнаружение новых источников)
            dorking_results = await self._search_engine_dorking(session)
            await self._process_batch(dorking_results)

            # 2. Сбор ссылок со статических источников
            all_work = [
                (NEWS_SOURCES, "a", {}, "page"),
                (TG_CHANNELS, "div", {"class_": "tgme_widget_message_text"}, None),
                (SOCIAL_SOURCES, "a", {}, "page"),
                (PHONE_SITES, "div", {}, None),
            ]

            tasks = []
            for sources, tag, kwargs, page_param in all_work:
                for base_url in sources:
                    tasks.append(self._scrape_source_multi_page(session, base_url, tag, page_param, max_pages_per_source, **kwargs))
            
            # Собираем данные со всех страниц параллельно
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

        log.info("✅ OSINT: Cycle finished.")

    async def _scrape_source_multi_page(self, session, base_url, tag, page_param, max_pages, **kwargs):
        """Вспомогательный метод для параллельного скрапинга страниц одного источника."""
        all_items = []
        for page in range(1, max_pages + 1):
            url = base_url
            if page_param and page > 1:
                sep = "&" if "?" in url else "?"
                url = f"{base_url}{sep}{page_param}={page}"
            
            items = await self._fetch_with_retry(session, url, tag, **kwargs)
            if not items: break
            all_items.extend(items)
            await asyncio.sleep(0.5) # Мини-пауза для вежливости
        return all_items

    async def _search_engine_dorking(self, session) -> list[dict]:
        """Поиск новых источников через DuckDuckGo (HTML-версия)."""
        queries = ["новые схемы мошенничества 2024", "жалобы на номера телефонов мошенников", "forum мошенничество"]
        found = []
        log.info(f"🕵️‍♂️ OSINT: Performing search engine dorking...")
        
        for query in queries:
            search_url = f"https://html.duckduckgo.com/html/?q={query}"
            try:
                async with session.get(search_url, timeout=10) as resp:
                    if resp.status == 200:
                        soup = BeautifulSoup(await resp.text(), "html.parser")
                        for a in soup.find_all("a", class_="result__a"):
                            href = a.get("href")
                            if href and "http" in href:
                                found.append({"url": href, "title": a.get_text()})
            except Exception as e:
                log.warning(f"Dorking failed for {query}: {e}")
            await asyncio.sleep(2)
        return found

    async def search(self, query: str) -> dict:
        """Публичный поиск (DuckDuckGo)."""
        found_links = []
        headers = {"User-Agent": "Mozilla/5.0"}
        async with aiohttp.ClientSession(headers=headers) as session:
            search_url = f"https://html.duckduckgo.com/html/?q={query}"
            try:
                async with session.get(search_url, timeout=10) as resp:
                    if resp.status == 200:
                        soup = BeautifulSoup(await resp.text(), "html.parser")
                        for a in soup.find_all("a", class_="result__a"):
                            href = a.get("href")
                            if href and "http" in href:
                                found_links.append({"url": href, "title": a.get_text().strip()})
            except Exception as e:
                log.error(f"Manual OSINT search failed: {e}")
                
        return {
            "query": query,
            "total_results": len(found_links),
            "links": found_links[:5]
        }

    async def run_historical_scan(self, months=3):
        """Разовая загрузка старых данных (глубокий поиск)."""
        log.info(f"⏳ OSINT: Starting HISTORICAL scan for the last {months} months...")
        # Для 3 месяцев обычно достаточно 10-20 страниц на источник
        await self.run_discovery_cycle(max_pages_per_source=15)
        log.info("🏆 OSINT: Historical scan completed.")

    async def _fetch_with_retry(self, session, url, tag, retries=2, **kwargs) -> list[dict]:
        """Парсинг с повторными попытками."""
        for i in range(retries + 1):
            try:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        return self._parse_elements(html, url, tag, **kwargs)
                    elif resp.status == 429: # Rate limit
                        await asyncio.sleep(10 * (i + 1))
            except Exception as e:
                if i == retries: log.warning(f"OSINT: Failed to fetch {url}: {e}")
                await asyncio.sleep(2)
        return []

    def _parse_elements(self, html, base_url, tag, **kwargs) -> list[dict]:
        """Извлечение данных из HTML."""
        soup = BeautifulSoup(html, "html.parser")
        results = []
        for el in soup.find_all(tag, **kwargs):
            if tag == "a" and el.get("href"):
                href = el["href"]
                if not href.startswith("http"):
                    from urllib.parse import urljoin
                    href = urljoin(base_url, href)
                
                text = el.get_text().strip().lower()
                if any(k in text for k in ["мошен", "схем", "номер", "развод", "взлом"]):
                    results.append({"url": href, "title": el.get_text().strip()})
            else:
                text = el.get_text().strip()
                if len(text) > 50:
                    results.append({"text": text, "url": base_url})
        return results

    async def _process_batch(self, items: list[dict], is_text_only: bool = False):
        """Параллельная многопоточная обработка статей."""
        tasks = []
        for item in items[:50]: # Увеличили лимит до 50
            url = item.get("url")
            if url and not is_text_only:
                is_visited = await self.db.is_url_visited(url)
                if is_visited:
                    continue
            
            if url:
                await self.db.mark_url_visited(url)
            
            if is_text_only:
                tasks.append(self._analyze_text_with_sem(item.get("text", ""), item.get("url", "")))
            else:
                tasks.append(self._process_article_with_sem(item["url"], item.get("title", "No Title")))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _process_article_with_sem(self, url: str, title: str):
        """Обертка для статьи с семафором."""
        async with self._semaphore:
            await self._process_article(url, title)

    async def _analyze_text_with_sem(self, text: str, source_url: str):
        """Обертка для текста с семафором."""
        async with self._semaphore:
            await self._analyze_text(text, source_url)

    async def _process_article(self, url: str, title: str):
        """Загрузка контента и запуск анализа."""
        # Пропускаем явно лишние ссылки
        if any(x in url for x in ["facebook.com", "twitter.com", "instagram.com"]): return

        log.info(f"🧠 OSINT: Deep scan: {title[:50]}...")
        async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
            try:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        soup = BeautifulSoup(await resp.text(), "html.parser")
                        text = " ".join([p.get_text() for p in soup.find_all(["p", "article", "section"])])
                        await self._analyze_text(text, url)
            except: pass

    async def _analyze_text(self, text: str, source_url: str):
        """Анализ через LLM и сохранение."""
        if len(text) < 150: return

        prompt = """Ты — OSINT-агент. Проанализируй текст на признаки новых схем мошенничества.
        Выдели: 1. Описание схемы. 2. Телефоны. 3. Юзернеймы ТГ или ссылки.
        Ответь ТОЛЬКО JSON: {"scheme": "...", "phones": ["+7..."], "links": ["..."]}
        """
        
        data = await self.llm.analyze(text[:4000], custom_prompt=prompt)
        
        phones = data.get("phones", [])
        scheme = data.get("scheme", "Новая схема")
        
        if phones:
            for phone in phones:
                clean_phone = re.sub(r"[^\d+]", "", phone)
                if len(clean_phone) >= 10:
                    await self.db.add_phone_report(
                        clean_phone, "scam", 
                        f"🤖 OSINT: {scheme}. Источник: {source_url}", 0
                    )
                    log.info(f"🆕 Agent DETECTED SCAMMER: {clean_phone}")

        # Можно добавить сохранение ссылок в будущем
