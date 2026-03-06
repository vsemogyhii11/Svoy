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

# === ИСТОЧНИКИ: МАКСИМАЛЬНЫЙ ОХВАТ ===

# 1. НОВОСТНЫЕ АГРЕГАТОРЫ (Россия + СНГ)
NEWS_SOURCES = [
    # Федеральные
    "https://ria.ru/keyword_moshennichestvo/",
    "https://tass.ru/search?q=мошенничество",
    "https://www.rbc.ru/tags/?tag=мошенничество",
    "https://Lenta.ru/tags/moshennichestvo/",
    "https://gazeta.ru/tag/moshennichestvo.shtml",
    "https://kommersant.ru/tag/мошенничество",
    "https://vedomosti.ru/search?query=мошенничество",
    "https://iz.ru/tag/moshennichestvo",
    "https://rg.ru/tema/moshennichestvo/",
    "https://mk.ru/search/moshennichestvo",
    "https://kp.ru/search/moshennichestvo",
    "https://aif.ru/search?query=мошенничество",
    # Финансовые
    "https://banki.ru/news/daytheme/?tag=мошенничество",
    "https://finversia.ru/search/?q=мошенничество",
    "https://investing.com/news/stock-market-news/moshennichestvo",
    # Региональные
    "https://ngs.ru/search/?text=мошенники",
    "https://e1.ru/search/?text=мошенники",
    "https://fontanka.ru/search/?query=мошенники",
    "https://dp.ru/search?query=мошенничество",
    # Казахстан
    "https://tengrinews.kz/tag/moshennichestvo/",
    "https://kursiv.kz/search/?q=мошенничество",
    # Беларусь
    "https://naviny.by/search?query=махлярства",
]

# 2. TELEGRAM КАНАЛЫ (веб-превью)
TG_CHANNELS = [
    # Официальные
    "https://t.me/s/infosec_scam",
    "https://t.me/s/bad_list_ru",
    "https://t.me/s/scambase_ru",
    "https://t.me/s/moscow_fraud",
    "https://t.me/s/stopcoronavirus",
    # Народные
    "https://t.me/s/antiscam_russia",
    "https://t.me/s/scam_hunters",
    "https://t.me/s/fraud_alerts",
    "https://t.me/s/cyberpolice_ru",
    "https://t.me/s/security_news",
    # Региональные
    "https://t.me/s/moscow_scams",
    "https://t.me/s/spb_fraud",
    "https://t.me/s/ekb_scams",
    "https://t.me/s/kazan_fraud",
]

# 3. СОЦСЕТИ (МАКСИМАЛЬНЫЙ ОХВАТ)
SOCIAL_SOURCES = [
    # ВКонтакте (основные группы про мошенников)
    "https://vk.com/wall-21144004?q=мошенничество",
    "https://vk.com/wall-185911576?q=мошенники",
    "https://vk.com/wall-114177?q=развод",
    "https://vk.com/search?c%5Bq%5D=мошенники&c%5Bsection%5D=community",
    "https://vk.com/wall-168950252?q=скам",
    "https://vk.com/wall-198273283?q=обман",
    "https://vk.com/wall-205925990?q=кидалово",
    "https://vk.com/wall-162925467?q=фишинг",
    "https://vk.com/wall-172155963?q=дропы",
    "https://vk.com/wall-180050562?q=кардинг",
    # Одноклассники
    "https://ok.ru/search?text=мошенничество",
    "https://ok.ru/search?text=обман",
    "https://ok.ru/search?text=развод",
    # Facebook
    "https://facebook.com/search/posts/?q=мошенничество",
    "https://facebook.com/search/posts/?q=scam+russia",
    "https://facebook.com/groups/search/?q=fraud",
    # Twitter/X
    "https://twitter.com/search?q=мошенничество%20(from%3Aru)",
    "https://twitter.com/search?q=скам%20lang%3Aru",
    "https://twitter.com/search?q=развод%20lang%3Aru",
    # Instagram (через веб)
    "https://instagram.com/explore/tags/мошенники/",
    "https://instagram.com/explore/tags/скам/",
    # TikTok
    "https://tiktok.com/search?q=мошенники",
    "https://tiktok.com/search?q=развод",
    "https://tiktok.com/search?q=скам",
    # YouTube Community
    "https://youtube.com/results?search_query=мошенники+сообщество",
    "https://youtube.com/results?search_query=развод+обзор",
    # Pinterest
    "https://pinterest.ru/search/pins/?q=мошенники",
    # Reddit
    "https://reddit.com/search?q=ru+scam",
    "https://reddit.com/r/AskARussian/search/?q=мошенники",
    # Quora
    "https://quora.com/search?q=Russian+scam",
    # LiveJournal
    "https://livejournal.com/search?q=мошенники",
    # Telegram (расширенный список)
    "https://t.me/s/antiscam_alerts",
    "https://t.me/s/fraud_watch",
    "https://t.me/s/scam_detector",
    "https://t.me/s/cyber_security_news",
    "https://t.me/s/ru_scams",
    "https://t.me/s/moscow_fraud_alerts",
    "https://t.me/s/spb_scams",
    "https://t.me/s/ekb_fraud",
    "https://t.me/s/kazan_scams",
    "https://t.me/s/novosibirsk_fraud",
    "https://t.me/s/sochi_scams",
    "https://t.me/s/krasnodar_fraud",
    "https://t.me/s/rostov_scams",
    "https://t.me/s/chelyabinsk_fraud",
    "https://t.me/s/samara_scams",
    "https://t.me/s/ufa_fraud",
    "https://t.me/s/volgograd_scams",
    "https://t.me/s/saratov_fraud",
    "https://t.me/s/tyumen_scams",
    "https://t.me/s/vladivostok_fraud",
    "https://t.me/s/khabarovsk_scams",
    "https://t.me/s/krasnoyarsk_fraud",
    "https://t.me/s/perm_scams",
    "https://t.me/s/voronezh_fraud",
]

# 3.1 Мессенджеры (публичные чаты)
MESSENGER_SOURCES = [
    # WhatsApp (через веб-зеркала)
    "https://faq.whatsapp.com/search?q=scam",
    # Viber
    "https://viber.com/search?q=мошенники",
    # Discord
    "https://discord.com/search?q=ru+scam",
    # Slack
    "https://slack.com/search?q=fraud",
    # MAX (российский мессенджер)
    "https://max.ru/search?q=мошенники",
    "https://max.ru/search?q=скам",
    "https://max.ru/search?q=развод",
    # VK Мессенджер
    "https://vk.com/im/search?q=мошенники",
    # ICQ New
    "https://icq.com/search?q=scam",
    # TamTam
    "https://tamtam.chat/search?q=мошенники",
    # eXpress
    "https://express.ru/search?q=мошенники",
    # Сферум
    "https://sferum.ru/search?q=мошенники",
]

# 3.2 Платформы для блогов
BLOG_SOURCES = [
    # Дзен
    "https://dzen.ru/search?text=мошенники",
    "https://dzen.ru/search?text=скам",
    # Teletype
    "https://teletype.in/search?q=мошенники",
    # Medium (RU)
    "https://medium.com/search?q=russian+scam",
    # Blogger
    "https://blogger.com/search?q=мошенники",
    # WordPress RU
    "https://wordpress.com/search?q=скам",
]

# 3.3 Агрегаторы контента
CONTENT_AGGREGATORS = [
    # Яндекс.Дзен
    "https://dzen.ru/id/мошенники",
    # Google News
    "https://news.google.com/search?q=мошенничество+ru",
    # Яндекс.Новости
    "https://yandex.ru/news/search?text=мошенники",
    # Mail.ru Новости
    "https://news.mail.ru/search/?q=мошенничество",
    # Рамблер
    "https://rambler.ru/search?query=мошенники",
    # Yahoo
    "https://search.yahoo.com/search?p=russian+scam",
]

# 3.4 Нишевые соцсети
NICHE_SOCIAL = [
    # GitHub (issues про скам)
    "https://github.com/search?q=russian+scam&type=issues",
    # GitLab
    "https://gitlab.com/search?search=scam",
    # StackOverflow
    "https://stackoverflow.com/search?q=scam",
    # HackerNews
    "https://news.ycombinator.com/search?q=scam",
    # ProductHunt
    "https://producthunt.com/search?q=scam",
]

# ОБЪЕДИНЁННЫЙ СПИСОК ВСЕХ СОЦСЕТЕЙ
ALL_SOCIAL = (
    SOCIAL_SOURCES +
    MESSENGER_SOURCES +
    BLOG_SOURCES +
    CONTENT_AGGREGATORS +
    NICHE_SOCIAL
)

# 4. ВИДЕО ПЛАТФОРМЫ
VIDEO_SOURCES = [
    # YouTube
    "https://youtube.com/results?search_query=мошенники+развод",
    "https://youtube.com/results?search_query=скам+предупреждение",
    # TikTok
    "https://tiktok.com/search?q=мошенники",
    # RuTube
    "https://rutube.ru/search/?query=мошенничество",
    # Дзен
    "https://dzen.ru/search?text=мошенничество",
]

# 5. ФОРУМЫ И СООБЩЕСТВА
FORUM_SOURCES = [
    "https://pikabu.ru/tag/Мошенничество/new",
    "https://forum.ixbt.com/topic.cgi?id=89:123456&q=мошенники",
    "https://cyberforum.ru/search.php?q=мошенники",
    "https://habr.com/ru/search/?q=мошенничество&target_type=posts",
    "https://dtf.ru/search?query=мошенники",
    "https://vc.ru/search?query=мошенничество",
    "https://yadi.sk/discuss",
    "https://4pda.to/forum/index.php?act=search&source=pst&query=мошенники",
]

# 6. САЙТЫ ОТЗЫВОВ
REVIEW_SOURCES = [
    "https://otzovik.com/reviews/internet-moshennichestvo/",
    "https://irecommend.ru/tags/moshennichestvo",
    "https://www.banki.ru/services/responses/list/tag/moshennichestvo/",
    "https://zoon.ru/msk/reviews/tag/moshennichestvo/",
    "https://flamp.ru/reviews/tag/moshenniki/",
    "https://2gis.ru/reviews/tag/moshennichestvo",
]

# 7. БАЗЫ ЖАЛОБ НА НОМЕРА
PHONE_SITES = [
    "https://zvonili.com/",
    "https://кто-звонил.рф/comments/",
    "https://mysms.ru/reviews",
    "https://eto-razvod.ru/complaints/",
    "https://vshoke.net/antimoshennik/",
    "https://nomer.org/search/",
    "https://phonebook.kz/search/",
    "https://tellows.ru/search/",
    "https://kto-zvonil.ru/",
    "https://telefon-baza.ru/",
    "https://base-phone.ru/",
    "https://scam-numbers.info/",
]

# 8. DARK WEB / PASTE SITES (публичные зеркала)
PASTE_SOURCES = [
    "https://pastebin.com/search?q=carding+ru",
    "https://ghostbin.com/search?q=carding",
    "https://controlc.com/search?q=carding",
]

# 9. МАРКЕТПЛЕЙСЫ (отзывы о продавцах)
MARKETPLACES = [
    "https://ozon.ru/reviews/seller/scam",
    "https://wildberries.ru/catalog/search?text=мошенник",
    "https://avito.ru/search?text=мошенники",
    "https://youla.ru/search?q=мошенники",
    "https://drom.ru/reviews/dealer/scam",
]

# 10. КРИПТО СООБЩЕСТВА
CRYPTO_SOURCES = [
    "https://bitcoinforum.com/search?q=scam",
    "https://cryptonews.ru/search/?q=мошенничество",
    "https://bits.media/search/?q=мошенники",
    "https://forklog.com/search/?s=мошенничество",
]

# ОБЪЕДИНЁННЫЙ СПИСОК ВСЕХ ИСТОЧНИКОВ
ALL_SOURCES = (
    NEWS_SOURCES +
    TG_CHANNELS +
    SOCIAL_SOURCES +
    VIDEO_SOURCES +
    FORUM_SOURCES +
    REVIEW_SOURCES +
    PHONE_SITES +
    PASTE_SOURCES +
    MARKETPLACES +
    CRYPTO_SOURCES
)

# КЛЮЧЕВЫЕ СЛОВА ДЛЯ ПОИСКА
SEARCH_KEYWORDS = [
    "мошенники",
    "скам",
    "развод",
    "обман",
    "кидалово",
    "фишинг",
    "кардинг",
    "дропы",
    "звонили мошенники",
    "sms мошенники",
    "интернет мошенники",
]

class OSINTAgent:
    """Глубокий OSINT-агент: новости + соцсети + форумы + отзывы."""

    def __init__(self, db: Database, llm: LLMAnalyzer):
        self.db = db
        self.llm = llm
        self._is_running = False
        self._semaphore = asyncio.Semaphore(20)  # Увеличено: 10 → 20 параллельных задач
        self._request_count = 0
        self._last_reset = 0

    async def start(self):
        """Запуск цикла мониторинга."""
        if self._is_running: return
        self._is_running = True
        log.info("🚀 OSINT Agents started (MAXIMUM COVERAGE - 100+ sources)")

        while self._is_running:
            try:
                # Быстрый цикл: каждые 3 минуты (было 15)
                await self.run_discovery_cycle()
            except Exception as e:
                log.error(f"Critical error in OSINT cycle: {e}")

            # Ждем 3 минуты между циклами (было 15)
            await asyncio.sleep(180)

    async def run_discovery_cycle(self, max_pages_per_source=5):
        """Полный обход ВСЕХ категорий с максимальной глубиной."""
        log.info(f"🚀 OSINT: Starting MAXIMUM COVERAGE cycle ({len(ALL_SOURCES)} sources, depth: {max_pages_per_source} pages)...")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
            "Referer": "https://www.google.com/"
        }

        async with aiohttp.ClientSession(headers=headers) as session:
            # 1. Поисковый доркинг (динамическое обнаружение)
            dorking_results = await self._search_engine_dorking(session)
            await self._process_batch(dorking_results)

            # 2. НОВОСТИ (приоритет 1)
            log.info(f"📰 Scanning {len(NEWS_SOURCES)} news sources...")
            tasks = [self._scrape_source_multi_page(session, url, "a", "page", max_pages_per_source) for url in NEWS_SOURCES[:10]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 3. TELEGRAM КАНАЛЫ (приоритет 2)
            log.info(f"📱 Scanning {len(TG_CHANNELS)} Telegram channels...")
            tasks = [self._fetch_with_retry(session, url, "div", {"class_": "tgme_widget_message_text"}) for url in TG_CHANNELS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 4. СОЦСЕТИ (ПРИОРИТЕТ 1 - максимум охвата!)
            log.info(f"📱 Scanning {len(ALL_SOCIAL)} social media sources (MAXIMUM)...")
            # Сканируем больше страниц для соцсетей
            tasks = [self._scrape_source_multi_page(session, url, "div", "page", 8) for url in ALL_SOCIAL[:40]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)
            
            # Дополнительные соцсети (второй поток)
            tasks = [self._fetch_with_retry(session, url, "article") for url in ALL_SOCIAL[40:60]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 5. ФОРУМЫ (приоритет 4)
            log.info(f"💬 Scanning {len(FORUM_SOURCES)} forums...")
            tasks = [self._scrape_source_multi_page(session, url, "div", "page", 3) for url in FORUM_SOURCES[:8]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 6. БАЗЫ НОМЕРОВ (приоритет 5)
            log.info(f"📞 Scanning {len(PHONE_SITES)} phone databases...")
            tasks = [self._scrape_source_multi_page(session, url, "div", "page", max_pages_per_source) for url in PHONE_SITES[:8]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 7. ОТЗЫВЫ (приоритет 6)
            log.info(f"⭐ Scanning {len(REVIEW_SOURCES)} review sites...")
            tasks = [self._scrape_source_multi_page(session, url, "div", "page", 3) for url in REVIEW_SOURCES[:5]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 8. ВИДЕО (приоритет 7)
            log.info(f"🎥 Scanning {len(VIDEO_SOURCES)} video platforms...")
            tasks = [self._fetch_with_retry(session, url, "a") for url in VIDEO_SOURCES[:3]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 9. МАРКЕТПЛЕЙСЫ (приоритет 8)
            log.info(f"🛒 Scanning {len(MARKETPLACES)} marketplaces...")
            tasks = [self._scrape_source_multi_page(session, url, "div", "page", 2) for url in MARKETPLACES[:3]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

            # 10. КРИПТО (приоритет 9)
            log.info(f"₿ Scanning {len(CRYPTO_SOURCES)} crypto sources...")
            tasks = [self._fetch_with_retry(session, url, "div") for url in CRYPTO_SOURCES[:3]]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for items in results:
                if isinstance(items, list):
                    await self._process_batch(items)

        log.info(f"✅ OSINT: Cycle finished. Total requests: {self._request_count}")

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
