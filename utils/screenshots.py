import asyncio
import logging
from playwright.async_api import async_playwright
import os

log = logging.getLogger("svoy_bot.utils.screenshots")

class ScreenshotTaker:
    """Утилита для создания скриншотов сайтов через Playwright."""

    def __init__(self, output_dir="data/screenshots"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    async def take_screenshot(self, url: str) -> str:
        """Делает скриншот и возвращает путь к файлу."""
        import hashlib
        filename = hashlib.md5(url.encode()).hexdigest() + ".png"
        path = os.path.join(self.output_dir, filename)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.set_viewport_size({"width": 1280, "height": 720})
                
                log.info(f"📸 Taking screenshot of {url}...")
                await page.goto(url, timeout=30000, wait_until="networkidle")
                await page.screenshot(path=path)
                await browser.close()
                return path
        except Exception as e:
            log.error(f"Failed to take screenshot of {url}: {e}")
            return None
