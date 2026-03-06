"""
Проверка номеров телефонов по базе мошенников.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PhoneCheckResult:
    """Результат проверки номера."""
    phone: str
    risk_level: str        # safe / suspicious / danger / spam
    description: str = ""
    reports: int = 0

    @property
    def emoji(self) -> str:
        if self.risk_level == "danger":
            return "🔴"
        elif self.risk_level in ("suspicious", "spam"):
            return "🟡"
        return "🟢"


class PhoneChecker:
    """Проверка номеров телефонов."""

    def __init__(self, phones_path: str = "data/scam_phones.json"):
        self.path = Path(phones_path)
        if not self.path.exists():
            self.path = Path(__file__).parent.parent / phones_path
        
        data = self._load_data(self.path)
        self.numbers = data.get("numbers", {})
        self.prefixes_warning = data.get("prefixes_warning", [])

    def _load_data(self, path: Path) -> dict:
        if not path.exists():
            return {"numbers": {}, "prefixes_warning": []}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_data(self) -> None:
        """Сохраняет базу в файл."""
        data = {
            "numbers": self.numbers,
            "prefixes_warning": self.prefixes_warning
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def normalize_phone(self, raw: str) -> str:
        """Приводит номер к формату +7XXXXXXXXXX."""
        digits = re.sub(r"[^\d+]", "", raw)
        # 89... -> +79...
        if digits.startswith("8") and len(digits) == 11:
            digits = "+7" + digits[1:]
        # 79... -> +79...
        elif digits.startswith("7") and len(digits) == 11:
            digits = "+" + digits
        # Уже с +7
        elif not digits.startswith("+"):
            digits = "+" + digits
        return digits

    def extract_phones(self, text: str) -> list[str]:
        """Извлекает номера телефонов из текста."""
        # Различные форматы: +7xxx, 8xxx, 8(xxx), 8-xxx
        patterns = [
            r'[\+]?[78][\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}',
            r'[\+]?[78]\d{10}',
        ]
        phones = set()
        for pattern in patterns:
            for match in re.findall(pattern, text):
                normalized = self.normalize_phone(match)
                if len(re.sub(r"[^\d]", "", normalized)) >= 11:
                    phones.add(normalized)
        return list(phones)

    def check_phone(self, phone: str) -> PhoneCheckResult:
        """Проверяет один номер."""
        normalized = self.normalize_phone(phone)

        # 1. Точное совпадение в базе
        if normalized in self.numbers:
            entry = self.numbers[normalized]
            return PhoneCheckResult(
                phone=normalized,
                risk_level=entry.get("type", "danger"),
                description=entry.get("description", "Номер в базе мошенников"),
                reports=entry.get("reports", 0)
            )

        # 2. Предупреждение по префиксу (мягкое)
        for prefix in self.prefixes_warning:
            if normalized.startswith(prefix):
                return PhoneCheckResult(
                    phone=normalized,
                    risk_level="safe",
                    description=(
                        f"Городской код {prefix}. "
                        f"В базе мошенников не найден, но будьте внимательны — "
                        f"мошенники часто подменяют городские номера."
                    )
                )

        # 3. Нет в базе
        return PhoneCheckResult(
            phone=normalized,
            risk_level="safe",
            description="Номер не найден в базе мошенников."
        )

    def check_all(self, text: str) -> list[PhoneCheckResult]:
        """Находит и проверяет все номера в тексте."""
        phones = self.extract_phones(text)
        return [self.check_phone(p) for p in phones]

    def add_number(self, phone: str, type_: str, description: str) -> None:
        """Добавляет номер в базу и сохраняет её."""
        normalized = self.normalize_phone(phone)
        if normalized in self.numbers:
            self.numbers[normalized]["reports"] = (
                self.numbers[normalized].get("reports", 0) + 1
            )
        else:
            self.numbers[normalized] = {
                "type": type_,
                "description": description,
                "reports": 1,
            }
        self._save_data()
