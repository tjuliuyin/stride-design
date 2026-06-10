"""可注入时钟（SPEC §7：时间相关安全用例可确定性验证）。"""
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone


class Clock(ABC):
    @abstractmethod
    def now(self) -> datetime:
        """返回带 UTC 时区的当前时间。"""


class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FakeClock(Clock):
    """测试用时钟：从固定时间起步，可手动前进。"""

    def __init__(self, start: datetime | None = None):
        self._now = start or datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now += timedelta(**kwargs)


def iso(dt: datetime) -> str:
    """UTC ISO-8601 文本（SPEC §6：所有时间为 UTC ISO-8601）。"""
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)
