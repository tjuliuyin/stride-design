"""持久化固定窗口限流器。

SR-04 [来源: C-04.2/3, T-01, T-03, T-10]: 登录/注册/找回密码/token 校验多维限流，
超限抛 AuthError(RATE_LIMITED, retry_after)。阈值由 AuthConfig 注入，
不可被请求数据覆盖。
"""
from datetime import datetime, timedelta, timezone

from .clock import Clock, iso
from .errors import AuthError, ErrorCode
from .storage import Storage

MAX_WINDOW_SECONDS = 86400


class RateLimiter:
    def __init__(self, storage: Storage, clock: Clock):
        self._storage = storage
        self._clock = clock

    def check(self, bucket: str, limit: int, window_seconds: int) -> None:
        """计数并校验；超限抛 RATE_LIMITED（含 retry_after 秒数）。"""
        now = self._clock.now()
        epoch = int(now.timestamp())
        window_start_epoch = (epoch // window_seconds) * window_seconds
        window_start = iso(datetime.fromtimestamp(window_start_epoch, tz=timezone.utc))
        count = self._storage.bump_rate(bucket + ":" + str(window_seconds), window_start)
        if count > limit:
            retry_after = window_start_epoch + window_seconds - epoch
            raise AuthError(ErrorCode.RATE_LIMITED, retry_after=max(retry_after, 1))

    def purge_expired(self) -> int:
        """SR-22.3: 清理过期窗口行。"""
        cutoff = iso(self._clock.now() - timedelta(seconds=MAX_WINDOW_SECONDS * 2))
        return self._storage.purge_rate_windows_before(cutoff)
