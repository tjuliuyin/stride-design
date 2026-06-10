"""结构化审计日志与强制脱敏。

SR-13 [来源: C-11.1/3, C-01.3, T-06, T-22]:
- 审计事件覆盖全部认证/管理/发送事件，字段 who/when/where/what/result；
- 写入口统一经 sanitize()：口令明文、token 明文（≥32 字符 base64url 串）、
  完整邮箱/手机号一律拦截或掩码；
- 审计写入失败不阻塞主流程，但置降级标记。
"""
import json
import re
import uuid

from .clock import Clock, iso
from .masking import mask_email, mask_phone
from .storage import Storage

# ≥32 字符的 base64url 连续串视为疑似 token/凭据（SR-13.3）
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,}")
_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+[1-9]\d{6,14}")
# 值无论内容一律拒绝入审计的键名
_FORBIDDEN_KEYS = {"password", "old_password", "new_password", "password_hash"}


def sanitize_text(value: str) -> str:
    value = _EMAIL_RE.sub(lambda m: mask_email(m.group(0)), value)
    value = _PHONE_RE.sub(lambda m: mask_phone(m.group(0)), value)
    value = _TOKEN_RE.sub("[REDACTED]", value)
    return value


def sanitize(detail):
    """递归脱敏 detail 结构。"""
    if isinstance(detail, dict):
        return {
            k: "[REDACTED]" if k.lower() in _FORBIDDEN_KEYS else sanitize(v)
            for k, v in detail.items()
        }
    if isinstance(detail, list):
        return [sanitize(v) for v in detail]
    if isinstance(detail, str):
        return sanitize_text(detail)
    return detail


class AuditLog:
    """事件类型常量见 service.py 调用点。"""

    def __init__(self, storage: Storage, clock: Clock):
        self._storage = storage
        self._clock = clock
        self.degraded = False  # SR-13.4: 写入失败降级标记

    def log(self, event_type: str, *, user_id=None, actor_id=None, ip=None,
            user_agent=None, result="success", detail=None) -> None:
        try:
            clean = sanitize(detail or {})
            self._storage.add_audit(
                event_id=str(uuid.uuid4()),
                event_type=event_type,
                ts=iso(self._clock.now()),  # UTC ISO-8601，注入时钟（SR-13.2）
                user_id=user_id,
                actor_id=actor_id,
                ip=ip,
                user_agent=sanitize_text(user_agent) if user_agent else None,
                result=result,
                detail=json.dumps(clean, ensure_ascii=False, sort_keys=True),
            )
        except Exception:
            # SR-13.4: 审计失败不阻塞主流程
            self.degraded = True
