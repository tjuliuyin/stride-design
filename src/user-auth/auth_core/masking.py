"""PII 脱敏与盲索引。

SR-14 [来源: C-09.2/4, T-17, T-29]: 邮箱等值检索一律经盲索引 HMAC-SHA256(pepper, normalized)；
mask_email / mask_phone 纯函数供展示与审计脱敏复用。
"""
import hashlib
import hmac


def blind_index(pepper: bytes, value: str) -> str:
    # SR-14: 不可逆盲索引，pepper 由配置注入（空 pepper 在 AuthService 构造期被拒绝）
    return hmac.new(pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    """liuyin0214@gmail.com -> l***@gmail.com；超短本地部分整体掩码。"""
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    if len(local) <= 1:
        return "***@" + domain
    return local[0] + "***@" + domain


def mask_phone(phone: str) -> str:
    """+8613812341234 -> +86138****1234；不足 8 位有效数字整体掩码。"""
    if len(phone) < 8:
        return "***"
    return phone[:6] + "****" + phone[-4:]
