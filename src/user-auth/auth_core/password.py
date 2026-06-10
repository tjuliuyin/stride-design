"""口令哈希、口令策略与泄露口令检查。

SR-01 [来源: C-01.1, T-17]: scrypt(n=2**14, r=8, p=1, dklen=64) + 每用户 16B 随机盐，
存储格式自描述（scrypt$n=16384,r=8,p=1$<salt_b64>$<hash_b64>）。
生产环境注：标准库限制下采用 scrypt（OWASP 认可）；生产部署推荐迁移 argon2id
（memory 19 MiB / iterations 2 / parallelism 1），格式前缀已预留平滑迁移空间。
SR-02 [来源: C-02, T-01]: 长度 12~128 + 泄露口令检查 + 禁止包含邮箱本地部分。
SR-05 [来源: C-04.4, T-07]: dummy_verify 用于用户不存在路径的恒时校验。
"""
import base64
import hashlib
import hmac
import secrets
from abc import ABC, abstractmethod

from .errors import ErrorCode, ValidationError

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 64
_PREFIX = f"scrypt$n={_SCRYPT_N},r={_SCRYPT_R},p={_SCRYPT_P}$"

# SR-05.2: 固定盐 dummy 哈希，拉平"用户不存在"与"口令错误"路径耗时
_DUMMY_SALT = b"\x00" * 16

PASSWORD_MIN = 12
PASSWORD_MAX = 128


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DKLEN,
    )


def hash_password(password: str) -> str:
    # SR-01: 每用户独立 CSPRNG 盐
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt)
    return (
        _PREFIX
        + base64.b64encode(salt).decode("ascii")
        + "$"
        + base64.b64encode(digest).decode("ascii")
    )


def verify_password(password: str, stored: str) -> bool:
    if not stored or not stored.startswith(_PREFIX):
        return False
    try:
        _, _, salt_b64, hash_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    digest = _scrypt(password, salt)
    # SR-01: hmac.compare_digest 防时序侧信道
    return hmac.compare_digest(digest, expected)


def dummy_verify() -> None:
    """SR-05.2: 用户不存在时执行等参数 scrypt 拉平耗时。"""
    _scrypt("dummy-password-for-timing", _DUMMY_SALT)


class BreachChecker(ABC):
    """SR-02.2: 泄露口令检查接口。生产替换为 HIBP k-anonymity 实现（SR-36）。"""

    @abstractmethod
    def is_breached(self, password: str) -> bool: ...


class LocalListBreachChecker(BreachChecker):
    """内置常见泄露口令清单（演示规模；生产用 HIBP，见 SR-36）。"""

    _BUILTIN = {
        "password123456", "123456password", "qwerty123456", "admin123456",
        "password1234", "iloveyou12345", "111111111111", "123456789012",
        "letmein12345", "welcome123456", "abc123456789", "monkey1234567",
        "dragon123456", "sunshine12345", "princess12345", "football12345",
    }

    def __init__(self, extra: set[str] | None = None):
        self._list = set(self._BUILTIN) | (extra or set())

    def is_breached(self, password: str) -> bool:
        return password.lower() in self._list


def check_password_policy(password: str, email: str, checker: BreachChecker) -> None:
    """SR-02: 注册/重置/修改口令统一调用。违规抛 ValidationError。"""
    if not isinstance(password, str) or not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
        raise ValidationError(ErrorCode.WEAK_PASSWORD)
    # SR-02.3: 口令（忽略大小写）不得包含邮箱本地部分。
    # 本地部分 < 4 字符时跳过：过短子串（如 a@x.com 的 "a"）必然出现在
    # 几乎任何口令中，逐字执行会拒绝所有口令，背离控制目标。
    local = email.partition("@")[0].lower()
    if len(local) >= 4 and local in password.lower():
        raise ValidationError(ErrorCode.WEAK_PASSWORD)
    # SR-02.2: 泄露口令检查
    if checker.is_breached(password):
        raise ValidationError(ErrorCode.BREACHED_PASSWORD)
