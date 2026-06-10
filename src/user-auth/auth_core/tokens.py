"""token 生成与哈希。

SR-06/SR-07/SR-08/SR-12 [来源: C-01.2, C-05, T-02, T-03, T-09]:
全部 token 由 secrets CSPRNG 生成（256 bit），服务端仅存 SHA-256 哈希，
比较一律使用 hmac.compare_digest。
"""
import hashlib
import hmac
import secrets


def generate_token() -> str:
    # SR-06.1 / SR-07.1: secrets.token_urlsafe(32) = 256 bit CSPRNG
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    # SR-06.2 / SR-07.2: 仅存哈希，DB 泄露不可冒用
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hashes_equal(a: str, b: str) -> bool:
    # 防时序侧信道比较
    return hmac.compare_digest(a, b)
