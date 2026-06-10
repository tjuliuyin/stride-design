"""类型化异常与错误码枚举。

SR-19 [来源: T-08]: 对外异常 message 为固定通用文案，不含 SQL/路径/堆栈等内部细节。
SR-05 [来源: C-04.4, T-07]: INVALID_CREDENTIALS / INVALID_TOKEN 对不同失败原因文案完全一致；
ACCOUNT_LOCKED 与 RATE_LIMITED 文案一致化以兼顾防枚举。
"""
from enum import Enum


class ErrorCode(str, Enum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    UNEXPECTED_FIELD = "UNEXPECTED_FIELD"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    WEAK_PASSWORD = "WEAK_PASSWORD"
    BREACHED_PASSWORD = "BREACHED_PASSWORD"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INVALID_TOKEN = "INVALID_TOKEN"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    REAUTH_FAILED = "REAUTH_FAILED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RATE_LIMITED = "RATE_LIMITED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    PASSWORD_RESET_REQUIRED = "PASSWORD_RESET_REQUIRED"
    ILLEGAL_STATE = "ILLEGAL_STATE"
    STORAGE_ERROR = "STORAGE_ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    SENDER_PARAM_ERROR = "SENDER_PARAM_ERROR"


# SR-19: 固定通用文案，禁止内插任何运行时细节。
_GENERIC_MESSAGES = {
    ErrorCode.VALIDATION_ERROR: "Invalid request.",
    ErrorCode.UNEXPECTED_FIELD: "Invalid request.",
    ErrorCode.CONSENT_REQUIRED: "Consent is required.",
    ErrorCode.WEAK_PASSWORD: "Password does not meet the policy.",
    ErrorCode.BREACHED_PASSWORD: "Password does not meet the policy.",
    ErrorCode.INVALID_CREDENTIALS: "Invalid email or password.",
    ErrorCode.INVALID_TOKEN: "Invalid or expired token.",
    ErrorCode.NOT_AUTHENTICATED: "Authentication required.",
    ErrorCode.REAUTH_FAILED: "Re-authentication failed.",
    ErrorCode.PERMISSION_DENIED: "Permission denied.",
    # SR-05: 锁定与限流文案一致，避免泄露账号存在性
    ErrorCode.RATE_LIMITED: "Too many requests. Please try again later.",
    ErrorCode.ACCOUNT_LOCKED: "Too many requests. Please try again later.",
    ErrorCode.PASSWORD_RESET_REQUIRED: "Password reset required.",
    ErrorCode.ILLEGAL_STATE: "Operation not allowed.",
    ErrorCode.STORAGE_ERROR: "A storage error occurred.",
    ErrorCode.CONFIG_ERROR: "Invalid configuration.",
    ErrorCode.SENDER_PARAM_ERROR: "Invalid sender parameters.",
}


class AuthCoreError(Exception):
    """库内所有异常的基类。"""

    def __init__(self, code: ErrorCode, retry_after: int | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(_GENERIC_MESSAGES[code])


class AuthError(AuthCoreError):
    """认证/授权/限流类错误。"""


class ValidationError(AuthCoreError):
    """输入校验错误（不进入存储层，SR-09）。"""


class IllegalStateError(AuthCoreError):
    def __init__(self):
        super().__init__(ErrorCode.ILLEGAL_STATE)


class StorageError(AuthCoreError):
    """存储层内部异常的统一转译（SR-19：细节不外泄）。"""

    def __init__(self):
        super().__init__(ErrorCode.STORAGE_ERROR)


class ConfigError(AuthCoreError):
    def __init__(self):
        super().__init__(ErrorCode.CONFIG_ERROR)


class SenderParamError(AuthCoreError):
    def __init__(self):
        super().__init__(ErrorCode.SENDER_PARAM_ERROR)
