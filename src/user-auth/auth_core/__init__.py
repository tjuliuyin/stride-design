"""auth_core —— 用户注册登录认证核心库（SPEC: specs/user-auth/03-spec.md）。"""
from .clock import Clock, FakeClock, SystemClock
from .errors import (AuthCoreError, AuthError, ConfigError, ErrorCode,
                     IllegalStateError, SenderParamError, StorageError,
                     ValidationError)
from .masking import mask_email, mask_phone
from .models import (AccountStatus, ActorContext, AuthConfig, ClientInfo,
                     LoginResult, Profile, RegisterRequest, RegisterResult,
                     Role, SessionContext)
from .notify import (EmailSender, FakeEmailSender, FakeSmsSender, SendResult,
                     SmsSender)
from .password import BreachChecker, LocalListBreachChecker
from .service import AuthService

__all__ = [
    "AuthService", "AuthConfig", "RegisterRequest", "RegisterResult",
    "LoginResult", "SessionContext", "Profile", "ClientInfo", "ActorContext",
    "Role", "AccountStatus", "Clock", "SystemClock", "FakeClock",
    "EmailSender", "SmsSender", "FakeEmailSender", "FakeSmsSender", "SendResult",
    "BreachChecker", "LocalListBreachChecker",
    "AuthCoreError", "AuthError", "ValidationError", "ConfigError",
    "StorageError", "IllegalStateError", "SenderParamError", "ErrorCode",
    "mask_email", "mask_phone",
]
