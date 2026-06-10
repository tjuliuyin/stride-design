"""邮件/短信发送抽象、Fake 实现与参数白名单网关。

SR-18 [来源: C-14.1/4, T-23, T-21, T-09]:
- 抽象基类 + 本期 Fake 实现（生产注入真实异步实现，SR-33）；
- params 白名单：仅允许非 PII 键；action_url 仅含不透明 token，无邮箱/手机号明文；
- SendResult.message_id 由调用方写入审计（T-22 举证）。
"""
import itertools
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import SenderParamError

# SR-18.2: 发送参数键白名单（非 PII）
ALLOWED_PARAM_KEYS = frozenset({"action_url", "expires_minutes", "retry_after"})
_EMAIL_IN_VALUE_RE = re.compile(r"@")
_PHONE_IN_VALUE_RE = re.compile(r"\+[1-9]\d{6,14}")


@dataclass(frozen=True)
class SendResult:
    message_id: str


class EmailSender(ABC):
    @abstractmethod
    def send(self, to_email: str, template_id: str, params: dict) -> SendResult: ...


class SmsSender(ABC):
    @abstractmethod
    def send(self, to_phone: str, template_id: str, params: dict) -> SendResult: ...


def validate_params(params: dict) -> None:
    """SR-18.2/3: 发送网关校验——未知键或值含 PII 一律拒绝。"""
    for key, value in params.items():
        if key not in ALLOWED_PARAM_KEYS:
            raise SenderParamError()
        text = str(value)
        if _EMAIL_IN_VALUE_RE.search(text) or _PHONE_IN_VALUE_RE.search(text):
            raise SenderParamError()


def send_email(sender: EmailSender, to_email: str, template_id: str,
               params: dict) -> SendResult:
    """全部邮件发送必须经此网关（service.py 唯一调用面）。"""
    validate_params(params)
    return sender.send(to_email, template_id, params)


class FakeEmailSender(EmailSender):
    """测试用：记录全部调用供断言。"""

    def __init__(self):
        self.sent: list[dict] = []
        self._seq = itertools.count(1)

    def send(self, to_email: str, template_id: str, params: dict) -> SendResult:
        message_id = "fake-msg-" + str(next(self._seq))
        self.sent.append({
            "to": to_email, "template_id": template_id,
            "params": dict(params), "message_id": message_id,
        })
        return SendResult(message_id=message_id)


class FakeSmsSender(SmsSender):
    def __init__(self):
        self.sent: list[dict] = []
        self._seq = itertools.count(1)

    def send(self, to_phone: str, template_id: str, params: dict) -> SendResult:
        validate_params(params)
        message_id = "fake-sms-" + str(next(self._seq))
        self.sent.append({
            "to": to_phone, "template_id": template_id,
            "params": dict(params), "message_id": message_id,
        })
        return SendResult(message_id=message_id)
