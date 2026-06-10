"""测试公共脚手架（SPEC §8：FakeClock + FakeEmailSender 注入）。"""
from auth_core import (AuthConfig, AuthService, ClientInfo, FakeClock,
                       FakeEmailSender, FakeSmsSender, LocalListBreachChecker,
                       RegisterRequest)

PEPPER = b"unit-test-pepper-not-for-production"
GOOD_PASSWORD = "correct-horse-battery-staple-9"


def client(ip: str = "203.0.113.1", user_agent: str = "UnitTest/1.0") -> ClientInfo:
    return ClientInfo(ip=ip, user_agent=user_agent)


def make_service():
    clock = FakeClock()
    sender = FakeEmailSender()
    svc = AuthService(
        db_path=":memory:",
        config=AuthConfig(),
        email_sender=sender,
        sms_sender=FakeSmsSender(),
        breach_checker=LocalListBreachChecker(),
        pepper=PEPPER,
        clock=clock,
    )
    return svc, clock, sender


def token_from(mail: dict) -> str:
    return mail["params"]["action_url"].split("token=")[1]


def register(svc, sender, email: str, password: str = GOOD_PASSWORD,
             phone: str | None = None, ip: str = "203.0.113.1"):
    req = RegisterRequest.from_dict({
        "email": email, "password": password, "phone": phone,
        "consent_version": "v1.0",
    })
    svc.register(req, client(ip=ip))
    return token_from(sender.sent[-1])


def register_and_activate(svc, sender, email: str,
                          password: str = GOOD_PASSWORD,
                          phone: str | None = None, ip: str = "203.0.113.1"):
    verify_token = register(svc, sender, email, password, phone, ip=ip)
    svc.verify_email(verify_token)
    return svc.login(email, password, client(ip=ip))
