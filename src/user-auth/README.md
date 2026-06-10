# auth_core —— 用户注册登录认证核心库

按 `specs/user-auth/03-spec.md` 实现（SPEC 驱动开发，阶段 4/5）。
Python 3.11，仅标准库。安全实现处的注释标注了对应安全需求编号（SR-xx）。

## 运行测试

```bash
cd src/user-auth
python3 -m unittest discover -s tests -t . -v
```

35 个用例：FT-01~FT-13（功能）+ ST-01~ST-22（安全，与 SR-01~SR-22 一一对应）。

## 最小使用示例

```python
from auth_core import (AuthService, AuthConfig, RegisterRequest, ClientInfo,
                       FakeEmailSender, FakeSmsSender, LocalListBreachChecker)

svc = AuthService(
    db_path="auth.db", config=AuthConfig(base_url="https://app.example.com"),
    email_sender=FakeEmailSender(),       # 生产替换为真实异步实现（SR-33）
    sms_sender=FakeSmsSender(),
    breach_checker=LocalListBreachChecker(),  # 生产替换为 HIBP（SR-36）
    pepper=load_pepper_from_kms(),        # 盲索引 pepper，必须来自密管（SR-26）
)
client = ClientInfo(ip="...", user_agent="...")
svc.register(RegisterRequest.from_dict({
    "email": "user@example.com", "password": "...", "consent_version": "v1.0",
}), client)
```

## 部署注意（摘自 SPEC §3.2）

- 口令 KDF 为 scrypt（标准库限制）；生产推荐迁移 argon2id（SR-01），存储格式已预留前缀
- TLS/HSTS、Cookie 属性、KMS、WAF/CAPTCHA、日志外送、MFA（有意延期，见 SR-25）
  等 18 项部署层要求见 SPEC SR-23 ~ SR-40 及其部署验收标准
