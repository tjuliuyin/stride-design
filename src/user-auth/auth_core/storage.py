"""sqlite3 仓储层。

SR-09 [来源: T-04, C-16.2]: 全部访问使用 `?` 占位符参数化查询；本模块禁止任何
f-string/%/+ 拼接 SQL 值（表名/列名为代码常量）。
SR-19 [来源: T-08]: sqlite3 内部异常统一转译为 StorageError，细节不外泄。
SR-22 [来源: T-18, C-05.2]: busy_timeout=5000，不持有长事务，提供清理任务。
"""
import sqlite3
from contextlib import contextmanager

from .errors import StorageError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT,
    email_bidx TEXT UNIQUE,
    phone TEXT,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL,
    force_password_reset INTEGER NOT NULL DEFAULT 0,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret_enc TEXT,
    created_at TEXT NOT NULL,
    email_verified_at TEXT,
    purge_after TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    payload TEXT
);
CREATE TABLE IF NOT EXISTS lockout_keys (
    email_key TEXT PRIMARY KEY,
    failed_count INTEGER NOT NULL DEFAULT 0,
    next_allowed_at TEXT,
    lockout_until TEXT
);
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key TEXT NOT NULL,
    window_start TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_key, window_start)
);
CREATE TABLE IF NOT EXISTS consent_records (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_version TEXT NOT NULL,
    consented_at TEXT NOT NULL,
    ip TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    ts TEXT NOT NULL,
    user_id TEXT,
    actor_id TEXT,
    ip TEXT,
    user_agent TEXT,
    result TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id, purpose);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
"""


class Storage:
    def __init__(self, db_path: str):
        try:
            self._conn = sqlite3.connect(db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA busy_timeout = 5000")  # SR-22.4
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError() from exc

    @contextmanager
    def _guard(self):
        """SR-19: 内部异常统一转译，str(StorageError) 不含 sqlite/SQL/路径。"""
        try:
            yield
            self._conn.commit()
        except sqlite3.Error as exc:
            try:
                self._conn.rollback()
            except sqlite3.Error:
                pass
            raise StorageError() from exc

    # ---------- users ----------

    def create_user(self, *, user_id, email, email_bidx, phone, password_hash,
                    status, created_at):
        with self._guard():
            self._conn.execute(
                "INSERT INTO users (id, email, email_bidx, phone, password_hash,"
                " status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user_id, email, email_bidx, phone, password_hash, status, created_at),
            )

    def find_user_by_bidx(self, email_bidx: str):
        """SR-14.1: 邮箱等值检索仅经盲索引列，不存在按明文 email 检索的代码路径。"""
        with self._guard():
            cur = self._conn.execute(
                "SELECT * FROM users WHERE email_bidx = ?", (email_bidx,)
            )
            return cur.fetchone()

    def find_user_by_id(self, user_id: str):
        with self._guard():
            cur = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            return cur.fetchone()

    def update_user_fields(self, user_id: str, **fields):
        """仅服务层内部调用；列名来自代码常量调用点，值全部参数化（SR-09.1）。"""
        allowed = {
            "email", "email_bidx", "phone", "password_hash", "status",
            "force_password_reset", "email_verified_at", "purge_after",
        }
        keys = list(fields.keys())
        if not keys or any(k not in allowed for k in keys):
            raise StorageError()
        assignments = ", ".join(k + " = ?" for k in keys)
        with self._guard():
            self._conn.execute(
                "UPDATE users SET " + assignments + " WHERE id = ?",
                (*[fields[k] for k in keys], user_id),
            )

    def delete_user(self, user_id: str):
        with self._guard():
            self._conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def list_unverified_before(self, cutoff_iso: str):
        with self._guard():
            cur = self._conn.execute(
                "SELECT id FROM users WHERE status = 'PENDING_VERIFICATION'"
                " AND created_at < ?", (cutoff_iso,),
            )
            return [r["id"] for r in cur.fetchall()]

    def list_purgeable(self, now_iso: str):
        with self._guard():
            cur = self._conn.execute(
                "SELECT id FROM users WHERE status = 'PENDING_DELETION'"
                " AND purge_after IS NOT NULL AND purge_after < ?", (now_iso,),
            )
            return [r["id"] for r in cur.fetchall()]

    # ---------- sessions ----------

    def create_session(self, *, token_hash, user_id, created_at, expires_at, ip, user_agent):
        with self._guard():
            self._conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at,"
                " expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (token_hash, user_id, created_at, created_at, expires_at, ip, user_agent),
            )

    def find_session(self, token_hash: str):
        with self._guard():
            cur = self._conn.execute(
                "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)
            )
            return cur.fetchone()

    def touch_session(self, token_hash: str, last_seen_at: str):
        with self._guard():
            self._conn.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                (last_seen_at, token_hash),
            )

    def delete_session(self, token_hash: str) -> int:
        with self._guard():
            cur = self._conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_hash,)
            )
            return cur.rowcount

    def delete_sessions_for_user(self, user_id: str) -> int:
        """SR-06.5: 改密/重置/注销/封禁/批量重置吊销全部会话。"""
        with self._guard():
            cur = self._conn.execute(
                "DELETE FROM sessions WHERE user_id = ?", (user_id,)
            )
            return cur.rowcount

    def count_sessions(self, user_id: str) -> int:
        with self._guard():
            cur = self._conn.execute(
                "SELECT COUNT(*) AS c FROM sessions WHERE user_id = ?", (user_id,)
            )
            return cur.fetchone()["c"]

    def delete_oldest_session(self, user_id: str):
        """SR-22.2: 单用户会话上限淘汰最旧。"""
        with self._guard():
            self._conn.execute(
                "DELETE FROM sessions WHERE token_hash = ("
                " SELECT token_hash FROM sessions WHERE user_id = ?"
                " ORDER BY created_at ASC, token_hash ASC LIMIT 1)",
                (user_id,),
            )

    def purge_sessions_before(self, now_iso: str, idle_cutoff_iso: str) -> int:
        with self._guard():
            cur = self._conn.execute(
                "DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ?",
                (now_iso, idle_cutoff_iso),
            )
            return cur.rowcount

    # ---------- tokens ----------

    def create_token(self, *, token_hash, user_id, purpose, created_at, expires_at,
                     payload=None):
        with self._guard():
            self._conn.execute(
                "INSERT INTO tokens (token_hash, user_id, purpose, created_at,"
                " expires_at, payload) VALUES (?, ?, ?, ?, ?, ?)",
                (token_hash, user_id, purpose, created_at, expires_at, payload),
            )

    def find_token(self, token_hash: str, purpose: str):
        with self._guard():
            cur = self._conn.execute(
                "SELECT * FROM tokens WHERE token_hash = ? AND purpose = ?",
                (token_hash, purpose),
            )
            return cur.fetchone()

    def mark_token_used(self, token_hash: str, used_at: str):
        with self._guard():
            self._conn.execute(
                "UPDATE tokens SET used_at = ? WHERE token_hash = ?",
                (used_at, token_hash),
            )

    def invalidate_unused_tokens(self, user_id: str, purpose: str, used_at: str) -> int:
        """SR-07.5: 重新申请后旧 token 立即失效（标记已用）。"""
        with self._guard():
            cur = self._conn.execute(
                "UPDATE tokens SET used_at = ? WHERE user_id = ? AND purpose = ?"
                " AND used_at IS NULL",
                (used_at, user_id, purpose),
            )
            return cur.rowcount

    def delete_tokens_for_user(self, user_id: str) -> int:
        with self._guard():
            cur = self._conn.execute(
                "DELETE FROM tokens WHERE user_id = ?", (user_id,)
            )
            return cur.rowcount

    def purge_expired_tokens(self, now_iso: str) -> int:
        with self._guard():
            cur = self._conn.execute(
                "DELETE FROM tokens WHERE expires_at < ? OR used_at IS NOT NULL",
                (now_iso,),
            )
            return cur.rowcount

    # ---------- lockout_keys（SR-03：键为 HMAC，不留明文邮箱） ----------

    def get_lockout(self, email_key: str):
        with self._guard():
            cur = self._conn.execute(
                "SELECT * FROM lockout_keys WHERE email_key = ?", (email_key,)
            )
            return cur.fetchone()

    def upsert_lockout(self, email_key: str, failed_count: int,
                       next_allowed_at: str | None, lockout_until: str | None):
        with self._guard():
            self._conn.execute(
                "INSERT INTO lockout_keys (email_key, failed_count, next_allowed_at,"
                " lockout_until) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(email_key) DO UPDATE SET failed_count = ?,"
                " next_allowed_at = ?, lockout_until = ?",
                (email_key, failed_count, next_allowed_at, lockout_until,
                 failed_count, next_allowed_at, lockout_until),
            )

    def clear_lockout(self, email_key: str):
        with self._guard():
            self._conn.execute(
                "DELETE FROM lockout_keys WHERE email_key = ?", (email_key,)
            )

    # ---------- rate_limits（SR-04） ----------

    def bump_rate(self, bucket_key: str, window_start: str) -> int:
        with self._guard():
            self._conn.execute(
                "INSERT INTO rate_limits (bucket_key, window_start, count)"
                " VALUES (?, ?, 1)"
                " ON CONFLICT(bucket_key, window_start) DO UPDATE SET count = count + 1",
                (bucket_key, window_start),
            )
            cur = self._conn.execute(
                "SELECT count FROM rate_limits WHERE bucket_key = ? AND window_start = ?",
                (bucket_key, window_start),
            )
            return cur.fetchone()["count"]

    def purge_rate_windows_before(self, cutoff_iso: str) -> int:
        with self._guard():
            cur = self._conn.execute(
                "DELETE FROM rate_limits WHERE window_start < ?", (cutoff_iso,)
            )
            return cur.rowcount

    # ---------- consent（SR-16） ----------

    def add_consent(self, *, user_id, consent_version, consented_at, ip):
        with self._guard():
            self._conn.execute(
                "INSERT INTO consent_records (user_id, consent_version, consented_at,"
                " ip) VALUES (?, ?, ?, ?)",
                (user_id, consent_version, consented_at, ip),
            )

    def get_consent(self, user_id: str):
        with self._guard():
            cur = self._conn.execute(
                "SELECT * FROM consent_records WHERE user_id = ?"
                " ORDER BY consented_at DESC", (user_id,),
            )
            return cur.fetchall()

    # ---------- audit（SR-13） ----------

    def add_audit(self, *, event_id, event_type, ts, user_id, actor_id, ip,
                  user_agent, result, detail):
        with self._guard():
            self._conn.execute(
                "INSERT INTO audit_events (event_id, event_type, ts, user_id,"
                " actor_id, ip, user_agent, result, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, event_type, ts, user_id, actor_id, ip, user_agent,
                 result, detail),
            )

    def query_audit(self, event_type: str | None = None):
        with self._guard():
            if event_type is None:
                cur = self._conn.execute("SELECT * FROM audit_events ORDER BY ts")
            else:
                cur = self._conn.execute(
                    "SELECT * FROM audit_events WHERE event_type = ? ORDER BY ts",
                    (event_type,),
                )
            return cur.fetchall()

    def distinct_audit_users_between(self, start_iso: str, end_iso: str):
        """SR-20.2: 时间窗内发生认证事件的去重 user_id（导出受影响用户）。"""
        with self._guard():
            cur = self._conn.execute(
                "SELECT DISTINCT user_id FROM audit_events WHERE ts >= ? AND ts <= ?"
                " AND user_id IS NOT NULL",
                (start_iso, end_iso),
            )
            return [r["user_id"] for r in cur.fetchall()]
