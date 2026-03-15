import sqlite3
import hashlib
import secrets
from typing import Optional, Tuple
import os
from datetime import datetime, timezone


class DB:
    def __init__(self, db_name: str = "db.db"):
        base_dir = os.path.dirname(__file__)
        self.db_path = os.path.join(base_dir, db_name)

        db_exists = os.path.exists(self.db_path)
        self._create_schema()

        if not db_exists:
            print(f"[DB] Created new database at: {self.db_path}")
        else:
            print(f"[DB] Using existing database at: {self.db_path}")

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=10,
            check_same_thread=False
        )
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    # Schema
    def _create_schema(self) -> None:
        with self._get_conn() as conn:
            cur = conn.cursor()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,

                    email TEXT,
                    email_verified INTEGER NOT NULL DEFAULT 0,

                    email_verify_otp_hash TEXT,
                    email_verify_otp_expires_at TEXT,
                    email_verify_otp_attempts INTEGER NOT NULL DEFAULT 0,
                    email_verify_otp_last_sent_at TEXT,

                    login_2fa_otp_hash TEXT,
                    login_2fa_otp_expires_at TEXT,
                    login_2fa_otp_attempts INTEGER NOT NULL DEFAULT 0,
                    login_2fa_otp_last_sent_at TEXT,

                    created_at TEXT DEFAULT (datetime('now', 'localtime'))
                );
            """)

            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
                ON users(email);
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    request_id TEXT NOT NULL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    patient_id TEXT,
                    status TEXT DEFAULT 'PENDING',
                    prediction_label TEXT,
                    prediction_confidence REAL,
                    uploaded_at TEXT DEFAULT (datetime('now', 'localtime')),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)

            conn.commit()

    def close(self) -> None:
        pass

    # Helpers
    @staticmethod
    def _calc_password_hash(plain_password: str, salt: str) -> str:
        return hashlib.sha256(
            (plain_password + salt).encode("utf-8")).hexdigest()

    @staticmethod
    def _local_now_str() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Auth
    def signup(self, username: str, password_plain: str,
               email: str) -> Tuple[bool, Optional[int]]:
        salt = secrets.token_hex(16)
        password_hash = self._calc_password_hash(password_plain, salt)

        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, salt, email, email_verified, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                    """,
                    (username, password_hash, salt, email, self._local_now_str())
                )
                conn.commit()
                return True, cur.lastrowid

        except sqlite3.IntegrityError as e:
            print(f"Signup integrity error: {e}")
            return False, None

        except Exception as e:
            print(f"Signup error: {e}")
            return False, None

    def login(self, username: str, password_plain: str) -> Optional[int]:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, password_hash, salt FROM users WHERE username = ?",
                    (username,)
                )
                row = cur.fetchone()
                if not row:
                    return None

                user_id, stored_hash, stored_salt = row
                calculated_hash = self._calc_password_hash(
                    password_plain, stored_salt)
                return int(user_id) if calculated_hash == stored_hash else None

        except Exception as e:
            print(f"Login error: {e}")
            return None

    # User helpers
    def get_user_id_by_username(self, username: str) -> Optional[int]:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id FROM users WHERE username = ?", (username,))
                row = cur.fetchone()
                return int(row[0]) if row else None
        except Exception as e:
            print(f"get_user_id_by_username error: {e}")
            return None

    def get_user_email(self, user_id: int) -> Optional[str]:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
                row = cur.fetchone()
                return row[0] if row and row[0] else None
        except Exception as e:
            print(f"get_user_email error: {e}")
            return None

    def is_email_verified(self, user_id: int) -> bool:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT email_verified FROM users WHERE id = ?", (user_id,))
                row = cur.fetchone()
                return bool(row[0]) if row else False
        except Exception as e:
            print(f"is_email_verified error: {e}")
            return False

    def set_email_verified(self, user_id: int, value: int = 1) -> bool:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE users SET email_verified = ? WHERE id = ?",
                    (int(value), user_id)
                )
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            print(f"set_email_verified error: {e}")
            return False

    # OTP helpers
    def _otp_columns(self, purpose: str) -> Tuple[str, str, str, str]:
        purpose = (purpose or "").strip().lower()

        if purpose == "email_verify":
            return (
                "email_verify_otp_hash",
                "email_verify_otp_expires_at",
                "email_verify_otp_attempts",
                "email_verify_otp_last_sent_at",
            )

        if purpose == "login_2fa":
            return (
                "login_2fa_otp_hash",
                "login_2fa_otp_expires_at",
                "login_2fa_otp_attempts",
                "login_2fa_otp_last_sent_at",
            )

        raise ValueError(f"Unsupported OTP purpose: {purpose}")

    def get_otp_meta(self,
                     user_id: int,
                     purpose: str) -> Tuple[Optional[str],
                                            Optional[str],
                                            int,
                                            Optional[str]]:
        try:
            hash_col, exp_col, attempts_col, last_sent_col = self._otp_columns(
                purpose)

            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    f"""
                    SELECT {hash_col}, {exp_col}, {attempts_col}, {last_sent_col}
                    FROM users
                    WHERE id = ?
                    """,
                    (user_id,)
                )
                row = cur.fetchone()
                if not row:
                    return None, None, 0, None

                otp_hash, expires_at, attempts, last_sent = row
                return otp_hash, expires_at, int(attempts or 0), last_sent

        except Exception as e:
            print(f"get_otp_meta error: {e}")
            return None, None, 0, None

    def set_otp_for_user(
            self,
            user_id: int,
            purpose: str,
            otp_hash: str,
            expires_at_iso: str) -> bool:
        try:
            hash_col, exp_col, attempts_col, last_sent_col = self._otp_columns(
                purpose)

            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    f"""
                    UPDATE users
                    SET {hash_col} = ?,
                        {exp_col} = ?,
                        {attempts_col} = 0,
                        {last_sent_col} = ?
                    WHERE id = ?
                    """,
                    (otp_hash, expires_at_iso, datetime.now(
                        timezone.utc).isoformat(), user_id)
                )
                conn.commit()
                return cur.rowcount > 0

        except Exception as e:
            print(f"set_otp_for_user error: {e}")
            return False

    def increment_otp_attempts(self, user_id: int, purpose: str) -> None:
        try:
            _hash_col, _exp_col, attempts_col, _last_sent_col = self._otp_columns(
                purpose)

            with self._get_conn() as conn:
                conn.execute(
                    f"UPDATE users SET {attempts_col} = {attempts_col} + 1 WHERE id = ?",
                    (user_id,)
                )
                conn.commit()
        except Exception as e:
            print(f"increment_otp_attempts error: {e}")

    def clear_otp(self, user_id: int, purpose: str) -> bool:
        try:
            hash_col, exp_col, attempts_col, last_sent_col = self._otp_columns(
                purpose)

            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    f"""
                    UPDATE users
                    SET {hash_col} = NULL,
                        {exp_col} = NULL,
                        {attempts_col} = 0,
                        {last_sent_col} = NULL
                    WHERE id = ?
                    """,
                    (user_id,)
                )
                conn.commit()
                return cur.rowcount > 0

        except Exception as e:
            print(f"clear_otp error: {e}")
            return False

    @staticmethod
    def _parse_iso(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def verify_otp_hash(self,
                        user_id: int,
                        purpose: str,
                        expected_hash: str,
                        max_attempts: int = 5) -> Tuple[bool,
                                                        str]:
        otp_hash, expires_at_s, attempts, _last_sent = self.get_otp_meta(
            user_id, purpose)

        if not otp_hash or not expires_at_s:
            return False, "No active code. Please request a new code."

        if attempts >= max_attempts:
            self.clear_otp(user_id, purpose)
            return False, "Too many attempts. Please request a new code."

        exp = self._parse_iso(expires_at_s)
        now = datetime.now(timezone.utc)
        if not exp or now > exp:
            return False, "Code expired. Please request a new code."

        if otp_hash != expected_hash:
            self.increment_otp_attempts(user_id, purpose)
            return False, "Invalid code"

        return True, "OK"

    def otp_resend_cooldown_remaining(
            self,
            user_id: int,
            purpose: str,
            cooldown_seconds: int = 60) -> int:
        try:
            _otp_hash, _exp, _attempts, last_sent = self.get_otp_meta(
                user_id, purpose)
            if not last_sent:
                return 0

            last_dt = self._parse_iso(last_sent)
            if not last_dt:
                return 0

            now = datetime.now(timezone.utc)
            elapsed = (now - last_dt).total_seconds()
            remaining = int(cooldown_seconds - elapsed)
            return remaining if remaining > 0 else 0

        except Exception as e:
            print(f"otp_resend_cooldown_remaining error: {e}")
            return 0

    # Scans
    def save_new_scan(
            self,
            request_id: str,
            user_id: int,
            patient_id: str) -> bool:
        uploaded_at = self._local_now_str()

        try:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scans (request_id, user_id, patient_id, status, uploaded_at)
                    VALUES (?, ?, ?, 'PENDING', ?)
                    """,
                    (request_id, user_id, patient_id, uploaded_at)
                )
                conn.commit()
            return True
        except Exception as e:
            print(f"Error saving scan: {e}")
            return False

    def update_scan(
            self,
            request_id: str,
            prediction_label: str,
            prediction_confidence: float) -> bool:
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE scans
                    SET status = 'COMPLETED',
                        prediction_label = ?,
                        prediction_confidence = ?
                    WHERE request_id = ?
                    """,
                    (prediction_label, prediction_confidence, request_id)
                )
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            print(f"Error updating scan: {e}")
            return False

    def mark_scan_error(self, request_id: str) -> None:
        try:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE scans SET status = 'ERROR' WHERE request_id = ?",
                    (request_id,)
                )
                conn.commit()
        except Exception as e:
            print(f"Error marking error: {e}")

    def get_user_history(self, user_id: int) -> list:
        try:
            with self._get_conn() as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT patient_id, status, prediction_label, prediction_confidence, uploaded_at
                    FROM scans
                    WHERE user_id = ?
                    ORDER BY uploaded_at DESC
                    """,
                    (user_id,)
                )
                rows = [dict(r) for r in cur.fetchall()]
                for row in rows:
                    if row.get("uploaded_at") is not None:
                        row["uploaded_at"] = str(row["uploaded_at"])
                return rows
        except Exception as e:
            print(f"History error: {e}")
            return []

    def get_patient_id_by_request_id(self, request_id: str) -> Optional[str]:
        try:
            with self._get_conn() as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                cur.execute(
                    """
                    SELECT patient_id
                    FROM scans
                    WHERE request_id = ?
                    """,
                    (request_id,)
                )

                row = cur.fetchone()

                if row:
                    return row["patient_id"]

                return None

        except Exception as e:
            print("DB error in get_patient_id_by_request_id:", e)
            return None


if __name__ == "__main__":
    db = DB("db.db")
    print("DB READY (SQLite)")
