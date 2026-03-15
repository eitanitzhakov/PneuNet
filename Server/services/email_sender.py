import os
import re
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import requests
from dotenv import load_dotenv


class EmailSender:
    _EMAIL_RE = re.compile(
        r"^(?=.{3,254}$)(?=.{1,64}@)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
    )

    def __init__(self, env_path: Optional[str] = None):
        if env_path:
            load_dotenv(env_path)
        else:
            load_dotenv()

        self.api_token = os.getenv("MAILERSEND_API_TOKEN", "").strip()
        self.from_email = os.getenv("MAIL_FROM_EMAIL", "").strip()
        self.from_name = os.getenv("MAIL_FROM_NAME", "PneuNet").strip()

        self.app_name = self.from_name
        self.support_email = self.from_email

        if not self.api_token:
            raise RuntimeError("Missing MAILERSEND_API_TOKEN in .env")
        if not self.from_email:
            raise RuntimeError("Missing MAIL_FROM_EMAIL in .env")

        self.endpoint = "https://api.mailersend.com/v1/email"

    # -------------------------
    # Send email
    # -------------------------
    def _send_raw(
        self,
        to_email: str,
        subject: str,
        html: str,
        text: str = "",
        to_name: str = "",
    ) -> Tuple[int, str]:
        payload = {
            "from": {"email": self.from_email, "name": self.from_name},
            "to": [{"email": to_email, "name": to_name}],
            "subject": subject,
            "html": html,
            "text": text,
        }

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            resp = requests.post(self.endpoint, json=payload,
                                 headers=headers, timeout=15)
            return resp.status_code, resp.text
        except requests.RequestException as e:
            return 0, str(e)

    # -------------------------
    # Email validation
    # -------------------------
    def is_email_format_valid(self, email: str) -> bool:
        email = (email or "").strip()
        if not email or len(email) > 254:
            return False
        return bool(self._EMAIL_RE.match(email))

    # -------------------------
    # OTP helpers
    # -------------------------
    @staticmethod
    def generate_otp_code() -> str:
        return f"{secrets.randbelow(1_000_000):06d}"

    @staticmethod
    def calc_otp_hash(purpose: str, username: str, otp_code: str) -> str:
        raw = f"{purpose}:{username}:{otp_code}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def expires_at_iso(minutes: int = 5) -> str:
        return (datetime.now(timezone.utc) +
                timedelta(minutes=minutes)).isoformat()

    # -------------------------
    # Generic OTP mail
    # -------------------------
    def _send_code_email(
        self,
        to_email: str,
        otp_code: str,
        minutes_valid: int,
        username_hint: str,
        subject_suffix: str,
        header_title: str,
        intro_text: str,
    ) -> Tuple[int, str]:
        subject = f"{self.app_name} | {subject_suffix}"
        account_line = f"<p><b>Account:</b> {username_hint}</p>" if username_hint else ""

        html = f"""
        <html>
        <body style="font-family:Arial;background:#f6f7fb;padding:30px;">
        <div style="max-width:600px;background:white;padding:25px;border-radius:10px;margin:auto">

        <h2>{self.app_name}</h2>
        <h3>{header_title}</h3>

        <p>{intro_text}</p>

        {account_line}

        <div style="font-size:32px;font-weight:bold;
        letter-spacing:4px;
        background:#f3f4f6;
        padding:15px;
        text-align:center;
        border-radius:8px;
        margin:20px 0">
        {otp_code}
        </div>

        <p>This code expires in <b>{minutes_valid} minutes</b>.</p>

        <p>If you didn't request this, you can ignore this email.</p>
        <p>For security, do not share this code with anyone.</p>

        <hr>

        <p style="font-size:12px;color:#666">
        Sent automatically by {self.app_name}. Do not reply.
        </p>

        </div>
        </body>
        </html>
        """

        text = (
            f"{self.app_name}\n\n"
            f"{header_title}\n"
            f"Your code: {otp_code}\n"
            f"Expires in {minutes_valid} minutes.\n\n"
            "If you didn't request this, ignore this email. Do not share the code."
        )

        return self._send_raw(to_email, subject, html, text)

    def send_signup_verification_code(
        self,
        to_email: str,
        otp_code: str,
        minutes_valid: int = 10,
        username_hint: str = "",
    ) -> Tuple[int, str]:
        return self._send_code_email(
            to_email=to_email,
            otp_code=otp_code,
            minutes_valid=minutes_valid,
            username_hint=username_hint,
            subject_suffix="Email verification",
            header_title="Verify your email",
            intro_text="Please use the verification code below to complete your registration.",
        )

    def send_login_2fa_code(
        self,
        to_email: str,
        otp_code: str,
        minutes_valid: int = 5,
        username_hint: str = "",
    ) -> Tuple[int, str]:
        return self._send_code_email(
            to_email=to_email,
            otp_code=otp_code,
            minutes_valid=minutes_valid,
            username_hint=username_hint,
            subject_suffix="Login verification",
            header_title="Two-factor authentication",
            intro_text="Please use the verification code below to complete your login.",
        )

    # תאימות לאחור
    def send_verification_code(
        self,
        to_email: str,
        otp_code: str,
        minutes_valid: int = 5,
        username_hint: str = "",
    ) -> Tuple[int, str]:
        return self.send_login_2fa_code(
            to_email=to_email,
            otp_code=otp_code,
            minutes_valid=minutes_valid,
            username_hint=username_hint,
        )

    # -------------------------
    # Positive result alert
    # -------------------------
    def send_positive_result_alert(
        self,
        to_email: str,
        patient_id: str,
        confidence: float,
    ) -> Tuple[int, str]:
        conf_pct = confidence * 100
        subject = f"{self.app_name} | Positive result detected"

        html = f"""
        <html>
        <body style="font-family:Arial;background:#f6f7fb;padding:30px;">
        <div style="max-width:600px;background:white;padding:25px;border-radius:10px;margin:auto">

        <h2>{self.app_name}</h2>
        <h3 style="color:#b91c1c">Clinical Alert</h3>

        <p>A positive finding was detected by the AI model.</p>

        <p><b>Patient ID:</b> {patient_id}</p>
        <p><b>Model confidence:</b> {conf_pct:.4f}%</p>


        <p>Please review this case in the application.</p>

        <div style="background:#fff7ed;border:1px solid #fed7aa;padding:12px;border-radius:8px;margin-top:15px;font-size:13px">
        Notice: This is an automated alert and is not a medical diagnosis.
        Clinical validation is required.
        </div>

        <hr>

        <p style="font-size:12px;color:#666">
        Sent automatically by {self.app_name}. Do not reply.
        </p>

        </div>
        </body>
        </html>
        """

        text = (
            f"{self.app_name} alert\n\n"
            f"Positive finding detected\n"
            f"Patient ID: {patient_id}\n"
            f"Confidence: {conf_pct:.2f}%\n"
        )

        return self._send_raw(to_email, subject, html, text)


if __name__ == "__main__":
    sender = EmailSender()
    email = input("Enter email: ").strip()

    print("Sending signup verification email...")
    otp1 = sender.generate_otp_code()
    print(sender.send_signup_verification_code(
        email, otp1, minutes_valid=10, username_hint="eitantest"))

    print("Sending login 2FA email...")
    otp2 = sender.generate_otp_code()
    print(sender.send_login_2fa_code(email, otp2,
          minutes_valid=5, username_hint="eitantest"))

    print("Sending alert email...")
    print(sender.send_positive_result_alert(
        email, patient_id="TEST124", confidence=0.87))
