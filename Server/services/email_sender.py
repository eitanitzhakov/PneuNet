import os
import re
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import requests
from dotenv import load_dotenv


class EmailSender:
    """
    Email service for sending OTP codes and notifications via Resend API.

    Handles email delivery of authentication codes (signup verification,
    2FA login) and positive pneumonia detection alerts. Validates email
    formats and manages OTP generation with expiration.

    Purpose:
        Provide reliable email notification service for user
        authentication and medical alert workflows.

    Configuration:
        - Requires RESEND_API_KEY environment variable
        - Requires MAIL_FROM_EMAIL environment variable
        - Optional MAIL_FROM_NAME (defaults to "PneuNet")

    Email Types:
        1. Signup verification: OTP code for email confirmation
        2. 2FA login: OTP code for login confirmation
        3. Positive alert: Notification of pneumonia detection

    OTP Generation:
        - 6-digit random codes
        - Hashed with SHA-256 before storage
        - 5-minute expiration by default
        - Rate-limited: 60-second cooldown between resends

    Attributes:
        api_token (str): Resend API key from environment.
        from_email (str): Sender email address.
        from_name (str): Sender display name.
        endpoint (str): Resend API endpoint URL.
    """

    _EMAIL_RE = re.compile(
        r"^(?=.{3,254}$)(?=.{1,64}@)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
    )

    def __init__(self, env_path: Optional[str] = None):
        """
        Initialize email sender by loading API credentials from environment.

        Args:
            env_path (Optional[str]): Path to .env file (None uses default).

        Raises:
            RuntimeError: If RESEND_API_KEY or MAIL_FROM_EMAIL missing.
        """
        from pathlib import Path

        if env_path:
            load_dotenv(env_path)
        else:
            default_env = Path(__file__).resolve().parent / ".env"
            load_dotenv(default_env)

        self.api_token = os.getenv("RESEND_API_KEY", "").strip()
        self.from_email = os.getenv("MAIL_FROM_EMAIL", "").strip()
        self.from_name = os.getenv("MAIL_FROM_NAME", "PneuNet").strip()
        self.endpoint = "https://api.resend.com/emails"

        if not self.api_token:
            raise RuntimeError("Missing RESEND_API_KEY in .env")
        if not self.from_email:
            raise RuntimeError("Missing MAIL_FROM_EMAIL in .env")

    def _send_raw(
        self,
        to_email: str,
        subject: str,
        html: str,
        text: str = "",
    ) -> Tuple[int, str]:
        """
        Send a raw email request using the Resend API.

        Args:
            to_email (str): Recipient email address.
            subject (str): Email subject line.
            html (str): HTML email body.
            text (str): Plain text email body.

        Returns:
            Tuple[int, str]: HTTP status code and response message.
        """
        payload = {
            "from": f"{self.from_name} <{self.from_email}>",
            "to": [to_email],
            "subject": subject,
            "html": html,
            "text": text,
        }

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(
                self.endpoint,
                json=payload,
                headers=headers,
                timeout=15,
            )

            print("MAIL PAYLOAD:", payload)
            print("MAIL STATUS:", resp.status_code)
            print("MAIL RESPONSE:", resp.text)

            return resp.status_code, resp.text

        except requests.RequestException as e:
            return 0, str(e)

    def is_email_format_valid(self, email: str) -> bool:
        """
        Validate the format of an email address.

        Args:
            email (str): Email address to validate.

        Returns:
            bool: True if the email format is valid.
        """
        email = (email or "").strip()

        if not email or len(email) > 254:
            return False

        return bool(self._EMAIL_RE.match(email))

    @staticmethod
    def generate_otp_code() -> str:
        """
        Generate a random 6-digit OTP code.

        Returns:
            str: Generated OTP code.
        """
        return f"{secrets.randbelow(1_000_000):06d}"

    @staticmethod
    def calc_otp_hash(
        purpose: str,
        username: str,
        otp_code: str,
    ) -> str:
        """
        Calculate a SHA-256 hash for an OTP code.

        Args:
            purpose (str): OTP purpose type.
            username (str): Associated username.
            otp_code (str): OTP verification code.

        Returns:
            str: SHA-256 hexadecimal hash.
        """

        raw = f"{purpose}:{username}:{otp_code}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def expires_at_iso(minutes: int = 5) -> str:
        """
        Generate an ISO formatted expiration timestamp for OTP validation.

        The returned timestamp is based on the current UTC time and is
        used to determine when an OTP code becomes invalid.

        Args:
            minutes (int): Number of minutes until expiration.

        Returns:
            str: ISO formatted expiration datetime string.
        """
        return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()

    def _base_html_email(self, body_html: str) -> str:
        """
        Build the base HTML template used for all outgoing system emails.

        The function wraps the provided HTML content inside a styled
        email layout that includes system branding, formatting,
        and footer information.

        Args:
            body_html (str): Inner HTML content of the email.

        Returns:
            str: Complete formatted HTML email template.
        """
        return f"""
        <html>
        <body style="font-family:Arial;background:#f6f7fb;padding:30px;">

        <div style="
            max-width:600px;
            background:white;
            padding:25px;
            border-radius:10px;
            margin:auto
        ">

        <h2>{self.from_name}</h2>

        {body_html}

        <hr>

        <p style="font-size:12px;color:#666">
        Sent automatically by {self.from_name}. Do not reply.
        </p>

        </div>
        </body>
        </html>
        """

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
        """
        Generate and send a formatted OTP verification email.

        The function builds both HTML and plain-text email versions,
        inserts the verification code into the template, and sends
        the email through the Resend API service.

        Args:
            to_email (str): Recipient email address.
            otp_code (str): OTP verification code.
            minutes_valid (int): OTP expiration duration in minutes.
            username_hint (str): Username displayed in the email.
            subject_suffix (str): Additional subject text.
            header_title (str): Main email title.
            intro_text (str): Introductory email message.

        Returns:
            Tuple[int, str]: HTTP status code and API response message.
        """
        subject = f"{self.from_name} | {subject_suffix}"

        account_line = (
            f"<p><b>Account:</b> {username_hint}</p>" if username_hint else ""
        )

        body_html = f"""
        <h3>{header_title}</h3>

        <p>{intro_text}</p>

        {account_line}

        <div style="
            font-size:32px;
            font-weight:bold;
            letter-spacing:4px;
            background:#f3f4f6;
            padding:15px;
            text-align:center;
            border-radius:8px;
            margin:20px 0
        ">
        {otp_code}
        </div>

        <p>This code expires in <b>{minutes_valid} minutes</b>.</p>

        <p>If you didn't request this, you can ignore this email.</p>

        <p>For security, do not share this code with anyone.</p>
        """

        html = self._base_html_email(body_html)

        text = (
            f"{self.from_name}\n\n"
            f"{header_title}\n"
            f"Your code: {otp_code}\n"
            f"Expires in {minutes_valid} minutes.\n\n"
            "If you didn't request this, ignore this email.\n"
            "Do not share the code."
        )

        return self._send_raw(
            to_email=to_email,
            subject=subject,
            html=html,
            text=text,
        )

    def send_signup_verification_code(
        self,
        to_email: str,
        otp_code: str,
        minutes_valid: int = 5,
        username_hint: str = "",
    ) -> Tuple[int, str]:
        """
        Send an email verification code for user registration.

        This function sends a formatted OTP email used to verify
        the user's email address during the signup process.

        Args:
            to_email (str): Recipient email address.
            otp_code (str): OTP verification code.
            minutes_valid (int): OTP expiration time in minutes.
            username_hint (str): Username displayed in the email.

        Returns:
            Tuple[int, str]: HTTP status code and API response message.
        """
        return self._send_code_email(
            to_email=to_email,
            otp_code=otp_code,
            minutes_valid=minutes_valid,
            username_hint=username_hint,
            subject_suffix="Email verification",
            header_title="Verify your email",
            intro_text=(
                "Please use the verification code below to complete your registration."
            ),
        )

    def send_login_2fa_code(
        self,
        to_email: str,
        otp_code: str,
        minutes_valid: int = 5,
        username_hint: str = "",
    ) -> Tuple[int, str]:
        """
        Send a two-factor authentication verification email.

        The email contains a temporary OTP code required to complete
        the user login authentication process.

        Args:
            to_email (str): Recipient email address.
            otp_code (str): OTP verification code.
            minutes_valid (int): OTP expiration time in minutes.
            username_hint (str): Username displayed in the email.

        Returns:
            Tuple[int, str]: HTTP status code and API response message.
        """
        return self._send_code_email(
            to_email=to_email,
            otp_code=otp_code,
            minutes_valid=minutes_valid,
            username_hint=username_hint,
            subject_suffix="Login verification",
            header_title="Two-factor authentication",
            intro_text=(
                "Please use the verification code below to complete your login."
            ),
        )

    def send_verification_code(
        self,
        to_email: str,
        otp_code: str,
        minutes_valid: int = 5,
        username_hint: str = "",
    ) -> Tuple[int, str]:
        """
        Send a generic verification code email.

        This function acts as a wrapper around the login 2FA
        email sending functionality.

        Args:
            to_email (str): Recipient email address.
            otp_code (str): OTP verification code.
            minutes_valid (int): OTP expiration time in minutes.
            username_hint (str): Username displayed in the email.

        Returns:
            Tuple[int, str]: HTTP status code and API response message.
        """
        return self.send_login_2fa_code(
            to_email=to_email,
            otp_code=otp_code,
            minutes_valid=minutes_valid,
            username_hint=username_hint,
        )

    def send_positive_result_alert(
        self,
        to_email: str,
        patient_id: str,
        confidence: float,
    ) -> Tuple[int, str]:
        """
        Send an automated alert email for a positive AI prediction result.

        The email notifies the recipient that the AI model detected
        a potentially positive clinical finding and includes the
        patient identifier and prediction confidence score.

        Args:
            to_email (str): Recipient email address.
            patient_id (str): Patient identifier.
            confidence (float): AI prediction confidence score.

        Returns:
            Tuple[int, str]: HTTP status code and API response message.
        """
        conf_pct = confidence * 100
        subject = f"{self.from_name} | Positive result detected"

        body_html = f"""
        <h3 style="color:#b91c1c">Clinical Alert</h3>

        <p>A positive finding was detected by the AI model.</p>

        <p><b>Patient ID:</b> {patient_id}</p>

        <p><b>Model confidence:</b> {conf_pct:.8f}%</p>

        <p>Please review this case in the application.</p>

        <div style="
            background:#fff7ed;
            border:1px solid #fed7aa;
            padding:12px;
            border-radius:8px;
            margin-top:15px;
            font-size:13px
        ">
        Notice: This is an automated alert and is not a medical diagnosis.
        Clinical validation is required.
        </div>
        """

        html = self._base_html_email(body_html)

        text = (
            f"{self.from_name} alert\n\n"
            f"Positive finding detected\n"
            f"Patient ID: {patient_id}\n"
            f"Confidence: {conf_pct:.2f}%\n"
        )

        return self._send_raw(
            to_email=to_email,
            subject=subject,
            html=html,
            text=text,
        )


if __name__ == "__main__":
    sender = EmailSender()
    email = input("Enter email: ").strip()

    print("Sending signup verification email...")
    otp1 = sender.generate_otp_code()
    print(
        sender.send_signup_verification_code(
            email,
            otp1,
            minutes_valid=10,
            username_hint="eitantest",
        )
    )

    print("Sending login 2FA email...")
    otp2 = sender.generate_otp_code()
    print(
        sender.send_login_2fa_code(
            email,
            otp2,
            minutes_valid=5,
            username_hint="eitantest",
        )
    )

    print("Sending alert email...")
    print(
        sender.send_positive_result_alert(
            email,
            patient_id="TEST124",
            confidence=0.87,
        )
    )
