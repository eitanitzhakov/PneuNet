import socket
import threading
import struct
import base64
import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, Tuple

from .json_protocol import JsonProtocol
from .secure_json_protocol import SecureJsonProtocol
from .cipher import Cipher
from db.db import DB
from .constants import NONCE
from ai.prediction import Predictor
from services.email_sender import EmailSender


class Server:
    EMAIL_VERIFY_PURPOSE = "email_verify"
    LOGIN_2FA_PURPOSE = "login_2fa"

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        backlog: int = 100,
        timeout_sec: int = 600,
        max_clients: int = 200,
        weights_path: str = r"C:\Users\eitan\PycharmProjects\PneuNet\Server\ai\best (1).pth",
        arch: str = "tf_efficientnet_b4_ns",
        img_size: int = 380,
        device: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.backlog = backlog
        self.timeout_sec = timeout_sec
        self.max_clients = max_clients

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.protocol = JsonProtocol()

        self.upload_index: Dict[str, str] = {}
        self._upload_lock = threading.Lock()

        self.db = DB()

        try:
            self.mailer = EmailSender()
            print("[SERVER] EmailSender initialized.")
        except Exception as e:
            self.mailer = None
            print(f"[SERVER] Warning: EmailSender disabled: {e}")

        try:
            self.predictor = Predictor(
                weights_path=weights_path,
                arch=arch,
                img_size=img_size,
                device=device,
            )
            print(f"[SERVER] Model loaded. arch={arch}")
        except Exception as e:
            print(f"[SERVER] Warning: Failed to load model: {e}")
            self.predictor = None

        self._executor = ThreadPoolExecutor(max_workers=self.max_clients)
        self._shutdown = threading.Event()

        self.OTP_RESEND_COOLDOWN_SEC = 60

    def start(self) -> None:
        self.sock.bind((self.host, self.port))
        self.sock.listen(self.backlog)
        print(f"[SERVER] Listening on {self.host}:{self.port} (max_clients={self.max_clients})")

        try:
            while not self._shutdown.is_set():
                client_sock, addr = self.sock.accept()
                self._executor.submit(self.handle_client, client_sock, addr)
        except KeyboardInterrupt:
            print("[SERVER] KeyboardInterrupt -> shutting down")
        finally:
            self.stop()

    def stop(self) -> None:
        self._shutdown.set()
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        print("[SERVER] Stopped")

    def handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]) -> None:
        print(f"[SERVER] Connection from {addr}")
        try:
            client_sock.settimeout(self.timeout_sec)
            with client_sock:
                dh_server, pk_server = Cipher.get_dh_public_key()
                pk_server_b64 = base64.b64encode(pk_server).decode("ascii")
                self.protocol.send(client_sock, {"type": "DH_SERVER_PK", "pk": pk_server_b64})

                msg = self.protocol.recv(client_sock)
                if not msg or msg.get("type") != "DH_CLIENT_PK":
                    print(f"[SERVER] Handshake failed {addr}")
                    return

                pk_client = base64.b64decode(msg.get("pk").encode("ascii"))
                shared_key = Cipher.get_dh_shared_key(dh_server, pk_client, lngth=32)

                cipher = Cipher(shared_key, NONCE)
                secure_protocol = SecureJsonProtocol(self.protocol, cipher)

                secure_protocol.send(client_sock, {"type": "SECURE_OK"})

                current_user_id: Optional[int] = None

                pending_email_verify_user_id: Optional[int] = None
                pending_email_verify_username: str = ""

                pending_2fa_user_id: Optional[int] = None
                pending_2fa_username: str = ""

                while True:
                    msg = secure_protocol.recv(client_sock)
                    if msg is None:
                        break

                    (
                        resp,
                        should_close,
                        current_user_id,
                        pending_email_verify_user_id,
                        pending_email_verify_username,
                        pending_2fa_user_id,
                        pending_2fa_username,
                    ) = self.on_message(
                        client_sock=client_sock,
                        msg=msg,
                        secure_protocol=secure_protocol,
                        cipher=cipher,
                        user_id=current_user_id,
                        pending_email_verify_user_id=pending_email_verify_user_id,
                        pending_email_verify_username=pending_email_verify_username,
                        pending_2fa_user_id=pending_2fa_user_id,
                        pending_2fa_username=pending_2fa_username,
                    )

                    if resp is not None:
                        secure_protocol.send(client_sock, resp)

                    if should_close:
                        print(f" Closing session for {addr}")
                        break

        except Exception as e:
            import traceback
            print(f"[SERVER] Client error {addr}: {e}")
            print(traceback.format_exc())

        finally:
            try:
                print("[SERVER] Closing client socket")
                client_sock.close()
                print("[SERVER] Client socket closed")
            except Exception as e:
                print(f"[SERVER] Error closing client socket: {e}")

    def on_message(
        self,
        client_sock: socket.socket,
        msg: Dict[str, Any],
        secure_protocol: SecureJsonProtocol,
        cipher: Cipher,
        user_id: Optional[int],
        pending_email_verify_user_id: Optional[int],
        pending_email_verify_username: str,
        pending_2fa_user_id: Optional[int],
        pending_2fa_username: str,
    ) -> Tuple[Optional[Dict[str, Any]], bool, Optional[int], Optional[int], str, Optional[int], str]:

        mtype = str(msg.get("type", "")).upper().strip()

        if mtype == "PING":
            return {
                "type": "PONG"
            }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # SIGNUP
        # -------------------------
        if mtype == "SIGNUP":
            try:
                if not self.mailer:
                    return {"type": "ERROR", "message": "Email sender not configured"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                username = (msg.get("username") or "").strip()
                password = (msg.get("password") or "").strip()
                email = (msg.get("email") or "").strip()

                if not username or not password or not email:
                    return {"type": "ERROR", "message": "username/password/email required"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if not self.mailer.is_email_format_valid(email):
                    return {"type": "ERROR", "message": "Invalid email format"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                ok, new_uid = self.db.signup(username, password, email)
                if not ok or not new_uid:
                    return {"type": "ERROR", "message": "Username or email already exists / Signup failed"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                self.db.set_email_verified(new_uid, 0)

                cooldown_left = self.db.otp_resend_cooldown_remaining(
                    new_uid,
                    self.EMAIL_VERIFY_PURPOSE,
                    self.OTP_RESEND_COOLDOWN_SEC
                )
                if cooldown_left > 0:
                    return {"type": "ERROR", "message": f"Please wait {cooldown_left}s before requesting another code."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                otp_code = self.mailer.generate_otp_code()
                otp_hash = self.mailer.calc_otp_hash(self.EMAIL_VERIFY_PURPOSE, username, otp_code)
                expires_at = self.mailer.expires_at_iso(minutes=10)

                if not self.db.set_otp_for_user(new_uid, self.EMAIL_VERIFY_PURPOSE, otp_hash, expires_at):
                    return {"type": "ERROR", "message": "Failed to store verification OTP"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                status, resp_text = self.mailer.send_signup_verification_code(
                    to_email=email,
                    otp_code=otp_code,
                    minutes_valid=10,
                    username_hint=username,
                )
                if status != 202:
                    return {
                        "type": "ERROR",
                        "message": f"Failed to send verification email (status={status})",
                        "details": resp_text[:500]
                    }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                pending_email_verify_user_id = new_uid
                pending_email_verify_username = username

                return {
                    "type": "SIGNUP_VERIFY_REQUIRED",
                    "user_id": new_uid,
                    "message": "Verification code sent to your email. Please verify to activate the account."
                }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            except Exception as e:
                return {"type": "ERROR", "message": f"SIGNUP exception: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # RESEND_EMAIL_CODE
        # -------------------------
        if mtype == "RESEND_EMAIL_CODE":
            try:
                if not self.mailer:
                    return {"type": "ERROR", "message": "Email sender not configured"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if not pending_email_verify_user_id or not pending_email_verify_username:
                    return {"type": "ERROR", "message": "No pending email verification. Please SIGNUP or LOGIN again."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                cooldown_left = self.db.otp_resend_cooldown_remaining(
                    pending_email_verify_user_id,
                    self.EMAIL_VERIFY_PURPOSE,
                    self.OTP_RESEND_COOLDOWN_SEC
                )
                if cooldown_left > 0:
                    return {"type": "ERROR", "message": f"Please wait {cooldown_left}s before requesting another code."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                email = self.db.get_user_email(pending_email_verify_user_id)
                if not email or not self.mailer.is_email_format_valid(email):
                    return {"type": "ERROR", "message": "Invalid email on account. Contact admin."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                otp_code = self.mailer.generate_otp_code()
                otp_hash = self.mailer.calc_otp_hash(self.EMAIL_VERIFY_PURPOSE, pending_email_verify_username, otp_code)
                expires_at = self.mailer.expires_at_iso(minutes=10)

                if not self.db.set_otp_for_user(
                    pending_email_verify_user_id,
                    self.EMAIL_VERIFY_PURPOSE,
                    otp_hash,
                    expires_at
                ):
                    return {"type": "ERROR", "message": "Failed to store OTP"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                status, resp_text = self.mailer.send_signup_verification_code(
                    to_email=email,
                    otp_code=otp_code,
                    minutes_valid=10,
                    username_hint=pending_email_verify_username,
                )
                if status != 202:
                    return {
                        "type": "ERROR",
                        "message": f"Failed to send email (status={status})",
                        "details": resp_text[:500]
                    }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                return {"type": "RESEND_OK", "message": "Verification code resent."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            except Exception as e:
                return {"type": "ERROR", "message": f"RESEND_EMAIL_CODE exception: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # VERIFY_EMAIL
        # -------------------------
        if mtype == "VERIFY_EMAIL":
            try:
                if not self.mailer:
                    return {"type": "ERROR", "message": "Email sender not configured"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                otp_code = (msg.get("otp_code") or "").strip()
                username = (msg.get("username") or "").strip()

                if not pending_email_verify_user_id or not pending_email_verify_username:
                    return {"type": "ERROR", "message": "No pending email verification. Please SIGNUP or LOGIN again."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if username and username != pending_email_verify_username:
                    return {"type": "ERROR", "message": "Username mismatch. Please SIGNUP or LOGIN again."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if not otp_code:
                    return {"type": "ERROR", "message": "otp_code required"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                expected_hash = self.mailer.calc_otp_hash(self.EMAIL_VERIFY_PURPOSE, pending_email_verify_username, otp_code)
                ok, reason = self.db.verify_otp_hash(
                    pending_email_verify_user_id,
                    self.EMAIL_VERIFY_PURPOSE,
                    expected_hash,
                    max_attempts=5
                )
                if not ok:
                    return {"type": "ERROR", "message": reason}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                self.db.set_email_verified(pending_email_verify_user_id, 1)
                self.db.clear_otp(pending_email_verify_user_id, self.EMAIL_VERIFY_PURPOSE)
                self.db.clear_otp(pending_email_verify_user_id, self.LOGIN_2FA_PURPOSE)

                verified_uid = pending_email_verify_user_id
                pending_email_verify_user_id = None
                pending_email_verify_username = ""

                return {"type": "EMAIL_VERIFIED_OK", "user_id": verified_uid}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            except Exception as e:
                return {"type": "ERROR", "message": f"VERIFY_EMAIL exception: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # LOGIN
        # -------------------------
        if mtype == "LOGIN":
            try:
                username = (msg.get("username") or "").strip()
                password = (msg.get("password") or "").strip()
                if not username or not password:
                    return {"type": "ERROR", "message": "Username/password required"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                uid = self.db.login(username, password)
                if not uid:
                    return {"type": "ERROR", "message": "User not found or wrong password"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                # ---- NEW: reopen email verification flow on login ----
                if not self.db.is_email_verified(uid):
                    pending_email_verify_user_id = uid
                    pending_email_verify_username = username

                    if not self.mailer:
                        return {
                            "type": "EMAIL_VERIFICATION_REQUIRED",
                            "message": "Your email is not verified yet. Email service is currently unavailable."
                        }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                    email = self.db.get_user_email(uid)
                    if not email or not self.mailer.is_email_format_valid(email):
                        return {
                            "type": "EMAIL_VERIFICATION_REQUIRED",
                            "message": "Your email is not verified yet. The email on this account is invalid. Contact admin."
                        }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                    cooldown_left = self.db.otp_resend_cooldown_remaining(
                        uid,
                        self.EMAIL_VERIFY_PURPOSE,
                        self.OTP_RESEND_COOLDOWN_SEC
                    )

                    if cooldown_left > 0:
                        return {
                            "type": "EMAIL_VERIFICATION_REQUIRED",
                            "message": f"Your email is not verified yet. You can request a new code in {cooldown_left}s."
                        }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                    try:
                        otp_code = self.mailer.generate_otp_code()
                        otp_hash = self.mailer.calc_otp_hash(self.EMAIL_VERIFY_PURPOSE, username, otp_code)
                        expires_at = self.mailer.expires_at_iso(minutes=10)

                        if self.db.set_otp_for_user(uid, self.EMAIL_VERIFY_PURPOSE, otp_hash, expires_at):
                            status, resp_text = self.mailer.send_signup_verification_code(
                                to_email=email,
                                otp_code=otp_code,
                                minutes_valid=10,
                                username_hint=username,
                            )

                            if status == 202:
                                return {
                                    "type": "EMAIL_VERIFICATION_REQUIRED",
                                    "message": "Your email is not verified yet. A new verification code was sent to your email."
                                }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                            return {
                                "type": "EMAIL_VERIFICATION_REQUIRED",
                                "message": f"Your email is not verified yet. Automatic resend failed (status={status}). Please click 'Resend code'.",
                                "details": resp_text[:500]
                            }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                        return {
                            "type": "EMAIL_VERIFICATION_REQUIRED",
                            "message": "Your email is not verified yet. Failed to create a new verification code. Please click 'Resend code'."
                        }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                    except Exception as e:
                        return {
                            "type": "EMAIL_VERIFICATION_REQUIRED",
                            "message": f"Your email is not verified yet. Could not send a new code automatically: {e}"
                        }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if not self.mailer:
                    return {"type": "ERROR", "message": "2FA unavailable (email sender not configured)"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                cooldown_left = self.db.otp_resend_cooldown_remaining(
                    uid,
                    self.LOGIN_2FA_PURPOSE,
                    self.OTP_RESEND_COOLDOWN_SEC
                )
                if cooldown_left > 0:
                    return {"type": "ERROR", "message": f"Please wait {cooldown_left}s before requesting another code."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                email = self.db.get_user_email(uid)
                if not email or not self.mailer.is_email_format_valid(email):
                    return {"type": "ERROR", "message": "Invalid email on account. Contact admin."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                otp_code = self.mailer.generate_otp_code()
                otp_hash = self.mailer.calc_otp_hash(self.LOGIN_2FA_PURPOSE, username, otp_code)
                expires_at = self.mailer.expires_at_iso(minutes=5)

                if not self.db.set_otp_for_user(uid, self.LOGIN_2FA_PURPOSE, otp_hash, expires_at):
                    return {"type": "ERROR", "message": "Failed to store OTP"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                status, resp_text = self.mailer.send_login_2fa_code(
                    to_email=email,
                    otp_code=otp_code,
                    minutes_valid=5,
                    username_hint=username,
                )
                if status != 202:
                    return {
                        "type": "ERROR",
                        "message": f"Failed to send 2FA email (status={status})",
                        "details": resp_text[:500]
                    }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                pending_2fa_user_id = uid
                pending_2fa_username = username

                return {"type": "LOGIN_2FA_REQUIRED", "message": "Verification code sent to your email."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            except Exception as e:
                return {"type": "ERROR", "message": f"LOGIN exception: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # RESEND_2FA_CODE
        # -------------------------
        if mtype == "RESEND_2FA_CODE":
            try:
                if not self.mailer:
                    return {"type": "ERROR", "message": "Email sender not configured"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if not pending_2fa_user_id or not pending_2fa_username:
                    return {"type": "ERROR", "message": "No pending 2FA session. Please LOGIN again."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                cooldown_left = self.db.otp_resend_cooldown_remaining(
                    pending_2fa_user_id,
                    self.LOGIN_2FA_PURPOSE,
                    self.OTP_RESEND_COOLDOWN_SEC
                )
                if cooldown_left > 0:
                    return {"type": "ERROR", "message": f"Please wait {cooldown_left}s before requesting another code."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                email = self.db.get_user_email(pending_2fa_user_id)
                if not email or not self.mailer.is_email_format_valid(email):
                    return {"type": "ERROR", "message": "Invalid email on account. Contact admin."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                otp_code = self.mailer.generate_otp_code()
                otp_hash = self.mailer.calc_otp_hash(self.LOGIN_2FA_PURPOSE, pending_2fa_username, otp_code)
                expires_at = self.mailer.expires_at_iso(minutes=5)

                if not self.db.set_otp_for_user(
                    pending_2fa_user_id,
                    self.LOGIN_2FA_PURPOSE,
                    otp_hash,
                    expires_at
                ):
                    return {"type": "ERROR", "message": "Failed to store OTP"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                status, resp_text = self.mailer.send_login_2fa_code(
                    to_email=email,
                    otp_code=otp_code,
                    minutes_valid=5,
                    username_hint=pending_2fa_username,
                )
                if status != 202:
                    return {
                        "type": "ERROR",
                        "message": f"Failed to send email (status={status})",
                        "details": resp_text[:500]
                    }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                return {"type": "RESEND_OK", "message": "Verification code resent."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            except Exception as e:
                return {"type": "ERROR", "message": f"RESEND_2FA_CODE exception: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # VERIFY_2FA
        # -------------------------
        if mtype == "VERIFY_2FA":
            try:
                if not self.mailer:
                    return {"type": "ERROR", "message": "2FA unavailable"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                otp_code = (msg.get("otp_code") or "").strip()
                username = (msg.get("username") or "").strip()

                if not pending_2fa_user_id or not pending_2fa_username:
                    return {"type": "ERROR", "message": "No pending 2FA session. Please LOGIN again."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if username and username != pending_2fa_username:
                    return {"type": "ERROR", "message": "Username mismatch. Please LOGIN again."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                if not otp_code:
                    return {"type": "ERROR", "message": "otp_code required"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                expected_hash = self.mailer.calc_otp_hash(self.LOGIN_2FA_PURPOSE, pending_2fa_username, otp_code)
                ok, reason = self.db.verify_otp_hash(
                    pending_2fa_user_id,
                    self.LOGIN_2FA_PURPOSE,
                    expected_hash,
                    max_attempts=5
                )
                if not ok:
                    return {"type": "ERROR", "message": reason}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

                self.db.clear_otp(pending_2fa_user_id, self.LOGIN_2FA_PURPOSE)
                user_id = pending_2fa_user_id

                pending_2fa_user_id = None
                pending_2fa_username = ""

                return {"type": "LOGIN_OK", "user_id": user_id}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            except Exception as e:
                return {"type": "ERROR", "message": f"VERIFY_2FA exception: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # Auth gate
        # -------------------------
        if user_id is None and mtype != "CLOSE":
            return {"type": "ERROR", "message": "Auth required"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # UPLOAD
        # -------------------------
        if mtype == "UPLOAD":
            request_id = str(msg.get("request_id") or "").strip()
            file_size = int(msg.get("file_size", 0))
            ext = str(msg.get("ext", "bin")).strip()
            expected_sha = str(msg.get("sha256", "")).strip()
            patient_id = str(msg.get("patient_id") or "Unknown").strip()

            if not request_id or file_size <= 0:
                return {"type": "ERROR", "message": "Invalid upload parameters"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            secure_protocol.send(client_sock, {"type": "READY", "request_id": request_id})

            save_dir = "uploads"
            os.makedirs(save_dir, exist_ok=True)
            path = os.path.join(save_dir, f"{request_id}.{ext}")

            try:
                self._receive_encrypted_file(client_sock, path, file_size, cipher)
            except Exception as e:
                return {"type": "ERROR", "message": f"Upload failed: {str(e)}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            actual_sha = self._calc_file_hash(path)
            if expected_sha and actual_sha != expected_sha:
                try:
                    os.remove(path)
                except Exception:
                    pass
                return {"type": "ERROR", "message": "Integrity check failed (SHA mismatch)"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            if not self.db.save_new_scan(request_id, user_id, actual_sha, patient_id):
                return {"type": "ERROR", "message": "DB Error saving scan"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            with self._upload_lock:
                self.upload_index[request_id] = path

            return {
                "type": "UPLOAD_OK",
                "request_id": request_id,
                "sha256": actual_sha
            }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # PREDICT
        # -------------------------
        if mtype == "PREDICT":
            request_id = str(msg.get("request_id") or "").strip()
            if not request_id:
                return {"type": "ERROR", "message": "missing request_id"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            with self._upload_lock:
                path = self.upload_index.get(request_id)

            if not path or not os.path.exists(path):
                return {"type": "ERROR", "message": "File not found. Upload first."}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            if not self.predictor:
                return {"type": "ERROR", "message": "Model not loaded"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            try:
                prediction = self.predictor.predict(path)
                conf = float(prediction.get("prob", 0.0))
                label = str(prediction.get("label", "UNKNOWN"))

                self.db.update_scan(request_id, label, conf)

                is_positive = label.upper() in ("PNEUMONIA", "POSITIVE", "POS", "1")
                if is_positive and self.mailer:
                    try:
                        email = self.db.get_user_email(user_id)
                        if email and self.mailer.is_email_format_valid(email):
                            self.mailer.send_positive_result_alert(
                                to_email=email,
                                patient_id=str(self.db.get_patient_id_by_request_id(request_id) or "Unknown"),
                                confidence=conf,
                            )
                    except Exception:
                        import traceback
                        print("[SERVER] Warning: failed to send positive alert:")
                        traceback.print_exc()

                try:
                    os.remove(path)
                except Exception as e:
                    print(f"[SERVER] Error deleting file {path}: {e}")

                with self._upload_lock:
                    self.upload_index.pop(request_id, None)

                return {
                    "type": "PREDICT_OK",
                    "request_id": request_id,
                    "prediction": prediction
                }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

            except Exception as e:
                self.db.mark_scan_error(request_id)
                return {"type": "ERROR", "message": f"Prediction failed: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        # -------------------------
        # HISTORY
        # -------------------------
        if mtype == "HISTORY":
            try:
                return {
                    "type": "HISTORY_OK",
                    "history": self.db.get_user_history(user_id)
                }, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username
            except Exception as e:
                return {"type": "ERROR", "message": f"History failed: {e}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        if mtype == "CLOSE":
            print("Closing socket")
            return {"type": "BYE"}, True, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

        return {"type": "ERROR", "message": f"Unknown command: {mtype}"}, False, user_id, pending_email_verify_user_id, pending_email_verify_username, pending_2fa_user_id, pending_2fa_username

    def _receive_encrypted_file(self, sock: socket.socket, path: str, total_size: int, cipher: Cipher):
        received_bytes_original = 0
        with open(path, "wb") as f:
            while received_bytes_original < total_size:
                header = self._recv_exact(sock, 4)
                if not header:
                    raise ConnectionError("Connection lost reading header")

                (chunk_len,) = struct.unpack(">I", header)
                if chunk_len <= 0 or chunk_len > 10_000_000:
                    raise RuntimeError(f"Invalid chunk_len={chunk_len}")

                encrypted_chunk = self._recv_exact(sock, chunk_len)
                if not encrypted_chunk:
                    raise ConnectionError("Connection lost reading chunk")

                b64_bytes = cipher.aes_decrypt(encrypted_chunk)
                raw_bytes = base64.b64decode(b64_bytes)
                f.write(raw_bytes)
                received_bytes_original += len(raw_bytes)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    @staticmethod
    def _calc_file_hash(path: str) -> str:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
