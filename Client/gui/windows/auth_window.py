from ..base.client_window import ClientWindow
from ..dialogs.otp_dialog import OTPDialog
from ..services.password_strength_checker import PasswordStrengthChecker
from ..workers.worker import Worker
from .home_window import HomeWindow
from core.client import Client

from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QDialog
)

from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QPoint
from PySide6.QtGui import QCursor


class AuthWindow(ClientWindow):
    def __init__(self):
        super().__init__()
        self.password_checker = PasswordStrengthChecker()

        self.setWindowTitle("Medical Login System")
        self.resize(900, 550)
        self.setStyleSheet("background-color: #f0f2f5; font-family: 'Segoe UI';")

        try:
            self.client = Client(host="127.0.0.1", port=8080, timeout_sec=600)
        except Exception as e:
            self.message_service.show_error(self, "Init Error", "Could not initialize the client.", str(e))
            self.client = None

        self.container = QFrame(self)
        self.container.setGeometry(50, 50, 800, 450)
        self.container.setStyleSheet("background-color: white; border-radius: 20px; border: 1px solid #ddd;")

        self.home_window = None

        self._pending_signup_username = ""
        self._pending_login_username = ""
        self._auth_flow = None  # None | "signup_verify" | "login_2fa" | "login_email_verify"

        self.setup_signup_form()
        self.setup_login_form()
        self.setup_overlay()

    def setup_signup_form(self):
        self.signup_widget = QFrame(self.container)
        self.signup_widget.setGeometry(0, 0, 400, 450)
        self.signup_widget.setStyleSheet("background-color: transparent; border: none;")

        layout = QVBoxLayout(self.signup_widget)
        layout.setContentsMargins(50, 50, 50, 50)

        title = QLabel("Create Account")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #333;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(20)

        self.reg_name = QLineEdit(placeholderText="Username")
        self.reg_email = QLineEdit(placeholderText="Email")
        self.reg_pass = QLineEdit(placeholderText="Password")
        self.reg_pass.setEchoMode(QLineEdit.EchoMode.Password)

        for le in [self.reg_name, self.reg_email, self.reg_pass]:
            le.setStyleSheet("border: none; border-bottom: 2px solid #ccc; padding: 8px; font-size: 14px;")
            layout.addWidget(le)

        self.pw_status = QLabel("Password strength: waiting...")
        self.pw_status.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(self.pw_status)
        layout.addSpacing(18)

        self.btn_signup = QPushButton("SIGN UP")
        self.btn_signup.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_signup.setStyleSheet("""
                QPushButton { background-color: #007acc; color: white; border-radius: 10px; padding: 12px; font-weight: bold;}
                QPushButton:hover { background-color: #005c99; }
                QPushButton:disabled { background-color: #9ca3af; }
            """)
        self.btn_signup.clicked.connect(self.handle_signup_click)
        layout.addWidget(self.btn_signup)
        self.btn_signup.setEnabled(False)

        self.reg_pass.textChanged.connect(self.on_password_changed)
        layout.addStretch()

        btn_switch = QPushButton("Already have an account? Login")
        btn_switch.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_switch.setStyleSheet("color: #666; border: none; font-weight: bold; background: transparent;")
        btn_switch.clicked.connect(self.animate_to_login)
        layout.addWidget(btn_switch, alignment=Qt.AlignmentFlag.AlignCenter)

    def on_password_changed(self, text: str):
        ok, msg = self.password_checker.check(text)
        if ok:
            self.pw_status.setText(msg)
            self.pw_status.setStyleSheet("color: #16a34a; font-size: 12px; font-weight: 600;")
            self.btn_signup.setEnabled(True)
        else:
            self.pw_status.setText(f"Weak password: {msg}")
            self.pw_status.setStyleSheet("color: #dc2626; font-size: 12px; font-weight: 600;")
            self.btn_signup.setEnabled(False)

    def setup_login_form(self):
        self.login_widget = QFrame(self.container)
        self.login_widget.setGeometry(400, 0, 400, 450)
        self.login_widget.setStyleSheet("background-color: transparent; border: none;")

        layout = QVBoxLayout(self.login_widget)
        layout.setContentsMargins(50, 50, 50, 50)

        title = QLabel("Login")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #333;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(40)

        self.login_user = QLineEdit(placeholderText="Username")
        self.login_pass = QLineEdit(placeholderText="Password")
        self.login_pass.setEchoMode(QLineEdit.EchoMode.Password)

        for le in [self.login_user, self.login_pass]:
            le.setStyleSheet("border: none; border-bottom: 2px solid #ccc; padding: 8px; font-size: 14px;")
            layout.addWidget(le)

        layout.addSpacing(40)

        self.btn_login = QPushButton("LOGIN")
        self.btn_login.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_login.setStyleSheet("""
                QPushButton { background-color: #007acc; color: white; border-radius: 10px; padding: 12px; font-weight: bold;}
                QPushButton:hover { background-color: #005c99; }
            """)
        self.btn_login.clicked.connect(self.handle_login_click)
        layout.addWidget(self.btn_login)
        layout.addStretch()

        btn_switch = QPushButton("New here? Sign Up")
        btn_switch.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_switch.setStyleSheet("color: #666; border: none; font-weight: bold; background: transparent;")
        btn_switch.clicked.connect(self.animate_to_signup)
        layout.addWidget(btn_switch, alignment=Qt.AlignmentFlag.AlignCenter)

    def setup_overlay(self):
        self.overlay = QFrame(self.container)
        self.overlay.setGeometry(0, 0, 400, 450)
        self.update_overlay_style(left=True)

        layout = QVBoxLayout(self.overlay)
        lbl_logo = QLabel("PneuNet")
        lbl_logo.setStyleSheet(
            "font-size: 40px; font-weight: bold; color: white; background: transparent; border: none;"
        )
        lbl_desc = QLabel("Secure Medical Analysis")
        lbl_desc.setStyleSheet("font-size: 16px; color: #eee; background: transparent; border: none;")

        layout.addStretch()
        layout.addWidget(lbl_logo, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_desc, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()

        self.anim = QPropertyAnimation(self.overlay, b"pos")
        self.anim.setDuration(500)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutQuart)

    def update_overlay_style(self, left=True):
        radius = "20px 0px 0px 20px" if left else "0px 20px 20px 0px"
        self.overlay.setStyleSheet(f"""
                QFrame {{
                    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00d2ff, stop:1 #3a7bd5);
                    border-radius: {radius};
                    border: none;
                }}
            """)

    def animate_to_signup(self):
        self.anim.setStartValue(QPoint(0, 0))
        self.anim.setEndValue(QPoint(400, 0))
        self.update_overlay_style(left=False)
        self.anim.start()

    def animate_to_login(self):
        self.anim.setStartValue(QPoint(400, 0))
        self.anim.setEndValue(QPoint(0, 0))
        self.update_overlay_style(left=True)
        self.anim.start()

    def _ensure_connection(self):
        if not self.client:
            raise RuntimeError("Client not initialized.")
        if not self.client.is_connected:
            self.client.connect()

    def _clear_signup_fields(self):
        self.reg_name.clear()
        self.reg_email.clear()
        self.reg_pass.clear()
        self.pw_status.setText("Password strength: waiting...")
        self.pw_status.setStyleSheet("color: #666; font-size: 12px;")
        self.btn_signup.setEnabled(False)

    def _clear_login_sensitive_fields(self):
        self.login_pass.clear()

    def _reset_auth_state(self):
        self._pending_signup_username = ""
        self._pending_login_username = ""
        self._auth_flow = None

    # ---- Login ----
    def handle_login_click(self):
        username = self.login_user.text().strip()
        password = self.login_pass.text().strip()

        if not username or not password:
            self.message_service.show_warning(self, "Error", "Please enter username and password.")
            return

        self._pending_login_username = username
        self._auth_flow = "login_2fa"

        self.btn_login.setEnabled(False)
        self.btn_login.setText("Connecting...")

        self.worker = Worker(self._do_login, username, password)
        self.worker.finished.connect(lambda resp: self.on_login_done(resp, username))
        self.worker.error.connect(self.on_auth_error)
        self.worker.start()

    def _do_login(self, u, p):
        self._ensure_connection()
        return self.client.login(u, p)

    def on_login_done(self, response, username: str):
        self.btn_login.setEnabled(True)
        self.btn_login.setText("LOGIN")

        if not isinstance(response, dict):
            self.message_service.show_warning(self, "Login Failed", "Unexpected response from server.")
            return

        if response.get("type") == "ERROR":
            self._clear_login_sensitive_fields()
            self.message_service.show_warning(
                self,
                "Login Failed",
                response.get("message", "Unknown error")
            )
            return

        # ---- NEW: login can reopen email verification flow ----
        if response.get("type") == "EMAIL_VERIFICATION_REQUIRED":
            self._auth_flow = "login_email_verify"
            self._pending_signup_username = username

            dlg = OTPDialog(
                title="Email Verification",
                subtitle=response.get(
                    "message",
                    "Your email is not verified yet. Enter the code sent to your email to activate your account."
                ),
                on_verify=lambda otp: self._verify_email(username, otp),
                on_resend=lambda: self._resend_email_code(),
                parent=self
            )

            if dlg.exec() == QDialog.DialogCode.Accepted:
                self._clear_login_sensitive_fields()
                self._reset_auth_state()
                self.message_service.show_info(self, "Success", "Email verified! You can now login.")
            return

        if response.get("type") == "LOGIN_2FA_REQUIRED":
            dlg = OTPDialog(
                title="Two-Factor Verification",
                subtitle="A verification code was sent to your email. Enter it to complete login.",
                on_verify=lambda otp: self._verify_2fa(username, otp),
                on_resend=lambda: self._resend_2fa(),
                parent=self
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self._clear_login_sensitive_fields()
                self._reset_auth_state()
                self.home_window = HomeWindow(self.client, username=username)
                self.home_window.show()
                self.hide()
            return

        if response.get("type") == "LOGIN_OK":
            self._clear_login_sensitive_fields()
            self._reset_auth_state()
            self.home_window = HomeWindow(self.client, username=username)
            self.home_window.show()
            self.hide()
            return

        self.message_service.show_warning(self, "Login Failed", "Unexpected response from server.")

    def _verify_2fa(self, username: str, otp: str):
        resp = self.client.verify_2fa(username, otp)
        if resp.get("type") == "LOGIN_OK":
            return True, "OK"
        if resp.get("type") == "ERROR":
            return False, resp.get("message", "Verification failed")
        return False, f"Unexpected response: {resp}"

    def _resend_2fa(self):
        resp = self.client.resend_2fa_code()
        if resp.get("type") == "RESEND_OK":
            return True, resp.get("message", "Code resent.")
        if resp.get("type") == "ERROR":
            return False, resp.get("message", "Resend failed")
        return False, f"Unexpected response: {resp}"

    # ---- Signup ----
    def handle_signup_click(self):
        name = self.reg_name.text().strip()
        email = self.reg_email.text().strip()
        password = self.reg_pass.text().strip()

        if not name or not email or not password:
            self.message_service.show_warning(self, "Error", "Please fill all signup fields.")
            return

        self._pending_signup_username = name
        self._auth_flow = "signup_verify"

        self.btn_signup.setEnabled(False)
        self.btn_signup.setText("Registering...")

        self.worker = Worker(self._do_signup, name, password, email)
        self.worker.finished.connect(lambda resp: self.on_signup_done(resp, name))
        self.worker.error.connect(self.on_auth_error)
        self.worker.start()

    def _do_signup(self, u, p, e):
        self._ensure_connection()
        return self.client.signup(u, p, e)

    def on_signup_done(self, response, username: str):
        self.btn_signup.setEnabled(True)
        self.btn_signup.setText("SIGN UP")

        if not isinstance(response, dict):
            self.message_service.show_warning(self, "Signup Failed", "Unexpected response from server.")
            return

        if response.get("type") == "ERROR":
            self.message_service.show_warning(
                self,
                "Signup Failed",
                response.get("message", "Unknown error")
            )
            return

        if response.get("type") == "SIGNUP_VERIFY_REQUIRED":
            dlg = OTPDialog(
                title="Email Verification",
                subtitle="A verification code was sent to your email. Enter it to activate your account.",
                on_verify=lambda otp: self._verify_email(username, otp),
                on_resend=lambda: self._resend_email_code(),
                parent=self
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self.login_user.setText(username)
                self._clear_signup_fields()
                self._reset_auth_state()
                self.message_service.show_info(self, "Success", "Email verified! You can now login.")
                self.animate_to_login()
            return

        self.message_service.show_warning(self, "Signup Failed", "Unexpected response from server.")

    def _verify_email(self, username: str, otp: str):
        resp = self.client.verify_email(username, otp)
        if resp.get("type") == "EMAIL_VERIFIED_OK":
            return True, "OK"
        if resp.get("type") == "ERROR":
            return False, resp.get("message", "Verification failed")
        return False, f"Unexpected response: {resp}"

    def _resend_email_code(self):
        resp = self.client.resend_email_code()
        if resp.get("type") == "RESEND_OK":
            return True, resp.get("message", "Code resent.")
        if resp.get("type") == "ERROR":
            return False, resp.get("message", "Resend failed")
        return False, f"Unexpected response: {resp}"

    def on_auth_error(self, tb: str):
        self.btn_login.setEnabled(True)
        self.btn_login.setText("LOGIN")
        self.btn_signup.setEnabled(True)
        self.btn_signup.setText("SIGN UP")
        self._clear_login_sensitive_fields()

        self.message_service.show_error(
            self,
            "Authentication/Network Error",
            "Something went wrong while communicating with the server.",
            tb
        )