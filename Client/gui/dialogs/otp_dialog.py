from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
)
from PySide6.QtCore import Qt


class OTPDialog(QDialog):
    """
    Modal dialog for entering and verifying OTP (one-time password) codes.

    Provides dedicated UI for two authentication flows: email verification
    during signup and 2FA verification during login. Includes code entry
    field, verification button, resend option, and status messaging.

    Purpose:
        Encapsulate OTP verification UI and user interactions in a
        reusable modal dialog component.

    Usage Pattern:
        ```python
        dlg = OTPDialog(
            title="Email Verification",
            subtitle="Check your email for the code",
            on_verify=lambda code: (success, msg),
            on_resend=lambda: (success, msg),
            parent=self
        )
        if dlg.exec() == QDialog.DialogCode.Accepted:
            # User successfully verified OTP
        ```

    Attributes:
        code (QLineEdit): 6-digit code input field.
        btn_verify (QPushButton): Verify button.
        btn_resend (QPushButton): Resend code button.
        status (QLabel): Status message display.
    """

    def __init__(self, title: str, subtitle: str, on_verify, on_resend, parent=None):
        """
        Initialize OTP dialog with callbacks.

        Args:
            title (str): Dialog title (e.g., "Email Verification").
            subtitle (str): Instructions shown to user.
            on_verify (Callable): Function called with OTP code.
                Must return (success_bool, message_str).
            on_resend (Callable): Function called when resend clicked.
                Must return (success_bool, message_str).
            parent: Parent widget for modality.
        """
        super().__init__(parent)

        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(420, 220)

        self.on_verify = on_verify
        self.on_resend = on_resend

        root = QVBoxLayout(self)

        lbl_t = QLabel(title)
        lbl_s = QLabel(subtitle)

        self.code = QLineEdit()
        self.code.setPlaceholderText("Enter 6-digit code")
        self.code.setMaxLength(6)
        self.code.setInputMethodHints(Qt.InputMethodHint.ImhDigitsOnly)

        row = QHBoxLayout()

        self.btn_verify = QPushButton("Verify")
        self.btn_verify.clicked.connect(self._verify_clicked)

        self.btn_resend = QPushButton("Resend code")
        self.btn_resend.clicked.connect(self._resend_clicked)

        row.addWidget(self.btn_verify)
        row.addWidget(self.btn_resend)

        self.status = QLabel("")

        root.addWidget(lbl_t)
        root.addWidget(lbl_s)
        root.addWidget(self.code)
        root.addLayout(row)
        root.addWidget(self.status)

    def _set_busy(self, busy: bool, text: str = ""):
        """
        Update UI state during async verification/resend operations.

        Args:
            busy (bool): True to disable buttons and show loading.
            text (str): Optional status message to display.
        """
        self.btn_verify.setEnabled(not busy)
        self.btn_resend.setEnabled(not busy)

        if text:
            self.status.setText(text)

    def _verify_clicked(self):
        """
        Handle verify button click. Calls on_verify callback.

        Accepts dialog on success, shows error message on failure.
        """
        otp = self.code.text().strip()

        if not otp:
            self.status.setText("Please enter the code.")
            return

        self._set_busy(True, "Verifying...")

        try:
            ok, msg = self.on_verify(otp)

            if ok:
                self.accept()
            else:
                self._set_busy(False, msg or "Invalid code.")

        except Exception as e:
            self._set_busy(False, str(e))

    def _resend_clicked(self):
        """
        Handle resend button click. Calls on_resend callback.

        Clears code field on success, displays status message.
        """
        self._set_busy(True, "Requesting new code...")

        try:
            ok, msg = self.on_resend()

            if ok:
                self.code.clear()

            self._set_busy(False, msg)

        except Exception as e:
            self._set_busy(False, str(e))
