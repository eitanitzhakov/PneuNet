from PySide6.QtWidgets import QDialog, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout
from PySide6.QtCore import Qt


class OTPDialog(QDialog):

    def __init__(self, title: str, subtitle: str, on_verify, on_resend, parent=None):
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

        self.btn_verify.setEnabled(not busy)
        self.btn_resend.setEnabled(not busy)

        if text:
            self.status.setText(text)

    def _verify_clicked(self):

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

        self._set_busy(True, "Requesting new code...")

        try:
            ok, msg = self.on_resend()

            if ok:
                self.code.clear()

            self._set_busy(False, msg)

        except Exception as e:
            self._set_busy(False, str(e))