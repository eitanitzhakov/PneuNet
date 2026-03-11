import os

from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QFrame,
)

from ..base.client_window import ClientWindow
from ..panels.history_panel import HistoryPanel
from ..panels.upload_panel import UploadPanel
from ..panels.result_panel import ResultPanel
from ..workers.worker import Worker
from ..workers.analysis_worker import AnalysisWorker
from core.client import Client


class HomeWindow(ClientWindow):
    def __init__(self, client: Client, username: str = ""):
        super().__init__()
        self.client = client
        self.username = username

        self.history_worker = None
        self.analysis_worker = None

        self.setWindowTitle("PneuNet - Dashboard")
        self.resize(1100, 650)

        self.setStyleSheet("""
            QWidget {
                background-color: #f5f7fa;
                font-family: 'Segoe UI';
            }

            QFrame#TopBar {
                background: white;
                border: 1px solid #e6e8ee;
                border-radius: 14px;
            }

            QFrame#HistoryPanel,
            QFrame#UploadPanel,
            QFrame#ResultPanel {
                background: white;
                border: 1px solid #e6e8ee;
                border-radius: 16px;
            }

            QLabel#PanelTitle {
                font-size: 16px;
                font-weight: 700;
                color: #222;
                background: transparent;
            }

            QLabel#HintText {
                color: #6b7280;
                font-size: 12px;
                background: transparent;
            }

            QLabel#PathLabel {
                color: #111827;
                font-size: 12px;
                background: #f3f4f6;
                padding: 8px;
                border-radius: 10px;
            }

            QListWidget {
                border: 1px solid #eef0f5;
                border-radius: 12px;
                padding: 6px;
                background: #fbfcff;
            }

            QTextEdit {
                border: 1px solid #eef0f5;
                border-radius: 12px;
                padding: 10px;
                background: #fbfcff;
                font-size: 13px;
                color: #111;
            }

            QPushButton {
                background-color: #007acc;
                color: white;
                font-weight: bold;
                border-radius: 10px;
                padding: 10px;
                font-size: 14px;
                border: 1px solid #005c99;
            }

            QPushButton:hover {
                background-color: #005c99;
            }

            QPushButton:pressed {
                background-color: #004080;
            }

            QPushButton:disabled {
                background-color: #9ca3af;
                border: 1px solid #9ca3af;
            }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        top = QFrame()
        top.setObjectName("TopBar")

        top_l = QHBoxLayout(top)
        top_l.setContentsMargins(14, 10, 14, 10)

        brand = QLabel("PneuNet")
        brand.setStyleSheet("font-size: 18px; font-weight: 900; color: #111827; background: transparent;")

        user_lbl = QLabel(f"Signed in as: {username or 'User'}")
        user_lbl.setStyleSheet("color: #6b7280; font-size: 12px; background: transparent;")

        top_l.addWidget(brand)
        top_l.addStretch()
        top_l.addWidget(user_lbl)

        row = QHBoxLayout()
        row.setSpacing(12)

        self.result = ResultPanel()
        self.result.setMinimumWidth(420)

        self.upload = UploadPanel()
        self.upload.setMinimumWidth(320)

        self.history = HistoryPanel()
        self.history.setMinimumWidth(260)

        row.addWidget(self.result, 2)
        row.addWidget(self.upload, 1)
        row.addWidget(self.history, 1)

        root.addWidget(top)
        root.addLayout(row, 1)

        self.upload.runRequested.connect(self.on_run_requested)
        self.history.itemSelected.connect(self.result.display_history_item)

        self.refresh_history()

    def refresh_history(self):
        self.history_worker = Worker(self.client.get_history)
        self.history_worker.finished.connect(self._on_history_loaded)
        self.history_worker.error.connect(self._on_history_error)
        self.history_worker.start()

    def _on_history_loaded(self, resp):
        if isinstance(resp, dict) and resp.get("type") == "ERROR":
            self.history.load_items([])
            self.result.result_box.setPlainText(resp.get("message", "History error"))
            return

        if resp and isinstance(resp, dict) and resp.get("type") == "HISTORY_OK":
            items = resp.get("history", [])
            self.history.load_items(items)

    def _on_history_error(self, tb):
        self.history.load_items([])
        self.result.result_box.setPlainText("History load failed.")
        self.message_service.show_error(
            self,
            "History Error",
            "Could not load analysis history.",
            tb
        )

    def on_run_requested(self, file_path: str, patient_id: str):
        self.upload.set_loading(True)
        self.upload.set_progress(0, 100)
        self.result.result_box.setPlainText("Processing... Uploading and Analyzing...")

        self.analysis_worker = AnalysisWorker(self.client, file_path, patient_id)
        self.analysis_worker.progress.connect(self.upload.set_progress)
        self.analysis_worker.finished.connect(lambda res: self._on_analysis_finished(res, file_path, patient_id))
        self.analysis_worker.error.connect(self._on_analysis_error)
        self.analysis_worker.start()

    def _on_analysis_finished(self, result, file_path: str, patient_id: str):
        self.upload.set_loading(False)
        self.upload.set_progress(100, 100)
        self.result.display_prediction(result, patient_id, os.path.basename(file_path))
        self.refresh_history()

    def _on_analysis_error(self, tb: str):
        self.upload.set_loading(False)
        self.result.result_box.setPlainText("Analysis failed.")
        self.message_service.show_error(
            self,
            "Analysis Failed",
            "The file could not be analyzed. Please try again.",
            tb
        )