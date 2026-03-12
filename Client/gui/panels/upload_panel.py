import os

from PySide6.QtWidgets import (
    QFrame,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QInputDialog,
    QProgressBar,
)
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QCursor


class UploadPanel(QFrame):
    runRequested = Signal(str, str)  # filepath, patient_id

    def __init__(self):
        super().__init__()
        self.setObjectName("UploadPanel")

        self._selected_path = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("Upload File")
        title.setObjectName("PanelTitle")

        desc = QLabel("Add a medical scan (Image).")
        desc.setObjectName("HintText")
        desc.setWordWrap(True)

        self.path_lbl = QLabel("No file selected")
        self.path_lbl.setObjectName("PathLabel")
        self.path_lbl.setWordWrap(True)

        self.btn_choose = QPushButton("Choose File")
        self.btn_choose.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_choose.clicked.connect(self.choose_file)

        self.btn_run = QPushButton("Run Analysis")
        self.btn_run.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.btn_run.clicked.connect(self.run_analysis)
        self.btn_run.setEnabled(False)

        self.pbar = QProgressBar()
        self.pbar.setValue(0)
        self.pbar.setVisible(False)

        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addSpacing(6)
        layout.addWidget(self.path_lbl)
        layout.addSpacing(6)
        layout.addWidget(self.btn_choose)
        layout.addWidget(self.btn_run)
        layout.addWidget(self.pbar)
        layout.addStretch()

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file",
            "",
            "Images (*.png *.jpg *.jpeg);;All files (*.*)"
        )
        if path:
            self._selected_path = path
            self.path_lbl.setText(os.path.basename(path))
            self.btn_run.setEnabled(True)
            self.pbar.setVisible(False)
            self.pbar.setValue(0)

    def run_analysis(self):
        if not self._selected_path:
            QMessageBox.warning(self, "Missing file", "Please choose a file first.")
            return

        patient_id, ok = QInputDialog.getText(self, "Patient Identification", "Enter Patient ID Number:")
        if not ok:
            return

        patient_id = patient_id.strip()
        if not patient_id:
            QMessageBox.warning(self, "Invalid Input", "Patient ID cannot be empty.")
            return

        self.runRequested.emit(self._selected_path, patient_id)

    def set_loading(self, loading: bool):
        self.btn_run.setEnabled(not loading)
        self.btn_choose.setEnabled(not loading)
        self.pbar.setVisible(loading)
        if loading:
            self.pbar.setRange(0, 100)
            self.pbar.setValue(0)

    def set_progress(self, sent: int, total: int):
        if total <= 0:
            return
        pct = int((sent / total) * 100)
        pct = max(0, min(100, pct))
        self.pbar.setValue(pct)