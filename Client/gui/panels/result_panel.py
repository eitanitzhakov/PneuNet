import json
from datetime import datetime

from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QTextEdit


class ResultPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("ResultPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("Analysis Result")
        title.setObjectName("PanelTitle")

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setPlaceholderText("Results will appear here after you run analysis...")

        layout.addWidget(title)
        layout.addWidget(self.result_box, 1)

    def display_prediction(self, pred_data: dict, patient_id: str = "", file_name: str = ""):
        prediction = pred_data.get("prediction", {}) if isinstance(pred_data, dict) else {}

        label = prediction.get("label", "Unknown")

        raw_conf = prediction.get("confidence", None)
        if raw_conf is None:
            raw_conf = prediction.get("prob", 0.0)

        conf = float(raw_conf) * 100.0
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")

        latency_ms = prediction.get("latency_ms", None)
        latency_line = f"<p><b>Latency:</b> {latency_ms} ms</p>" if latency_ms is not None else ""

        html = f"""
            <h3 style="color: #007acc;">Analysis Complete</h3>
            <p><b>Date:</b> {ts}</p>
            <p><b>Patient ID:</b> {patient_id}</p>
            <p><b>File:</b> {file_name}</p>
            {latency_line}
            <hr>
            <h2 style="color: #222;">Diagnosis: {label}</h2>
            <p style="font-size: 14px;">Confidence: <b>{conf:.8f}%</b></p>
        """
        self.result_box.setHtml(html)

    def display_history_item(self, data: dict):
        filtered = dict(data)
        pretty = json.dumps(filtered, indent=2, ensure_ascii=False)
        self.result_box.setPlainText(pretty)