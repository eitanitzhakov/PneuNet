from datetime import datetime

from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QTextEdit


class ResultPanel(QFrame):
    """
    Display panel for analysis predictions and historical scan details.

    Shows formatted results including diagnosis label, confidence score,
    latency metrics, patient ID, and timestamp. Renders content as
    styled HTML for professional appearance.

    Purpose:
        Present pneumonia prediction results and historical scan
        information in a readable, well-formatted display.

    Display modes:
        1. Initial state: Placeholder text
        2. Live prediction: Results from current analysis
        3. Historical: Details from past scan records

    Attributes:
        result_box (QTextEdit): Read-only rich text display.
    """

    def __init__(self):
        """
        Initialize result panel with read-only text display.
        """

        super().__init__()
        self.setObjectName("ResultPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("Analysis Result")
        title.setObjectName("PanelTitle")

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setPlaceholderText(
            "Results will appear here after you run analysis..."
        )

        layout.addWidget(title)
        layout.addWidget(self.result_box, 1)

    def display_prediction(
        self, pred_data: dict, patient_id: str = "", file_name: str = ""
    ):
        """
        Display results from a newly completed analysis.

        Args:
            pred_data (dict): Response from server's predict() call.
                Expected keys: prediction (dict with label, prob/confidence,
                latency_ms).
            patient_id (str): Patient identifier for context.
            file_name (str): Uploaded file name for reference.
        """
        prediction = (
            pred_data.get("prediction", {}) if isinstance(pred_data, dict) else {}
        )

        label = prediction.get("label", "Unknown")

        raw_conf = prediction.get("confidence", None)
        if raw_conf is None:
            raw_conf = prediction.get("prob", 0.0)

        conf = float(raw_conf) * 100.0
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")

        latency_ms = prediction.get("latency_ms", None)
        latency_line = (
            f"<p><b>Latency:</b> {latency_ms} ms</p>" if latency_ms is not None else ""
        )

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
        """
        Display details of a historical scan selected from history panel.

        Args:
            data (dict): Historical scan record from database.
                Expected keys: prediction_label, prediction_confidence,
                patient_id, uploaded_at.
        """
        label = data.get("prediction_label", "Unknown")
        confidence = data.get("prediction_confidence", "")
        patient_id = data.get("patient_id", "")
        uploaded_at = data.get("uploaded_at", "")

        if confidence != "":
            confidence = float(confidence) * 100.0
            confidence_line = (
                f"<p style='font-size: 14px;'>Confidence: <b>{confidence:.8f}%</b></p>"
            )
        else:
            confidence_line = ""

        html = f"""
            <h3 style="color: #007acc;">Analysis Complete</h3>
            <p><b>Date:</b> {uploaded_at}</p>
            <p><b>Patient ID:</b> {patient_id}</p>
            <hr>
            <h2 style="color: #222;">Diagnosis: {label}</h2>
            {confidence_line}
        """

        self.result_box.setHtml(html)
