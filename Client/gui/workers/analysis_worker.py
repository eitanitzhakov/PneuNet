import traceback
from PySide6.QtCore import QThread, Signal


class AnalysisWorker(QThread):

    finished = Signal(object)
    error = Signal(str)
    progress = Signal(int, int)

    def __init__(self, client, file_path: str, patient_id: str):

        super().__init__()

        self.client = client
        self.file_path = file_path
        self.patient_id = patient_id

    def run(self):

        try:

            upload_resp = self.client.upload(
                self.file_path,
                self.patient_id,
                on_progress=lambda sent, total: self.progress.emit(sent, total)
            )

            req_id = upload_resp.get("request_id")

            pred_resp = self.client.predict(req_id)

            self.finished.emit(pred_resp)

        except Exception:

            self.error.emit(traceback.format_exc())
