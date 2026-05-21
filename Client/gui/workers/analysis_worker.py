import traceback
from PySide6.QtCore import QThread, Signal


class AnalysisWorker(QThread):
    """
    Background worker thread orchestrating upload and inference workflow.

    Combines two-step process: upload medical image to server and request
    AI model inference. Emits progress signals during upload for visual
    feedback via progress bar.

    Purpose:
        Run potentially blocking upload + predict operations without
        freezing the GUI. Allow real-time progress tracking.

    Workflow:
        1. Upload file with on_progress callback
        2. Extract request_id from upload response
        3. Request inference using request_id
        4. Emit prediction results on success
        5. Emit error signal on any failure

    Signals:
        - finished(dict): Emitted with prediction results on success
        - error(str): Emitted with traceback on failure
        - progress(int, int): Emitted during upload with (bytes_sent, total_bytes)

    Attributes:
        client (Client): Network client instance.
        file_path (str): Path to image file to upload.
        patient_id (str): Patient identifier.
    """

    finished = Signal(object)
    error = Signal(str)
    progress = Signal(int, int)

    def __init__(self, client, file_path: str, patient_id: str):
        """
        Initialize worker with client and file metadata.

        Args:
            client (Client): Authenticated client instance.
            file_path (str): Path to medical image file.
            patient_id (str): Patient identifier for scan record.
        """
        super().__init__()

        self.client = client
        self.file_path = file_path
        self.patient_id = patient_id

    def run(self):
        """
        Execute upload and inference workflow in thread.

        Emits progress signals during file transfer, finished signal
        on completion, or error signal if any step fails.
        """
        try:
            upload_resp = self.client.upload(
                self.file_path,
                self.patient_id,
                on_progress=lambda sent, total: self.progress.emit(sent, total),
            )

            req_id = upload_resp.get("request_id")

            pred_resp = self.client.predict(req_id)

            self.finished.emit(pred_resp)

        except Exception:
            self.error.emit(traceback.format_exc())
