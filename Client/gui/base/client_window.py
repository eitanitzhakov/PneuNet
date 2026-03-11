from PySide6.QtWidgets import QWidget
from ..services.message_service import MessageService


class ClientWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.message_service = MessageService()
        self.client = None

    def close_client_connection(self):
        try:
            if self.client is not None:
                if self.client.is_connected:
                    self.client.close()
        except Exception as e:
            print("Client close error:", e)

    def closeEvent(self, event):
        self.close_client_connection()
        event.accept()