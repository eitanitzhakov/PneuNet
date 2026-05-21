from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QWidget
from ..services.message_service import MessageService


class ClientWindow(QWidget):
    """
    Base class for PneuNet GUI windows with integrated client connection.

    Provides common functionality for all application windows including
    client instance management and graceful connection shutdown on
    window close.

    Purpose:
        Centralize client lifecycle management across all GUI components.

    Attributes:
        message_service (MessageService): Service for dialogs.
        client (Optional[Client]): Shared client instance.
    """

    def __init__(self):
        """
        Initialize base window with client and message service.
        """
        super().__init__()
        self.message_service = MessageService()
        self.client = None

    def close_client_connection(self):
        """
        Safely close client connection if established.
        """

        try:
            if self.client is not None:
                if self.client.is_connected:
                    self.client.close()
        except Exception as e:
            print("Client close error:", e)

    def closeEvent(self, event: QCloseEvent):
        """
        Handle window close event by cleanly shutting down client.

        Args:
            event (QCloseEvent): Close event from Qt framework.
        """
        self.close_client_connection()
        event.accept()
