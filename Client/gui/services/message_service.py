from PySide6.QtWidgets import QMessageBox


class MessageService:
    """
    Service for displaying user-facing message dialogs.

    Provides unified interface for info, warning, and error notifications
    across the application.

    Purpose:
        Centralize message dialog logic for consistency and testability.
    """

    def show_info(self, parent, title: str, message: str):
        """
        Display informational message dialog.

        Args:
            parent (QWidget): Parent window.
            title (str): Dialog title.
            message (str): Message text.
        """
        QMessageBox.information(parent, title, message)

    def show_warning(self, parent, title: str, message: str):
        """
        Display warning message dialog.

        Args:
            parent (QWidget): Parent window.
            title (str): Dialog title.
            message (str): Message text.
        """
        QMessageBox.warning(parent, title, message)

    def show_error(self, parent, title: str, message: str, details: str = ""):
        """
        Display error message dialog with optional detailed text.

        Args:
            parent (QWidget): Parent window.
            title (str): Dialog title.
            message (str): Message text.
            details (str): Optional detailed error information.
        """
        box = QMessageBox(parent)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle(title)
        box.setText(message)
        if details:
            box.setDetailedText(details)
        box.exec()
