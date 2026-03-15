from PySide6.QtWidgets import QMessageBox


class MessageService:

    def show_info(self, parent, title: str, message: str):
        QMessageBox.information(parent, title, message)

    def show_warning(self, parent, title: str, message: str):
        QMessageBox.warning(parent, title, message)

    def show_error(self, parent, title: str, message: str, details: str = ""):
        box = QMessageBox(parent)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle(title)
        box.setText(message)
        if details:
            box.setDetailedText(details)
        box.exec()
