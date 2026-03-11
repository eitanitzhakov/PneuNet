import sys
from PySide6.QtWidgets import QApplication, QMessageBox

from gui.windows.auth_window import AuthWindow


def main():

    app = QApplication(sys.argv)

    try:
        window = AuthWindow()
        window.show()
    except Exception as e:
        QMessageBox.critical(None, "Startup Error", str(e))
        sys.exit(1)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()