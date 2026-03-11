from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QListWidget, QListWidgetItem
from PySide6.QtCore import Signal, Qt


class HistoryPanel(QFrame):
    itemSelected = Signal(dict)

    def __init__(self):
        super().__init__()
        self.setObjectName("HistoryPanel")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("History")
        title.setObjectName("PanelTitle")

        self.listw = QListWidget()
        self.listw.itemClicked.connect(self._on_item_clicked)

        hint = QLabel("Select a previous run to view its result.")
        hint.setObjectName("HintText")
        hint.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(self.listw, 1)
        layout.addWidget(hint)

    def load_items(self, history_list: list):
        self.listw.clear()

        for item_data in history_list:
            patient_id = item_data.get("patient_id") or "Unknown"
            ts = item_data.get("uploaded_at") or item_data.get("timestamp", "") or ""
            display_text = f"{ts} | {patient_id}"

            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, item_data)
            self.listw.addItem(item)

    def _on_item_clicked(self, item: QListWidgetItem):
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            self.itemSelected.emit(data)