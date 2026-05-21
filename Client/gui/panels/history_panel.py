from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel, QListWidget, QListWidgetItem
from PySide6.QtCore import Signal, Qt


class HistoryPanel(QFrame):
    """
    Scrollable list panel displaying user's past medical image analyses.

    Shows timestamped scan records with patient IDs. Supports item
    selection to view detailed results in ResultPanel. Emits signal
    when item clicked.

    Purpose:
        Provide quick access to historical scan records with visual
        selection interface.

    Signals:
        - itemSelected(dict): Emitted when user clicks a history item,
          carrying the full scan record.

    Attributes:
        listw (QListWidget): List of historical scans.
        itemSelected (Signal): Emitted on item selection.
    """

    itemSelected = Signal(dict)

    def __init__(self):
        """
        Initialize history panel with empty list.
        """

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
        """
        Populate list with scan history records.

        Args:
            history_list (list): List of scan dictionaries from server.
                Each dict should contain: patient_id, uploaded_at.
        """
        self.listw.clear()

        for item_data in history_list:
            patient_id = item_data.get("patient_id") or "Unknown"
            ts = item_data.get("uploaded_at") or item_data.get("timestamp", "") or ""
            display_text = f"{ts} | {patient_id}"

            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, item_data)
            self.listw.addItem(item)

    def _on_item_clicked(self, item: QListWidgetItem):
        """
        Handle list item selection and emit itemSelected signal.

        Args:
            item (QListWidgetItem): Clicked list item.
        """
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            self.itemSelected.emit(data)
