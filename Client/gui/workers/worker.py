import traceback
from PySide6.QtCore import QThread, Signal


class Worker(QThread):
    """
    Qt worker thread for running blocking operations without freezing GUI.

    Executes an arbitrary function on a separate thread and emits
    signals when finished or on error. Used for network requests,
    file operations, and other I/O-bound tasks.

    Purpose:
        Enable responsive GUI by offloading long-running operations
        to background threads.

    Signals:
        - finished(object): Emitted with function result on success
        - error(str): Emitted with traceback on exception

    Usage:
        ```python
        worker = Worker(client.upload, file_path, patient_id)
        worker.finished.connect(on_upload_done)
        worker.error.connect(on_upload_error)
        worker.start()
        ```
    """

    finished = Signal(object)
    error = Signal(str)

    def __init__(self, func, *args, **kwargs):
        """
        Initialize worker with function and arguments.

        Args:
            func (Callable): Function to execute.
            *args: Positional arguments for function.
            **kwargs: Keyword arguments for function.
        """
        super().__init__()

        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """
        Execute the function and emit result or error signal.

        Called automatically when thread starts. Catches all
        exceptions and emits error signal with traceback.
        """
        try:
            result = self.func(*self.args, **self.kwargs)

            self.finished.emit(result)

        except Exception:
            self.error.emit(traceback.format_exc())
