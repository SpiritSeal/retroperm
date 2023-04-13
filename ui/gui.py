from PySide6.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QLabel, QProgressBar
from PySide6.QtCore import Qt, QThread, Signal
import sys
import time
import retroperm
from retroperm.project import RetropermProject
from retroperm.rules.filesystem_rule import FilesystemRule
from pathlib2 import Path

TEST_BINARIES = Path(__file__).parent.parent/'tests'/'executables'

class BackendThread(QThread):
    result = Signal(str)

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def run(self):
        # time.sleep(3)  # Simulate a long-running task

        # retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        retro_proj = RetropermProject(self.filename)
        resolved_data = retro_proj.resolve_abusable_functions()
        # print("resolved data", resolved_data)
        res_func = resolved_data['open']
        # print(res_func.args_by_location[0x40122a]['filename'])

        my_rule_good = FilesystemRule('/home/mahaloz/.global.bsconf', 'filename', is_whitelist=True, is_dir=False)
        my_rule_bad = FilesystemRule('/etc/passwd', 'filename', is_whitelist=False, is_dir=False)
        retro_proj.init_rules([my_rule_good, my_rule_bad], override_default=True)
        output = retro_proj.validate_rules()
        # print(output)

        result = str(output)

        # result = self.test_file(self.filename)
        self.result.emit(result)

    # def test_file(self, filename):
    #     # TODO: Implement the backend function
    #     # For now, just return a dummy result
    #     return 'File loaded successfully!'


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setGeometry(100, 100, 300, int(200*1.5))
        self.setWindowTitle('File Loader')

        # Create a button that will open a file dialog
        self.file_button = QPushButton('Load File', self)
        self.file_button.move(100, 100)
        self.file_button.clicked.connect(self.load_file)

        # Add a label to show the result of the backend function
        self.result_label = QLabel(self)
        self.result_label.setAlignment(Qt.AlignCenter)
        self.result_label.setGeometry(50, 150, 200, 30*2)
        self.result_label.setWordWrap(True)

        # Add a progress bar to act as the spinner
        self.spinner = QProgressBar(self)
        self.spinner.setGeometry(100, 130, 100, 20)
        self.spinner.setRange(0, 0)  # Set the range to 0-0 to make it a spinner
        self.spinner.hide()

        self.show()

    def load_file(self):
        # Open a file dialog and get the selected file
        filename, _ = QFileDialog.getOpenFileName(self, 'Open File', '.', 'All Files (*);;Python Files (*.py)')
        if filename:
            # Start a new thread to run the backend function
            self.spinner.setValue(0)
            self.spinner.show()
            self.thread = BackendThread(filename)
            self.thread.result.connect(self.show_result)
            self.thread.start()

    def show_result(self, result):
        # Update the GUI with the result of the backend function
        self.result_label.setText(result)
        self.spinner.hide()


app = QApplication(sys.argv)
window = MainWindow()
sys.exit(app.exec())
