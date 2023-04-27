import re
import sys
import ast
from pathlib import Path
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QTextEdit, QPushButton, QWidget
from retroperm.project import RetropermProject
from retroperm.rules import Rule
from retroperm.rules.filesystem_rule import FilesystemRule
from retroperm.rules.ban_library_function_rule import BanLibraryFunctionRule
from retroperm.rules.ban_category_rule import BanCategoryRule

# TEST_BINARIES = Path("test_binaries")
TEST_BINARIES = Path(__file__).parent.parent / "tests" / "executables"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class VstTester:
    def __init__(self):
        self.retro_proj_clean = RetropermProject(TEST_BINARIES / "GoodArpeggiator.so.o")
        self.retro_proj_mal = RetropermProject(TEST_BINARIES / "BadArpeggiator.so.o")

    def iterprint(self, header: str, payload: dict):
        result = bcolors.HEADER + header + bcolors.ENDC + "\n"
        for key, v in payload.items():
            if v.startswith("Failed"):
                result += f'{bcolors.WARNING}{key}: {v}{bcolors.ENDC}\n'
            else:
                result += f'{bcolors.OKGREEN}{key}: {v}{bcolors.ENDC}\n'
        return result

    def eval_flow(self, proj: RetropermProject, header: str):
        ban_filesystem = BanCategoryRule('filesystem')
        ban_network = BanCategoryRule('network')
        my_rule_good = FilesystemRule("/home/mahaloz/.global.bsconf", 'filename', is_whitelist=True, is_dir=False)
        my_rule_bad = FilesystemRule("/etc/passwd", 'filename', is_whitelist=False, is_dir=False)

        rule_list = [ban_filesystem, ban_network, my_rule_good, my_rule_bad]
        proj.init_rules(rule_list, override_default=True)
        output = proj.validate_rules()

        result = self.iterprint(header, output)
        result += "\n"

        if output[ban_filesystem].startswith("Failed"):
            resolved_data = self.retro_proj_mal.resolve_abusable_functions()
            rfo = resolved_data['resolved_function_data']

            match_list = ast.literal_eval(re.findall(r'\[.*\]', output[my_rule_bad])[0])

            for match in match_list:
                if match not in rfo:
                    continue
                match_rfo = rfo[match]
                vals = list(match_rfo.args_by_location.values())
                result += f'{bcolors.OKCYAN}{str(vals)}{bcolors.ENDC}\n'

        return result

    def run_test(self):
        resolved_data_clean = self.retro_proj_clean.resolve_abusable_functions()
        resolved_data_mal = self.retro_proj_mal.resolve_abusable_functions()

        results = []
        results.append(self.eval_flow(self.retro_proj_clean, '`CleanVST` Rule Validation'))
        results.append(self.eval_flow(self.retro_proj_mal, '`MalVST` Rule Validation'))
        return "\n".join(results)


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.tester = VstTester()

        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)

        self.result_text = QTextEdit(self)
        self.result_text.setReadOnly(True)

        run_button = QPushButton("Run Test", self)
        run_button.clicked.connect(self.run_test)

        layout.addWidget(self.result_text)
        layout.addWidget(run_button)

        self.setCentralWidget(central_widget)

    def run_test(self):
        self.result_text.clear()
        result = self.tester.run_test()
        self.result_text.insertPlainText(result)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWin = MainWindow()
    mainWin.show()
    sys.exit(app.exec_())
