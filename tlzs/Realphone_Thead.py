import re
import subprocess
from PyQt5.QtCore import QThread, pyqtSignal


class Realphone_Thead(QThread):
    Part_changed = pyqtSignal(str)
    Part_end = pyqtSignal(dict)
    Part_log = pyqtSignal(int)
    Part_totle = pyqtSignal(int)

    def __init__(self, pid, parent=None):
        super().__init__(parent)
        self.pid = pid

        # 获取进程中的线程句柄

    def send(self, message):
        self.Part_changed.emit(f"{message}")

    def get_command_result(self, command):
        result = subprocess.run(f'platform-tools\\adb shell su -c "{command}"', shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result

    def run(self):
        try:

            self.Part_totle.emit(0)

            self.get_command_result(f"/data/local/tmp/dumpmm  {self.pid} /sdcard/memory_data.bin")
            subprocess.run(f'platform-tools\\adb pull /sdcard/memory_data.bin', shell=True, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            file_dict = {"erro": 0}
            with open('memory_data.bin', "rb") as f:
                memory_data = f.read()
            file_dict['count_4_totle'] = sum(1 for _ in re.finditer(b'[ -~\x80-\xff]{4,}', memory_data))
            file_dict['all_files_path'] = 'memory_data.bin'
            self.Part_end.emit(file_dict)
            del memory_data

        except subprocess.CalledProcessError as e:
            self.Part_end.emit({"erro": e.stderr})
        except Exception as e:
            self.Part_end.emit({"erro": e})
