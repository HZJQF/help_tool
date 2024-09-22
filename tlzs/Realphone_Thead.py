# 定义必要的常量
import ctypes
import re
import subprocess
from ctypes import wintypes

from PyQt5.QtCore import QThread, pyqtSignal

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
TH32CS_SNAPTHREAD = 0x00000004


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD)
    ]

    # 定义 MEMORY_BASIC_INFORMATION 结构体


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

    def __str__(self):
        return f"BaseAddress: {self.BaseAddress:#x}, RegionSize: {self.RegionSize:#x}"


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
            matches = re.finditer(b'[\x01-\xff]{4,}', memory_data)
            count_4_totle = 0
            for match in matches:
                count_4_totle += 1
            file_dict['count_4_totle'] = count_4_totle
            file_dict['all_files_path'] = 'memory_data.bin'

            self.Part_end.emit(file_dict)

        except subprocess.CalledProcessError as e:
            self.Part_end.emit({"erro": e.stderr})
        except Exception as e:
            self.Part_end.emit({"erro": e})
