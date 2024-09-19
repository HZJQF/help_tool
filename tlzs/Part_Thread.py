# 定义必要的常量
import ctypes
import io
import re
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


class Part_Thread(QThread):
    Part_changed = pyqtSignal(str)
    Part_end = pyqtSignal(dict)
    Part_log = pyqtSignal(int)
    Part_totle = pyqtSignal(int)

    def __init__(self, pid, parent=None):
        super().__init__(parent)
        self.pid = pid
        self.memory_data = None

        # 获取进程中的线程句柄

    def get_thread_handles(self, pid):
        try:
            snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if snapshot == -1:
                self.send("无法创建线程快照。")
                return []

            thread_entry = THREADENTRY32()
            thread_entry.dwSize = ctypes.sizeof(THREADENTRY32)

            threads = []
            if ctypes.windll.kernel32.Thread32First(snapshot, ctypes.byref(thread_entry)):
                while True:
                    if thread_entry.th32OwnerProcessID == pid:
                        threads.append(thread_entry.th32ThreadID)
                    if not ctypes.windll.kernel32.Thread32Next(snapshot, ctypes.byref(thread_entry)):
                        break

            ctypes.windll.kernel32.CloseHandle(snapshot)
            return threads
        except Exception as e:
            self.send(f"获取线程句柄时出错: {e}")
            return []

        # 打开进程

    def open_process(self, pid):
        try:
            process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if not process_handle:
                self.Part_end.emit({})
                self.send(f"无法打开进程 (PID: {pid})。")

            return process_handle
        except Exception as e:
            self.send(f"打开进程时出错: {e}")

            return None

        # 暂停进程

    def suspend_process(self, pid):
        try:
            thread_handles = self.get_thread_handles(pid)
            for thread_id in thread_handles:
                thread_handle = ctypes.windll.kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, thread_id)
                if thread_handle:
                    ctypes.windll.kernel32.SuspendThread(thread_handle)
                    ctypes.windll.kernel32.CloseHandle(thread_handle)
            self.send(f"进程 (PID: {pid}) 已暂停。")
        except Exception as e:
            self.send(f"暂停进程时出错: {e}")

        # 恢复进程

    def resume_process(self, pid):
        try:
            thread_handles = self.get_thread_handles(pid)
            for thread_id in thread_handles:
                thread_handle = ctypes.windll.kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, thread_id)
                if thread_handle:
                    ctypes.windll.kernel32.ResumeThread(thread_handle)
                    ctypes.windll.kernel32.CloseHandle(thread_handle)
            self.send(f"进程 (PID: {pid}) 已恢复。")
        except Exception as e:
            self.send(f"恢复进程时出错: {e}")

        # 读取内存

    def read_process_memory(self, process_handle, address, size):
        try:
            buffer = ctypes.create_string_buffer(size)
            bytesRead = ctypes.c_size_t(0)
            if ctypes.windll.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(address), buffer, size,
                                                        ctypes.byref(bytesRead)):
                return buffer.raw[:bytesRead.value]
            else:
                self.send(f"读取模型失败 (地址: {address:#x})。")

                return None
        except Exception as e:
            self.send(f"读取模型时出错: {e}")
            return None

        # 获取内存信息

    def get_memory_info(self, process_handle):
        address = 0
        while True:
            mbi = MEMORY_BASIC_INFORMATION()
            result = ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi),
                                                           ctypes.sizeof(mbi))
            if not result:
                break
            yield mbi
            address += mbi.RegionSize

        # 转储进程内存

    def dump_process_memory(self, pid, ):
        process_handle = self.open_process(pid)
        if not process_handle:
            self.send(f"无法打开进程 (PID: {pid})，模型加载失败。")
            return

        try:
            # 用于存储内存数据的变量

            self.memory_data = bytearray()

            # 遍历获取内存信息
            with open('memory_data.bin', "wb") as f:
                for mbi in self.get_memory_info(process_handle):
                    if mbi.State == 0x1000 and mbi.Protect == 0x04:
                        memory = self.read_process_memory(process_handle, mbi.BaseAddress, mbi.RegionSize)
                        if memory:
                            f.write(memory)
                            self.memory_data.extend(memory)  # 将内存数据追加到 memory_data 中

            file_dict = {}
            # strings = self.process_memory_data(self.memory_data, 1024, b'[\x01-\xff]{4,}', 4)
            self.Part_totle.emit(0)
            matches = re.finditer(b'[\x01-\xff]{4,}', self.memory_data)
            count_4_totle = 0
            for match in matches:
                count_4_totle += 1

            file_dict['count_4_totle'] = count_4_totle
            file_dict['all_files_path'] = 'memory_data.bin'
            self.Part_end.emit(file_dict)

        except Exception as e:
            self.send(f"失败！内存转储失败: {e}")

        finally:
            ctypes.windll.kernel32.CloseHandle(process_handle)

    def process_memory_data(self, memory_data, chunk_size, pattern, tail_length):
        pattern = re.compile(pattern)
        strings = set()

        # 保留的尾部数据长度为 256 字节
        tail_length = tail_length

        previous_chunk_end = b''

        file_stream = io.BytesIO(memory_data)

        total_size = len(memory_data)
        total_chunks = (total_size + chunk_size - 1) // chunk_size  # 计算总块数
        self.Part_totle.emit(total_chunks)  # 发射总进度信号
        processed_chunks = 0

        while True:
            chunk = file_stream.read(chunk_size)
            if not chunk:
                break

            # 将前一块的尾部与当前块合并
            combined_chunk = previous_chunk_end + chunk

            # 查找匹配项
            matches = pattern.findall(combined_chunk)
            strings.update(matches)

            # 更新前一块的尾部数据
            previous_chunk_end = chunk[-tail_length:] if len(chunk) > tail_length else chunk

            processed_chunks += 1

            # 发射当前进度
            if processed_chunks % max(1, total_chunks // 100) == 0 or processed_chunks == total_chunks:
                self.Part_log.emit(processed_chunks)  # 更新进度条

        return list(strings)

    def send(self, message):
        self.Part_changed.emit(f"{message}")

    def run(self):
        try:
            # 暂停进程
            self.send("正在暂停进程...")
            self.suspend_process(self.pid)

            # 转储进程内存
            self.dump_process_memory(self.pid)

            # 恢复进程
            self.send("正在恢复进程...")
            self.resume_process(self.pid)

        except ValueError:
            self.send("输入的 PID 无效。")
        except Exception as e:
            self.send(f"程序运行时出错: {e}")
            # 恢复进程
            self.send("正在恢复进程...")
            self.resume_process(self.pid)

            self.Part_end.emit({})
            return
