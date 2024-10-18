import ctypes
import re
import subprocess
from ctypes import wintypes
import keyboard
import psutil
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QComboBox, QStackedWidget, \
    QGridLayout, QButtonGroup, QGroupBox, QRadioButton, QTextEdit, QProgressBar, QAction, QMessageBox, \
    QFileDialog
import CustomTextEdit
import Realphone_Thead
import WorkerThread
import Part_Thread
from ShortcutDialog import ShortcutDialog

PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
TH32CS_SNAPTHREAD = 0x00000004

from PyQt5.QtWidgets import QDialog, QLineEdit, QPushButton, QVBoxLayout


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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # 设置窗口标题和大小
        self.Realphone_worker = None
        self.tt = None
        self.HOTKEY_ID = 885
        self.shortcut_key = 'Ctrl+Shift+G'
        self.setWindowTitle("推理助手")
        self.setGeometry(500, 200, 1000, 750)
        self.pid = None
        self.file_path = None
        self.hash_name = None
        self.worker = None
        self.Part_worker = None
        # 创建主窗口的布局和中心小部件
        self.central_widget = QWidget()
        # 创建纵向布局
        self.vbox_layout = QVBoxLayout()
        self.hbox_layout_top = QHBoxLayout()
        # 创建横向布局
        self.hbox_layout = QHBoxLayout()
        self.hbox_layout_find = QHBoxLayout()

        self.textbox = QLineEdit(self)
        # 设置输入验证器为浮点数验证器（可以改为 QIntValidator 以限制为整数）
        int_validator = QIntValidator()
        self.textbox.setValidator(int_validator)
        self.textbox.setPlaceholderText("请输入进程ID")  # 设置占位符文本

        # 创建下拉框
        self.comboBox = QComboBox(self)

        # 当下拉框选项改变时，更新标签
        self.comboBox.currentIndexChanged.connect(self.on_combobox_changed)

        # 创建一个 QStackedWidget 用于切换控件
        self.stacked_widget = QStackedWidget(self)
        self.stacked_widget.addWidget(self.comboBox)
        self.stacked_widget.addWidget(self.textbox)

        # 创建按钮来触发文件选择对话框
        self.button = QPushButton("选择模型文件", self)
        self.button2 = QPushButton(f"加载模型({self.shortcut_key})", self)

        self.button.clicked.connect(self.open_file_dialog)
        self.button2.clicked.connect(self.loadfile)

        self.hbox_layout.addWidget(self.stacked_widget)
        self.hbox_layout.addWidget(self.button2)
        self.hbox_layout.addWidget(self.button)

        self.QRadioButton_layout = QGridLayout()
        self.QRadioButton_layout2 = QGridLayout()
        self.QRadioButton_layout3 = QGridLayout()
        self.QRadioButton_layout4 = QGridLayout()

        # 创建按钮组
        self.button_group = QButtonGroup(self)
        self.button_group2 = QButtonGroup(self)
        self.button_group3 = QButtonGroup(self)
        self.button_group4 = QButtonGroup(self)
        self.groupBox = QGroupBox(self)
        self.groupBox.setTitle("哈希算法系列")
        self.groupBox2 = QGroupBox(self)
        self.groupBox2.setTitle("其他常用系列")

        self.groupBox3 = QGroupBox(self)
        self.groupBox3.setTitle("猜测可能的明文格式")
        self.radio_button1 = QRadioButton("MD5", self)
        self.radio_button2 = QRadioButton("SHA1", self)
        self.radio_button3 = QRadioButton("SHA256", self)
        self.radio_button4 = QRadioButton("HMACMD5", self)
        self.radio_button5 = QRadioButton("HMACSHA1", self)
        self.radio_button6 = QRadioButton("HMACSHA256", self)
        self.radio_button7 = QRadioButton("AES", self)
        self.radio_button8 = QRadioButton("DES", self)
        self.radio_button9 = QRadioButton("3DES", self)

        self.radio_button10 = QRadioButton("无限制格式", self)
        self.radio_button11 = QRadioButton("json格式", self)

        self.radio_button12 = QRadioButton("自定义进程id", self)
        self.radio_button13 = QRadioButton("自定义进程", self)

        self.radio_button14 = QRadioButton("SM3", self)
        self.radio_button15 = QRadioButton("LD安卓模拟器", self)
        self.radio_button16 = QRadioButton("真机", self)

        self.radio_button17 = QRadioButton("rsa证书导出", self)
        self.radio_button18 = QRadioButton("明文搜索", self)
        self.radio_button19 = QRadioButton("SM4", self)
        self.radio_button20 = QRadioButton("全部算法(不含HMAC)", self)
        self.radio_button21 = QRadioButton("普通模式", self)
        self.radio_button22 = QRadioButton("深入模式", self)
        self.radio_button23 = QRadioButton("选择本地模型", self)
        self.radio_button24 = QRadioButton("WX小程序", self)
        self.radio_button25 = QRadioButton("明文格式", self)

        self.radio_button12.toggled.connect(self.on_radio_button_toggled)
        self.radio_button13.toggled.connect(self.on_radio_button_toggled)
        self.radio_button15.toggled.connect(self.on_radio_button_toggled)
        self.radio_button16.toggled.connect(self.on_radio_button_toggled)
        self.radio_button23.toggled.connect(self.on_radio_button_toggled)
        self.radio_button24.toggled.connect(self.on_radio_button_toggled)

        self.QRadioButton_layout.addWidget(self.radio_button1, 0, 0)
        self.QRadioButton_layout.addWidget(self.radio_button2, 0, 1)
        self.QRadioButton_layout.addWidget(self.radio_button3, 0, 2)
        self.QRadioButton_layout.addWidget(self.radio_button4, 0, 3)
        self.QRadioButton_layout.addWidget(self.radio_button5)
        self.QRadioButton_layout.addWidget(self.radio_button6)
        self.QRadioButton_layout.addWidget(self.radio_button14)
        self.QRadioButton_layout2.addWidget(self.radio_button7, 0, 0)
        self.QRadioButton_layout2.addWidget(self.radio_button8, 0, 1)
        self.QRadioButton_layout2.addWidget(self.radio_button9, 0, 2)
        self.QRadioButton_layout2.addWidget(self.radio_button17, 0, 3)
        self.QRadioButton_layout2.addWidget(self.radio_button18)
        self.QRadioButton_layout2.addWidget(self.radio_button19)
        self.QRadioButton_layout2.addWidget(self.radio_button20)

        self.QRadioButton_layout3.addWidget(self.radio_button25, 0, 0)
        self.QRadioButton_layout3.addWidget(self.radio_button11, 0, 1)
        self.QRadioButton_layout3.addWidget(self.radio_button10, 0, 2)

        self.QRadioButton_layout4.addWidget(self.radio_button13, 0, 0)
        self.QRadioButton_layout4.addWidget(self.radio_button12, 0, 1)

        self.QRadioButton_layout4.addWidget(self.radio_button15, 0, 2)
        self.QRadioButton_layout4.addWidget(self.radio_button16)
        self.QRadioButton_layout4.addWidget(self.radio_button24)
        self.QRadioButton_layout4.addWidget(self.radio_button23)

        self.button_group.addButton(self.radio_button1)
        self.button_group.addButton(self.radio_button2)
        self.button_group.addButton(self.radio_button3)
        self.button_group.addButton(self.radio_button4)
        self.button_group.addButton(self.radio_button5)
        self.button_group.addButton(self.radio_button6)
        self.button_group.addButton(self.radio_button7)
        self.button_group.addButton(self.radio_button8)
        self.button_group.addButton(self.radio_button9)
        self.button_group.addButton(self.radio_button17)
        self.button_group.addButton(self.radio_button18)
        self.button_group.addButton(self.radio_button19)
        self.button_group.addButton(self.radio_button20)
        self.button_group.addButton(self.radio_button14)

        self.radio_button4.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button5.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button6.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button17.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button18.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button19.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button20.toggled.connect(self.on_radio_button_toggled_suanfa)

        self.radio_button1.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button2.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button3.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button7.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button8.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button9.toggled.connect(self.on_radio_button_toggled_suanfa)
        self.radio_button14.toggled.connect(self.on_radio_button_toggled_suanfa)

        self.button_group2.addButton(self.radio_button10)
        self.button_group2.addButton(self.radio_button11)
        self.button_group2.addButton(self.radio_button25)
        self.button_group3.addButton(self.radio_button12)
        self.button_group3.addButton(self.radio_button13)
        self.button_group3.addButton(self.radio_button15)
        self.button_group3.addButton(self.radio_button16)
        self.button_group3.addButton(self.radio_button23)
        self.button_group3.addButton(self.radio_button24)

        self.text_knowedit = QTextEdit(self)
        self.text_knowedit.setPlaceholderText("在这里输入你知道的部分明文...")  # 设置占位符文本

        self.text_unknowedit = QTextEdit(self)
        self.text_unknowedit.setPlaceholderText("在这里输入你知道的密文...")  # 设置占位符文本

        self.text_messageedit = CustomTextEdit.CustomTextEdit(self)
        self.text_messageedit.setStyleSheet("background-color: black; color: white;")
        self.text_messageedit.setReadOnly(True)  # 设置为只读

        self.button_group4.addButton(self.radio_button21)
        self.button_group4.addButton(self.radio_button22)
        # 创建开始按钮
        self.task_button = QPushButton("开始推理", self)

        self.hbox_layout_find.addWidget(self.radio_button21)
        self.radio_button21.setChecked(True)
        self.hbox_layout_find.addWidget(self.radio_button22)
        self.hbox_layout_find.addWidget(self.task_button)
        self.hbox_layout_find.setStretch(0, 1)
        self.hbox_layout_find.setStretch(1, 1)
        self.hbox_layout_find.setStretch(2, 3)
        self.task_button.clicked.connect(self.start_worker)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.hide()

        self.setCentralWidget(self.central_widget)
        self.central_widget.setLayout(self.hbox_layout_top)
        self.hbox_layout_top.addLayout(self.vbox_layout)
        self.hbox_layout_top.addWidget(self.text_messageedit)
        self.vbox_layout.addLayout(self.QRadioButton_layout4)
        self.vbox_layout.addLayout(self.hbox_layout)
        self.vbox_layout.addWidget(self.groupBox)
        self.vbox_layout.addWidget(self.groupBox2)

        self.groupBox.setLayout(self.QRadioButton_layout)
        self.groupBox2.setLayout(self.QRadioButton_layout2)

        self.vbox_layout.addWidget(self.text_knowedit)
        self.vbox_layout.addWidget(self.groupBox3)
        self.groupBox3.setLayout(self.QRadioButton_layout3)
        self.vbox_layout.addWidget(self.text_unknowedit)

        self.vbox_layout.addLayout(self.hbox_layout_find)
        self.vbox_layout.addWidget(self.progress_bar)
        self.radio_button25.setChecked(True)
        self.radio_button13.setChecked(True)

        self.register_hotkeys()

        # 创建菜单栏
        self.create_menu()

        # 创建状态栏
        self.statusBar().showMessage("准备就绪")

    def register_hotkeys(self):

        keyboard.unhook_all()
        keyboard.add_hotkey(self.shortcut_key, self.on_hotkey)

    def on_hotkey(self):

        self.button2.click()

    def closeEvent(self, event):
        keyboard.unhook_all()

    def start_worker(self):
        if self.button_group4.checkedButton().text() == "普通模式":
            is_deep = 0
        else:
            is_deep = 1

        if self.task_button.text() == "停止推理":
            if self.worker:
                self.worker.stop()
                self.worker.terminate()
            self.progress_bar.hide()
            self.task_button.setText('开始推理')
            return

        if not self.file_path or not isinstance(self.file_path, dict):
            self.statusBar().showMessage("模型为空请加载模型", 5000)
            return

        if not self.button_group.checkedButton():
            self.statusBar().showMessage("算法名为空", 5000)
            return

        if not self.button_group.checkedButton().text() == 'rsa证书导出' and not self.button_group.checkedButton().text() == '明文搜索' and not self.text_unknowedit.toPlainText():
            self.statusBar().showMessage("密文内容为空", 5000)
            return

        if self.button_group.checkedButton().text() == '明文搜索' and not self.text_knowedit.toPlainText():
            self.statusBar().showMessage("明文内容为空", 5000)
            return

        selected_button = self.button_group.checkedButton()

        if selected_button:
            self.hash_name = selected_button.text()
        else:
            self.statusBar().showMessage("没有选中的按钮", 5000)
            return

        if self.task_button.text() == "开始推理":
            self.task_button.setText('停止推理')

        if self.hash_name == "全部算法(不含HMAC)":
            is_deep = 0
            self.task_button.setEnabled(False)
            self.worker = WorkerThread.WorkerAllThread(self.file_path, self.hash_name, self.text_knowedit.toPlainText(),
                                                       self.text_unknowedit.toPlainText(),
                                                       self.button_group2.checkedButton().text(), 1, is_deep)
            self.worker.message_changed.connect(self.append_message)
            self.worker.message_end.connect(self.worker_end)
            self.worker.message_log.connect(self.worker_log)
            self.worker.message_totle.connect(self.worker_totle)
            self.progress_bar.show()
            self.worker.start()


        else:
            self.task_button.setEnabled(False)
            self.worker = WorkerThread.WorkerAllThread(self.file_path, self.hash_name, self.text_knowedit.toPlainText(),
                                                       self.text_unknowedit.toPlainText(),
                                                       self.button_group2.checkedButton().text(), 0, is_deep)

            self.worker.message_changed.connect(self.append_message)
            self.worker.message_end.connect(self.worker_end)
            self.worker.message_log.connect(self.worker_log)
            self.worker.message_totle.connect(self.worker_totle)
            self.progress_bar.show()
            self.worker.start()

    def worker_end(self, is_first):
        if is_first == 1:
            self.task_button.setEnabled(True)
            return

        if is_first == 2:
            self.task_button.setEnabled(False)
            return

        self.task_button.setEnabled(True)
        self.progress_bar.hide()
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setValue(0)
        self.task_button.setText('开始推理')

    def worker_totle(self, value):
        self.progress_bar.setMaximum(value)
        self.progress_bar.setValue(0)

    def worker_log(self, value):
        self.progress_bar.setValue(int(value[0]))
        if value[1]:
            self.progress_bar.setFormat(value[1])

    def append_message(self, message):
        self.text_messageedit.append(message)

    def create_menu(self):
        # 创建菜单栏
        menu_bar = self.menuBar()

        # 创建 "文件" 菜单
        file_menu = menu_bar.addMenu("文件")

        # 添加 "退出" 动作
        exit_action = QAction("退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setStatusTip("退出应用程序")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # 添加快捷键设置功能
        set_shortcut_action = QAction("加载模型的全局快捷键", self)
        set_shortcut_action.triggered.connect(self.show_shortcut_dialog)
        file_menu.addAction(set_shortcut_action)

        # 创建 "帮助" 菜单
        help_menu = menu_bar.addMenu("帮助")

        # 添加 "关于" 动作
        about_action = QAction("关于", self)
        about_action.setStatusTip("关于这个程序")
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

    def show_shortcut_dialog(self):
        dialog = ShortcutDialog(self)
        dialog.shortcut_edit.setText(f'当前快捷键: {self.shortcut_key}')
        if dialog.exec_() == QDialog.Accepted:
            # 如果对话框被接受，则设置新快捷键
            if dialog.shortcut_info:
                self.shortcut_key = dialog.shortcut_info
                self.register_hotkeys()
                self.button2.setText(f"加载模型({self.shortcut_key})")

    def show_about_dialog(self):
        # 显示关于对话框
        self.statusBar().showMessage("这是推理助手程序", 5000)

    def on_combobox_changed(self, index):
        # 获取当前选中的进程 PID

        self.pid = self.comboBox.itemData(index)

    def update_process_list(self):
        # 获取所有进程的 PID 和名称
        processes = []

        for pid in psutil.pids():
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                processes.append((process_name, pid))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # 按名称首字母排序进程列表
        processes = sorted(processes, key=lambda x: x[0].lower())

        # 清空下拉框中的所有现有条目
        self.comboBox.clear()

        # 将排序后的进程名称和 PID 添加到下拉框
        for process_name, pid in processes:
            self.comboBox.addItem(f"{process_name} (PID: {pid})", pid)

    def update_phone_list(self):
        # 获取所有进程的 PID 和名称
        processes = []
        pattern = r'\s+(\d+)\s+(\d+)\s+'
        try:
            # 清空下拉框中的所有现有条目
            self.comboBox.clear()
            for pid in self.get_command_result('ps -A |grep u0_').splitlines():
                a = re.findall(pattern, pid)[0]
                processes.append((pid.split(' ')[-1], a[0], a[1]))
            processes = sorted(processes, key=lambda x: x[0].lower())
            for process_name in processes:
                self.comboBox.addItem(f"{process_name[0]}(PID:{process_name[1]} PPID:{process_name[2]})",
                                      process_name[1])

        except subprocess.CalledProcessError as e:
            self.open_Message(e.stderr)
        # except Exception as e:
        #     self.open_Message(e)

    def on_radio_button_toggled(self):

        if not self.sender().isChecked():
            return

        if self.button_group3.checkedButton().text() == "自定义进程":
            self.button.hide()
            self.stacked_widget.show()
            self.update_process_list()
            self.stacked_widget.setCurrentIndex(0)

        elif self.button_group3.checkedButton().text() == "选择本地模型":
            self.textbox.setPlaceholderText('请选择模型文件')
            self.button.show()
            self.stacked_widget.show()
            self.pid = None
            self.stacked_widget.setCurrentIndex(1)

        elif self.button_group3.checkedButton().text() == "自定义进程id":
            self.textbox.setPlaceholderText('请输入进程ID')
            self.button.hide()
            self.stacked_widget.show()
            self.pid = None
            self.stacked_widget.setCurrentIndex(1)

        elif self.button_group3.checkedButton().text() == "LD安卓模拟器":
            self.button.hide()
            self.stacked_widget.hide()
            pl = psutil.pids()
            self.pid = None
            for pid in pl:
                try:
                    if 'BoxHeadless' in psutil.Process(pid).name():
                        self.pid = pid
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        elif self.button_group3.checkedButton().text() == "真机":
            self.button.hide()
            self.update_phone_list()
            self.stacked_widget.show()
            self.pid = None
            self.stacked_widget.setCurrentIndex(0)

        elif self.button_group3.checkedButton().text() == "WX小程序":
            self.button.hide()
            self.stacked_widget.hide()
            self.pid = None


        else:
            self.pid = None

        self.textbox.setText('')
        self.file_path = ''

    def open_Message(self, ee_ss):
        # 创建提示窗
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Information)  # 设置图标
        msg_box.setText(f"{ee_ss}")  # 提示信息
        msg_box.setWindowTitle("提示")  # 窗口标题
        msg_box.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)  # 按钮
        response = msg_box.exec_()  # 显示提示窗并等待响应

        # 根据用户的选择进行处理
        if response == QMessageBox.Ok:
            pass
        else:
            pass

    def get_command_result(self, command):

        result = subprocess.run(f'platform-tools\\adb shell su -c "{command}"', shell=True, check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout

    def on_radio_button_toggled_suanfa(self):
        if not self.sender().isChecked():
            return
        if self.button_group.checkedButton().text() == "AES" or self.button_group.checkedButton().text() == "DES" or self.button_group.checkedButton().text() == "3DES" or self.button_group.checkedButton().text() == "SM4":
            self.radio_button21.show()
            self.radio_button22.show()

        else:
            self.radio_button21.hide()
            self.radio_button22.hide()

        if self.button_group.checkedButton().text() == "HMACMD5" or self.button_group.checkedButton().text() == "HMACSHA1" or self.button_group.checkedButton().text() == "HMACSHA256":
            self.text_knowedit.setPlaceholderText("在这里输入你知道的部分明文...(不填很慢)")  # 设置占位符文本
            return
        if self.button_group.checkedButton().text() == "明文搜索":
            self.text_knowedit.setPlaceholderText("在这里输入你知道的部分明文...(必填)")  # 设置占位符文本
            return

        self.text_knowedit.setPlaceholderText("在这里输入你知道的部分明文...")  # 设置占位符文本

    def get_thread_handles(self, pid):
        try:
            snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if snapshot == -1:
                self.append_message("无法创建线程快照。")
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
            self.append_message(f"获取线程句柄时出错: {e}")
            return []

        # 打开进程

    def resume_process(self, pid):
        try:
            thread_handles = self.get_thread_handles(pid)
            for thread_id in thread_handles:
                thread_handle = ctypes.windll.kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, thread_id)
                if thread_handle:
                    ctypes.windll.kernel32.ResumeThread(thread_handle)
                    ctypes.windll.kernel32.CloseHandle(thread_handle)
            self.append_message(f"进程 (PID: {pid}) 已恢复。")
        except Exception as e:
            self.append_message(f"恢复进程时出错: {e}")

        # 读取内存

    def open_file_dialog(self):
        if self.button_group3.checkedButton().text() == '选择本地模型':
            # 打开文件选择对话框
            options = QFileDialog.Options()
            options |= QFileDialog.ReadOnly
            self.file_path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*);;文本文件 (*.txt)",
                                                            options=options)
            if self.file_path:
                # 在标签中显示选定的文件路径
                self.pid = self.file_path
                self.textbox.setText(f"选定的模型路径: {self.file_path}")
                self.statusBar().showMessage(f"选定的模型路径: {self.file_path}", 5000)
            else:
                self.pid = None
                self.textbox.setText('')

    def loadfile(self):

        if self.button_group3.checkedButton().text() == "真机":
            if self.comboBox.currentData():
                self.task_button.setEnabled(False)
                self.button2.setEnabled(False)
                self.Realphone_worker = Realphone_Thead.Realphone_Thead(self.comboBox.currentData())
                self.Realphone_worker.Part_changed.connect(self.append_message)
                self.Realphone_worker.Part_end.connect(self.Realphone_end)
                self.Realphone_worker.Part_log.connect(self.Realphone_log)
                self.Realphone_worker.Part_totle.connect(self.Realphone_totle)
                self.Realphone_worker.start()
                self.progress_bar.show()
                return

        if self.button_group3.checkedButton().text() == "WX小程序":
            self.task_button.setEnabled(False)
            self.button2.setEnabled(False)
            self.Part_worker = Part_Thread.Part_Thread(
                str("WX小程序"))
            self.Part_worker.Part_changed.connect(self.append_message)
            self.Part_worker.Part_end.connect(self.Part_end)
            self.Part_worker.Part_log.connect(self.Part_log)
            self.Part_worker.Part_totle.connect(self.Part_totle)
            self.Part_worker.start()
            self.progress_bar.show()

        pid = self.pid

        if self.button_group3.checkedButton().text() == '自定义进程id':
            if not self.textbox.text():
                self.statusBar().showMessage(f"进程id为空", 5000)
            else:
                pid = int(self.textbox.text())

        if not pid:
            if self.button_group3.checkedButton().text() == "选择本地模型":
                self.statusBar().showMessage(f"没有找到模型", 5000)
            else:
                self.statusBar().showMessage(f"没有找到进程", 5000)
            return

        if self.button2.text() == f"加载模型({self.shortcut_key})":
            self.task_button.setEnabled(False)
            self.button2.setEnabled(False)

        self.Part_worker = Part_Thread.Part_Thread(
            str(pid) if self.button_group3.checkedButton().text() == '选择本地模型' else int(pid))
        self.Part_worker.Part_changed.connect(self.append_message)
        self.Part_worker.Part_end.connect(self.Part_end)
        self.Part_worker.Part_log.connect(self.Part_log)
        self.Part_worker.Part_totle.connect(self.Part_totle)
        self.Part_worker.start()
        self.progress_bar.show()

    def Part_end(self, value):
        self.button2.setEnabled(True)
        self.progress_bar.hide()
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setValue(0)
        self.button2.setText(f'加载模型({self.shortcut_key})')
        self.task_button.setEnabled(True)
        if value:
            self.file_path = value
            self.text_messageedit.append(f"成功！加载成功")
            self.statusBar().showMessage("加载成功", 5000)
        else:
            self.statusBar().showMessage("失败！加载失败", 5000)

    def Part_log(self, value):
        self.progress_bar.setValue(value)

    def Part_totle(self, value):
        self.progress_bar.setMaximum(value)
        self.progress_bar.setValue(0)

    def Realphone_end(self, value):
        self.button2.setEnabled(True)
        self.progress_bar.hide()
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setValue(0)
        self.button2.setText(f'加载模型({self.shortcut_key})')
        self.task_button.setEnabled(True)
        if not value.get('erro'):
            self.file_path = value
            self.text_messageedit.append(f"成功！模型加载成功")
            self.statusBar().showMessage("模型加载成功", 5000)
        else:
            self.text_messageedit.append(f"失败！模型加载失败")
            self.text_messageedit.append(f"{value.get('erro')}")
            self.statusBar().showMessage("模型加载失败", 5000)

    def Realphone_log(self, value):
        self.progress_bar.setValue(value)

    def Realphone_totle(self, value):
        self.progress_bar.setMaximum(value)
        self.progress_bar.setValue(0)
