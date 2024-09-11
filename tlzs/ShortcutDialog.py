from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import QDialog, QLineEdit, QPushButton, QVBoxLayout, QLabel


class ShortcutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.shortcut_info = None
        self.setWindowTitle("设置快捷键")

        self.label = QLabel("按下新的快捷键")
        self.shortcut_edit = QLineEdit()
        self.shortcut_edit.setEnabled(False)

        self.save_button = QPushButton("保存")
        self.save_button.clicked.connect(self.save_shortcut)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.shortcut_edit)
        layout.addWidget(self.save_button)
        self.setLayout(layout)

    def keyPressEvent(self, event):
        key = event.key()
        modifiers = event.modifiers()
        key_name = QKeySequence(key).toString(QKeySequence.NativeText)
        modifiers_name = self.modifiers_to_string(modifiers)

        try:
            key_name.encode()
            # 显示按键信息
            self.shortcut_info = f'{modifiers_name}+{key_name}' if modifiers_name else key_name

        except:
            pass

        self.shortcut_edit.setText(f'按下的快捷键: {f'{modifiers_name}+{key_name}' if modifiers_name else key_name}')


    def modifiers_to_string(self, modifiers):
        modifier_str = []
        if modifiers & Qt.ControlModifier:
            modifier_str.append('Ctrl')
        if modifiers & Qt.ShiftModifier:
            modifier_str.append('Shift')
        if modifiers & Qt.AltModifier:
            modifier_str.append('Alt')
        if modifiers & Qt.MetaModifier:  # MetaModifier对应的是Command键在Mac上
            modifier_str.append('Meta')
        return '+'.join(modifier_str)

    def save_shortcut(self):

        # 保存快捷键设置
        self.accept()  # 关闭对话框
