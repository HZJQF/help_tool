from PyQt5.QtWidgets import QTextEdit, QAction


class CustomTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(CustomTextEdit, self).__init__(parent)
        self.setReadOnly(True)

    def contextMenuEvent(self, event):
        # 获取默认的上下文菜单
        menu = self.createStandardContextMenu()

        # 添加自定义的“清除”选项
        clear_action = QAction("清除", self)
        clear_action.triggered.connect(self.clear_content)
        menu.addAction(clear_action)

        # 设置菜单的样式表以修改背景颜色及悬停样式
        menu.setStyleSheet("""
            QMenu {
                background-color: black;
            }
            QMenu::item:selected {
                background-color: lightgray;
            }
        """)

        # 在鼠标点击的位置显示菜单
        menu.exec_(event.globalPos())

    def clear_content(self):
        # 清除文本内容
        self.clear()
