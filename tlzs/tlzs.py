import sys
import MainWindow
from PyQt5.QtWidgets import QApplication
import qdarkstyle


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    main_window = MainWindow.MainWindow()
    main_window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
