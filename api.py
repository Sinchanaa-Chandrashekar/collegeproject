from PyQt5 import QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QLineEdit
import urllib3
import re
import typing

def urlExtract(url: typing.AnyStr):
    urls = re.split('www', url)
    return urls

class linedit(QLineEdit):
    def __init__(self, call):
        super().__init__()
        self.call = call

    def keyPressEvent(self, event: QtGui.QKeyEvent) -> None:
        if(event.key() == Qt.Key.Key_Return):
            self.call()
        return super().keyPressEvent(event)
        