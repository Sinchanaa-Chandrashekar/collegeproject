from PyQt5 import QtWidgets as qt, QtCore as qc, QtGui as qg
from sys import argv, exit
import api, Untitled


class MainWindow(qt.QMainWindow):
    def __init__(self):
        super().__init__()
        self.widget = qt.QWidget()
        self.widget .setObjectName('mainwidget')
        self.hlayout = qt.QVBoxLayout()
        self.linedit = api.linedit(self.new_table)
        self.linedit.text()
        self.linedit.setFocus()
        self.linedit.setEnabled(True)
        self.linedit.setFixedWidth(500)
        self.linedit.setPlaceholderText('Enter your Url here andd press Enter.')
        font = qg.QFont()
        font.setPixelSize(20)
        font.setFamily('Open sans')
        self.linedit.setFont(font)
        self.label = qt.QLabel()
        pic = qg.QPixmap('./assets/phishing-detection.png')
        self.label.setPixmap(pic)
        self.label.setObjectName('image')
        self.table = qt.QTableWidget()
        self.table.hide()
        self.hlayout.addWidget(self.label, 1, qc.Qt.AlignCenter)
        self.hlayout.addWidget(self.linedit, 5, qc.Qt.AlignCenter | qc.Qt.AlignTop)
        self.hlayout.addWidget(self.table, 10)
        self.widget.setLayout(self.hlayout)
        self.setCentralWidget(self.widget)
        self.setWindowTitle("Phishing Detector")
        self.setGeometry(0,0,1300, 720)
        self.setStyleSheet(
            """
                background-color: #212121;
                color: white;
                QLabel#image{
                    border-raidus: 10%;
                    border: none;
                }
            """
        )
        self.show()

    def new_table(self):
        url = self.linedit.text()
        if url == "":
            self.linedit.setPlaceholderText('Please Enter a URL.')
        else:
            value = Untitled.callabale_info(url, [])
            new = value[0][0]
            feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection',
                        'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                        'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']
            self.table.setColumnCount(feature_names.__len__())              
            self.table.setRowCount(1)
            self.table.setHorizontalHeaderLabels(feature_names)
            self.messagedialog = qt.QMessageBox()
            for i in range(0, feature_names.__len__()):
                tablewidgetitem = qt.QTableWidgetItem(str(new[i]))
                self.table.setItem(0, i, tablewidgetitem)
                self.table.show()
            self.messagedialog.setText(value[1])
            self.messagedialog.show()

def main():
    app = qt.QApplication(argv)
    ex = MainWindow()
    exit(app.exec_())

if __name__ == "__main__":
    main()