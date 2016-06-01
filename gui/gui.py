#!/usr/bin/env python
'''
    to do
    '''
import sys, os
import socket
from PyQt4 import QtCore, QtGui, uic

data_dir = os.path.dirname(os.path.realname(__file__))

class Ui_MainWindow(object):
    def setUi(self, MainWindow):
        uic.loadUi(os.path.join(data_dir, 'frontend.ui'), self)


class myMainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setUi(self)
        self.setWindowTitle("PF")
        self.tableView.setShowGrid(False)



if __name__ == "__main__":
    #
    # to do
    #
    app = QApplication(sys.argv)
    window = myMainWindow()
    window.show()
    sys.exit(app.exec_())
