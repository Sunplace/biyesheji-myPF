#!/usr/bin/env python
#-*- coding:utf-8 --*-

import sys, os, thread, time, string, threading
from PyQt4.QtGui import QApplication, QStandardItem, QDialog, QMenu, QStandardItemModel, QAction, QMainWindow, QListWidget, QListWidgetItem, QWidget, QTableWidgetItem, QSortFilterProxyModel
import resource
from PyQt4.QtCore import pyqtSignal, Qt, QModelIndex, pyqtSlot, QString
from multiprocessing import Lock
import socket
import psutil


from PyQt4 import QtCore, QtGui, uic

data_dir = os.path.dirname(os.path.realpath(__file__))

#global vars
modellock = Lock()
current_layout_lock = Lock()
msg_lock = Lock()


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        uic.loadUi(os.path.join(data_dir, 'frontend.ui'), self)


class Ui_Dialog(object):
    def setupUi(self, DialogOut):
        uic.loadUi(os.path.join(data_dir, 'addrule.ui'), self)

class Ui_MsgDialog(object):
    def setupUi(self, DialogOut):
        uic.loadUi(os.path.join(data_dir, 'message.ui'), self)


class msgDialog(QDialog, Ui_MsgDialog):
    #some var
    msgsig = pyqtSignal(str)
    displaymsg = True

    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
        self.setWindowTitle(u"解析过程")
        self.msgsig.connect(self.message)

    @pyqtSlot(str)
    def message(self, msg):
        msg_lock.acquire()
        if self.isVisible():
            if self.displaymsg:
                print ("msg event")
                self.plainTextEdit.appendPlainText(msg)
        else:
            pass
            #print ("Invisible")
        msg_lock.release()

    def closeEvent(self, event):
        print ("close event")
        event.accept()

    def keyPressEvent(self, event):
        key = event.key()
        #print (key)
        if key == QtCore.Qt.Key_Q:
            print ("key q")
            msg_lock.acquire()
            self.displaymsg = (not self.displaymsg)
            msg_lock.release()


class myDialog(QDialog, Ui_Dialog):
    #

    def __init__(self):
        QDialog.__init__(self)
        self.setupUi(self)
        self.setWindowTitle(u"添加规则")

        #self.buttonBox.accepted.connect(self.Okclicked)
        #self.buttonBox.rejected.connect(self.Cancelclicked)
        #self.buttonBox.button(QtGui.QDialogButtonBox.Reset).clicked().connect(self.foo)
        #self.buttonBox.button(QtGui.QDialogButtonBox.Cancel).clicked().connect(self.CancelClicked)
        self.pushButton_confirm.clicked.connect(self.confirm)
        self.pushButton_cancel.clicked.connect(self.close)

    def confirm(self):
        print ("confirm clicked")
        self.plainTextEdit.clear()
        if(self.direction_out.isChecked()):
            direction = "OUT"
        else:
            direction = "IN"
        lport = str(self.lport.text())
        if(lport.isdigit()):
            if(int(lport) > 0 and int(lport) < 65536):
                pass
            else:
                #self.plainTextEdit.appendPlainText("local port must bigger than 0, and less than 65536,[1:65535], or '-' to represent all port")
                self.plainTextEdit.appendPlainText(u"本地端口必须介于1与65535之间，-代表所有端口");
                self.lport.clear()
                return
        else:
            if(lport == '-'):
                pass
            else:
                #self.plainTextEdit.appendPlainText("local port must be a number,[1:65535], or '-' to represent all port")
                self.plainTextEdit.appendPlainText(u"本地端口必须介于1与65535之间，-代表所有端口");
                self.lport.clear()
                return
        raddr = str(self.raddr.text())
        if(raddr == '-'):
            pass
        elif(raddr.find('/') != -1):
            addr,mask = raddr.split('/')
            if(int(mask) < 1 or int(mask) > 24):
                self.plainTextEdit.appendPlainText(u"远程地址：子网/子网掩码出错");
                self.raddr.clear()
                return
            else:
                pass                    #check the subnet and mask in python is difficult,so pass
        else:
            tmp = raddr.split('.')
            if(len(tmp) != 4):
                #self.plainTextEdit.appendPlainText("remote address must be like that: xxx.xxx.xxx.xxx, xxx is a digit between 1-254")
                self.plainTextEdit.appendPlainText(u"远程地址必须如xxx.xxx.xxx.xxx或者xxx.xxx.xxx.xxx/xx,-代表所有地址")
                self.raddr.clear()
                return
            else:
                for item in tmp:
                    if(not item.isdigit()):
                        #self.plainTextEdit.appendPlainText("remote address must be like that: xxx.xxx.xxx.xxx, xxx is a digit between 1-254")
                        self.plainTextEdit.appendPlainText(u"远程地址必须如xxx.xxx.xxx.xxx或者xxx.xxx.xxx.xxx/xx,-代表所有地址")
                        self.raddr.clear()
                        return
                    else:
                        if(int(item) < 1 or int(item) > 254):
                            #self.plainTextEdit.appendPlainText("remote address must be like that: xxx.xxx.xxx.xxx, xxx is a digit between 1-254")
                            self.plainTextEdit.appendPlainText(u"远程地址必须如xxx.xxx.xxx.xxx或者xxx.xxx.xxx.xxx/xx,-代表所有地址")
                            self.raddr.clear()
                            return
        rport = str(self.rport.text())
        if(rport.isdigit()):
            if(int(rport) > 0 and int(rport) < 65536):
                pass
            else:
                #self.plainTextEdit.appendPlainText("remote port must bigger than 0, and less than 65536,[1:65535], or '-' to represent all port")
                self.plainTextEdit.appendPlainText(u"远程端口必须介于1与65535之间，-代表所有端口")
                self.rport.clear()
                return
        else:
            if(rport == '-'):
                pass
            else:
                #self.plainTextEdit.appendPlainText("remote port must be a number,[1:65535], or '-' to represent all port")
                self.plainTextEdit.appendPlainText(u"远程端口必须介于1与65535之间，-代表所有端口")
                self.rport.clear()
                return
        if(self.protocol_tcp.isChecked()):
            proto = "TCP"
        else:
            proto = "UDP"
        if(self.target_drop.isChecked()):
            target = "DROP"
        else:
            target = "ACCEPT"
        #proto = self.protocol.text()
        #target = self.target.text()
        #print (direction)
        print (direction + ':' + lport + ':' + raddr + ':' + rport + ':' + proto + ':' + target) 
        self.plainTextEdit.appendPlainText(u"添加规则.... \n" +
                u"方向: " + direction + "\n" +
                u"本地端口: " + lport + "\n" +
                u"远程地址: " + raddr + "\n" +
                u"远程端口: " + rport + "\n" +
                u"协议: " + proto + "\n" +
                u"去向: " + target )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( ('127.0.0.1', 9999))
        sock.send("-a " + direction + " " + lport + " " + raddr + " " + rport + " " + proto + " " + target)
        data = sock.recv(1024)
        print (data)
        self.plainTextEdit.appendPlainText(u"成功?:" + data)
        self.lport.clear()
        self.raddr.clear()
        self.rport.clear()
        self.direction_out.setChecked(True)
        self.protocol_tcp.setChecked(True)
        self.target_drop.setChecked(True)
        window.refreshrulessig.emit()



    def cancel(self):
        print ("Cancel clicked")

    def closeEvent(self, event):
        print ("close event")
        event.accept()


class myMainWindow(QMainWindow, Ui_MainWindow):
    askusersig = pyqtSignal(str, str, str, str, str, str) #connected to askUserOUT
    refreshmodelsig = pyqtSignal(str)
    update_bytestatssig = pyqtSignal(str)
    refreshconnectionssig = pyqtSignal()
    refreshrulessig = pyqtSignal()
    prevstats = ''
    model = None
    sourcemodel = None
    menu = None
    #index = None
    out_rules_num = 0

    def __init__(self):
        QMainWindow.__init__(self)
        self.setupUi(self)
        #title2 = '我的个人防火墙'
        #print title2
        #title = QString(u'我的个人防火墙')
        self.setWindowTitle(u'我的个人防火墙')
        #self.setWindowTitle(title)
        self.tableView.setShowGrid(False)
        self.actionDisplay.triggered.connect(self.displayconnections)
        self.actionList_Rules.triggered.connect(self.listrules)
        self.actionAdd_Rules.triggered.connect(self.addrules)
        self.actionDisconnect.triggered.connect(self.disconnection)
        self.actionReconnect.triggered.connect(self.reconnection)
        self.actionMessage.triggered.connect(self.message)
        self.actionExit.triggered.connect(self.realQuit)
        self.refreshconnectionssig.connect(self.refreshconnections)
        self.refreshrulessig.connect(self.refreshrules)
        #msgQueue.put('LIST')        

    def message(self):
        dialog = msgdialog
        dialog.show()

    def disconnection(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( ('127.0.0.1', 9999) )
        sock.send("--disconnect")
        data = sock.recv(1024)
        print data
        sock.close()

    def reconnection(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( ('127.0.0.1', 9999) )
        sock.send("--reconnect")
        data = sock.recv(1024)
        print data
        sock.close()

    def addrules(self):
        dialog = addruledialog
        dialog.show()

    def contextMenuEvent(self, event):
        current_layout_lock.acquire()
        if(self.sourcemodel.current_layout == "conn"):
            current_layout_lock.release()
            return
        current_layout_lock.release()
        #self.index = self.sourcemodel.indexAt(event.pos())
        self.menu = QMenu(self)
        delete_ruleAction = QAction(u"删除", self)
        delete_ruleAction.triggered.connect(self.deleterule)
        self.menu.addAction(delete_ruleAction)
        self.menu.popup(QtGui.QCursor.pos())

    def deleterule(self):
        #index = self.tableView.selectedIndexes()
        #print(index[0].row())
        row_num = (self.tableView.selectedIndexes())[0].row()
        if(row_num < self.out_rules_num):
            #print ("-d OUT " + str(row_num + 1))
            cmd_del = "-d OUT " + str(row_num + 1)
        else:
            #print ("-d IN " + str(row_num - self.out_rules_num + 1))
            cmd_del = "-d IN " + str(row_num - self.out_rules_num + 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 9999))
        sock.send(cmd_del)
        result = sock.recv(1024)
        print(result)
        sock.close()
        self.refreshrules()



    def listrules(self):
        self.sourcemodel.layout_change_to_rule_sig.emit()
        self.refreshrules()

    def refreshrules(self):
        #self.sourcemodel.layout_change_to_rule_sig.emit()
        current_layout_lock.acquire()
        if(self.sourcemodel.current_layout != "rule"):
            print ("refreshrules error")
            current_layout_lock.release()
            return
        self.sourcemodel.layoutAboutToBeChanged.emit()
        self.sourcemodel.removeRows(0, self.sourcemodel.rowCount())
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 9999))
        sock.send("--list")
        ruleslist = ''
        while(True):
            data = sock.recv(1024)
            if not data:
                break
            ruleslist = ruleslist + data
        sock.close()
        #print (ruleslist)
        if ruleslist:
            self.out_rules_num = 0
            for ruleline in ruleslist[0:-1].split('\n'):
                #print ( 'line: ' + line)
                items = ruleline.split()
                print (items)
                if(items[0] == 'direction:OUT'):
                    self.out_rules_num += 1
                direction = QStandardItem((items[0].split(':'))[1])
                lport = QStandardItem((items[1].split(':'))[1])
                raddr = QStandardItem((items[3].split(':'))[1])
                rport = QStandardItem((items[5].split(':'))[1])
                proto = QStandardItem((items[6].split(':'))[1])
                target = QStandardItem((items[7].split(':'))[1])
                #print (direction + ':' + lport + ':' + raddr + ':' + rport + ':' + proto + ':' + target) 
                self.sourcemodel.appendRow( (direction, lport, raddr, rport, proto, target) )

        self.sourcemodel.layoutChanged.emit()
        current_layout_lock.release()

    def displayconnections(self):
        '''
        if(self.sourcemodel.current_layout == "conn"):
            self.refreshconnectionssig.emit()
        else:
            self.sourcemode.layout_change_to_conn_sig.emit()
            self.refreshconnections()
            '''
        self.sourcemodel.layout_change_to_conn_sig.emit()
        self.refreshconnections()
        


    def refreshconnections(self):
        current_layout_lock.acquire()
        if(self.sourcemodel.current_layout != "conn"):
            print ("refreshconnections error")
            current_layout_lock.release()
            return
        self.sourcemodel.layoutAboutToBeChanged.emit()
        self.sourcemodel.removeRows(0, self.sourcemodel.rowCount())
        for conn in psutil.net_connections("inet4"):
            if(conn.type == socket.SOCK_STREAM):
                proto = QStandardItem("tcp")
            else:
                proto = QStandardItem("udp")
            laddr = QStandardItem(conn.laddr[0])
            lport = QStandardItem(str(conn.laddr[1]))
            if(len(conn.raddr) == 0):
                continue
            raddr = QStandardItem(conn.raddr[0])
            rport = QStandardItem(str(conn.raddr[1]))
            status = QStandardItem(conn.status)
            pid = QStandardItem(str(conn.pid))
            if(conn.pid != None):
                p = psutil.Process(conn.pid)
                name = QStandardItem(p.name())
            else:
                name = QStandardItem("None")
            family = QStandardItem("ipv4")
            self.sourcemodel.appendRow( (family, proto, laddr, lport, raddr, rport, status, pid, name))
        self.sourcemodel.layoutChanged.emit()
        current_layout_lock.release()



    

    def closeEvent(self, event):
        event.ignore()
        self.hide()


    def realQuit(self): 
        #print "see you later..."
        time.sleep(1) 
        exit(1)


def testfunc():
    while (True):
        current_layout_lock.acquire()        
        #print (window.sourcemodel.current_layout)
        if(window.sourcemodel.current_layout == "conn"):
            window.refreshconnectionssig.emit()
        current_layout_lock.release()
        time.sleep(3)

def msgserv():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind( ('127.0.0.1', 9998) )
    while (True):
        data, addr = sock.recvfrom(1024)
        if not data:
            break
        #print (data)
        #if msgdialog.isVisble()
        msgdialog.msgsig.emit(data)



class myModel(QStandardItemModel):
    layout_changed_sig = pyqtSignal()
    layout_change_to_conn_sig = pyqtSignal()
    layout_change_to_rule_sig = pyqtSignal()
    current_layout = "conn"
    
    def __init__(self):
        QStandardItemModel.__init__(self)
        self.layout_changed_sig.connect(self.layout_changed)
        self.layout_change_to_conn_sig.connect(self.layout_change_to_conn)
        self.layout_change_to_rule_sig.connect(self.layout_change_to_rule)
        self.setHorizontalHeaderLabels((u"协议簇",u"类型",u"本地地址", u"本地端口",u"远程地址", u"远程端口",
                                              u"状态",u"进程ID",u"进程名"))
        
    @pyqtSlot()
    def layout_changed(self):
        self.layoutAboutToBeChanged.emit()
        self.layoutChanged.emit()

    @pyqtSlot()
    def layout_change_to_conn(self):
        current_layout_lock.acquire()
        if(self.current_layout == "conn"):
            current_layout_lock.release()
            return
        self.clear()
        self.current_layout = "conn"
        self.setHorizontalHeaderLabels((u"协议簇",u"类型",u"本地地址", u"本地端口",u"远程地址", u"远程端口",
                                              u"状态",u"进程ID",u"进程名"))
        current_layout_lock.release()

    @pyqtSlot()
    def layout_change_to_rule(self):
        current_layout_lock.acquire()
        if(self.current_layout == "rule"):
            current_layout_lock.release()
            return
        self.clear()
        self.current_layout = "rule"
        self.setHorizontalHeaderLabels((u"方向",u"本地端口",u"远程地址",u"远程端口",
                                              u"协议",u"去向"))
        current_layout_lock.release()
        
   
class mySortFilterProxyModel(QSortFilterProxyModel):
    toggle_mode_sig = pyqtSignal(str)
    mode = 'SHOW ALL'
              
    def __init__(self):
        QSortFilterProxyModel.__init__(self) 
        self.toggle_mode_sig.connect(self.toggle_mode)        
        
    @pyqtSlot(str)
    def toggle_mode(self, mode_in):
        mode = str(mode_in)
        self.mode = mode
        self.sourceModel().layoutAboutToBeChanged.emit()
        self.sourceModel().layoutChanged.emit() 
       

    def headerData(self, section, orientation, role):
        if orientation != Qt.Vertical or role != Qt.DisplayRole:
            return QSortFilterProxyModel.headerData(self, section, orientation, role)
        return section+1

   
    def filterAcceptsRow(self, row, parent):
        if self.mode == 'SHOW ALL':
            return True
        #else mode == 'SHOW ACTIVE ONLY'
        smodel = self.sourceModel()
        pid = str(smodel.itemFromIndex(smodel.index(row,1)).text())
        if (pid == 'N/A'):
            return False
        else:
            return True
        

    def lessThan(self, left, right):
        if left.column() not in (1,4,5,6,7):
            return QSortFilterProxyModel.lessThan(self, left, right)
        model = self.sourceModel()
        try:
            leftint = int(model.data(left).toPyObject())
        except:
            leftint = 0
        try:
            rightint = int(model.data(right).toPyObject())
        except:
            rightint = 0
        return  leftint < rightint




if __name__ == "__main__":


    app=QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window = myMainWindow()

    menu = QMenu()
    actionShow = QAction("PF",menu)
    actionExit = QAction("Exit",menu)
    menu.addAction(actionShow)
    menu.addAction(actionExit)
    actionShow.triggered.connect(window.show)
    actionExit.triggered.connect(window.realQuit)

    sourcemodel = myModel()  
    model = mySortFilterProxyModel()
    model.setSourceModel(sourcemodel)
    model.setDynamicSortFilter(True)

    window.tableView.setSortingEnabled(True)
    window.tableView.setModel(model)
    window.model = model
    window.sourcemodel = sourcemodel

    addruledialog = myDialog()
    msgdialog = msgDialog()

    thread = threading.Thread( target = testfunc)
    thread.daemon = True
    thread.start()

    thread = threading.Thread( target = msgserv)
    thread.daemon = True
    thread.start()

    window.show()
    sys.exit(app.exec_())
