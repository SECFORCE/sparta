#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2020 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

# check for dependencies first (make sure all non-standard dependencies are checked for here)
# TODO: review this.
try:
    from sqlalchemy.orm import scoped_session as scoped_session
except ImportError as e:
    print("[-] Import failed. SQLAlchemy library not found. \nTry installing it with: apt install python3-sqlalchemy")
    print(e)
    exit(1)
    
try:
    from PyQt5 import QtGui, QtCore, QtWidgets
except ImportError as e:
    print("[-] Import failed. PyQt5 library not found. \nTry installing it with: apt install python3-pyqt5")
    print(e)
    exit(1)

import sys
import argparse
from app.logic import Logic
from ui.gui import Ui_MainWindow
from ui.view import View
from controller.controller import Controller

# this class is used to catch events such as arrow key presses or close window (X)
class MyEventFilter(QtCore.QObject):
    
    def eventFilter(self, receiver, event):
        # catch up/down arrow key presses in hoststable
        #if(event.type() == QtCore.QEvent.KeyPress and (receiver == view.ui.HostsTableView or receiver == view.ui.ServiceNamesTableView or receiver == view.ui.ToolsTableView or receiver == view.ui.ToolHostsTableView or receiver == view.ui.ScriptsTableView or receiver == view.ui.ServicesTableView or receiver == view.settingsWidget.toolForHostsTableWidget or receiver == view.settingsWidget.toolForServiceTableWidget or receiver == view.settingsWidget.toolForTerminalTableWidget)):
        if(event.type() == QtCore.QEvent.KeyPress and (receiver == view.ui.HostsTableView or receiver == view.ui.ServiceNamesTableView or receiver == view.ui.ToolsTableView or receiver == view.ui.ToolHostsTableView or receiver == view.ui.ScriptsTableView or receiver == view.ui.ServicesTableView)):
            key = event.key()
            if not receiver.selectionModel().selectedRows():
                return True
            index = receiver.selectionModel().selectedRows()[0].row()
            
            if key == QtCore.Qt.Key_Down: 
                newindex = index + 1
                receiver.selectRow(newindex)
                receiver.clicked.emit(receiver.selectionModel().selectedRows()[0])

            elif key == QtCore.Qt.Key_Up:
                newindex = index - 1
                receiver.selectRow(newindex)
                receiver.clicked.emit(receiver.selectionModel().selectedRows()[0])

            elif QtWidgets.QApplication.keyboardModifiers() == QtCore.Qt.ControlModifier and key == QtCore.Qt.Key_C:    
                selected = receiver.selectionModel().currentIndex()
                clipboard = QtWidgets.QApplication.clipboard()
                clipboard.setText(selected.data().toString())

            return True
            
        elif(event.type() == QtCore.QEvent.Close and receiver == MainWindow):
            event.ignore()
            view.appExit()
            return True
            
        else:      
            return super(MyEventFilter,self).eventFilter(receiver, event)    # normal event processing

if __name__ == "__main__":
    # Parse arguments and kick off scans if needed
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Automatically launch a staged nmap against the target IP range")
    parser.add_argument("-f", "--file", help="Import nmap XML file and kick off automated attacks")
    args = parser.parse_args()

    app = QtWidgets.QApplication(sys.argv)
    myFilter = MyEventFilter()                        # to capture events
    app.installEventFilter(myFilter)
    app.setWindowIcon(QtGui.QIcon('./images/icons/logo.png'))

    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)

    try:    
        qss_file = open('./ui/sparta.qss').read()
    except IOError as e:
        print("[-] The sparta.qss file is missing. Your installation seems to be corrupted. Try downloading the latest version.")
        exit(0)

    MainWindow.setStyleSheet(qss_file)
    logic = Logic()                                    # Model prep (logic, db and models)
    view = View(ui, MainWindow)                        # View prep (gui)
    controller = Controller(view, logic)            # Controller prep (communication between model and view)

    MainWindow.show()
    
    if args.target:
        print("[+] Target was specified.")
        controller.addHosts(args.target, True, True)

    if args.file:
        print("[+] Nmap XML file was provided.")
        controller.importNmap(args.file)        

    sys.exit(app.exec_())
