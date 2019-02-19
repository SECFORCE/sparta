#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2019 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

# check for dependencies first (make sure all non-standard dependencies are checked for here)
try:
	from sqlalchemy.orm import scoped_session as scoped_session
	import elixir
except ImportError, e:
	print "[-] Import failed. Elixir library not found. \nTry installing it with: apt install python-elixir"
	exit(1)
	
try:
	from PyQt4 import QtGui, QtCore
except ImportError, e:
	print "[-] Import failed. PyQt4 library not found. \nTry installing it with: apt install python-qt4"
	print e
	exit(1)

from app.logic import *
from ui.gui import *
from ui.view import *
from controller.controller import *

# this class is used to catch events such as arrow key presses or close window (X)
class MyEventFilter(QObject):
	
	def eventFilter(self, receiver, event):
		# catch up/down arrow key presses in hoststable
		if(event.type() == QEvent.KeyPress and (receiver == view.ui.HostsTableView or receiver == view.ui.ServiceNamesTableView or receiver == view.ui.ToolsTableView or receiver == view.ui.ToolHostsTableView or receiver == view.ui.ScriptsTableView or receiver == view.ui.ServicesTableView or receiver == view.settingsWidget.toolForHostsTableWidget or receiver == view.settingsWidget.toolForServiceTableWidget or receiver == view.settingsWidget.toolForTerminalTableWidget)):
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

			elif QtGui.QApplication.keyboardModifiers() == QtCore.Qt.ControlModifier and key == QtCore.Qt.Key_C:	
				selected = receiver.selectionModel().currentIndex()
				clipboard = QtGui.QApplication.clipboard()
				clipboard.setText(selected.data().toString())

			return True
			
		elif(event.type() == QEvent.Close and receiver == MainWindow):
			event.ignore()
			view.appExit()
			return True
			
		else:      
			return super(MyEventFilter,self).eventFilter(receiver, event)	# normal event processing

if __name__ == "__main__":

	app = QtGui.QApplication(sys.argv)
	myFilter = MyEventFilter()						# to capture events
	app.installEventFilter(myFilter)
	app.setWindowIcon(QIcon('./images/icons/logo.png'))
	
	MainWindow = QtGui.QMainWindow()
	ui = Ui_MainWindow()
	ui.setupUi(MainWindow)

	try:	
		qss_file = open('./ui/sparta.qss').read()
	except IOError, e:
		print "[-] The sparta.qss file is missing. Your installation seems to be corrupted. Try downloading the latest version."
		exit(0)

	MainWindow.setStyleSheet(qss_file)

	logic = Logic()									# Model prep (logic, db and models)
	view = View(ui, MainWindow)						# View prep (gui)
	controller = Controller(view, logic)			# Controller prep (communication between model and view)

	MainWindow.show()
	sys.exit(app.exec_())
