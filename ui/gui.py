#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2014 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

#from PyQt4 import QtCore, QtGui
from ui.dialogs import *												# for the screenshots (image viewer)

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_MainWindow(object):
	def setupUi(self, MainWindow):
		MainWindow.setObjectName(_fromUtf8("MainWindow"))
		MainWindow.resize(1010, 754)
		
		self.centralwidget = QtGui.QWidget(MainWindow)
		self.centralwidget.setObjectName(_fromUtf8("centralwidget"))	# do not change this name
		self.gridLayout = QtGui.QGridLayout(self.centralwidget)
		self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
		self.splitter_2 = QtGui.QSplitter(self.centralwidget)
		self.splitter_2.setOrientation(QtCore.Qt.Vertical)
		self.splitter_2.setObjectName(_fromUtf8("splitter_2"))
		
		self.MainTabWidget = QtGui.QTabWidget(self.splitter_2)
		self.MainTabWidget.setObjectName(_fromUtf8("MainTabWidget"))
		self.ScanTab = QtGui.QWidget()
		self.ScanTab.setObjectName(_fromUtf8("ScanTab"))
		self.gridLayout_2 = QtGui.QGridLayout(self.ScanTab)
		self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
		self.splitter = QtGui.QSplitter(self.ScanTab)
		self.splitter.setOrientation(QtCore.Qt.Horizontal)
		self.splitter.setObjectName(_fromUtf8("splitter"))
	
		# size policies
		self.sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
		self.sizePolicy.setHorizontalStretch(0)							# this specifies that the widget will keep its width when the window is resized
		self.sizePolicy.setVerticalStretch(0)
		
		self.sizePolicy2 = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
		self.sizePolicy2.setHorizontalStretch(1)						# this specifies that the widget will expand its width when the window is resized
		self.sizePolicy2.setVerticalStretch(0)		
		
		self.setupLeftPanel()
		self.setupRightPanel()
		self.setupMainTabs()
		self.setupBottomPanel()
		
		self.gridLayout.addWidget(self.splitter_2, 0, 0, 1, 1)
		MainWindow.setCentralWidget(self.centralwidget)

		self.setupMenuBar(MainWindow)
		self.retranslateUi(MainWindow)		
		self.setDefaultIndexes()
		QtCore.QMetaObject.connectSlotsByName(MainWindow)

	def setupLeftPanel(self):
		self.HostsTabWidget = QtGui.QTabWidget(self.splitter)
		self.sizePolicy.setHeightForWidth(self.HostsTabWidget.sizePolicy().hasHeightForWidth())
		self.HostsTabWidget.setSizePolicy(self.sizePolicy)
		self.HostsTabWidget.setObjectName(_fromUtf8("HostsTabWidget"))

		self.HostsTab = QtGui.QWidget()
		self.HostsTab.setObjectName(_fromUtf8("HostsTab"))
		self.keywordTextInput = QtGui.QLineEdit()
		self.FilterApplyButton = QtGui.QToolButton()
		self.searchIcon = QtGui.QIcon()
		self.searchIcon.addPixmap(QtGui.QPixmap(_fromUtf8("./images/search.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.FilterApplyButton.setIconSize(QtCore.QSize(29,21))
		self.FilterApplyButton.setIcon(self.searchIcon)
		self.FilterAdvancedButton = QtGui.QToolButton()
		self.advancedIcon = QtGui.QIcon()
		self.advancedIcon.addPixmap(QtGui.QPixmap(_fromUtf8("./images/advanced.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
		self.FilterAdvancedButton.setIconSize(QtCore.QSize(19,19))
		self.FilterAdvancedButton.setIcon(self.advancedIcon)
		self.vlayout = QtGui.QVBoxLayout(self.HostsTab)
		self.vlayout.setObjectName(_fromUtf8("vlayout"))
		self.HostsTableView = QtGui.QTableView(self.HostsTab)
		self.HostsTableView.setObjectName(_fromUtf8("HostsTableView"))
		self.vlayout.addWidget(self.HostsTableView)
		
		self.addHostsOverlay = QtGui.QTextEdit(self.HostsTab)			# the overlay widget that appears over the hosttableview		
		self.addHostsOverlay.setObjectName(_fromUtf8("addHostsOverlay"))
		self.addHostsOverlay.setText('Click here to add host(s) to scope')
		self.addHostsOverlay.setReadOnly(True)
		self.addHostsOverlay.setContextMenuPolicy(QtCore.Qt.NoContextMenu)

		###
		self.addHostsOverlay.setFont(QtGui.QFont('', 12))
		self.addHostsOverlay.setAlignment(Qt.AlignHCenter|Qt.AlignVCenter)
		###
		
		self.vlayout.addWidget(self.addHostsOverlay)
		self.hlayout = QtGui.QHBoxLayout()
		self.hlayout.addWidget(self.keywordTextInput)
		self.hlayout.addWidget(self.FilterApplyButton)
		self.hlayout.addWidget(self.FilterAdvancedButton)
		self.vlayout.addLayout(self.hlayout)
		self.HostsTabWidget.addTab(self.HostsTab, _fromUtf8(""))

		self.ServicesLeftTab = QtGui.QWidget()
		self.ServicesLeftTab.setObjectName(_fromUtf8("ServicesLeftTab"))
		self.horizontalLayout_2 = QtGui.QHBoxLayout(self.ServicesLeftTab)
		self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
		self.ServiceNamesTableView = QtGui.QTableView(self.ServicesLeftTab)
		self.ServiceNamesTableView.setObjectName(_fromUtf8("ServiceNamesTableView"))
		self.horizontalLayout_2.addWidget(self.ServiceNamesTableView)
		self.HostsTabWidget.addTab(self.ServicesLeftTab, _fromUtf8(""))

		self.ToolsTab = QtGui.QWidget()
		self.ToolsTab.setObjectName(_fromUtf8("ToolsTab"))
		self.horizontalLayout_3 = QtGui.QHBoxLayout(self.ToolsTab)
		self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
		self.ToolsTableView = QtGui.QTableView(self.ToolsTab)
		self.ToolsTableView.setObjectName(_fromUtf8("ToolsTableView"))
		self.horizontalLayout_3.addWidget(self.ToolsTableView)
		self.HostsTabWidget.addTab(self.ToolsTab, _fromUtf8(""))		

	def setupRightPanel(self):
		self.ServicesTabWidget = QtGui.QTabWidget()
		self.ServicesTabWidget.setEnabled(True)
		self.sizePolicy2.setHeightForWidth(self.ServicesTabWidget.sizePolicy().hasHeightForWidth())
		self.ServicesTabWidget.setSizePolicy(self.sizePolicy2)
		self.ServicesTabWidget.setObjectName(_fromUtf8("ServicesTabWidget"))		
		self.splitter.addWidget(self.ServicesTabWidget)

		###

		self.splitter_3 = QtGui.QSplitter()
		self.splitter_3.setOrientation(QtCore.Qt.Horizontal)
		self.splitter_3.setObjectName(_fromUtf8("splitter_3"))
		self.splitter_3.setSizePolicy(self.sizePolicy2)					# this makes the tools tab stay the same width when resizing the window
		
		###
		
		self.ToolHostsWidget = QtGui.QWidget()
		self.ToolHostsWidget.setObjectName(_fromUtf8("ToolHostsTab"))		
		self.ToolHostsLayout = QtGui.QVBoxLayout(self.ToolHostsWidget)
		self.ToolHostsLayout.setObjectName(_fromUtf8("verticalLayout"))
		self.ToolHostsTableView = QtGui.QTableView(self.ToolHostsWidget)
		self.ToolHostsTableView.setObjectName(_fromUtf8("ServicesTableView"))
		self.ToolHostsLayout.addWidget(self.ToolHostsTableView)
		self.splitter_3.addWidget(self.ToolHostsWidget)
		
		self.DisplayWidget = QtGui.QWidget()
		self.DisplayWidget.setObjectName('ToolOutput')
		self.DisplayWidget.setSizePolicy(self.sizePolicy2)
		#self.toolOutputTextView = QtGui.QTextEdit(self.DisplayWidget)
		self.toolOutputTextView = QtGui.QPlainTextEdit(self.DisplayWidget)
		self.toolOutputTextView.setReadOnly(True)
		self.DisplayWidgetLayout = QtGui.QHBoxLayout(self.DisplayWidget)
		self.DisplayWidgetLayout.addWidget(self.toolOutputTextView)
		self.splitter_3.addWidget(self.DisplayWidget)

		self.ScreenshotWidget = ImageViewer()
		self.ScreenshotWidget.setObjectName('Screenshot')
		self.ScreenshotWidget.scrollArea.setSizePolicy(self.sizePolicy2)
		self.ScreenshotWidget.scrollArea.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
		self.splitter_3.addWidget(self.ScreenshotWidget.scrollArea)

		self.splitter.addWidget(self.splitter_3)

		###
		
		self.ServicesRightTab = QtGui.QWidget()
		self.ServicesRightTab.setObjectName(_fromUtf8("ServicesRightTab"))
		self.verticalLayout = QtGui.QVBoxLayout(self.ServicesRightTab)
		self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
		self.ServicesTableView = QtGui.QTableView(self.ServicesRightTab)
		self.ServicesTableView.setObjectName(_fromUtf8("ServicesTableView"))
		self.verticalLayout.addWidget(self.ServicesTableView)
		self.ServicesTabWidget.addTab(self.ServicesRightTab, _fromUtf8(""))
		
		self.ScriptsTab = QtGui.QWidget()
		self.ScriptsTab.setObjectName(_fromUtf8("ScriptsTab"))
		self.horizontalLayout_6 = QtGui.QHBoxLayout(self.ScriptsTab)
		self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
				
		self.splitter_4 = QtGui.QSplitter(self.ScriptsTab)
		self.splitter_4.setOrientation(QtCore.Qt.Horizontal)
		self.splitter_4.setObjectName(_fromUtf8("splitter_4"))
		
		self.ScriptsTableView = QtGui.QTableView()
		self.ScriptsTableView.setObjectName(_fromUtf8("ScriptsTableView"))		
		self.splitter_4.addWidget(self.ScriptsTableView)
		
		self.ScriptsOutputTextEdit = QtGui.QPlainTextEdit()
		self.ScriptsOutputTextEdit.setObjectName(_fromUtf8("ScriptsOutputTextEdit"))
		self.ScriptsOutputTextEdit.setReadOnly(True)		
		self.splitter_4.addWidget(self.ScriptsOutputTextEdit)		
		self.horizontalLayout_6.addWidget(self.splitter_4)	
		self.ServicesTabWidget.addTab(self.ScriptsTab, _fromUtf8(""))
		
		self.InformationTab = QtGui.QWidget()
		self.InformationTab.setObjectName(_fromUtf8("InformationTab"))			
		self.ServicesTabWidget.addTab(self.InformationTab, _fromUtf8(""))
		
		self.NotesTab = QtGui.QWidget()
		self.NotesTab.setObjectName(_fromUtf8("NotesTab"))
		self.horizontalLayout_4 = QtGui.QHBoxLayout(self.NotesTab)
		self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
		#self.NotesTextEdit = QtGui.QTextEdit(self.NotesTab)
		self.NotesTextEdit = QtGui.QPlainTextEdit(self.NotesTab)
		self.NotesTextEdit.setObjectName(_fromUtf8("NotesTextEdit"))
		self.horizontalLayout_4.addWidget(self.NotesTextEdit)
		self.ServicesTabWidget.addTab(self.NotesTab, _fromUtf8(""))		

	def setupMainTabs(self):
		self.gridLayout_2.addWidget(self.splitter, 0, 0, 1, 1)
		self.gridLayout_3 = QtGui.QGridLayout()
		self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))	
		self.gridLayout_2.addLayout(self.gridLayout_3, 0, 0, 1, 1)
		self.MainTabWidget.addTab(self.ScanTab, _fromUtf8(""))	
		
		self.BruteTab = QtGui.QWidget()
		self.BruteTab.setObjectName(_fromUtf8("BruteTab"))
		self.horizontalLayout_7 = QtGui.QHBoxLayout(self.BruteTab)
		self.horizontalLayout_7.setObjectName(_fromUtf8("horizontalLayout_7"))
		self.BruteTabWidget = QtGui.QTabWidget(self.BruteTab)
		self.BruteTabWidget.setObjectName(_fromUtf8("BruteTabWidget"))
		self.horizontalLayout_7.addWidget(self.BruteTabWidget)
		self.MainTabWidget.addTab(self.BruteTab, _fromUtf8(""))		

	def setupBottomPanel(self):
		self.BottomTabWidget = QtGui.QTabWidget(self.splitter_2)
		self.BottomTabWidget.setSizeIncrement(QtCore.QSize(0, 0))
		self.BottomTabWidget.setBaseSize(QtCore.QSize(0, 0))
		self.BottomTabWidget.setObjectName(_fromUtf8("BottomTabWidget"))
		
		self.LogTab = QtGui.QWidget()
		self.LogTab.setObjectName(_fromUtf8("LogTab"))
		self.horizontalLayout_5 = QtGui.QHBoxLayout(self.LogTab)
		self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
		self.ProcessesTableView = QtGui.QTableView(self.LogTab)
		self.ProcessesTableView.setObjectName(_fromUtf8("ProcessesTableView"))
		self.horizontalLayout_5.addWidget(self.ProcessesTableView)
		self.BottomTabWidget.addTab(self.LogTab, _fromUtf8(""))
#		self.TerminalTab = QtGui.QWidget()
#		self.TerminalTab.setObjectName(_fromUtf8("TerminalTab"))
#		self.BottomTabWidget.addTab(self.TerminalTab, _fromUtf8(""))
#		self.PythonTab = QtGui.QWidget()
#		self.PythonTab.setObjectName(_fromUtf8("PythonTab"))
#		self.BottomTabWidget.addTab(self.PythonTab, _fromUtf8(""))		

	def setupMenuBar(self, MainWindow):
		self.menubar = QtGui.QMenuBar(MainWindow)
		self.menubar.setGeometry(QtCore.QRect(0, 0, 1010, 25))
		self.menubar.setObjectName(_fromUtf8("menubar"))
		self.menuFile = QtGui.QMenu(self.menubar)
		self.menuFile.setObjectName(_fromUtf8("menuFile"))
#		self.menuEdit = QtGui.QMenu(self.menubar)
#		self.menuEdit.setObjectName(_fromUtf8("menuEdit"))
		self.menuSettings = QtGui.QMenu(self.menubar)
		self.menuSettings.setObjectName(_fromUtf8("menuSettings"))
		self.menuHelp = QtGui.QMenu(self.menubar)
		self.menuHelp.setObjectName(_fromUtf8("menuHelp"))
		MainWindow.setMenuBar(self.menubar)
		self.statusbar = QtGui.QStatusBar(MainWindow)
		self.statusbar.setObjectName(_fromUtf8("statusbar"))
		MainWindow.setStatusBar(self.statusbar)
		self.actionExit = QtGui.QAction(MainWindow)
		self.actionExit.setObjectName(_fromUtf8("actionExit"))
		self.actionOpen = QtGui.QAction(MainWindow)
		self.actionOpen.setObjectName(_fromUtf8("actionOpen"))
		self.actionSave = QtGui.QAction(MainWindow)
		self.actionSave.setObjectName(_fromUtf8("actionSave"))
		self.actionImportNmap = QtGui.QAction(MainWindow)
		self.actionImportNmap.setObjectName(_fromUtf8("actionImportNmap"))
		self.actionSaveAs = QtGui.QAction(MainWindow)
		self.actionSaveAs.setObjectName(_fromUtf8("actionSaveAs"))
		self.actionNew = QtGui.QAction(MainWindow)
		self.actionNew.setObjectName(_fromUtf8("actionNew"))
		self.actionAddHosts = QtGui.QAction(MainWindow)
		self.actionAddHosts.setObjectName(_fromUtf8("actionAddHosts"))
		self.menuFile.addAction(self.actionNew)
		self.menuFile.addAction(self.actionOpen)
		self.menuFile.addAction(self.actionSave)
		self.menuFile.addAction(self.actionSaveAs)
		self.menuFile.addSeparator()
		self.menuFile.addAction(self.actionAddHosts)
		self.menuFile.addAction(self.actionImportNmap)
		self.menuFile.addSeparator()
		self.menuFile.addAction(self.actionExit)
		self.menubar.addAction(self.menuFile.menuAction())
#		self.menubar.addAction(self.menuEdit.menuAction())
#		self.menubar.addAction(self.menuSettings.menuAction())
		self.menubar.addAction(self.menuSettings.menuAction())
		self.actionSettings = QtGui.QAction(MainWindow)
		self.actionSettings.setObjectName(_fromUtf8("getSettingsMenu"))
		self.menuSettings.addAction(self.actionSettings)

		self.actionHelp = QtGui.QAction(MainWindow)
		self.actionHelp.setObjectName(_fromUtf8("getHelp"))
		self.menuHelp.addAction(self.actionHelp)
		self.menubar.addAction(self.menuHelp.menuAction())		

	def setDefaultIndexes(self):
		self.MainTabWidget.setCurrentIndex(1)
		self.HostsTabWidget.setCurrentIndex(1)
		self.ServicesTabWidget.setCurrentIndex(1)
		self.BruteTabWidget.setCurrentIndex(1)
		self.BottomTabWidget.setCurrentIndex(0)		

	def retranslateUi(self, MainWindow):
		MainWindow.setWindowTitle(QtGui.QApplication.translate("MainWindow", "Sparta v0.0001", None, QtGui.QApplication.UnicodeUTF8))
		self.HostsTabWidget.setTabText(self.HostsTabWidget.indexOf(self.HostsTab), QtGui.QApplication.translate("MainWindow", "Hosts", None, QtGui.QApplication.UnicodeUTF8))
		self.HostsTabWidget.setTabText(self.HostsTabWidget.indexOf(self.ServicesLeftTab), QtGui.QApplication.translate("MainWindow", "Services", None, QtGui.QApplication.UnicodeUTF8))
		self.HostsTabWidget.setTabText(self.HostsTabWidget.indexOf(self.ToolsTab), QtGui.QApplication.translate("MainWindow", "Tools", None, QtGui.QApplication.UnicodeUTF8))
		self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.ServicesRightTab), QtGui.QApplication.translate("MainWindow", "Services", None, QtGui.QApplication.UnicodeUTF8))
		self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.ScriptsTab), QtGui.QApplication.translate("MainWindow", "Scripts", None, QtGui.QApplication.UnicodeUTF8))
		self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.InformationTab), QtGui.QApplication.translate("MainWindow", "Information", None, QtGui.QApplication.UnicodeUTF8))
		self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.NotesTab), QtGui.QApplication.translate("MainWindow", "Notes", None, QtGui.QApplication.UnicodeUTF8))
#		self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.ScreenshotsTab), QtGui.QApplication.translate("MainWindow", "Screenshots", None, QtGui.QApplication.UnicodeUTF8))
		self.MainTabWidget.setTabText(self.MainTabWidget.indexOf(self.ScanTab), QtGui.QApplication.translate("MainWindow", "Scan", None, QtGui.QApplication.UnicodeUTF8))
		#self.BruteTabWidget.setTabText(self.BruteTabWidget.indexOf(self.tab), QtGui.QApplication.translate("MainWindow", "Tab 1", None, QtGui.QApplication.UnicodeUTF8))
		#self.BruteTabWidget.setTabText(self.BruteTabWidget.indexOf(self.tab_2), QtGui.QApplication.translate("MainWindow", "Tab 2", None, QtGui.QApplication.UnicodeUTF8))
		self.MainTabWidget.setTabText(self.MainTabWidget.indexOf(self.BruteTab), QtGui.QApplication.translate("MainWindow", "Brute", None, QtGui.QApplication.UnicodeUTF8))
		self.BottomTabWidget.setTabText(self.BottomTabWidget.indexOf(self.LogTab), QtGui.QApplication.translate("MainWindow", "Log", None, QtGui.QApplication.UnicodeUTF8))
#		self.BottomTabWidget.setTabText(self.BottomTabWidget.indexOf(self.TerminalTab), QtGui.QApplication.translate("MainWindow", "Terminal", None, QtGui.QApplication.UnicodeUTF8))
#		self.BottomTabWidget.setTabText(self.BottomTabWidget.indexOf(self.PythonTab), QtGui.QApplication.translate("MainWindow", "Python", None, QtGui.QApplication.UnicodeUTF8))
		self.menuFile.setTitle(QtGui.QApplication.translate("MainWindow", "File", None, QtGui.QApplication.UnicodeUTF8))
#		self.menuEdit.setTitle(QtGui.QApplication.translate("MainWindow", "Edit", None, QtGui.QApplication.UnicodeUTF8))
#		self.menuSettings.setTitle(QtGui.QApplication.translate("MainWindow", "Settings", None, QtGui.QApplication.UnicodeUTF8))
		self.menuHelp.setTitle(QtGui.QApplication.translate("MainWindow", "Help", None, QtGui.QApplication.UnicodeUTF8))
		self.actionExit.setText(QtGui.QApplication.translate("MainWindow", "Exit", None, QtGui.QApplication.UnicodeUTF8))
		self.actionExit.setToolTip(QtGui.QApplication.translate("MainWindow", "Exit the application", None, QtGui.QApplication.UnicodeUTF8))
		self.actionExit.setShortcut(QtGui.QApplication.translate("MainWindow", "Ctrl+Q", None, QtGui.QApplication.UnicodeUTF8))
		self.actionOpen.setText(QtGui.QApplication.translate("MainWindow", "Open", None, QtGui.QApplication.UnicodeUTF8))
		self.actionOpen.setToolTip(QtGui.QApplication.translate("MainWindow", "Open an existing project file", None, QtGui.QApplication.UnicodeUTF8))
		self.actionOpen.setShortcut(QtGui.QApplication.translate("MainWindow", "Ctrl+O", None, QtGui.QApplication.UnicodeUTF8))
		self.actionSave.setText(QtGui.QApplication.translate("MainWindow", "Save", None, QtGui.QApplication.UnicodeUTF8))
		self.actionSave.setToolTip(QtGui.QApplication.translate("MainWindow", "Save the current project", None, QtGui.QApplication.UnicodeUTF8))
		self.actionSave.setShortcut(QtGui.QApplication.translate("MainWindow", "Ctrl+S", None, QtGui.QApplication.UnicodeUTF8))
		self.actionImportNmap.setText(QtGui.QApplication.translate("MainWindow", "Import nmap", None, QtGui.QApplication.UnicodeUTF8))
		self.actionImportNmap.setToolTip(QtGui.QApplication.translate("MainWindow", "Import an nmap xml file", None, QtGui.QApplication.UnicodeUTF8))
		self.actionImportNmap.setShortcut(QtGui.QApplication.translate("MainWindow", "Ctrl+I", None, QtGui.QApplication.UnicodeUTF8))
		self.actionSaveAs.setText(QtGui.QApplication.translate("MainWindow", "Save As", None, QtGui.QApplication.UnicodeUTF8))
		self.actionNew.setText(QtGui.QApplication.translate("MainWindow", "New", None, QtGui.QApplication.UnicodeUTF8))
		self.actionNew.setShortcut(QtGui.QApplication.translate("MainWindow", "Ctrl+N", None, QtGui.QApplication.UnicodeUTF8))
		self.actionAddHosts.setText(QtGui.QApplication.translate("MainWindow", "Add host(s) to scope", None, QtGui.QApplication.UnicodeUTF8))
		self.actionAddHosts.setShortcut(QtGui.QApplication.translate("MainWindow", "Ctrl+H", None, QtGui.QApplication.UnicodeUTF8))
		self.actionSettings.setText(QtGui.QApplication.translate("MainWindow", "Preferences", None, QtGui.QApplication.UnicodeUTF8))
		self.actionHelp.setText(QtGui.QApplication.translate("MainWindow", "Help", None, QtGui.QApplication.UnicodeUTF8))
		self.actionHelp.setShortcut(QtGui.QApplication.translate("MainWindow", "F1", None, QtGui.QApplication.UnicodeUTF8))

if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

