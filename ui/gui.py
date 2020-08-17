#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2020 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from PyQt5 import QtCore
from PyQt5.QtCore import Qt, QMetaObject, QSize, QRect
from PyQt5.QtGui import QIcon, QPixmap, QFont
from PyQt5.QtWidgets import QWidget, QGridLayout, QSplitter, QTabWidget, QSizePolicy
from PyQt5.QtWidgets import QLineEdit, QToolButton, QVBoxLayout, QHBoxLayout, QTableView
from PyQt5.QtWidgets import QTextEdit, QPlainTextEdit, QMenuBar, QMenu, QStatusBar
from PyQt5.QtWidgets import QAction, QApplication
from ui.dialogs import ImageViewer

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(1010, 754)
        
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))    # do not change this name
        self.gridLayout = QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.splitter_2 = QSplitter(self.centralwidget)
        self.splitter_2.setOrientation(Qt.Vertical)
        self.splitter_2.setObjectName(_fromUtf8("splitter_2"))
        
        self.MainTabWidget = QTabWidget(self.splitter_2)
        self.MainTabWidget.setObjectName(_fromUtf8("MainTabWidget"))
        self.ScanTab = QWidget()
        self.ScanTab.setObjectName(_fromUtf8("ScanTab"))
        self.gridLayout_2 = QGridLayout(self.ScanTab)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.splitter = QSplitter(self.ScanTab)
        self.splitter.setOrientation(Qt.Horizontal)
        self.splitter.setObjectName(_fromUtf8("splitter"))
    
        # size policies
        self.sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.sizePolicy.setHorizontalStretch(0)                         # this specifies that the widget will keep its width when the window is resized
        self.sizePolicy.setVerticalStretch(0)
        
        self.sizePolicy2 = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.sizePolicy2.setHorizontalStretch(1)                        # this specifies that the widget will expand its width when the window is resized
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
        QMetaObject.connectSlotsByName(MainWindow)

    def setupLeftPanel(self):
        self.HostsTabWidget = QTabWidget(self.splitter)
        self.sizePolicy.setHeightForWidth(self.HostsTabWidget.sizePolicy().hasHeightForWidth())
        self.HostsTabWidget.setSizePolicy(self.sizePolicy)
        self.HostsTabWidget.setObjectName(_fromUtf8("HostsTabWidget"))

        self.HostsTab = QWidget()
        self.HostsTab.setObjectName(_fromUtf8("HostsTab"))
        self.keywordTextInput = QLineEdit()
        self.FilterApplyButton = QToolButton()
        self.searchIcon = QIcon()
        self.searchIcon.addPixmap(QPixmap(_fromUtf8("./images/search.png")), QIcon.Normal, QIcon.Off)
        self.FilterApplyButton.setIconSize(QSize(29,21))
        self.FilterApplyButton.setIcon(self.searchIcon)
        self.FilterAdvancedButton = QToolButton()
        self.advancedIcon = QIcon()
        self.advancedIcon.addPixmap(QPixmap(_fromUtf8("./images/advanced.png")), QIcon.Normal, QIcon.Off)
        self.FilterAdvancedButton.setIconSize(QSize(19,19))
        self.FilterAdvancedButton.setIcon(self.advancedIcon)
        self.vlayout = QVBoxLayout(self.HostsTab)
        self.vlayout.setObjectName(_fromUtf8("vlayout"))
        self.HostsTableView = QTableView(self.HostsTab)
        self.HostsTableView.setObjectName(_fromUtf8("HostsTableView"))
        self.vlayout.addWidget(self.HostsTableView)
        
        self.addHostsOverlay = QTextEdit(self.HostsTab)           # the overlay widget that appears over the hosttableview        
        self.addHostsOverlay.setObjectName(_fromUtf8("addHostsOverlay"))
        self.addHostsOverlay.setText('Click here to add host(s) to scope')
        self.addHostsOverlay.setReadOnly(True)
        self.addHostsOverlay.setContextMenuPolicy(Qt.NoContextMenu)

        ###
        self.addHostsOverlay.setFont(QFont('', 12))
        self.addHostsOverlay.setAlignment(Qt.AlignHCenter|Qt.AlignVCenter)
        ###
        
        self.vlayout.addWidget(self.addHostsOverlay)
        self.hlayout = QHBoxLayout()
        self.hlayout.addWidget(self.keywordTextInput)
        self.hlayout.addWidget(self.FilterApplyButton)
        self.hlayout.addWidget(self.FilterAdvancedButton)
        self.vlayout.addLayout(self.hlayout)
        self.HostsTabWidget.addTab(self.HostsTab, _fromUtf8(""))

        self.ServicesLeftTab = QWidget()
        self.ServicesLeftTab.setObjectName(_fromUtf8("ServicesLeftTab"))
        self.horizontalLayout_2 = QHBoxLayout(self.ServicesLeftTab)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.ServiceNamesTableView = QTableView(self.ServicesLeftTab)
        self.ServiceNamesTableView.setObjectName(_fromUtf8("ServiceNamesTableView"))
        self.horizontalLayout_2.addWidget(self.ServiceNamesTableView)
        self.HostsTabWidget.addTab(self.ServicesLeftTab, _fromUtf8(""))

        self.ToolsTab = QWidget()
        self.ToolsTab.setObjectName(_fromUtf8("ToolsTab"))
        self.horizontalLayout_3 = QHBoxLayout(self.ToolsTab)
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.ToolsTableView = QTableView(self.ToolsTab)
        self.ToolsTableView.setObjectName(_fromUtf8("ToolsTableView"))
        self.horizontalLayout_3.addWidget(self.ToolsTableView)
        self.HostsTabWidget.addTab(self.ToolsTab, _fromUtf8(""))        

    def setupRightPanel(self):
        self.ServicesTabWidget = QTabWidget()
        self.ServicesTabWidget.setEnabled(True)
        self.sizePolicy2.setHeightForWidth(self.ServicesTabWidget.sizePolicy().hasHeightForWidth())
        self.ServicesTabWidget.setSizePolicy(self.sizePolicy2)
        self.ServicesTabWidget.setObjectName(_fromUtf8("ServicesTabWidget"))        
        self.splitter.addWidget(self.ServicesTabWidget)

        ###

        self.splitter_3 = QSplitter()
        self.splitter_3.setOrientation(Qt.Horizontal)
        self.splitter_3.setObjectName(_fromUtf8("splitter_3"))
        self.splitter_3.setSizePolicy(self.sizePolicy2)                 # this makes the tools tab stay the same width when resizing the window
        
        ###
        
        self.ToolHostsWidget = QWidget()
        self.ToolHostsWidget.setObjectName(_fromUtf8("ToolHostsTab"))       
        self.ToolHostsLayout = QVBoxLayout(self.ToolHostsWidget)
        self.ToolHostsLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.ToolHostsTableView = QTableView(self.ToolHostsWidget)
        self.ToolHostsTableView.setObjectName(_fromUtf8("ServicesTableView"))
        self.ToolHostsLayout.addWidget(self.ToolHostsTableView)
        self.splitter_3.addWidget(self.ToolHostsWidget)
        
        self.DisplayWidget = QWidget()
        self.DisplayWidget.setObjectName('ToolOutput')
        self.DisplayWidget.setSizePolicy(self.sizePolicy2)
        #self.toolOutputTextView = QTextEdit(self.DisplayWidget)
        self.toolOutputTextView = QPlainTextEdit(self.DisplayWidget)
        self.toolOutputTextView.setReadOnly(True)
        self.DisplayWidgetLayout = QHBoxLayout(self.DisplayWidget)
        self.DisplayWidgetLayout.addWidget(self.toolOutputTextView)
        self.splitter_3.addWidget(self.DisplayWidget)

        self.ScreenshotWidget = ImageViewer()
        self.ScreenshotWidget.setObjectName('Screenshot')
        self.ScreenshotWidget.scrollArea.setSizePolicy(self.sizePolicy2)
        self.ScreenshotWidget.scrollArea.setContextMenuPolicy(Qt.CustomContextMenu)
        self.splitter_3.addWidget(self.ScreenshotWidget.scrollArea)

        self.splitter.addWidget(self.splitter_3)

        ###
        
        self.ServicesRightTab = QWidget()
        self.ServicesRightTab.setObjectName(_fromUtf8("ServicesRightTab"))
        self.verticalLayout = QVBoxLayout(self.ServicesRightTab)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.ServicesTableView = QTableView(self.ServicesRightTab)
        self.ServicesTableView.setObjectName(_fromUtf8("ServicesTableView"))
        self.verticalLayout.addWidget(self.ServicesTableView)
        self.ServicesTabWidget.addTab(self.ServicesRightTab, _fromUtf8(""))
        
        self.ScriptsTab = QWidget()
        self.ScriptsTab.setObjectName(_fromUtf8("ScriptsTab"))
        self.horizontalLayout_6 = QHBoxLayout(self.ScriptsTab)
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
                
        self.splitter_4 = QSplitter(self.ScriptsTab)
        self.splitter_4.setOrientation(Qt.Horizontal)
        self.splitter_4.setObjectName(_fromUtf8("splitter_4"))
        
        self.ScriptsTableView = QTableView()
        self.ScriptsTableView.setObjectName(_fromUtf8("ScriptsTableView"))      
        self.splitter_4.addWidget(self.ScriptsTableView)
        
        self.ScriptsOutputTextEdit = QPlainTextEdit()
        self.ScriptsOutputTextEdit.setObjectName(_fromUtf8("ScriptsOutputTextEdit"))
        self.ScriptsOutputTextEdit.setReadOnly(True)        
        self.splitter_4.addWidget(self.ScriptsOutputTextEdit)       
        self.horizontalLayout_6.addWidget(self.splitter_4)  
        self.ServicesTabWidget.addTab(self.ScriptsTab, _fromUtf8(""))
        
        self.InformationTab = QWidget()
        self.InformationTab.setObjectName(_fromUtf8("InformationTab"))          
        self.ServicesTabWidget.addTab(self.InformationTab, _fromUtf8(""))
        
        self.NotesTab = QWidget()
        self.NotesTab.setObjectName(_fromUtf8("NotesTab"))
        self.horizontalLayout_4 = QHBoxLayout(self.NotesTab)
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        #self.NotesTextEdit = QTextEdit(self.NotesTab)
        self.NotesTextEdit = QPlainTextEdit(self.NotesTab)
        self.NotesTextEdit.setObjectName(_fromUtf8("NotesTextEdit"))
        self.horizontalLayout_4.addWidget(self.NotesTextEdit)
        self.ServicesTabWidget.addTab(self.NotesTab, _fromUtf8(""))     

    def setupMainTabs(self):
        self.gridLayout_2.addWidget(self.splitter, 0, 0, 1, 1)
        self.gridLayout_3 = QGridLayout()
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))  
        self.gridLayout_2.addLayout(self.gridLayout_3, 0, 0, 1, 1)
        self.MainTabWidget.addTab(self.ScanTab, _fromUtf8(""))  
        
        self.BruteTab = QWidget()
        self.BruteTab.setObjectName(_fromUtf8("BruteTab"))
        self.horizontalLayout_7 = QHBoxLayout(self.BruteTab)
        self.horizontalLayout_7.setObjectName(_fromUtf8("horizontalLayout_7"))
        self.BruteTabWidget = QTabWidget(self.BruteTab)
        self.BruteTabWidget.setObjectName(_fromUtf8("BruteTabWidget"))
        self.horizontalLayout_7.addWidget(self.BruteTabWidget)
        self.MainTabWidget.addTab(self.BruteTab, _fromUtf8(""))     

    def setupBottomPanel(self):
        self.BottomTabWidget = QTabWidget(self.splitter_2)
        self.BottomTabWidget.setSizeIncrement(QSize(0, 0))
        self.BottomTabWidget.setBaseSize(QSize(0, 0))
        self.BottomTabWidget.setObjectName(_fromUtf8("BottomTabWidget"))
        
        self.LogTab = QWidget()
        self.LogTab.setObjectName(_fromUtf8("LogTab"))
        self.horizontalLayout_5 = QHBoxLayout(self.LogTab)
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        self.ProcessesTableView = QTableView(self.LogTab)
        self.ProcessesTableView.setObjectName(_fromUtf8("ProcessesTableView"))
        self.horizontalLayout_5.addWidget(self.ProcessesTableView)
        self.BottomTabWidget.addTab(self.LogTab, _fromUtf8(""))
#       self.TerminalTab = QWidget()
#       self.TerminalTab.setObjectName(_fromUtf8("TerminalTab"))
#       self.BottomTabWidget.addTab(self.TerminalTab, _fromUtf8(""))
#       self.PythonTab = QWidget()
#       self.PythonTab.setObjectName(_fromUtf8("PythonTab"))
#       self.BottomTabWidget.addTab(self.PythonTab, _fromUtf8(""))      

    def setupMenuBar(self, MainWindow):
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setGeometry(QRect(0, 0, 1010, 25))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        self.menuFile = QMenu(self.menubar)
        self.menuFile.setObjectName(_fromUtf8("menuFile"))
#       self.menuEdit = QMenu(self.menubar)
#       self.menuEdit.setObjectName(_fromUtf8("menuEdit"))
#        self.menuSettings = QMenu(self.menubar)
#        self.menuSettings.setObjectName(_fromUtf8("menuSettings"))
        self.menuHelp = QMenu(self.menubar)
        self.menuHelp.setObjectName(_fromUtf8("menuHelp"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)
        self.actionExit = QAction(MainWindow)
        self.actionExit.setObjectName(_fromUtf8("actionExit"))
        self.actionOpen = QAction(MainWindow)
        self.actionOpen.setObjectName(_fromUtf8("actionOpen"))
        self.actionSave = QAction(MainWindow)
        self.actionSave.setObjectName(_fromUtf8("actionSave"))
        self.actionImportNmap = QAction(MainWindow)
        self.actionImportNmap.setObjectName(_fromUtf8("actionImportNmap"))
        self.actionSaveAs = QAction(MainWindow)
        self.actionSaveAs.setObjectName(_fromUtf8("actionSaveAs"))
        self.actionNew = QAction(MainWindow)
        self.actionNew.setObjectName(_fromUtf8("actionNew"))
        self.actionAddHosts = QAction(MainWindow)
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
#       self.menubar.addAction(self.menuEdit.menuAction())
#       self.menubar.addAction(self.menuSettings.menuAction())
#        self.menubar.addAction(self.menuSettings.menuAction())
#        self.actionSettings = QAction(MainWindow)
#        self.actionSettings.setObjectName(_fromUtf8("getSettingsMenu"))
#        self.menuSettings.addAction(self.actionSettings)

        self.actionHelp = QAction(MainWindow)
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
        MainWindow.setWindowTitle(QApplication.translate("MainWindow", "SPARTA 2.0", None))
        self.HostsTabWidget.setTabText(self.HostsTabWidget.indexOf(self.HostsTab), QApplication.translate("MainWindow", "Hosts", None))
        self.HostsTabWidget.setTabText(self.HostsTabWidget.indexOf(self.ServicesLeftTab), QApplication.translate("MainWindow", "Services", None))
        self.HostsTabWidget.setTabText(self.HostsTabWidget.indexOf(self.ToolsTab), QApplication.translate("MainWindow", "Tools", None))
        self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.ServicesRightTab), QApplication.translate("MainWindow", "Services", None))
        self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.ScriptsTab), QApplication.translate("MainWindow", "Scripts", None))
        self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.InformationTab), QApplication.translate("MainWindow", "Information", None))
        self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.NotesTab), QApplication.translate("MainWindow", "Notes", None))
#       self.ServicesTabWidget.setTabText(self.ServicesTabWidget.indexOf(self.ScreenshotsTab), QApplication.translate("MainWindow", "Screenshots", None))
        self.MainTabWidget.setTabText(self.MainTabWidget.indexOf(self.ScanTab), QApplication.translate("MainWindow", "Scan", None))
        #self.BruteTabWidget.setTabText(self.BruteTabWidget.indexOf(self.tab), QApplication.translate("MainWindow", "Tab 1", None))
        #self.BruteTabWidget.setTabText(self.BruteTabWidget.indexOf(self.tab_2), QApplication.translate("MainWindow", "Tab 2", None))
        self.MainTabWidget.setTabText(self.MainTabWidget.indexOf(self.BruteTab), QApplication.translate("MainWindow", "Brute", None))
        self.BottomTabWidget.setTabText(self.BottomTabWidget.indexOf(self.LogTab), QApplication.translate("MainWindow", "Log", None))
#       self.BottomTabWidget.setTabText(self.BottomTabWidget.indexOf(self.TerminalTab), QApplication.translate("MainWindow", "Terminal", None))
#       self.BottomTabWidget.setTabText(self.BottomTabWidget.indexOf(self.PythonTab), QApplication.translate("MainWindow", "Python", None))
        self.menuFile.setTitle(QApplication.translate("MainWindow", "File", None))
#       self.menuEdit.setTitle(QApplication.translate("MainWindow", "Edit", None))
#       self.menuSettings.setTitle(QApplication.translate("MainWindow", "Settings", None))
        self.menuHelp.setTitle(QApplication.translate("MainWindow", "Help", None))
        self.actionExit.setText(QApplication.translate("MainWindow", "Exit", None))
        self.actionExit.setToolTip(QApplication.translate("MainWindow", "Exit the application", None))
        self.actionExit.setShortcut(QApplication.translate("MainWindow", "Ctrl+Q", None))
        self.actionOpen.setText(QApplication.translate("MainWindow", "Open", None))
        self.actionOpen.setToolTip(QApplication.translate("MainWindow", "Open an existing project file", None))
        self.actionOpen.setShortcut(QApplication.translate("MainWindow", "Ctrl+O", None))
        self.actionSave.setText(QApplication.translate("MainWindow", "Save", None))
        self.actionSave.setToolTip(QApplication.translate("MainWindow", "Save the current project", None))
        self.actionSave.setShortcut(QApplication.translate("MainWindow", "Ctrl+S", None))
        self.actionImportNmap.setText(QApplication.translate("MainWindow", "Import nmap", None))
        self.actionImportNmap.setToolTip(QApplication.translate("MainWindow", "Import an nmap xml file", None))
        self.actionImportNmap.setShortcut(QApplication.translate("MainWindow", "Ctrl+I", None))
        self.actionSaveAs.setText(QApplication.translate("MainWindow", "Save As", None))
        self.actionNew.setText(QApplication.translate("MainWindow", "New", None))
        self.actionNew.setShortcut(QApplication.translate("MainWindow", "Ctrl+N", None))
        self.actionAddHosts.setText(QApplication.translate("MainWindow", "Add host(s) to scope", None))
        self.actionAddHosts.setShortcut(QApplication.translate("MainWindow", "Ctrl+H", None))
        #self.actionSettings.setText(QApplication.translate("MainWindow", "Preferences", None))
        self.actionHelp.setText(QApplication.translate("MainWindow", "Help", None))
        self.actionHelp.setShortcut(QApplication.translate("MainWindow", "F1", None))

"""
if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    MainWindow = QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

"""