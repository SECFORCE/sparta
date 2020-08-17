#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2020 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os
#from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QImage, QPixmap, QMovie, QFont
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QWidget, QPlainTextEdit
from PyQt5.QtWidgets import QSizePolicy, QScrollArea, QMessageBox, QLineEdit, QSpacerItem, QCheckBox
from PyQt5.QtWidgets import QPushButton, QRadioButton, QComboBox, QGroupBox, QButtonGroup, QFileDialog

from app.auxiliary import getTimestamp

# progress bar widget that displayed when long operations are taking place (eg: nmap, opening project)
class ProgressWidget(QDialog):
    def __init__(self, text, parent=None):
        QDialog.__init__(self, parent)
        self.text = text
        self.setWindowTitle(text)
        self.setupLayout()

    def setupLayout(self):
        self.setWindowModality(True)
        vbox = QVBoxLayout()
        self.label = QLabel('')
        self.progressBar = QProgressBar()
        vbox.addWidget(self.label)
        vbox.addWidget(self.progressBar)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        vbox.addLayout(hbox)
        self.setLayout(vbox)

    def setProgress(self, progress):
        self.progressBar.setValue(progress)

    def setText(self, text):
        self.text = text
        self.setWindowTitle(text)
        
    def reset(self, text):
        self.text = text
        self.setWindowTitle(text)
        self.setProgress(0)

# this class is used to display screenshots and perform zoom operations on the images
class ImageViewer(QWidget):
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)

        self.scaleFactor = 0.0

        self.imageLabel = QLabel()
        self.imageLabel.setBackgroundRole(QPalette.Base)
        self.imageLabel.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored)
        self.imageLabel.setScaledContents(True)

        self.scrollArea = QScrollArea()
        self.scrollArea.setBackgroundRole(QPalette.Dark)
        self.scrollArea.setWidget(self.imageLabel)

    def open(self, fileName):
        if fileName:
            image = QImage(fileName)
            if image.isNull():
                QMessageBox.information(self, "Image Viewer","Cannot load %s." % fileName)
                return

            self.imageLabel.setPixmap(QPixmap.fromImage(image))
            self.scaleFactor = 1.0                
            self.fitToWindow()                                          # by default, fit to window/widget size

    def zoomIn(self):
        self.scaleImage(1.25)

    def zoomOut(self):
        self.scaleImage(0.8)

    def normalSize(self):
        self.fitToWindow(False)
        self.imageLabel.adjustSize()
        self.scaleFactor = 1.0

    def fitToWindow(self, fit=True):
        self.scrollArea.setWidgetResizable(fit)

    def scaleImage(self, factor):
        self.fitToWindow(False)
        self.scaleFactor *= factor
        self.imageLabel.resize(self.scaleFactor * self.imageLabel.pixmap().size())

        self.adjustScrollBar(self.scrollArea.horizontalScrollBar(), factor)
        self.adjustScrollBar(self.scrollArea.verticalScrollBar(), factor)

    def adjustScrollBar(self, scrollBar, factor):
        scrollBar.setValue(int(factor * scrollBar.value() + ((factor - 1) * scrollBar.pageStep()/2)))

# this class is used to display the process status GIFs
class ImagePlayer(QWidget):
    def __init__(self, filename, parent=None):
        QWidget.__init__(self, parent)
        self.movie = QMovie(filename)                             # load the file into a QMovie
        self.movie_screen = QLabel()
        self.movie_screen.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.movie_screen)
        self.setLayout(main_layout)
        self.movie.setCacheMode(QMovie.CacheAll)
        self.movie.setSpeed(100)
        self.movie_screen.setMovie(self.movie)
        self.movie.start()
#       self.show()

# dialog shown when the user selects "Add host(s)" from the menu
class AddHostsDialog(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)
        self.setupLayout()
        
    def setupLayout(self):
        self.setModal(True)
        self.setWindowTitle('Add host(s) to scope')
        self.setFixedSize(340, 210)

        self.flayout = QVBoxLayout()
        
        self.label1 = QLabel(self)
        self.label1.setText('IP Range')
        self.textinput = QLineEdit(self)
        self.hlayout = QHBoxLayout()
        self.hlayout.addWidget(self.label1)
        self.hlayout.addWidget(self.textinput)        
        
        self.label2 = QLabel(self)
        self.label2.setText('eg: 192.168.1.0/24 10.10.10.10-20 1.2.3.4 ')
        self.font = QFont('Arial', 10)
        self.label2.setFont(self.font)
        self.label2.setAlignment(Qt.AlignRight)
        self.spacer = QSpacerItem(15,15)
        ###
        self.validationLabel = QLabel(self)
        self.validationLabel.setText('Invalid input. Please try again!')
        self.validationLabel.setStyleSheet('QLabel { color: red }')
        ###
        self.spacer2 = QSpacerItem(5,5)
        
        self.discovery = QCheckBox(self)
        self.discovery.setText('Run nmap host discovery')
        self.discovery.toggle()     # on by default
        self.nmap = QCheckBox(self)
        self.nmap.setText('Run staged nmap scan')
        self.nmap.toggle()          # on by default
        
        self.cancelButton = QPushButton('Cancel', self)
        self.cancelButton.setMaximumSize(110, 30)
        self.addButton = QPushButton('Add to scope', self)
        self.addButton.setMaximumSize(110, 30)
        self.addButton.setDefault(True)
        self.hlayout2 = QHBoxLayout()
        self.hlayout2.addWidget(self.cancelButton)
        self.hlayout2.addWidget(self.addButton)
        self.flayout.addLayout(self.hlayout)
        self.flayout.addWidget(self.label2)
        ###
        self.flayout.addWidget(self.validationLabel)
        self.validationLabel.hide()
        ###
        self.flayout.addItem(self.spacer)
        self.flayout.addWidget(self.discovery)
        self.flayout.addWidget(self.nmap)
        self.flayout.addItem(self.spacer2)
        self.flayout.addLayout(self.hlayout2)
        self.setLayout(self.flayout)

class BruteWidget(QWidget):
    
    def __initold__(self, ip, port, service, hydraServices, hydraNoUsernameServices, hydraNoPasswordServices, bruteSettings, generalSettings, parent=None):
        QWidget.__init__(self, parent)
        self.ip = ip
        self.port = port
        self.service = service
        self.hydraServices = hydraServices
        self.hydraNoUsernameServices = hydraNoUsernameServices
        self.hydraNoPasswordServices = hydraNoPasswordServices
        self.bruteSettings = bruteSettings
        self.generalSettings = generalSettings
        self.pid = -1                                                   # will store hydra's pid so we can kill it
        self.setupLayout()
        
        self.browseUsersButton.clicked.connect(lambda: self.wordlistDialog())
        self.browsePasswordsButton.clicked.connect(lambda: self.wordlistDialog('Choose password list'))
        self.usersTextinput.textEdited.connect(self.singleUserRadio.toggle)
        self.passwordsTextinput.textEdited.connect(self.singlePassRadio.toggle)
        self.userlistTextinput.textEdited.connect(self.userListRadio.toggle)
        self.passlistTextinput.textEdited.connect(self.passListRadio.toggle)
        self.checkAddMoreOptions.stateChanged.connect(self.showMoreOptions)
        
    def __init__(self, ip, port, service, settings, parent=None):
        QWidget.__init__(self, parent)
        self.ip = ip
        self.port = port
        self.service = service

#       self.hydraServices = hydraServices
#       self.hydraNoUsernameServices = hydraNoUsernameServices
#       self.hydraNoPasswordServices = hydraNoPasswordServices
#       self.bruteSettings = bruteSettings
#       self.generalSettings = generalSettings
        self.settings = settings
        self.pid = -1                                                   # will store hydra's pid so we can kill it
        self.setupLayout()
        
        self.browseUsersButton.clicked.connect(lambda: self.wordlistDialog())
        self.browsePasswordsButton.clicked.connect(lambda: self.wordlistDialog('Choose password list'))
        self.usersTextinput.textEdited.connect(self.singleUserRadio.toggle)
        self.passwordsTextinput.textEdited.connect(self.singlePassRadio.toggle)
        self.userlistTextinput.textEdited.connect(self.userListRadio.toggle)
        self.passlistTextinput.textEdited.connect(self.passListRadio.toggle)
        self.checkAddMoreOptions.stateChanged.connect(self.showMoreOptions)     
        
    def setupLayout(self):
        
        # sometimes nmap service name is different from hydra service name
        if self.service is None:
            self.service = ''
        elif self.service == "login":
            self.service = "rlogin"
        elif self.service == "ms-sql-s":
            self.service = "mssql"
        elif self.service == "ms-wbt-server":
            self.service = "rdp"
        elif self.service == "netbios-ssn" or self.service == "netbios-ns" or self.service == "microsoft-ds":
            self.service = "smb"
        elif self.service == "postgresql":
            self.service = "postgres"
        elif self.service == "vmware-auth":
            self.service = "vmauthd"

        self.label1 = QLabel()
        self.label1.setText('IP')
        #self.label1.setFixedWidth(10)          # experimental
        #self.label1.setAlignment(Qt.AlignLeft)
        self.ipTextinput = QLineEdit()
        self.ipTextinput.setText(str(self.ip))
        self.ipTextinput.setFixedWidth(125)
        
        self.label2 = QLabel()
        self.label2.setText('Port')
        #self.label2.setFixedWidth(10)          # experimental
        #self.label2.setAlignment(Qt.AlignLeft)
        self.portTextinput = QLineEdit()
        self.portTextinput.setText(str(self.port))
        self.portTextinput.setFixedWidth(60)
        
        self.label3 = QLabel()
        self.label3.setText('Service')
        #self.label3.setFixedWidth(10)          # experimental
        #self.label3.setAlignment(Qt.AlignLeft)
        self.serviceComboBox = QComboBox()
        self.serviceComboBox.insertItems(0, self.settings.brute_services.split(","))
        self.serviceComboBox.setStyleSheet("QComboBox { combobox-popup: 0; }")
        
        # autoselect service from combo box
        for i in range(len(self.settings.brute_services.split(","))):
            if str(self.service) in self.settings.brute_services.split(",")[i]:
                self.serviceComboBox.setCurrentIndex(i)
                break

#       self.labelPath = QLineEdit()                              # this is the extra input field to insert the path to brute force
#       self.labelPath.setFixedWidth(800)
#       self.labelPath.setText('/')

        self.runButton = QPushButton('Run')
        self.runButton.setMaximumSize(110, 30)
        self.runButton.setDefault(True) # new
        
        ###
        self.validationLabel = QLabel(self)
        self.validationLabel.setText('Invalid input. Please try again!')
        self.validationLabel.setStyleSheet('QLabel { color: red }')
        ###

        self.hlayout = QHBoxLayout()
        self.hlayout.addWidget(self.label1)
        self.hlayout.addWidget(self.ipTextinput)
        self.hlayout.addWidget(self.label2)
        self.hlayout.addWidget(self.portTextinput)  
        self.hlayout.addWidget(self.label3)
        self.hlayout.addWidget(self.serviceComboBox)
        self.hlayout.addWidget(self.runButton)
        ###
        self.hlayout.addWidget(self.validationLabel)
        self.validationLabel.hide()
        ###
        self.hlayout.addStretch()

        self.singleUserRadio = QRadioButton()
        self.label4 = QLabel()
        self.label4.setText('Username')
        self.label4.setFixedWidth(70)
        self.usersTextinput = QLineEdit()
        self.usersTextinput.setFixedWidth(125)
        self.usersTextinput.setText(self.settings.brute_default_username)
        self.userListRadio = QRadioButton()
        self.label5 = QLabel()
        self.label5.setText('Username list')
        self.label5.setFixedWidth(90)
        self.userlistTextinput = QLineEdit()
        self.userlistTextinput.setFixedWidth(125)
        self.browseUsersButton = QPushButton('Browse')
        self.browseUsersButton.setMaximumSize(80, 30)
        
        self.foundUsersRadio = QRadioButton()
        self.label9 = QLabel()
        self.label9.setText('Found usernames')
        self.label9.setFixedWidth(117)      
        
        self.userGroup = QButtonGroup()
        self.userGroup.addButton(self.singleUserRadio)
        self.userGroup.addButton(self.userListRadio)
        self.userGroup.addButton(self.foundUsersRadio)
        self.foundUsersRadio.toggle()

        self.hlayout2 = QHBoxLayout()
        self.hlayout2.addWidget(self.singleUserRadio)
        self.hlayout2.addWidget(self.label4)
        self.hlayout2.addWidget(self.usersTextinput)
        self.hlayout2.addWidget(self.userListRadio)
        self.hlayout2.addWidget(self.label5)
        self.hlayout2.addWidget(self.userlistTextinput)
        self.hlayout2.addWidget(self.browseUsersButton)
        self.hlayout2.addWidget(self.foundUsersRadio)
        self.hlayout2.addWidget(self.label9)
        self.hlayout2.addStretch()
        
        #add usernames wordlist
        self.singlePassRadio = QRadioButton()
        self.label6 = QLabel()
        self.label6.setText('Password')
        self.label6.setFixedWidth(70)
        self.passwordsTextinput = QLineEdit()
        self.passwordsTextinput.setFixedWidth(125)
        self.passwordsTextinput.setText(self.settings.brute_default_password)
        self.passListRadio = QRadioButton()
        self.label7 = QLabel()
        self.label7.setText('Password list')
        self.label7.setFixedWidth(90)
        self.passlistTextinput = QLineEdit()
        self.passlistTextinput.setFixedWidth(125)
        self.browsePasswordsButton = QPushButton('Browse')
        self.browsePasswordsButton.setMaximumSize(80, 30)
        
        self.foundPasswordsRadio = QRadioButton()
        self.label10 = QLabel()
        self.label10.setText('Found passwords')
        self.label10.setFixedWidth(115) 
        
        self.passGroup = QButtonGroup()
        self.passGroup.addButton(self.singlePassRadio)
        self.passGroup.addButton(self.passListRadio)
        self.passGroup.addButton(self.foundPasswordsRadio)
        self.foundPasswordsRadio.toggle()

        self.label8 = QLabel()
        self.label8.setText('Threads')
        self.label8.setFixedWidth(60)
        self.threadOptions = []
        for i in range(1, 129):
            self.threadOptions.append(str(i))
        self.threadsComboBox = QComboBox()
        self.threadsComboBox.insertItems(0, self.threadOptions)
        self.threadsComboBox.setMinimumContentsLength(3)
        self.threadsComboBox.setMaxVisibleItems(3)
        self.threadsComboBox.setStyleSheet("QComboBox { combobox-popup: 0; }")
        self.threadsComboBox.setCurrentIndex(15)    
    
        self.hlayout3 = QHBoxLayout()
        self.hlayout3.addWidget(self.singlePassRadio)
        self.hlayout3.addWidget(self.label6)
        self.hlayout3.addWidget(self.passwordsTextinput)
        self.hlayout3.addWidget(self.passListRadio)
        self.hlayout3.addWidget(self.label7)
        self.hlayout3.addWidget(self.passlistTextinput)
        self.hlayout3.addWidget(self.browsePasswordsButton)
        self.hlayout3.addWidget(self.foundPasswordsRadio)
        self.hlayout3.addWidget(self.label10)
        self.hlayout3.addStretch()
        self.hlayout3.addWidget(self.label8)
        self.hlayout3.addWidget(self.threadsComboBox)
        #self.hlayout3.addStretch()

        #label6.setText('Try blank password')
        self.checkBlankPass = QCheckBox()
        self.checkBlankPass.setText('Try blank password')
        self.checkBlankPass.toggle()
        #add 'try blank password'
        #label7.setText('Try login as password')
        self.checkLoginAsPass = QCheckBox()
        self.checkLoginAsPass.setText('Try login as password')
        self.checkLoginAsPass.toggle()
        #add 'try login as password'
        #label8.setText('Loop around users')
        self.checkLoopUsers = QCheckBox()
        self.checkLoopUsers.setText('Loop around users')
        self.checkLoopUsers.toggle()
        #add 'loop around users'
        #label9.setText('Exit on first valid')
        self.checkExitOnValid = QCheckBox()
        self.checkExitOnValid.setText('Exit on first valid')
        self.checkExitOnValid.toggle()
        #add 'exit after first valid combination is found'
        self.checkVerbose = QCheckBox()
        self.checkVerbose.setText('Verbose')        

        self.checkAddMoreOptions = QCheckBox()
        self.checkAddMoreOptions.setText('Additional Options')
        
        ###
        self.labelPath = QLineEdit()                              # this is the extra input field to insert the path to brute force
        self.labelPath.setFixedWidth(800)
        self.labelPath.setText('/')
        ###
        
        self.hlayout4 = QHBoxLayout()
        self.hlayout4.addWidget(self.checkBlankPass)
        self.hlayout4.addWidget(self.checkLoginAsPass)
        self.hlayout4.addWidget(self.checkLoopUsers)
        self.hlayout4.addWidget(self.checkExitOnValid)
        self.hlayout4.addWidget(self.checkVerbose)
        self.hlayout4.addWidget(self.checkAddMoreOptions)
        self.hlayout4.addStretch()

        self.layoutAddOptions = QHBoxLayout()
        self.layoutAddOptions.addWidget(self.labelPath)
        self.labelPath.hide()
        self.layoutAddOptions.addStretch()
        
        self.display = QPlainTextEdit()
        self.display.setReadOnly(True)
        if self.settings.general_tool_output_black_background == 'True':
            #self.display.setStyleSheet("background: rgb(0,0,0)")       # black background
            #self.display.setTextColor(QtGui.QColor('white'))           # white font
            p = self.display.palette()
            p.setColor(QPalette.Base, Qt.black)                   # black background
            p.setColor(QPalette.Text, Qt.white)                   # white font
            self.display.setPalette(p)
            self.display.setStyleSheet("QMenu { color:black;}") #font-size:18px; width: 150px; color:red; left: 20px;}"); # set the menu font color: black
        
        self.vlayout = QVBoxLayout()
        self.vlayout.addLayout(self.hlayout)
        self.vlayout.addLayout(self.hlayout4)
        self.vlayout.addLayout(self.layoutAddOptions)
        self.vlayout.addLayout(self.hlayout2)
        self.vlayout.addLayout(self.hlayout3)
        self.vlayout.addWidget(self.display)
        self.setLayout(self.vlayout)

    # TODO: need to check all the methods that need an additional input field and add them here
#   def showMoreOptions(self, text):
#       if str(text) == "http-head":        
#           self.labelPath.show()
#       else:
#           self.labelPath.hide()
            
    def showMoreOptions(self):
        if self.checkAddMoreOptions.isChecked():
            self.labelPath.show()
        else:
            self.labelPath.hide()

    def wordlistDialog(self, title='Choose username list'):
    
        if title == 'Choose username list':
            filename = QFileDialog.getOpenFileName(self, title, self.settings.brute_username_wordlist_path)
            self.userlistTextinput.setText(str(filename[0]))
            self.userListRadio.toggle()
        else:
            filename = QFileDialog.getOpenFileName(self, title, self.settings.brute_password_wordlist_path)
            self.passlistTextinput.setText(str(filename[0]))
            self.passListRadio.toggle()

    def buildHydraCommand(self, runningfolder, userlistPath, passlistPath):
        
        self.ip = self.ipTextinput.text()
        self.port = self.portTextinput.text()
        self.service = str(self.serviceComboBox.currentText())
        self.command = "hydra "+self.ip+" -s "+self.port+" -o "
        self.outputfile = runningfolder+"/hydra/"+getTimestamp()+"-"+self.ip+"-"+self.port+"-"+self.service+".txt"
        self.command += "\""+self.outputfile+"\""                       # deal with paths with spaces
        
        #self.service = str(self.serviceComboBox.currentText())
        
        #if not self.service == "snmp":                                 # no username required for snmp
        if not self.service in self.settings.brute_no_username_services.split(","):
            if self.singleUserRadio.isChecked():
                self.command += " -l "+self.usersTextinput.text()
            elif self.foundUsersRadio.isChecked():
                self.command += " -L \""+userlistPath+"\""
            else:
                self.command += " -L \""+self.userlistTextinput.text()+"\""
                
        #if not self.service == "smtp-enum":                                # no password required for smtp-enum
        if not self.service in self.settings.brute_no_password_services.split(","):
            if self.singlePassRadio.isChecked():
                escaped_password = self.passwordsTextinput.text().replace('"', '\"\"\"')#.replace("'", "\'")
                self.command += " -p \""+escaped_password+"\""
                
            elif self.foundPasswordsRadio.isChecked():
                self.command += " -P \""+passlistPath+"\""
            else:
                self.command += " -P \""+self.passlistTextinput.text()+"\""

        if self.checkBlankPass.isChecked():
            self.command += " -e n"
            if self.checkLoginAsPass.isChecked():
                self.command += "s"
                
        elif self.checkLoginAsPass.isChecked():
                self.command += " -e s"
                
        if self.checkLoopUsers.isChecked():
            self.command += " -u"
        
        if self.checkExitOnValid.isChecked():
            self.command += " -f"

        if self.checkVerbose.isChecked():
            self.command += " -V"
            
        self.command += " -t "+str(self.threadsComboBox.currentText())
            
        self.command += " "+self.service

#       if self.labelPath.isVisible():                                  # append the additional field's content, if it was visible
        if self.checkAddMoreOptions.isChecked():
            self.command += " "+str(self.labelPath.text())              # TODO: sanitise this?

        #command = "echo "+escaped_password+" > /tmp/hydra-sub.txt"
        #os.system(str(command))
        return self.command
        
    def getPort(self):
        return self.port
        
    def toggleRunButton(self):
        if self.runButton.text() == 'Run':
            self.runButton.setText('Stop')
        else:
            self.runButton.setText('Run')

    def resetDisplay(self):                                             # used to be able to display the tool output in both the Brute tab and the tool display panel
        self.display.setParent(None)
        self.display = QPlainTextEdit()
        self.display.setReadOnly(True)
        if self.settings.general_tool_output_black_background == 'True':
            #self.display.setStyleSheet("background: rgb(0,0,0)")       # black background
            #self.display.setTextColor(QtGui.QColor('white'))           # white font
            p = self.display.palette()
            p.setColor(QPalette.Base, Qt.black)                   # black background
            p.setColor(QPalette.Text, Qt.white)                   # white font
            self.display.setPalette(p)
            self.display.setStyleSheet("QMenu { color:black;}") #font-size:18px; width: 150px; color:red; left: 20px;}"); # set the menu font color: black          
        self.vlayout.addWidget(self.display)

# dialog displayed when the user clicks on the advanced filters button      
class FiltersDialog(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)
        self.setupLayout()
        self.applyButton.clicked.connect(self.close)
        self.cancelButton.clicked.connect(self.close)

    def setupLayout(self):
        self.setModal(True)
        self.setWindowTitle('Filters')
        self.setFixedSize(640, 200)
        
        hostsBox = QGroupBox("Host Filters")        
        self.hostsUp = QCheckBox("Show up hosts")
        self.hostsUp.toggle()
        self.hostsDown = QCheckBox("Show down hosts")
        self.hostsChecked = QCheckBox("Show checked hosts")
        self.hostsChecked.toggle()
        hostLayout = QVBoxLayout()
        hostLayout.addWidget(self.hostsUp)
        hostLayout.addWidget(self.hostsDown)
        hostLayout.addWidget(self.hostsChecked)
        hostsBox.setLayout(hostLayout)
        
        portsBox = QGroupBox("Port Filters")
        self.portsOpen = QCheckBox("Show open ports")
        self.portsOpen.toggle()
        self.portsFiltered = QCheckBox("Show filtered ports")
        self.portsClosed = QCheckBox("Show closed ports")
        self.portsTcp = QCheckBox("Show tcp")
        self.portsTcp.toggle()
        self.portsUdp = QCheckBox("Show udp")
        self.portsUdp.toggle()
        servicesLayout = QVBoxLayout()
        servicesLayout.addWidget(self.portsOpen)
        servicesLayout.addWidget(self.portsFiltered)
        servicesLayout.addWidget(self.portsClosed)
        servicesLayout.addWidget(self.portsTcp)
        servicesLayout.addWidget(self.portsUdp)
        portsBox.setLayout(servicesLayout)
        
        keywordSearchBox = QGroupBox("Keyword Filters")
        self.hostKeywordText = QLineEdit()
        keywordLayout = QVBoxLayout()
        keywordLayout.addWidget(self.hostKeywordText)
        keywordSearchBox.setLayout(keywordLayout)
        
        hlayout = QHBoxLayout()
        hlayout.addWidget(hostsBox)
        hlayout.addWidget(portsBox)
        hlayout.addWidget(keywordSearchBox)
        
        buttonLayout = QHBoxLayout()
        self.applyButton = QPushButton('Apply', self)
        self.applyButton.setMaximumSize(110, 30)
        self.cancelButton = QPushButton('Cancel', self)
        self.cancelButton.setMaximumSize(110, 30)
        buttonLayout.addWidget(self.cancelButton)
        buttonLayout.addWidget(self.applyButton)
            
        layout = QVBoxLayout()      
        layout.addLayout(hlayout)
        layout.addLayout(buttonLayout)  
        self.setLayout(layout)
        
    def getFilters(self):
        #return [self.hostsUp.isChecked(), self.hostsDown.isChecked(), self.hostsChecked.isChecked(), self.portsOpen.isChecked(), self.portsFiltered.isChecked(), self.portsClosed.isChecked(), self.portsTcp.isChecked(), self.portsUdp.isChecked(), str(self.hostKeywordText.text()).split()]
        return [self.hostsUp.isChecked(), self.hostsDown.isChecked(), self.hostsChecked.isChecked(), self.portsOpen.isChecked(), self.portsFiltered.isChecked(), self.portsClosed.isChecked(), self.portsTcp.isChecked(), self.portsUdp.isChecked(), str(self.hostKeywordText.text()).split()]

    def setCurrentFilters(self, filters):
        if not self.hostsUp.isChecked() == filters[0]:
            self.hostsUp.toggle()
            
        if not self.hostsDown.isChecked() == filters[1]:
            self.hostsDown.toggle()
            
        if not self.hostsChecked.isChecked() == filters[2]:
            self.hostsChecked.toggle()
            
        if not self.portsOpen.isChecked() == filters[3]:
            self.portsOpen.toggle()
            
        if not self.portsFiltered.isChecked() == filters[4]:
            self.portsFiltered.toggle()
            
        if not self.portsClosed.isChecked() == filters[5]:
            self.portsClosed.toggle()
            
        if not self.portsTcp.isChecked() == filters[6]:
            self.portsTcp.toggle()
            
        if not self.portsUdp.isChecked() == filters[7]:
            self.portsUdp.toggle()
        
        self.hostKeywordText.setText(" ".join(filters[8]))
        
        
    def setKeywords(self, keywords):
        self.hostKeywordText.setText(keywords)

# widget in which the host information is shown
class HostInformationWidget(QWidget):
    
    def __init__(self, informationTab, parent=None):
        QWidget.__init__(self, parent)
        self.informationTab = informationTab
        self.setupLayout()
        self.updateFields()     # set default values
        
    def setupLayout(self):
        self.HostStatusLabel = QLabel()

        self.HostStateLabel = QLabel()
        self.HostStateText = QLabel()
        self.HostStateLayout = QHBoxLayout()
        self.HostStateLayout.addSpacing(20)
        self.HostStateLayout.addWidget(self.HostStateLabel)
        self.HostStateLayout.addWidget(self.HostStateText)
        self.HostStateLayout.addStretch()
        
        self.OpenPortsLabel = QLabel()
        self.OpenPortsText = QLabel()
        self.OpenPortsLayout = QHBoxLayout()
        self.OpenPortsLayout.addSpacing(20)
        self.OpenPortsLayout.addWidget(self.OpenPortsLabel)
        self.OpenPortsLayout.addWidget(self.OpenPortsText)
        self.OpenPortsLayout.addStretch()
        
        self.ClosedPortsLabel = QLabel()
        self.ClosedPortsText = QLabel()
        self.ClosedPortsLayout = QHBoxLayout()
        self.ClosedPortsLayout.addSpacing(20)
        self.ClosedPortsLayout.addWidget(self.ClosedPortsLabel)
        self.ClosedPortsLayout.addWidget(self.ClosedPortsText)
        self.ClosedPortsLayout.addStretch() 
        
        self.FilteredPortsLabel = QLabel()
        self.FilteredPortsText = QLabel()
        self.FilteredPortsLayout = QHBoxLayout()
        self.FilteredPortsLayout.addSpacing(20)
        self.FilteredPortsLayout.addWidget(self.FilteredPortsLabel)
        self.FilteredPortsLayout.addWidget(self.FilteredPortsText)
        self.FilteredPortsLayout.addStretch()   
        ###################
        self.AddressLabel = QLabel()
        
        self.IP4Label = QLabel()
        self.IP4Text = QLabel()
        self.IP4Layout = QHBoxLayout()
        self.IP4Layout.addSpacing(20)
        self.IP4Layout.addWidget(self.IP4Label)
        self.IP4Layout.addWidget(self.IP4Text)
        self.IP4Layout.addStretch()
        
        self.IP6Label = QLabel()
        self.IP6Text = QLabel()
        self.IP6Layout = QHBoxLayout()
        self.IP6Layout.addSpacing(20)
        self.IP6Layout.addWidget(self.IP6Label)
        self.IP6Layout.addWidget(self.IP6Text)
        self.IP6Layout.addStretch()
        
        self.MacLabel = QLabel()
        self.MacText = QLabel()
        self.MacLayout = QHBoxLayout()
        self.MacLayout.addSpacing(20)
        self.MacLayout.addWidget(self.MacLabel)
        self.MacLayout.addWidget(self.MacText)
        self.MacLayout.addStretch()
        
        self.dummyLabel = QLabel()
        self.dummyText = QLabel()
        self.dummyLayout = QHBoxLayout()
        self.dummyLayout.addSpacing(20)
        self.dummyLayout.addWidget(self.dummyLabel)
        self.dummyLayout.addWidget(self.dummyText)
        self.dummyLayout.addStretch()
        #########       
        self.OSLabel = QLabel()
        
        self.OSNameLabel = QLabel()
        self.OSNameText = QLabel()
        self.OSNameLayout = QHBoxLayout()
        self.OSNameLayout.addSpacing(20)
        self.OSNameLayout.addWidget(self.OSNameLabel)
        self.OSNameLayout.addWidget(self.OSNameText)
        self.OSNameLayout.addStretch()
        
        self.OSAccuracyLabel = QLabel()
        self.OSAccuracyText = QLabel()
        self.OSAccuracyLayout = QHBoxLayout()
        self.OSAccuracyLayout.addSpacing(20)
        self.OSAccuracyLayout.addWidget(self.OSAccuracyLabel)
        self.OSAccuracyLayout.addWidget(self.OSAccuracyText)
        self.OSAccuracyLayout.addStretch()
        
        font = QFont()        # in each different section
        font.setBold(True)
        self.HostStatusLabel.setText('Host Status')
        self.HostStatusLabel.setFont(font)
        self.HostStateLabel.setText("State:")
        self.OpenPortsLabel.setText('Open Ports:')
        self.ClosedPortsLabel.setText('Closed Ports:')
        self.FilteredPortsLabel.setText('Filtered Ports:')
        self.AddressLabel.setText('Addresses')
        self.AddressLabel.setFont(font)
        self.IP4Label.setText('IPv4:')
        self.IP6Label.setText('IPv6:')
        self.MacLabel.setText('MAC:')
        self.OSLabel.setText('Operating System')
        self.OSLabel.setFont(font)
        self.OSNameLabel.setText('Name:')
        self.OSAccuracyLabel.setText('Accuracy:')
        #########
        self.vlayout_1 = QVBoxLayout()
        self.vlayout_2 = QVBoxLayout()
        self.vlayout_3 = QVBoxLayout()
        self.hlayout_1 = QHBoxLayout()
        
        self.vlayout_1.addWidget(self.HostStatusLabel)
        self.vlayout_1.addLayout(self.HostStateLayout)
        self.vlayout_1.addLayout(self.OpenPortsLayout)
        self.vlayout_1.addLayout(self.ClosedPortsLayout)
        self.vlayout_1.addLayout(self.FilteredPortsLayout)
        
        self.vlayout_2.addWidget(self.AddressLabel)
        self.vlayout_2.addLayout(self.IP4Layout)
        self.vlayout_2.addLayout(self.IP6Layout)
        self.vlayout_2.addLayout(self.MacLayout)
        self.vlayout_2.addLayout(self.dummyLayout)
        
        self.hlayout_1.addLayout(self.vlayout_1)
        self.hlayout_1.addSpacing(20)
        self.hlayout_1.addLayout(self.vlayout_2)
        
        self.vlayout_3.addWidget(self.OSLabel)
        self.vlayout_3.addLayout(self.OSNameLayout)
        self.vlayout_3.addLayout(self.OSAccuracyLayout)
        self.vlayout_3.addStretch()
        
        self.vlayout_4 = QVBoxLayout()
        self.vlayout_4.addLayout(self.hlayout_1)
        self.vlayout_4.addSpacing(10)
        self.vlayout_4.addLayout(self.vlayout_3)
        
        self.hlayout_4 = QHBoxLayout(self.informationTab)
        self.hlayout_4.addLayout(self.vlayout_4)
        self.hlayout_4.insertStretch(-1,1)
        self.hlayout_4.addStretch()
                
    def updateFields(self, status='', openPorts='', closedPorts='', filteredPorts='', ipv4='', ipv6='', macaddr='', osMatch='', osAccuracy=''):
        self.HostStateText.setText(str(status))
        self.OpenPortsText.setText(str(openPorts))
        self.ClosedPortsText.setText(str(closedPorts))
        self.FilteredPortsText.setText(str(filteredPorts))
        self.IP4Text.setText(str(ipv4))
        self.IP6Text.setText(str(ipv6))
        self.MacText.setText(str(macaddr))
        self.OSNameText.setText(str(osMatch))
        self.OSAccuracyText.setText(str(osAccuracy))
