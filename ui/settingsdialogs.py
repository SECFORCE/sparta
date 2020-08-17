#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2020 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from PyQt5.QtCore import QObject, QEvent, QSize, Qt
from PyQt5.QtWidgets import QPushButton, QSpacerItem, QAbstractItemView, QGroupBox, QFileDialog
from PyQt5.QtWidgets import QTabBar, QStylePainter, QStyleOptionTab, QDialog, QTableWidgetItem
from PyQt5.QtWidgets import QStyle, QLabel, QLineEdit, QCheckBox, QHBoxLayout, QVBoxLayout, QTabWidget
from PyQt5.QtWidgets import QWidget, QComboBox, QTableWidget, QScrollArea
from app.auxiliary import clearLayout, validateCommandFormat, validateFile, validateString, validatePath, validateNmapPorts, validateNumeric, validateStringWithSpace

class Validate(QObject):                                         # used to validate user input on focusOut - more specifically only called to validate tool name in host/port/terminal commands tabs
    def eventFilter(self, widget, event):
        if event.type() == QEvent.FocusOut:                      # this horrible line is to avoid making the 'AddSettingsDialog' class visible from here
            widget.parent().parent().parent().parent().parent().parent().validateToolName()
            return False
        else:
            return False    # TODO: check this

# Borrowed this class from https://gist.github.com/LegoStormtroopr/5075267
# Credit and thanks to LegoStormtoopr (http://www.twitter.com/legostormtroopr)
class SettingsTabBarWidget(QTabBar):
    def __init__(self, parent=None, *args, **kwargs):
        self.tabSize = QSize(kwargs.pop('width',100), kwargs.pop('height',25))
        QTabBar.__init__(self, parent, *args, **kwargs)

    def paintEvent(self, event):
        painter = QStylePainter(self)
        option = QStyleOptionTab()

        for index in range(self.count()):
            self.initStyleOption(option, index)
            tabRect = self.tabRect(index)
            tabRect.moveLeft(10)
            painter.drawControl(QStyle.CE_TabBarTabShape, option)
            painter.drawText(tabRect, Qt.AlignVCenter | Qt.TextDontClip, self.tabText(index))
        painter.end()

    def tabSizeHint(self,index):
        return self.tabSize

class AddSettingsDialog(QDialog):                                 # dialog shown when the user selects settings menu
    def __init__(self, parent=None):
        QDialog.__init__(self, parent)

        self.setupLayout()
        self.setupConnections()

        self.validationPassed = True                                    # TODO: rethink
        self.previousTab = self.settingsTabWidget.tabText(self.settingsTabWidget.currentIndex())

        self.validate = Validate()
        self.hostActionNameText.installEventFilter(self.validate)
        self.portActionNameText.installEventFilter(self.validate)
        self.terminalActionNameText.installEventFilter(self.validate)
        self.hostTableRow = -1
        self.portTableRow = -1
        self.terminalTableRow = -1
        
        # TODO: maybe these shouldn't be hardcoded because the user can change them... rethink this?
        self.defaultServicesList = ["mysql-default","mssql-default","ftp-default","postgres-default","oracle-default"]

    def setupConnections(self):
        self.browseUsersListButton.clicked.connect(lambda: self.wordlistDialog())
        self.browsePasswordsListButton.clicked.connect(lambda: self.wordlistDialog('Choose password path'))

        self.addToolForHostButton.clicked.connect(self.addToolForHost)
        self.removeToolForHostButton.clicked.connect(self.removeToolForHost)
        self.addToolButton.clicked.connect(self.addToolForService)
        self.removeToolButton.clicked.connect(self.removeToolForService)
        self.addToolForTerminalButton.clicked.connect(self.addToolForTerminal)
        self.removeToolForTerminalButton.clicked.connect(self.removeToolForTerminal)

        self.addServicesButton.clicked.connect(lambda: self.moveService(self.servicesAllTableWidget, self.servicesActiveTableWidget))
        self.removeServicesButton.clicked.connect(lambda: self.moveService(self.servicesActiveTableWidget, self.servicesAllTableWidget))
        self.addTerminalServiceButton.clicked.connect(lambda: self.moveService(self.terminalServicesAllTable, self.terminalServicesActiveTable))
        self.removeTerminalServiceButton.clicked.connect(lambda: self.moveService(self.terminalServicesActiveTable, self.terminalServicesAllTable))
        
        self.toolForHostsTableWidget.clicked.connect(self.updateToolForHostInformation)
        self.toolForServiceTableWidget.clicked.connect(self.updateToolForServiceInformation)
        self.toolForTerminalTableWidget.clicked.connect(self.updateToolForTerminalInformation)

        self.hostActionNameText.textChanged.connect(lambda: self.realTimeToolNameUpdate(self.toolForHostsTableWidget, self.hostActionNameText.text()))
        self.portActionNameText.textChanged.connect(lambda: self.realTimeToolNameUpdate(self.toolForServiceTableWidget, self.portActionNameText.text()))
        self.terminalActionNameText.textChanged.connect(lambda: self.realTimeToolNameUpdate(self.toolForTerminalTableWidget, self.terminalActionNameText.text()))
        
        self.enableAutoAttacks.clicked.connect(lambda: self.enableAutoToolsTab())
        self.checkDefaultCred.clicked.connect(self.toggleDefaultServices)

        self.settingsTabWidget.currentChanged.connect(self.switchTabClick)
        self.ToolSettingsTab.currentChanged.connect(self.switchToolTabClick)

    ##################### ACTION FUNCTIONS (apply / cancel related) #####################

    def setSettings(self, settings):                                    # called by the controller once the config file has been read at start time and also when the cancel button is pressed to forget any changes.
        self.settings = settings
        self.resetGui()                                                 # clear any changes the user may have made and canceled.
        self.populateSettings()                                         # populate the GUI with the new settings

        self.hostActionsNumber = 1                                      # TODO: this is most likely not the best way to do it. we should check if New_Action_1 exists and if so increase the number until it doesn't exist. no need for a self.variable - can be a local one.
        self.portActionsNumber = 1
        self.terminalActionsNumber = 1

    def applySettings(self):                                            # called when apply button is pressed
        if self.validateCurrentTab(self.settingsTabWidget.tabText(self.settingsTabWidget.currentIndex())):
            self.updateSettings()
            return True
        return False
    
    def updateSettings(self):                                           # updates the local settings object (must be called when applying settings and only after validation succeeded)
                                                                        # LEO: reorganised stuff in a more logical way but no changes were made yet :)
        # update GENERAL tab settings
        self.settings.general_default_terminal = str(self.terminalComboBox.currentText())
        self.settings.general_max_fast_processes = str(self.fastProcessesComboBox.currentText())
        self.settings.general_screenshooter_timeout = str(self.screenshotTextinput.text())
        self.settings.general_web_services = str(self.webServicesTextinput.text())      

        if self.checkStoreClearPW.isChecked():
            self.settings.brute_store_cleartext_passwords_on_exit = 'True'
        else:
            self.settings.brute_store_cleartext_passwords_on_exit = 'False'
        
        if self.checkBlackBG.isChecked():
            self.settings.general_tool_output_black_background = 'True'
        else:
            self.settings.general_tool_output_black_background = 'False'

        # update BRUTE tab settings
        self.settings.brute_username_wordlist_path = str(self.userlistPath.text())
        self.settings.brute_password_wordlist_path = str(self.passwordlistPath.text())
        self.settings.brute_default_username = str(self.defaultUserText.text())
        self.settings.brute_default_password = str(self.defaultPassText.text())

        # update TOOLS tab settings
        self.settings.tools_nmap_stage1_ports = str(self.stage1Input.text())
        self.settings.tools_nmap_stage2_ports = str(self.stage2Input.text())
        self.settings.tools_nmap_stage3_ports = str(self.stage3Input.text())
        self.settings.tools_nmap_stage4_ports = str(self.stage4Input.text())
        self.settings.tools_nmap_stage5_ports = str(self.stage5Input.text())

        # update AUTOMATED ATTACKS tab settings
        if self.enableAutoAttacks.isChecked():
            self.settings.general_enable_scheduler = 'True'
        else:
            self.settings.general_enable_scheduler = 'False'
            
        # TODO: seems like all the other settings should be updated here as well instead of updating them in the validation function.

    #def initValues(self):                                              # LEO: renamed and changed the previous tabs defaults otherwise validation doesn't work the first time
    def resetGui(self):                                                 # called when the cancel button is clicked, to initialise everything
        self.validationPassed = True
        self.previousTab = 'General'
        self.previousToolTab = 'Tool Paths'
        self.hostTableRow = -1
        self.portTableRow = -1
        self.terminalTableRow = -1

        self.hostActionNameText.setText('')
        self.hostLabelText.setText(' ')
        self.hostLabelText.setReadOnly(True)
        self.hostCommandText.setText('init value')
        
        self.portActionNameText.setText('')
        self.portLabelText.setText(' ')
        self.portLabelText.setReadOnly(True)
        self.portCommandText.setText('init value')
        
        self.terminalActionNameText.setText('')
        self.terminalLabelText.setText(' ')
        self.terminalLabelText.setReadOnly(True)
        self.terminalCommandText.setText('init value')
        
        # reset layouts
        clearLayout(self.scrollVerLayout)
        clearLayout(self.defaultBoxVerlayout)
        self.terminalComboBox.clear()

    def populateSettings(self):                                         # called by setSettings at start up or when showing the settings dialog after a cancel action. it populates the GUI with the controller's settings object.
        self.populateGeneralTab()                                       # LEO: split it in functions so that it's less confusing and easier to refactor later
        self.populateBruteTab()
        self.populateToolsTab()
        self.populateAutomatedAttacksTab()

    def populateGeneralTab(self):       
        self.terminalsSupported = ['xterm','gnome-terminal']
        self.terminalComboBox.insertItems(0, self.terminalsSupported)

        self.fastProcessesComboBox.setCurrentIndex(int(self.settings.general_max_fast_processes) - 1)
        self.screenshotTextinput.setText(str(self.settings.general_screenshooter_timeout))
        self.webServicesTextinput.setText(str(self.settings.general_web_services))
                
        if self.settings.general_tool_output_black_background == 'True' and self.checkBlackBG.isChecked() == False:
            self.checkBlackBG.toggle()
        elif self.settings.general_tool_output_black_background == 'False' and self.checkBlackBG.isChecked() == True:
            self.checkBlackBG.toggle()
        
        if self.settings.brute_store_cleartext_passwords_on_exit == 'True' and self.checkStoreClearPW.isChecked() == False:
            self.checkStoreClearPW.toggle()
        elif self.settings.brute_store_cleartext_passwords_on_exit == 'False' and self.checkStoreClearPW.isChecked() == True:
            self.checkStoreClearPW.toggle()     

    def populateBruteTab(self):
        self.userlistPath.setText(self.settings.brute_username_wordlist_path)
        self.passwordlistPath.setText(self.settings.brute_password_wordlist_path)           
        self.defaultUserText.setText(self.settings.brute_default_username)
        self.defaultPassText.setText(self.settings.brute_default_password)  
            
    def populateToolsTab(self): 
        # POPULATE TOOL PATHS TAB
        self.nmapPathInput.setText(self.settings.tools_path_nmap)
        self.hydraPathInput.setText(self.settings.tools_path_hydra)
#       self.cutycaptPathInput.setText(self.settings.tools_path_cutycapt)
        self.textEditorPathInput.setText(self.settings.tools_path_texteditor)
 
        # POPULATE STAGED NMAP TAB
        self.stage1Input.setText(self.settings.tools_nmap_stage1_ports)
        self.stage2Input.setText(self.settings.tools_nmap_stage2_ports)
        self.stage3Input.setText(self.settings.tools_nmap_stage3_ports)
        self.stage4Input.setText(self.settings.tools_nmap_stage4_ports)
        self.stage5Input.setText(self.settings.tools_nmap_stage5_ports)

        # POPULATE TOOLS TABS (HOST/PORT/TERMINAL)
        self.toolForHostsTableWidget.setRowCount(len(self.settings.hostActions))
        for row in range(len(self.settings.hostActions)):
            # add a row to the table
            self.toolForHostsTableWidget.setItem(row, 0, QTableWidgetItem())
            # add the label for the port actions
            self.toolForHostsTableWidget.item(row, 0).setText(self.settings.hostActions[row][1])

        self.toolForServiceTableWidget.setRowCount(len(self.settings.portActions))
        for row in range(len(self.settings.portActions)):
            self.toolForServiceTableWidget.setItem(row, 0, QTableWidgetItem())
            self.toolForServiceTableWidget.item(row, 0).setText(self.settings.portActions[row][1])

        self.servicesAllTableWidget.setRowCount(len(self.settings.portActions))
        for row in range(len(self.settings.portActions)):
            self.servicesAllTableWidget.setItem(row, 0, QTableWidgetItem())
            self.servicesAllTableWidget.item(row, 0).setText(self.settings.portActions[row][3])

        self.toolForTerminalTableWidget.setRowCount(len(self.settings.portTerminalActions))
        for row in range(len(self.settings.portTerminalActions)):
            # add a row to the table
            self.toolForTerminalTableWidget.setItem(row, 0, QTableWidgetItem())
            # add the label fro the port actions
            self.toolForTerminalTableWidget.item(row, 0).setText(self.settings.portTerminalActions[row][1])
        self.terminalServicesAllTable.setRowCount(len(self.settings.portTerminalActions))
        for row in range(len(self.settings.portTerminalActions)):
            self.terminalServicesAllTable.setItem(row, 0, QTableWidgetItem())
            self.terminalServicesAllTable.item(row, 0).setText(self.settings.portTerminalActions[row][3])
                
    def populateAutomatedAttacksTab(self):                              # TODO: this one is still to big and ugly. needs work.
        self.typeDic = {}
        for i in range(len(self.settings.portActions)):
            # the dictionary contains the name, the text input and the layout for each tool
            self.typeDic.update({self.settings.portActions[i][1]:[QLabel(),QLineEdit(),QCheckBox(),QHBoxLayout()]})

        for keyNum in range(len(self.settings.portActions)):
            
            # populate the automated attacks tools tab with every tool that is not a default creds check
            if self.settings.portActions[keyNum][1] not in self.defaultServicesList: 

                self.typeDic[self.settings.portActions[keyNum][1]][0].setText(self.settings.portActions[keyNum][1])
                self.typeDic[self.settings.portActions[keyNum][1]][0].setFixedWidth(150)

                #if self.settings.portActions[keyNum][1] in self.settings.automatedAttacks.keys():
                foundToolInAA = False
                for t in self.settings.automatedAttacks:
                    if self.settings.portActions[keyNum][1] == t[0]:    
                        #self.typeDic[self.settings.portActions[keyNum][1]][1].setText(self.settings.automatedAttacks[self.settings.portActions[keyNum][1]])
                        self.typeDic[self.settings.portActions[keyNum][1]][1].setText(t[1])
                        self.typeDic[self.settings.portActions[keyNum][1]][2].toggle()
                        foundToolInAA = True
                        break
                        
                if not foundToolInAA:
                    self.typeDic[self.settings.portActions[keyNum][1]][1].setText(self.settings.portActions[keyNum][3])

                self.typeDic[self.settings.portActions[keyNum][1]][1].setFixedWidth(300)
                self.typeDic[self.settings.portActions[keyNum][1]][2].setObjectName(str(self.typeDic[self.settings.portActions[keyNum][1]][2]))
                self.typeDic[self.settings.portActions[keyNum][1]][3].addWidget(self.typeDic[self.settings.portActions[keyNum][1]][0])
                self.typeDic[self.settings.portActions[keyNum][1]][3].addWidget(self.typeDic[self.settings.portActions[keyNum][1]][1])
                self.typeDic[self.settings.portActions[keyNum][1]][3].addItem(self.enabledSpacer)
                self.typeDic[self.settings.portActions[keyNum][1]][3].addWidget(self.typeDic[self.settings.portActions[keyNum][1]][2])
                self.scrollVerLayout.addLayout(self.typeDic[self.settings.portActions[keyNum][1]][3])

            else:                                                       # populate the automated attacks tools tab with every tool that IS a default creds check
                # TODO: i get the feeling we shouldn't be doing this in the else. the else could just skip the default ones and outside of the loop we can go through self.defaultServicesList and take care of these separately.
                if self.settings.portActions[keyNum][1] == "mysql-default":
                    self.typeDic[self.settings.portActions[keyNum][1]][0].setText('mysql')
                elif self.settings.portActions[keyNum][1] == "mssql-default":
                    self.typeDic[self.settings.portActions[keyNum][1]][0].setText('mssql')
                elif self.settings.portActions[keyNum][1] == "ftp-default":
                    self.typeDic[self.settings.portActions[keyNum][1]][0].setText('ftp')
                elif self.settings.portActions[keyNum][1] == "postgres-default":
                    self.typeDic[self.settings.portActions[keyNum][1]][0].setText('postgres')
                elif self.settings.portActions[keyNum][1] == "oracle-default":
                    self.typeDic[self.settings.portActions[keyNum][1]][0].setText('oracle')

                self.typeDic[self.settings.portActions[keyNum][1]][0].setFixedWidth(150)
                self.typeDic[self.settings.portActions[keyNum][1]][2].setObjectName(str(self.typeDic[self.settings.portActions[keyNum][1]][2]))
                self.typeDic[self.settings.portActions[keyNum][1]][3].addWidget(self.typeDic[self.settings.portActions[keyNum][1]][0])
                self.typeDic[self.settings.portActions[keyNum][1]][3].addItem(self.enabledSpacer)
                self.typeDic[self.settings.portActions[keyNum][1]][3].addWidget(self.typeDic[self.settings.portActions[keyNum][1]][2])

                self.defaultBoxVerlayout.addLayout(self.typeDic[self.settings.portActions[keyNum][1]][3])

        self.scrollArea.setWidget(self.scrollWidget)
        self.globVerAutoToolsLayout.addWidget(self.scrollArea)      
        
    ##################### SWITCH TAB FUNCTIONS #####################
        
    def switchTabClick(self):                                           # LEO: this function had duplicate code with validateCurrentTab(). so now we call that one.
        if self.settingsTabWidget.tabText(self.settingsTabWidget.currentIndex()) == 'Tools':
            self.previousToolTab = self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex())

        print('previous tab is: ' + str(self.previousTab))
        if self.validateCurrentTab(self.previousTab):                   # LEO: we don't care about the return value in this case. it's just for debug.
            print('validation succeeded! switching tab! yay!')
                                                                        # save the previous tab for the next time we switch tabs. TODO: not sure this should be inside the IF but makes sense to me. no point in saving the previous if there is no change..
            self.previousTab = self.settingsTabWidget.tabText(self.settingsTabWidget.currentIndex())            
        else:
            print('nope! cannot let you switch tab! you fucked up!')

    def switchToolTabClick(self):                                       # TODO: check for duplicate code.
        if self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex()) == 'Host Commands':
            self.toolForHostsTableWidget.selectRow(0)
            self.updateToolForHostInformation(False)
            
        elif self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex()) == 'Port Commands':
            self.toolForServiceTableWidget.selectRow(0)
            self.updateToolForServiceInformation(False)
            
        elif self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex()) == 'Terminal Commands':
            self.toolForTerminalTableWidget.selectRow(0)
            self.updateToolForTerminalInformation(False)

        # LEO: I get the feeling the validation part could go into a validateCurrentToolTab() just like in the other switch tab function.
        if self.previousToolTab == 'Tool Paths':
            if not self.toolPathsValidate():
                self.ToolSettingsTab.setCurrentIndex(0)
  
        elif self.previousToolTab == 'Host Commands':
            if not self.validateCommandTabs(self.hostActionNameText, self.hostLabelText, self.hostCommandText):
                self.ToolSettingsTab.setCurrentIndex(1)
            else:
                self.updateHostActions()
                
        elif self.previousToolTab == 'Port Commands':
            if not self.validateCommandTabs(self.portActionNameText, self.portLabelText, self.portCommandText):
                self.ToolSettingsTab.setCurrentIndex(2)
            else:
                self.updatePortActions()
                
        elif self.previousToolTab == 'Terminal Commands':
            if not self.validateCommandTabs(self.terminalActionNameText, self.terminalLabelText, self.terminalCommandText):
                self.ToolSettingsTab.setCurrentIndex(3)
            else:
                self.updateTerminalActions()
                
        elif self.previousToolTab == 'Staged Nmap':
            if not self.validateStagedNmapTab():
                self.ToolSettingsTab.setCurrentIndex(4)
#           else:
#               self.updateTerminalActions()                            # LEO: commented out because it didn't look right, please check!
 
        self.previousToolTab = self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex())

    ##################### AUXILIARY FUNCTIONS #####################

    #def confInitState(self):                                           # LEO: renamed. i get the feeling this function is not necessary if we put this code somewhere else - eg: right before we apply/cancel. we'll see.
    def resetTabIndexes(self):                                          # called when the settings dialog is opened so that we always show the same tabs.
        self.settingsTabWidget.setCurrentIndex(0)
        self.ToolSettingsTab.setCurrentIndex(0)

    def toggleRedBorder(self, widget, red=True):                        # called by validation functions to display (or not) a red border around a text input widget when input is (in)valid. easier to change stylesheets in one place only.
        if red:
            widget.setStyleSheet("border: 1px solid red;")
        else:
            widget.setStyleSheet("border: 1px solid grey;")

    # LEO: I moved the really generic validation functions to the end of auxiliary.py and those are used by these slightly-less-generic ones.
    # .. the difference is that these ones also take care of the IF/ELSE which was being duplicated all over the code. everything should be simpler now.
    # note that I didn't use these everywhere because sometimes the IF/ELSE are not so straight-forward.
    
    def validateNumeric(self, widget):
        if not validateNumeric(str(widget.text())):
            self.toggleRedBorder(widget, True)
            return False
        else:
            self.toggleRedBorder(widget, False)
            return True

    def validateString(self, widget):
        if not validateString(str(widget.text())):                      # TODO: this is too strict in some cases...
            self.toggleRedBorder(widget, True)
            return False
        else:
            self.toggleRedBorder(widget, False)
            return True

    def validateStringWithSpace(self, widget):
        if not validateStringWithSpace(str(widget.text())):
            self.toggleRedBorder(widget, True)
            return False
        else:
            self.toggleRedBorder(widget, False)
            return True

    def validatePath(self, widget):
        if not validatePath(str(widget.text())):
            self.toggleRedBorder(widget, True)
            return False
        else:
            self.toggleRedBorder(widget, False)
            return True

    def validateFile(self, widget):
        if not validateFile(str(widget.text())):
            self.toggleRedBorder(widget, True)
            return False
        else:
            self.toggleRedBorder(widget, False)
            return True

    def validateCommandFormat(self, widget):
        if not validateCommandFormat(str(widget.text())):
            self.toggleRedBorder(widget, True)
            return False
        else:
            self.toggleRedBorder(widget, False)
            return True

    def validateNmapPorts(self, widget):
        if not validateNmapPorts(str(widget.text())):
            self.toggleRedBorder(widget, True)
            return False
        else:
            self.toggleRedBorder(widget, False)
            return True
        
    ##################### VALIDATION FUNCTIONS (per tab) #####################
    # LEO: the functions are more or less in the same order as the tabs in the GUI (top-down and left-to-right) except for generic functions

    def validateCurrentTab(self, tab):                                  # LEO: your updateSettings() was split in 2. validateCurrentTab() and updateSettings() since they have different functionality. also, we now have a 'tab' parameter so that we can reuse the code in switchTabClick and avoid duplicate code. the tab parameter will either be the current or the previous tab depending where we call this from.
        validationPassed = True
        if tab == 'General':
            if not self.validateGeneralTab():
                self.settingsTabWidget.setCurrentIndex(0)
                validationPassed = False

        elif tab == 'Brute':
            if not self.validateBruteTab():
                self.settingsTabWidget.setCurrentIndex(1)
                validationPassed = False

        elif tab == 'Tools':
            self.ToolSettingsTab.setCurrentIndex(0)
            currentToolsTab = self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex())
            if currentToolsTab == 'Tool Paths':
                if not self.toolPathsValidate():
                    self.settingsTabWidget.setCurrentIndex(2)
                    self.ToolSettingsTab.setCurrentIndex(0)
                    validationPassed = False

            elif currentToolsTab == 'Host Commands':
                if not self.validateCommandTabs(self.hostActionNameText, self.hostLabelText, self.hostCommandText):
                    self.settingsTabWidget.setCurrentIndex(2)
                    self.ToolSettingsTab.setCurrentIndex(1)
                    validationPassed = False
                else:
                    self.updateHostActions()
                    
            elif currentToolsTab == 'Port Commands':
                if not self.validateCommandTabs(self.portActionNameText, self.portLabelText, self.portCommandText):
                    self.settingsTabWidget.setCurrentIndex(2)
                    self.ToolSettingsTab.setCurrentIndex(2)
                    validationPassed = False
                else:
                    self.updatePortActions()
                    
            elif currentToolsTab == 'Terminal Commands':
                if not self.validateCommandTabs(self.terminalActionNameText, self.terminalLabelText, self.terminalCommandText):
                    self.settingsTabWidget.setCurrentIndex(2)
                    self.ToolSettingsTab.setCurrentIndex(3)
                    validationPassed = False
                else:
                    self.updateTerminalActions()
                    
            elif currentToolsTab == 'Staged Nmap':
                if not self.validateStagedNmapTab():
                    self.settingsTabWidget.setCurrentIndex(2)
                    self.ToolSettingsTab.setCurrentIndex(4)
                    validationPassed = False
            
            else:
                print('>>>> we should never be here. potential bug. 1') # LEO: added this just to help when testing. we'll remove it later.
        
        elif tab == 'Wordlists':
            print('Coming back from wordlists.')

        elif tab == 'Automated Attacks':
            print('Coming back from automated attacks.')
        
        else:
            print('>>>> we should never be here. potential bug. 2')     # LEO: added this just to help when testing. we'll remove it later.
        
        print('DEBUG: current tab is valid: ' + str(validationPassed))
        return validationPassed

    #def generalTabValidate(self):
    def validateGeneralTab(self):
        validationPassed = self.validateNumeric(self.screenshotTextinput)
        
        self.toggleRedBorder(self.webServicesTextinput, False)
        for service in str(self.webServicesTextinput.text()).split(','):# TODO: this is too strict! no spaces or comma allowed? we can clean up for the user in some simple cases. actually, i'm not sure we even need to split.
            if not validateString(service):
                self.toggleRedBorder(self.webServicesTextinput, True)
                validationPassed = False
                break

        return validationPassed

    #def bruteTabValidate(self):
    def validateBruteTab(self):                                         # LEO: do NOT change the order of the AND statements otherwise validation may not take place if first condition is False
        validationPassed = self.validatePath(self.userlistPath)
        validationPassed = self.validatePath(self.passwordlistPath) and validationPassed
        validationPassed = self.validateString(self.defaultUserText) and validationPassed
        validationPassed = self.validateString(self.defaultPassText) and validationPassed                   
        return validationPassed
    
    def toolPathsValidate(self):                
        validationPassed = self.validateFile(self.nmapPathInput)
        validationPassed = self.validateFile(self.hydraPathInput) and validationPassed
#       validationPassed = self.validateFile(self.cutycaptPathInput) and validationPassed
        validationPassed = self.validateFile(self.textEditorPathInput) and validationPassed
        return validationPassed

#   def commandTabsValidate(self):                                      # LEO: renamed and refactored
    def validateCommandTabs(self, nameInput, labelInput, commandInput): # only validates the tool name, label and command fields for host/port/terminal tabs
        validationPassed = True

        if self.validationPassed == False:                              # the self.validationPassed comes from the focus out event
            self.toggleRedBorder(nameInput, True)                       # TODO: this seems like a dodgy way to do it - functions should not depend on hope :) . maybe it's better to simply validate again. code will be clearer too.
            validationPassed = False
        else:
            self.toggleRedBorder(nameInput, False)

        validationPassed = self.validateStringWithSpace(labelInput) and validationPassed
        validationPassed = self.validateCommandFormat(commandInput) and validationPassed            
        return validationPassed

    # avoid using the same code for the selected tab. returns the fields for the current visible tab (host/ports/terminal)
    # TODO: don't like this too much. seems like we could just use parameters in the validate tool name function
    def selectGroup(self):      
        tabSelected = -1
        
        if self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex()) == 'Host Commands':
            tabSelected = 1
        elif self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex()) == 'Port Commands':
            tabSelected = 2
        elif self.ToolSettingsTab.tabText(self.ToolSettingsTab.currentIndex()) == 'Terminal Commands':
            tabSelected = 3

        if self.previousToolTab == 'Host Commands' or tabSelected == 1:
            tmpWidget = self.toolForHostsTableWidget
            tmpActionLineEdit = self.hostActionNameText
            tmpLabelLineEdit = self.hostLabelText
            tmpCommandLineEdit = self.hostCommandText
            actions = self.settings.hostActions
            tableRow = self.hostTableRow
        if self.previousToolTab == 'Port Commands' or tabSelected == 2:
            tmpWidget = self.toolForServiceTableWidget
            tmpActionLineEdit = self.portActionNameText
            tmpLabelLineEdit = self.portLabelText
            tmpCommandLineEdit = self.portCommandText
            actions = self.settings.portActions
            tableRow = self.portTableRow
        if self.previousToolTab == 'Terminal Commands' or tabSelected == 3:
            tmpWidget = self.toolForTerminalTableWidget
            tmpActionLineEdit = self.terminalActionNameText
            tmpLabelLineEdit = self.terminalLabelText
            tmpCommandLineEdit = self.terminalCommandText
            actions = self.settings.portTerminalActions
            tableRow = self.terminalTableRow
            
        return tmpWidget, tmpActionLineEdit, tmpLabelLineEdit, tmpCommandLineEdit, actions, tableRow

#   def validateInput(self):                                            # LEO: renamed
    def validateToolName(self):                                         # called when there is a focus out event. only validates the tool name (key) for host/port/terminal tabs
        selectGroup = self.selectGroup()
        tmpWidget = selectGroup[0]
        tmplineEdit = selectGroup[1]
        actions = selectGroup[4]
        row = selectGroup[5]

        if tmplineEdit:
            row = tmpWidget.currentRow()

            if row != -1:                                               # LEO: when the first condition is True the validateUniqueToolName is never called (bad if we want to show a nice error message for the unique key)
                if not validateString(str(tmplineEdit.text())) or not self.validateUniqueToolName(tmpWidget, row, str(tmplineEdit.text())):
                    tmplineEdit.setStyleSheet("border: 1px solid red;")
                    tmpWidget.setSelectionMode(QAbstractItemView.NoSelection)
                    self.validationPassed = False
                    print('the validation is: ' + str(self.validationPassed))
                    return self.validationPassed
                else:
                    tmplineEdit.setStyleSheet("border: 1px solid grey;")
                    tmpWidget.setSelectionMode(QAbstractItemView.SingleSelection)
                    self.validationPassed = True
                    print('the validation is: ' + str(self.validationPassed))
                    if tmpWidget.item(row,0).text() != str(actions[row][1]):
                        print('difference found')
                        actions[row][1] = tmpWidget.item(row,0).text()
                    return self.validationPassed                

    #def validateUniqueKey(self, widget, tablerow, text):               # LEO: renamed. +the function that calls this one already knows the selectGroup stuff so no need to duplicate.
    def validateUniqueToolName(self, widget, tablerow, text):               # LEO: the function that calls this one already knows the selectGroup stuff so no need to duplicate.
        if tablerow != -1:
            for row in [i for i in range(widget.rowCount()) if i not in [tablerow]]:
                if widget.item(row,0).text() == text:
                    return False
        return True

    #def nmapValidate(self):
    def validateStagedNmapTab(self):                                    # LEO: renamed and fixed bugs. TODO: this function is being called way too often. something seems wrong in the overall logic
        validationPassed = self.validateNmapPorts(self.stage1Input)
        validationPassed = self.validateNmapPorts(self.stage2Input) and validationPassed
        validationPassed = self.validateNmapPorts(self.stage3Input) and validationPassed
        validationPassed = self.validateNmapPorts(self.stage4Input) and validationPassed
        validationPassed = self.validateNmapPorts(self.stage5Input) and validationPassed
        return validationPassed

    ##################### TOOLS / HOST COMMANDS FUNCTIONS #####################

    def addToolForHost(self):
        #if self.commandTabsValidate():
        if self.validateCommandTabs(self.hostActionNameText, self.hostLabelText, self.hostCommandText):
            currentRows = self.toolForHostsTableWidget.rowCount()
            self.toolForHostsTableWidget.setRowCount(currentRows + 1)

            self.toolForHostsTableWidget.setItem(currentRows, 0, QTableWidgetItem())
            self.toolForHostsTableWidget.item(self.toolForHostsTableWidget.rowCount()-1, 0).setText('New_Action_'+str(self.hostActionsNumber))
            self.toolForHostsTableWidget.selectRow(currentRows)
            self.settings.hostActions.append(['', 'New_Action_'+str(self.hostActionsNumber), ''])
            self.hostActionsNumber +=1
            self.updateToolForHostInformation()

    def removeToolForHost(self):
        row = self.toolForHostsTableWidget.currentRow()
        
        # set default values to avoid the error when the first action is add and remove tools
        self.hostActionNameText.setText('removed')
        self.hostLabelText.setText('removed')
        self.hostCommandText.setText('removed')

        for tool in self.settings.hostActions:
            if tool[1] == str(self.hostActionNameText.text()):
                self.settings.hostActions.remove(tool)
                break

        self.toolForHostsTableWidget.removeRow(row)

        self.toolForHostsTableWidget.selectRow(row-1)

        self.hostTableRow = self.toolForHostsTableWidget.currentRow()

        self.updateToolForHostInformation(False)

    def updateHostActions(self):
        self.settings.hostActions[self.hostTableRow][0] = str(self.hostLabelText.text())
        self.settings.hostActions[self.hostTableRow][2] = str(self.hostCommandText.text())

    # update variable -> do not update the values when a line is removed
    def updateToolForHostInformation(self, update = True):      
        #if self.commandTabsValidate() == True:
        if self.validateCommandTabs(self.hostActionNameText, self.hostLabelText, self.hostCommandText):

            # do not update any values the first time or when the remove button is clicked
            if self.hostTableRow == -1 or update == False:
                pass
            else:
                self.updateHostActions()
            
#           self.hostLabelText.setStyleSheet("border: 1px solid grey;")
#           self.hostCommandText.setStyleSheet("border: 1px solid grey;")
            self.hostTableRow = self.toolForHostsTableWidget.currentRow()
            self.hostLabelText.setReadOnly(False)
            if self.toolForHostsTableWidget.item(self.hostTableRow, 0) is not None:
                key = self.toolForHostsTableWidget.item(self.hostTableRow, 0).text()
                for tool in self.settings.hostActions:
                    if tool[1] == key:
                        self.hostActionNameText.setText(tool[1])
                        self.hostLabelText.setText(tool[0])
                        self.hostCommandText.setText(tool[2])
        else:
            self.toolForHostsTableWidget.selectRow(self.hostTableRow)

    # this function is used to REAL TIME update the tool table when a user enters a edit a tool name in the HOST/PORT/TERMINAL commands tabs
    # LEO: this one replaces updateToolForHostTable + updateToolForServicesTable + updateToolForTerminalTable
    def realTimeToolNameUpdate(self, tablewidget, text):                # the name still sucks, sorry. at least it's refactored
        row = tablewidget.currentRow()
        if row != -1:
            tablewidget.item(row, 0).setText(str(text))

    ##################### TOOLS / PORT COMMANDS FUNCTIONS #####################

    def addToolForService(self):
        #if self.commandTabsValidate():
        if self.validateCommandTabs(self.portActionNameText, self.portLabelText, self.portCommandText):
            currentRows = self.toolForServiceTableWidget.rowCount()
            self.toolForServiceTableWidget.setRowCount(currentRows + 1)
            self.toolForServiceTableWidget.setItem(currentRows, 0, QTableWidgetItem())
            self.toolForServiceTableWidget.item(self.toolForServiceTableWidget.rowCount()-1, 0).setText('New_Action_'+str(self.portActionsNumber))
            self.toolForServiceTableWidget.selectRow(currentRows)
            self.settings.portActions.append(['', 'New_Action_'+str(self.portActionsNumber), ''])
            self.portActionsNumber +=1
            self.updateToolForServiceInformation()
    
    def removeToolForService(self):
        row = self.toolForServiceTableWidget.currentRow()
        self.portActionNameText.setText('removed')
        self.portLabelText.setText('removed')
        self.portCommandText.setText('removed')
        for tool in self.settings.portActions:
            if tool[1] == str(self.portActionNameText.text()):
                self.settings.portActions.remove(tool)
                break
        self.toolForServiceTableWidget.removeRow(row)
        self.toolForServiceTableWidget.selectRow(row-1)
        self.portTableRow = self.toolForServiceTableWidget.currentRow()
        self.updateToolForServiceInformation(False)

    def updatePortActions(self):
        self.settings.portActions[self.portTableRow][0] = str(self.portLabelText.text())
        self.settings.portActions[self.portTableRow][2] = str(self.portCommandText.text())

    def updateToolForServiceInformation(self, update = True):
        #if self.commandTabsValidate() == True:
        if self.validateCommandTabs(self.portActionNameText, self.portLabelText, self.portCommandText):
            # the first time do not update anything
            if self.portTableRow == -1 or update == False:
                print('no update')
                pass
            else:
                print('update done')
                self.updatePortActions()
#           self.portLabelText.setStyleSheet("border: 1px solid grey;")
#           self.portCommandText.setStyleSheet("border: 1px solid grey;")
            self.portTableRow = self.toolForServiceTableWidget.currentRow()
            self.portLabelText.setReadOnly(False)
            
            if self.toolForServiceTableWidget.item(self.portTableRow, 0) is not None:
                key = self.toolForServiceTableWidget.item(self.portTableRow, 0).text()
                for tool in self.settings.portActions:
                    if tool[1] == key:
                        self.portActionNameText.setText(tool[1])
                        self.portLabelText.setText(tool[0])
                        self.portCommandText.setText(tool[2])
                        #  for the case that the tool (ex. new added tool) does not have services assigned 
                        if len(tool) == 4:
                            servicesList = tool[3].split(',')
                            self.terminalServicesActiveTable.setRowCount(len(servicesList))
                            for i in range(len(servicesList)):
                                self.terminalServicesActiveTable.setItem(i, 0, QTableWidgetItem())
                                self.terminalServicesActiveTable.item(i, 0).setText(str(servicesList[i]))
        else:
            self.toolForServiceTableWidget.selectRow(self.portTableRow)

    ##################### TOOLS / TERMINAL COMMANDS FUNCTIONS #####################
            
    def addToolForTerminal(self):
        #if self.commandTabsValidate():
        if self.validateCommandTabs(self.terminalActionNameText, self.terminalLabelText, self.terminalCommandText):
            currentRows = self.toolForTerminalTableWidget.rowCount()
            self.toolForTerminalTableWidget.setRowCount(currentRows + 1)
            self.toolForTerminalTableWidget.setItem(currentRows, 0, QTableWidgetItem())
            self.toolForTerminalTableWidget.item(self.toolForTerminalTableWidget.rowCount()-1, 0).setText('New_Action_'+str(self.terminalActionsNumber))
            self.toolForTerminalTableWidget.selectRow(currentRows)
            self.settings.portTerminalActions.append(['', 'New_Action_'+str(self.terminalActionsNumber), ''])
            self.terminalActionsNumber +=1
            self.updateToolForTerminalInformation()
    
    def removeToolForTerminal(self):
        row = self.toolForTerminalTableWidget.currentRow()
        self.terminalActionNameText.setText('removed')
        self.terminalLabelText.setText('removed')
        self.terminalCommandText.setText('removed')
        for tool in self.settings.portTerminalActions:
            if tool[1] == str(self.terminalActionNameText.text()):
                self.settings.portTerminalActions.remove(tool)
                break
        self.toolForTerminalTableWidget.removeRow(row)
        self.toolForTerminalTableWidget.selectRow(row-1)
        self.portTableRow = self.toolForTerminalTableWidget.currentRow()
        self.updateToolForTerminalInformation(False)
        
    def updateTerminalActions(self):
        self.settings.portTerminalActions[self.terminalTableRow][0] = str(self.terminalLabelText.text())
        self.settings.portTerminalActions[self.terminalTableRow][2] = str(self.terminalCommandText.text())

    def updateToolForTerminalInformation(self, update = True):
        #if self.commandTabsValidate() == True:
        if self.validateCommandTabs(self.terminalActionNameText, self.terminalLabelText, self.terminalCommandText):
            # do not update anything the first time or when you remove a line
            if self.terminalTableRow == -1 or update == False:
                pass
            else:
                self.updateTerminalActions()

#           self.terminalLabelText.setStyleSheet("border: 1px solid grey;")
#           self.terminalCommandText.setStyleSheet("border: 1px solid grey;")
            self.terminalTableRow = self.toolForTerminalTableWidget.currentRow()
            self.terminalLabelText.setReadOnly(False)

            if self.toolForTerminalTableWidget.item(self.terminalTableRow, 0) is not None:
                key = self.toolForTerminalTableWidget.item(self.terminalTableRow, 0).text()
                for tool in self.settings.portTerminalActions:
                    if tool[1] == key:
                        self.terminalActionNameText.setText(tool[1])
                        self.terminalLabelText.setText(tool[0])
                        self.terminalCommandText.setText(tool[2])
                        #  for the case that the tool (ex. new added tool) does not have any service assigned 
                        if len(tool) == 4:
                            servicesList = tool[3].split(',')
                            self.terminalServicesActiveTable.setRowCount(len(servicesList))
                            for i in range(len(servicesList)):
                                self.terminalServicesActiveTable.setItem(i, 0, QTableWidgetItem())
                                self.terminalServicesActiveTable.item(i, 0).setText(str(servicesList[i]))
        else:
            self.toolForTerminalTableWidget.selectRow(self.terminalTableRow)

    ##################### TOOLS / AUTOMATED ATTACKS FUNCTIONS #####################

    def enableAutoToolsTab(self):                                       # when 'Run automated attacks' is checked this function is called
        if self.enableAutoAttacks.isChecked():
            self.AutoAttacksSettingsTab.setTabEnabled(1,True)
        else:
            self.AutoAttacksSettingsTab.setTabEnabled(1,False)

    #def selectDefaultServices(self):                                   # toggles select/deselect all default creds checkboxes
    def toggleDefaultServices(self):                                    # toggles select/deselect all default creds checkboxes  
        for service in self.defaultServicesList:
            if not self.typeDic[service][2].isChecked() == self.checkDefaultCred.isChecked():
                self.typeDic[service][2].toggle()

    #def addRemoveServices(self, add=True):
    def moveService(self, src, dst):                                    # in the multiple choice widget (port/terminal commands tabs) it transfers services bidirectionally
        if src.selectionModel().selectedRows():
            row = src.currentRow()
            dst.setRowCount(dst.rowCount() + 1)
            dst.setItem(dst.rowCount() - 1, 0, QTableWidgetItem())
            dst.item(dst.rowCount() - 1, 0).setText(str(src.item(row, 0).text()))
            src.removeRow(row)

    ##################### SETUP FUNCTIONS #####################
    def setupLayout(self):
        self.setModal(True)
        self.setWindowTitle('Settings')
        self.setFixedSize(900, 500)

        self.flayout = QVBoxLayout()
        self.settingsTabWidget = QTabWidget()
        self.settingsTabWidget.setTabBar(SettingsTabBarWidget(width=200,height=25))
        self.settingsTabWidget.setTabPosition(QTabWidget.West)    # put the tab titles on the left
        
        # left tab menu items
        self.GeneralSettingsTab = QWidget()
        self.BruteSettingsTab = QWidget()
        self.ToolSettingsTab = QTabWidget()
        self.WordlistsSettingsTab = QTabWidget()
        self.AutoAttacksSettingsTab = QTabWidget()

        self.setupGeneralTab()
        self.setupBruteTab()
        self.setupToolsTab()
        self.setupAutomatedAttacksTab()
        
        self.settingsTabWidget.addTab(self.GeneralSettingsTab,"General")
        self.settingsTabWidget.addTab(self.BruteSettingsTab,"Brute")
        self.settingsTabWidget.addTab(self.ToolSettingsTab,"Tools")
        self.settingsTabWidget.addTab(self.WordlistsSettingsTab,"Wordlists")
        self.settingsTabWidget.addTab(self.AutoAttacksSettingsTab,"Automated Attacks")

        self.settingsTabWidget.setCurrentIndex(0)
        
        self.flayout.addWidget(self.settingsTabWidget)
        
        self.horLayout1 = QHBoxLayout()
        self.cancelButton = QPushButton('Cancel')
        self.cancelButton.setMaximumSize(60, 30)
        self.applyButton = QPushButton('Apply')
        self.applyButton.setMaximumSize(60, 30)
        self.spacer2 = QSpacerItem(750,0)
        self.horLayout1.addItem(self.spacer2)   
        self.horLayout1.addWidget(self.applyButton)
        self.horLayout1.addWidget(self.cancelButton)

        self.flayout.addLayout(self.horLayout1)     
        self.setLayout(self.flayout)

    def setupGeneralTab(self):
        self.terminalLabel = QLabel()
        self.terminalLabel.setText('Terminal')
        self.terminalLabel.setFixedWidth(150)
        self.terminalComboBox = QComboBox()
        self.terminalComboBox.setFixedWidth(150)
        self.terminalComboBox.setMinimumContentsLength(3)
        self.terminalComboBox.setStyleSheet("QComboBox { combobox-popup: 0; }")
        self.terminalComboBox.setCurrentIndex(0)
        self.hlayout1 = QHBoxLayout()
        self.hlayout1.addWidget(self.terminalLabel)
        self.hlayout1.addWidget(self.terminalComboBox)
        self.hlayout1.addStretch()
            
        self.label3 = QLabel()
        self.label3.setText('Maximum processes')
        self.label3.setFixedWidth(150)
        self.fastProcessesNumber = []
        for i in range(1, 50):
            self.fastProcessesNumber.append(str(i))
        self.fastProcessesComboBox = QComboBox()
        self.fastProcessesComboBox.insertItems(0, self.fastProcessesNumber)
        self.fastProcessesComboBox.setMinimumContentsLength(3)
        self.fastProcessesComboBox.setStyleSheet("QComboBox { combobox-popup: 0; }")
        self.fastProcessesComboBox.setCurrentIndex(19)
        self.fastProcessesComboBox.setFixedWidth(150)
        self.fastProcessesComboBox.setMaxVisibleItems(3)
        self.hlayoutGeneral_4 = QHBoxLayout()
        self.hlayoutGeneral_4.addWidget(self.label3)
        self.hlayoutGeneral_4.addWidget(self.fastProcessesComboBox)
        self.hlayoutGeneral_4.addStretch()

        self.label1 = QLabel()
        self.label1.setText('Screenshot timeout')
        self.label1.setFixedWidth(150)
        self.screenshotTextinput = QLineEdit()
        self.screenshotTextinput.setFixedWidth(150)
        self.hlayoutGeneral_2 = QHBoxLayout()
        self.hlayoutGeneral_2.addWidget(self.label1)
        self.hlayoutGeneral_2.addWidget(self.screenshotTextinput)
        self.hlayoutGeneral_2.addStretch()
        
        self.label2 = QLabel()
        self.label2.setText('Web services')
        self.label2.setFixedWidth(150)
        self.webServicesTextinput = QLineEdit()
        self.webServicesTextinput.setFixedWidth(350)
        self.hlayoutGeneral_3 = QHBoxLayout()
        self.hlayoutGeneral_3.addWidget(self.label2)
        self.hlayoutGeneral_3.addWidget(self.webServicesTextinput)
        self.hlayoutGeneral_3.addStretch()
        
        self.checkStoreClearPW = QCheckBox()
        self.checkStoreClearPW.setText('Store cleartext passwords on exit')
        self.hlayoutGeneral_6 = QHBoxLayout()
        self.hlayoutGeneral_6.addWidget(self.checkStoreClearPW)

        self.checkBlackBG = QCheckBox()
        self.checkBlackBG.setText('Use black backgrounds for tool output')
        self.hlayout2 = QHBoxLayout()
        self.hlayout2.addWidget(self.checkBlackBG)

        self.vlayoutGeneral = QVBoxLayout(self.GeneralSettingsTab)        
        self.vlayoutGeneral.addLayout(self.hlayout1)
        self.vlayoutGeneral.addLayout(self.hlayoutGeneral_4)        
        self.vlayoutGeneral.addLayout(self.hlayoutGeneral_2)
        self.vlayoutGeneral.addLayout(self.hlayoutGeneral_3)
        self.vlayoutGeneral.addLayout(self.hlayoutGeneral_6)
        self.vlayoutGeneral.addLayout(self.hlayout2)

        self.generalSpacer = QSpacerItem(10,350)
        self.vlayoutGeneral.addItem(self.generalSpacer)

    def setupBruteTab(self):
        self.vlayoutBrute = QVBoxLayout(self.BruteSettingsTab)
        
        self.label5 = QLabel()
        self.label5.setText('Username lists path')
        self.label5.setFixedWidth(150)
        self.userlistPath = QLineEdit()
        self.userlistPath.setFixedWidth(350)
        self.browseUsersListButton = QPushButton('Browse')
        self.browseUsersListButton.setMaximumSize(80, 30)
        self.hlayoutGeneral_7 = QHBoxLayout()
        self.hlayoutGeneral_7.addWidget(self.label5)
        self.hlayoutGeneral_7.addWidget(self.userlistPath)
        self.hlayoutGeneral_7.addWidget(self.browseUsersListButton)
        self.hlayoutGeneral_7.addStretch()
        
        self.label6 = QLabel()
        self.label6.setText('Password lists path')
        self.label6.setFixedWidth(150)
        self.passwordlistPath = QLineEdit()
        self.passwordlistPath.setFixedWidth(350)
        self.browsePasswordsListButton = QPushButton('Browse')
        self.browsePasswordsListButton.setMaximumSize(80, 30)
        self.hlayoutGeneral_8 = QHBoxLayout()
        self.hlayoutGeneral_8.addWidget(self.label6)
        self.hlayoutGeneral_8.addWidget(self.passwordlistPath)
        self.hlayoutGeneral_8.addWidget(self.browsePasswordsListButton)
        self.hlayoutGeneral_8.addStretch()
        
        self.label7 = QLabel()
        self.label7.setText('Default username')
        self.label7.setFixedWidth(150)
        self.defaultUserText = QLineEdit()
        self.defaultUserText.setFixedWidth(125)
        self.hlayoutGeneral_9 = QHBoxLayout()
        self.hlayoutGeneral_9.addWidget(self.label7)
        self.hlayoutGeneral_9.addWidget(self.defaultUserText)
        self.hlayoutGeneral_9.addStretch()
        
        self.label8 = QLabel()
        self.label8.setText('Default password')
        self.label8.setFixedWidth(150)
        self.defaultPassText = QLineEdit()
        self.defaultPassText.setFixedWidth(125)
        self.hlayoutGeneral_10 = QHBoxLayout()
        self.hlayoutGeneral_10.addWidget(self.label8)
        self.hlayoutGeneral_10.addWidget(self.defaultPassText)
        self.hlayoutGeneral_10.addStretch()
        
        self.vlayoutBrute.addLayout(self.hlayoutGeneral_7)
        self.vlayoutBrute.addLayout(self.hlayoutGeneral_8)
        self.vlayoutBrute.addLayout(self.hlayoutGeneral_9)
        self.vlayoutBrute.addLayout(self.hlayoutGeneral_10)     
        self.bruteSpacer = QSpacerItem(10,380)
        self.vlayoutBrute.addItem(self.bruteSpacer)

    def setupToolsTab(self):
        self.ToolPathsWidget = QWidget()
        self.ToolSettingsTab.addTab(self.ToolPathsWidget, "Tool Paths")
        self.HostActionsWidget = QWidget()
        self.ToolSettingsTab.addTab(self.HostActionsWidget, "Host Commands")
        self.PortActionsWidget = QWidget()
        self.ToolSettingsTab.addTab(self.PortActionsWidget, "Port Commands")
        self.portTerminalActionsWidget = QWidget()
        self.ToolSettingsTab.addTab(self.portTerminalActionsWidget, "Terminal Commands")
        self.StagedNmapWidget = QWidget()
        self.ToolSettingsTab.addTab(self.StagedNmapWidget, "Staged Nmap")
        
        self.setupToolPathsTab()
        self.setupHostCommandsTab()
        self.setupPortCommandsTab()
        self.setupTerminalCommandsTab()
        self.setupStagedNmapTab()

    def setupToolPathsTab(self):
        self.nmapPathlabel = QLabel()
        self.nmapPathlabel.setText('Nmap')
        self.nmapPathlabel.setFixedWidth(100)
        self.nmapPathInput = QLineEdit()
        self.nmapPathHorLayout = QHBoxLayout()
        self.nmapPathHorLayout.addWidget(self.nmapPathlabel)
        self.nmapPathHorLayout.addWidget(self.nmapPathInput)
        self.nmapPathHorLayout.addStretch()
        
        self.hydraPathlabel = QLabel()
        self.hydraPathlabel.setText('Hydra')
        self.hydraPathlabel.setFixedWidth(100)
        self.hydraPathInput = QLineEdit()
        self.hydraPathHorLayout = QHBoxLayout()
        self.hydraPathHorLayout.addWidget(self.hydraPathlabel)
        self.hydraPathHorLayout.addWidget(self.hydraPathInput)
        self.hydraPathHorLayout.addStretch()
        
#       self.cutycaptPathlabel = QLabel()
#       self.cutycaptPathlabel.setText('Cutycapt')
#       self.cutycaptPathlabel.setFixedWidth(100)
#       self.cutycaptPathInput = QLineEdit()
#       self.cutycaptPathHorLayout = QHBoxLayout()
#       self.cutycaptPathHorLayout.addWidget(self.cutycaptPathlabel)
#       self.cutycaptPathHorLayout.addWidget(self.cutycaptPathInput)
#       self.cutycaptPathHorLayout.addStretch()
        
        self.textEditorPathlabel = QLabel()
        self.textEditorPathlabel.setText('Text editor')
        self.textEditorPathlabel.setFixedWidth(100)
        self.textEditorPathInput = QLineEdit()
        self.textEditorPathHorLayout = QHBoxLayout()
        self.textEditorPathHorLayout.addWidget(self.textEditorPathlabel)
        self.textEditorPathHorLayout.addWidget(self.textEditorPathInput)
        self.textEditorPathHorLayout.addStretch()
        
        self.toolsPathVerLayout = QVBoxLayout()       
        self.toolsPathVerLayout.addLayout(self.nmapPathHorLayout)
        self.toolsPathVerLayout.addLayout(self.hydraPathHorLayout)
#       self.toolsPathVerLayout.addLayout(self.cutycaptPathHorLayout)
        self.toolsPathVerLayout.addLayout(self.textEditorPathHorLayout)
        self.toolsPathVerLayout.addStretch()

        self.globToolsPathHorLayout = QHBoxLayout(self.ToolPathsWidget)
        self.globToolsPathHorLayout.addLayout(self.toolsPathVerLayout)
        self.toolsPathHorSpacer = QSpacerItem(50,0)                     # right margin spacer
        self.globToolsPathHorLayout.addItem(self.toolsPathHorSpacer)        

    def setupHostCommandsTab(self):
        self.toolForHostsTableWidget = QTableWidget(self.HostActionsWidget)
        self.toolForHostsTableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.toolForHostsTableWidget.setFixedWidth(180)
        self.toolForHostsTableWidget.setShowGrid(False)                 # to make the cells of the table read only
        self.toolForHostsTableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.toolForHostsTableWidget.setColumnCount(1)
        self.toolForHostsTableWidget.setHorizontalHeaderItem(0, QTableWidgetItem())
        self.toolForHostsTableWidget.horizontalHeaderItem(0).setText("Name")
        self.toolForHostsTableWidget.horizontalHeader().resizeSection(0,200)
        self.toolForHostsTableWidget.horizontalHeader().setVisible(False)
        self.toolForHostsTableWidget.verticalHeader().setVisible(False) # row header - is hidden
        self.toolForHostsTableWidget.setVerticalHeaderItem(0, QTableWidgetItem())
        
        self.horLayoutPortActions = QHBoxLayout()
        self.removeToolForHostButton = QPushButton('Remove')
        self.removeToolForHostButton.setMaximumSize(90, 30)
        self.addToolForHostButton = QPushButton('Add')
        self.addToolForHostButton.setMaximumSize(90, 30)
        self.horLayoutPortActions.addWidget(self.addToolForHostButton)
        self.horLayoutPortActions.addWidget(self.removeToolForHostButton)
        
        self.actionHost = QLabel()
        self.actionHost.setText('Tools')
        
        self.verLayoutPortActions = QVBoxLayout()
        self.verLayoutPortActions.addWidget(self.actionHost)
        self.verLayoutPortActions.addWidget(self.toolForHostsTableWidget)
        self.verLayoutPortActions.addLayout(self.horLayoutPortActions)
        
        self.verLayout1 = QVBoxLayout()
        
        self.horLayout4 = QHBoxLayout()
        self.label12 = QLabel()
        self.label12.setText('Tool')
        self.label12.setFixedWidth(70)
        self.hostActionNameText = QLineEdit()

        self.horLayout4.addWidget(self.label12)
        self.horLayout4.addWidget(self.hostActionNameText)
        
        self.label9 = QLabel()
        self.label9.setText('Label')
        self.label9.setFixedWidth(70)

        self.hostLabelText = QLineEdit()
        self.hostLabelText.setText(' ')
        self.hostLabelText.setReadOnly(True)

        self.horLayout1 = QHBoxLayout()
        self.horLayout1.addWidget(self.label9)
        self.horLayout1.addWidget(self.hostLabelText)
        
        self.horLayout2 = QHBoxLayout()
        self.label10 = QLabel()
        self.label10.setText('Command')
        self.label10.setFixedWidth(70)

        self.hostCommandText = QLineEdit()
        self.hostCommandText.setText('init value')
        self.horLayout2.addWidget(self.label10)
        self.horLayout2.addWidget(self.hostCommandText)     
        
        self.spacer6 = QSpacerItem(0,20)
        self.verLayout1.addItem(self.spacer6)
        self.verLayout1.addLayout(self.horLayout4)
        self.verLayout1.addLayout(self.horLayout1)
        self.verLayout1.addLayout(self.horLayout2)
        self.spacer1 = QSpacerItem(0,800)
        self.verLayout1.addItem(self.spacer1)
        
        self.globLayoutPortActions = QHBoxLayout(self.HostActionsWidget)
        self.globLayoutPortActions.addLayout(self.verLayoutPortActions)
        self.spacer5 = QSpacerItem(10,0)
        self.globLayoutPortActions.addItem(self.spacer5)
        self.globLayoutPortActions.addLayout(self.verLayout1)
        self.spacer2 = QSpacerItem(50,0)
        self.globLayoutPortActions.addItem(self.spacer2)

    def setupPortCommandsTab(self):
        self.label11 = QLabel()
        self.label11.setText('Tools')

        self.toolForServiceTableWidget = QTableWidget(self.PortActionsWidget)
        self.toolForServiceTableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.toolForServiceTableWidget.setFixedWidth(180)
        self.toolForServiceTableWidget.setShowGrid(False)
        self.toolForServiceTableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                                                                        # table headers
        self.toolForServiceTableWidget.setColumnCount(1)
        self.toolForServiceTableWidget.setHorizontalHeaderItem(0, QTableWidgetItem())
        self.toolForServiceTableWidget.horizontalHeaderItem(0).setText("Name")
        self.toolForServiceTableWidget.horizontalHeader().resizeSection(0,200)
        self.toolForServiceTableWidget.horizontalHeader().setVisible(False)
        self.toolForServiceTableWidget.verticalHeader().setVisible(False)
        self.toolForServiceTableWidget.setVerticalHeaderItem(0, QTableWidgetItem())
        
        self.horLayoutPortActions = QHBoxLayout()
        self.addToolButton = QPushButton('Add')
        self.addToolButton.setMaximumSize(90, 30)       
        self.removeToolButton = QPushButton('Remove')
        self.removeToolButton.setMaximumSize(90, 30)
        self.horLayoutPortActions.addWidget(self.addToolButton)
        self.horLayoutPortActions.addWidget(self.removeToolButton)

        self.verLayoutPortActions = QVBoxLayout()
        self.verLayoutPortActions.addWidget(self.label11)
        self.verLayoutPortActions.addWidget(self.toolForServiceTableWidget)     
        self.verLayoutPortActions.addLayout(self.horLayoutPortActions)

        self.verLayout1 = QVBoxLayout()
                                                                        # right side
        self.horLayout4 = QHBoxLayout()
        self.label12 = QLabel()
        self.label12.setText('Tool')
        self.label12.setFixedWidth(70)
        self.portActionNameText = QLineEdit()
        self.horLayout4.addWidget(self.label12)
        self.horLayout4.addWidget(self.portActionNameText)
        
        self.horLayout1 = QHBoxLayout()
        self.label9 = QLabel()
        self.label9.setText('Label')
        self.label9.setFixedWidth(70)
        self.portLabelText = QLineEdit()
        self.portLabelText.setText(' ')
        self.portLabelText.setReadOnly(True)
        self.horLayout1.addWidget(self.label9)
        self.horLayout1.addWidget(self.portLabelText)

        self.horLayout2 = QHBoxLayout()
        self.label10 = QLabel()
        self.label10.setText('Command')
        self.label10.setFixedWidth(70)
        self.portCommandText = QLineEdit()
        self.portCommandText.setText('init value')
        self.horLayout2.addWidget(self.label10)
        self.horLayout2.addWidget(self.portCommandText)
        
        self.servicesAllTableWidget = QTableWidget()
        self.servicesAllTableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.servicesAllTableWidget.setMaximumSize(150, 300)
        self.servicesAllTableWidget.setColumnCount(1)
        self.servicesAllTableWidget.horizontalHeader().resizeSection(0,150)
        self.servicesAllTableWidget.setHorizontalHeaderItem(0, QTableWidgetItem())
        self.servicesAllTableWidget.horizontalHeaderItem(0).setText("Name")
        self.servicesAllTableWidget.horizontalHeader().setVisible(False)
        self.servicesAllTableWidget.setShowGrid(False)
        self.servicesAllTableWidget.verticalHeader().setVisible(False)

        self.servicesActiveTableWidget = QTableWidget()
        self.servicesActiveTableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.servicesActiveTableWidget.setMaximumSize(150, 300)
        self.servicesActiveTableWidget.setColumnCount(1)
        self.servicesActiveTableWidget.horizontalHeader().resizeSection(0,150)
        self.servicesActiveTableWidget.setHorizontalHeaderItem(0, QTableWidgetItem())
        self.servicesActiveTableWidget.horizontalHeaderItem(0).setText("Name")
        self.servicesActiveTableWidget.horizontalHeader().setVisible(False)
        self.servicesActiveTableWidget.setShowGrid(False)
        self.servicesActiveTableWidget.verticalHeader().setVisible(False)
        
        self.verLayout2 = QVBoxLayout()
        
        self.addServicesButton = QPushButton('-->')
        self.addServicesButton.setMaximumSize(30, 30)
        self.removeServicesButton = QPushButton('<--')
        self.removeServicesButton.setMaximumSize(30, 30)
        
        self.spacer4 = QSpacerItem(0,90)                                # space above and below arrow buttons
        self.verLayout2.addItem(self.spacer4)
        self.verLayout2.addWidget(self.addServicesButton)
        self.verLayout2.addWidget(self.removeServicesButton)        
        self.verLayout2.addItem(self.spacer4)
        
        self.horLayout3 = QHBoxLayout()                           # space left of multiple choice widget
        self.spacer3 = QSpacerItem(78,0)
        self.horLayout3.addItem(self.spacer3)
        self.horLayout3.addWidget(self.servicesAllTableWidget)
        self.horLayout3.addLayout(self.verLayout2)
        self.horLayout3.addWidget(self.servicesActiveTableWidget)
        
        self.spacer6 = QSpacerItem(0,20)                                # top right space
        self.verLayout1.addItem(self.spacer6)
        self.verLayout1.addLayout(self.horLayout4)
        self.verLayout1.addLayout(self.horLayout1)
        self.verLayout1.addLayout(self.horLayout2)
        self.verLayout1.addLayout(self.horLayout3)
        self.spacer1 = QSpacerItem(0,50)                                # bottom right space
        self.verLayout1.addItem(self.spacer1)
        
        self.globLayoutPortActions = QHBoxLayout(self.PortActionsWidget)          
        self.globLayoutPortActions.addLayout(self.verLayoutPortActions)
        
        self.spacer5 = QSpacerItem(10,0)                                # space between left and right layouts
        self.globLayoutPortActions.addItem(self.spacer5)        
        self.globLayoutPortActions.addLayout(self.verLayout1)
        self.spacer2 = QSpacerItem(50,0)                                # right margin space
        self.globLayoutPortActions.addItem(self.spacer2)

    def setupTerminalCommandsTab(self):     
        self.actionTerminalLabel = QLabel()
        self.actionTerminalLabel.setText('Tools')       
        
        self.toolForTerminalTableWidget = QTableWidget(self.portTerminalActionsWidget)
        self.toolForTerminalTableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.toolForTerminalTableWidget.setFixedWidth(180)
        self.toolForTerminalTableWidget.setShowGrid(False)
        # to make the cells of the table read only
        self.toolForTerminalTableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
                                                                        # table headers
        self.toolForTerminalTableWidget.setColumnCount(1)
        self.toolForTerminalTableWidget.setHorizontalHeaderItem(0, QTableWidgetItem())        
        self.toolForTerminalTableWidget.horizontalHeaderItem(0).setText("Name")     
        self.toolForTerminalTableWidget.horizontalHeader().resizeSection(0,200)     
        self.toolForTerminalTableWidget.horizontalHeader().setVisible(False)
        self.toolForTerminalTableWidget.verticalHeader().setVisible(False)
        self.toolForTerminalTableWidget.setVerticalHeaderItem(0, QTableWidgetItem())
        
        self.horLayout1 = QHBoxLayout()
        self.addToolForTerminalButton = QPushButton('Add')
        self.addToolForTerminalButton.setMaximumSize(90, 30)        
        self.removeToolForTerminalButton = QPushButton('Remove')
        self.removeToolForTerminalButton.setMaximumSize(90, 30)
        self.horLayout1.addWidget(self.addToolForTerminalButton)
        self.horLayout1.addWidget(self.removeToolForTerminalButton)

        self.verLayout1 = QVBoxLayout()
        self.verLayout1.addWidget(self.actionTerminalLabel)
        self.verLayout1.addWidget(self.toolForTerminalTableWidget)
        self.verLayout1.addLayout(self.horLayout1)
        
        self.horLayout2 = QHBoxLayout()
        self.actionNameTerminalLabel = QLabel()
        self.actionNameTerminalLabel.setText('Tool')
        self.actionNameTerminalLabel.setFixedWidth(70)
        self.terminalActionNameText = QLineEdit()     
        self.horLayout2.addWidget(self.actionNameTerminalLabel)
        self.horLayout2.addWidget(self.terminalActionNameText)
        
        self.horLayout3 = QHBoxLayout()
        self.labelTerminalLabel = QLabel()
        self.labelTerminalLabel.setText('Label')
        self.labelTerminalLabel.setFixedWidth(70)
        self.terminalLabelText = QLineEdit()
        self.terminalLabelText.setText(' ')
        self.terminalLabelText.setReadOnly(True)
        self.horLayout3.addWidget(self.labelTerminalLabel)
        self.horLayout3.addWidget(self.terminalLabelText)
        
        self.horLayout4 = QHBoxLayout()
        self.commandTerminalLabel = QLabel()
        self.commandTerminalLabel.setText('Command')
        self.commandTerminalLabel.setFixedWidth(70)
        self.terminalCommandText = QLineEdit()
        self.terminalCommandText.setText('init value')
        self.horLayout4.addWidget(self.commandTerminalLabel)
        self.horLayout4.addWidget(self.terminalCommandText)
        
        self.terminalServicesAllTable = QTableWidget()
        self.terminalServicesAllTable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.terminalServicesAllTable.setMaximumSize(150, 300)
        self.terminalServicesAllTable.setColumnCount(1)
        self.terminalServicesAllTable.horizontalHeader().resizeSection(0,150)
        self.terminalServicesAllTable.setHorizontalHeaderItem(0, QTableWidgetItem())
        self.terminalServicesAllTable.horizontalHeaderItem(0).setText("Available Services")
        self.terminalServicesAllTable.horizontalHeader().setVisible(False)
        self.terminalServicesAllTable.setShowGrid(False)        
        self.terminalServicesAllTable.verticalHeader().setVisible(False)
        
        self.terminalServicesActiveTable = QTableWidget()
        self.terminalServicesActiveTable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.terminalServicesActiveTable.setMaximumSize(150, 300)
        self.terminalServicesActiveTable.setColumnCount(1)
        self.terminalServicesActiveTable.horizontalHeader().resizeSection(0,150)
        self.terminalServicesActiveTable.setHorizontalHeaderItem(0, QTableWidgetItem())
        self.terminalServicesActiveTable.horizontalHeaderItem(0).setText("Applied Services")
        self.terminalServicesActiveTable.horizontalHeader().setVisible(False)
        self.terminalServicesActiveTable.setShowGrid(False)
        self.terminalServicesActiveTable.verticalHeader().setVisible(False)
        
        self.addTerminalServiceButton = QPushButton('-->')
        self.addTerminalServiceButton.setMaximumSize(30, 30)
        self.removeTerminalServiceButton = QPushButton('<--')
        self.removeTerminalServiceButton.setMaximumSize(30, 30)
        
        self.verLayout3 = QVBoxLayout()
        self.spacer2 = QSpacerItem(0,90)
        self.verLayout3.addItem(self.spacer2)
        self.verLayout3.addWidget(self.addTerminalServiceButton)
        self.verLayout3.addWidget(self.removeTerminalServiceButton)
        self.verLayout3.addItem(self.spacer2)
        
        self.horLayout5 = QHBoxLayout()
        self.spacer3 = QSpacerItem(78,0)
        self.horLayout5.addItem(self.spacer3)
        self.horLayout5.addWidget(self.terminalServicesAllTable)
        self.horLayout5.addLayout(self.verLayout3)
        self.horLayout5.addWidget(self.terminalServicesActiveTable)
        
        self.verLayout2 = QVBoxLayout()
        self.spacer4 = QSpacerItem(0,20)
        self.verLayout2.addItem(self.spacer4)
        self.verLayout2.addLayout(self.horLayout2)
        self.verLayout2.addLayout(self.horLayout3)
        self.verLayout2.addLayout(self.horLayout4)
        self.verLayout2.addLayout(self.horLayout5)
        self.spacer5 = QSpacerItem(0,50)
        self.verLayout2.addItem(self.spacer5)
        
        self.globLayoutTerminalActions = QHBoxLayout(self.portTerminalActionsWidget)
        self.globLayoutTerminalActions.addLayout(self.verLayout1)
        self.spacer6 = QSpacerItem(10,0)
        self.globLayoutTerminalActions.addItem(self.spacer6)
        self.globLayoutTerminalActions.addLayout(self.verLayout2)
        self.spacer7 = QSpacerItem(50,0)
        self.globLayoutTerminalActions.addItem(self.spacer7)

    def setupStagedNmapTab(self):
        self.stage1label = QLabel()
        self.stage1label.setText('nmap stage 1')
        self.stage1label.setFixedWidth(100)
        self.stage1Input = QLineEdit()
        self.stage1Input.setFixedWidth(500)
        self.hlayout1 = QHBoxLayout()
        self.hlayout1.addWidget(self.stage1label)
        self.hlayout1.addWidget(self.stage1Input)
        
        self.stage2label = QLabel()
        self.stage2label.setText('nmap stage 2')
        self.stage2label.setFixedWidth(100)
        self.stage2Input = QLineEdit()
        self.stage2Input.setFixedWidth(500)
        self.hlayout2 = QHBoxLayout()
        self.hlayout2.addWidget(self.stage2label)
        self.hlayout2.addWidget(self.stage2Input)
        
        self.stage3label = QLabel()
        self.stage3label.setText('nmap stage 3')
        self.stage3label.setFixedWidth(100)
        self.stage3Input = QLineEdit()
        self.stage3Input.setFixedWidth(500)
        self.hlayout3 = QHBoxLayout()
        self.hlayout3.addWidget(self.stage3label)
        self.hlayout3.addWidget(self.stage3Input)
        
        self.stage4label = QLabel()
        self.stage4label.setText('nmap stage 4')
        self.stage4label.setFixedWidth(100)
        self.stage4Input = QLineEdit()
        self.stage4Input.setFixedWidth(500)
        self.hlayout4 = QHBoxLayout()
        self.hlayout4.addWidget(self.stage4label)
        self.hlayout4.addWidget(self.stage4Input)
        
        self.stage5label = QLabel()
        self.stage5label.setText('nmap stage 5')
        self.stage5label.setFixedWidth(100)
        self.stage5Input = QLineEdit()
        self.stage5Input.setFixedWidth(500)
        self.hlayout5 = QHBoxLayout()
        self.hlayout5.addWidget(self.stage5label)
        self.hlayout5.addWidget(self.stage5Input)
        
        self.vlayout1 = QVBoxLayout()     
        self.vlayout1.addLayout(self.hlayout1)
        self.vlayout1.addLayout(self.hlayout2)
        self.vlayout1.addLayout(self.hlayout3)
        self.vlayout1.addLayout(self.hlayout4)
        self.vlayout1.addLayout(self.hlayout5)
        self.vlayout1.addStretch()

        self.gHorLayout = QHBoxLayout(self.StagedNmapWidget)
        self.gHorLayout.addLayout(self.vlayout1)
        self.spacer2 = QSpacerItem(50,0)                                # right margin spacer
        self.gHorLayout.addItem(self.spacer2)

    def setupAutomatedAttacksTab(self):
        self.GeneralAutoSettingsWidget = QWidget()
        self.AutoAttacksSettingsTab.addTab(self.GeneralAutoSettingsWidget, "General")
        self.AutoToolsWidget = QWidget()
        self.AutoAttacksSettingsTab.addTab(self.AutoToolsWidget, "Tool Configuration")

        self.setupAutoAttacksGeneralTab()
        self.setupAutoAttacksToolTab()

    def setupAutoAttacksGeneralTab(self):
        self.globVerAutoSetLayout = QVBoxLayout(self.GeneralAutoSettingsWidget)

        self.enableAutoAttacks = QCheckBox()
        self.enableAutoAttacks.setText('Run automated attacks') 
        self.checkDefaultCred = QCheckBox()
        self.checkDefaultCred.setText('Check for default credentials')

        self.defaultBoxVerlayout = QVBoxLayout()  
        self.defaultCredentialsBox = QGroupBox("Default Credentials")
        self.defaultCredentialsBox.setLayout(self.defaultBoxVerlayout)
        self.globVerAutoSetLayout.addWidget(self.enableAutoAttacks)
        self.globVerAutoSetLayout.addWidget(self.checkDefaultCred)
        self.globVerAutoSetLayout.addWidget(self.defaultCredentialsBox)
        self.globVerAutoSetLayout.addStretch()

    def setupAutoAttacksToolTab(self):
        self.toolNameLabel = QLabel()
        self.toolNameLabel.setText('Tool')
        self.toolNameLabel.setFixedWidth(150)
        self.toolServicesLabel = QLabel()
        self.toolServicesLabel.setText('Services')
        self.toolServicesLabel.setFixedWidth(300)
        self.enableAllToolsLabel = QLabel()
        self.enableAllToolsLabel.setText('Run automatically')
        self.enableAllToolsLabel.setFixedWidth(150)

        self.autoToolTabHorLayout = QHBoxLayout()
        self.autoToolTabHorLayout.addWidget(self.toolNameLabel)
        self.autoToolTabHorLayout.addWidget(self.toolServicesLabel)
        self.autoToolTabHorLayout.addWidget(self.enableAllToolsLabel)

        self.scrollArea = QScrollArea()
        self.scrollWidget = QWidget()

        self.globVerAutoToolsLayout = QVBoxLayout(self.AutoToolsWidget)
        self.globVerAutoToolsLayout.addLayout(self.autoToolTabHorLayout)

        self.scrollVerLayout = QVBoxLayout(self.scrollWidget) 
        self.enabledSpacer = QSpacerItem(60,0)
        
        # by default the automated attacks are not activated and the tab is not enabled
        self.AutoAttacksSettingsTab.setTabEnabled(1,False)

    # for all the browse buttons
    def wordlistDialog(self, title='Choose username path'):
        if title == 'Choose username path':
            path = QFileDialog.getExistingDirectory(self, title, '/',  QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
            self.userlistPath.setText(str(path))
        else:
            path = QFileDialog.getExistingDirectory(self, title, '/')
            self.passwordlistPath.setText(str(path))

