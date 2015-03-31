#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2015 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import re
from PyQt4 import QtGui, QtCore
from auxiliary import *													# for bubble sort

class ProcessesTableModel(QtCore.QAbstractTableModel):
    
	def __init__(self, controller, processes = [[]], headers = [], parent = None):
		QtCore.QAbstractTableModel.__init__(self, parent)
		self.__headers = headers
		self.__processes = processes
		self.__controller = controller
		
	def setProcesses(self, processes):
		self.__processes = processes
		
	def getProcesses(self):
		return self.__processes

	def rowCount(self, parent):
		return len(self.__processes)

	def columnCount(self, parent):
		if not len(self.__processes) is 0:
			return len(self.__processes[0])
		return 0

	def headerData(self, section, orientation, role):
		if role == QtCore.Qt.DisplayRole:
			
			if orientation == QtCore.Qt.Horizontal:
				
				if section < len(self.__headers):
					return self.__headers[section]
				else:
					return "not implemented"

	def data(self, index, role):										# this method takes care of how the information is displayed
		if role == QtCore.Qt.DisplayRole:								# how to display each cell		
			value = ''
			row = index.row()
			column = index.column()

			if column == 1:
				value = self.__processes[row]['display']		
			elif column == 2:
				value = self.__processes[row]['pid']
			elif column == 3:
				value = self.__processes[row]['name']
			elif column == 4:
				if not self.__processes[row]['tabtitle'] == '':
					value = self.__processes[row]['tabtitle']
				else:
					value = self.__processes[row]['name']
			elif column == 5:
				value = self.__processes[row]['hostip']
			elif column == 6:
				if not self.__processes[row]['port'] == '' and not self.__processes[row]['protocol'] == '':
					value = self.__processes[row]['port'] + '/' + self.__processes[row]['protocol']
				else:
					value = self.__processes[row]['port']
			elif column == 7:
				value = self.__processes[row]['protocol']
			elif column == 8:
				value = self.__processes[row]['command']
			elif column == 9:
				value = self.__processes[row]['starttime']
			elif column == 10:
				value = self.__processes[row]['endtime']
			elif column == 11:
				value = self.__processes[row]['outputfile']	
			elif column == 12:	
				value = self.__processes[row]['output']
			elif column == 13:
				value = self.__processes[row]['status']
			elif column == 14:
				value = self.__processes[row]['closed']				
			return value			

	def sort(self, Ncol, order):
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		array=[]

		if Ncol == 3:            
			for i in range(len(self.__processes)):
				array.append(self.__processes[i]['name'])
		
		elif Ncol == 4:            
			for i in range(len(self.__processes)):
				array.append(self.__processes[i]['tabtitle'])
				
		elif Ncol == 5:
			for i in range(len(self.__processes)):
				array.append(IP2Int(self.__processes[i]['hostip']))
				
		elif Ncol == 6:
			for i in range(len(self.__processes)):
				if self.__processes[i]['port'] == '':
					return
				else:
					array.append(int(self.__processes[i]['port']))
				
		elif Ncol == 9:
			for i in range(len(self.__processes)):
				array.append(self.__processes[i]['starttime'])
		
		elif Ncol == 10:
			for i in range(len(self.__processes)):
				array.append(self.__processes[i]['endtime'])

		else:
			for i in range(len(self.__processes)):
				array.append(self.__processes[i]['status'])
		
		sortArrayWithArray(array, self.__processes)						# sort the services based on the values in the array

		if order == Qt.AscendingOrder:									# reverse if needed
			self.__processes.reverse()

		self.__controller.updateProcessesIcon()							# to make sure the progress GIF is displayed in the right place
			
		self.emit(SIGNAL("layoutChanged()"))

	def flags(self, index):												# method that allows views to know how to treat each item, eg: if it should be enabled, editable, selectable etc
		return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

	### getter functions ###

	def getProcessPidForRow(self, row):
		return self.__processes[row]['pid']
		
	def getProcessPidForId(self, dbId):
		for i in range(len(self.__processes)):
			if str(self.__processes[i]['id']) == str(dbId):
				return self.__processes[i]['pid']	

	def getProcessStatusForRow(self, row):
		return self.__processes[row]['status']

	def getProcessStatusForPid(self, pid):
		for i in range(len(self.__processes)):
			if str(self.__processes[i]['pid']) == str(pid):
				return self.__processes[i]['status']
				
	def getProcessStatusForId(self, dbId):
		for i in range(len(self.__processes)):
			if str(self.__processes[i]['id']) == str(dbId):
				return self.__processes[i]['status']

	def getProcessIdForRow(self, row):
		return self.__processes[row]['id']
		
	def getProcessIdForPid(self, pid):
		for i in range(len(self.__processes)):
			if str(self.__processes[i]['pid']) == str(pid):
				return self.__processes[i]['id']
				
	def getToolNameForRow(self, row):
		return self.__processes[row]['name']
		
	def getRowForToolName(self, toolname):
		for i in range(len(self.__processes)):
			if self.__processes[i]['name'] == toolname:
				return i

	def getRowForDBId(self, dbid):	# new
		for i in range(len(self.__processes)):
			if self.__processes[i]['id'] == dbid:
				return i

	def getIpForRow(self, row):
		return self.__processes[row]['hostip']

	def getPortForRow(self, row):
		return self.__processes[row]['port']

	def getProtocolForRow(self, row):
		return self.__processes[row]['protocol']
		
	def getOutputForRow(self, row):
		return self.__processes[row]['output']
		
	def getOutputfileForRow(self, row):
		return self.__processes[row]['outputfile']		
	
	def getDisplayForRow(self, row):
		return self.__processes[row]['display']
