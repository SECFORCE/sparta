#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2014 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import re
from PyQt4 import QtGui, QtCore
from PyQt4.QtGui import *												# for QFont
from auxiliary import *													# for bubble sort

class HostsTableModel(QtCore.QAbstractTableModel):
    
	def __init__(self, hosts = [[]], headers = [], parent = None):
		QtCore.QAbstractTableModel.__init__(self, parent)
		self.__headers = headers
		self.__hosts = hosts
		
	def setHosts(self, hosts):
		self.__hosts = hosts

	def rowCount(self, parent):
		return len(self.__hosts)

	def columnCount(self, parent):
		if not len(self.__hosts) is 0:
			return len(self.__hosts[0])
		return 0
		
	def headerData(self, section, orientation, role):
		if role == QtCore.Qt.DisplayRole:			
			if orientation == QtCore.Qt.Horizontal:				
				if section < len(self.__headers):
					return self.__headers[section]
				else:
					return "not implemented"

	def data(self, index, role):										# this method takes care of how the information is displayed
		if role == QtCore.Qt.DecorationRole:							# to show the operating system icon instead of text					
			if index.column() == 1:										# if trying to display the operating system
				os_string = self.__hosts[index.row()]['os_match']				
				if os_string == '':										# if there is no OS information, use the question mark icon
					return QtGui.QIcon("./images/question-icon.png")
					
				elif re.search('[lL]inux', os_string, re.I):
					return QtGui.QIcon("./images/linux-icon.png")
				
				elif re.search('[wW]indows', os_string, re.I):
					return QtGui.QIcon("./images/windows-icon.png")
					
				elif re.search('[cC]isco', os_string, re.I):
					return QtGui.QIcon("./images/cisco-big.jpg")
					
				elif re.search('HP ', os_string, re.I):
					return QtGui.QIcon("./images/hp-icon.png")

				elif re.search('[vV]x[wW]orks', os_string, re.I):
					return QtGui.QIcon("./images/hp-icon.png")
					
				elif re.search('[vV]m[wW]are', os_string, re.I):
					return QtGui.QIcon("./images/vmware-big.jpg")
				
				else:													# if it's an unknown OS also use the question mark icon
					return QtGui.QIcon("./images/question-icon.png")

		if role == QtCore.Qt.DisplayRole:								# how to display each cell
			value = ''
			row = index.row()
			column = index.column()
			if column == 0:
				value = self.__hosts[row]['id']
			elif column == 2:
				value = self.__hosts[row]['os_accuracy']
			elif column == 3:
				if not self.__hosts[row]['hostname'] == '':
					value = self.__hosts[row]['ip'] + ' ('+ self.__hosts[row]['hostname'] +')'
				else:
					value = self.__hosts[row]['ip']
			elif column == 4:
				value = self.__hosts[row]['ipv4']
			elif column == 5:
				value = self.__hosts[row]['ipv6']
			elif column == 6:
				value = self.__hosts[row]['macaddr']
			elif column == 7:
				value = self.__hosts[row]['status']
			elif column == 8:
				value = self.__hosts[row]['hostname']
			elif column == 9:
				value = self.__hosts[row]['vendor']
			elif column == 10:
				value = self.__hosts[row]['uptime']
			elif column == 11:
				value = self.__hosts[row]['lastboot']
			elif column == 12:
				value = self.__hosts[row]['distance']
			return value
			
		if role == QtCore.Qt.FontRole:
			# if a host is checked strike it out and make it italic
			if index.column() == 3 and self.__hosts[index.row()]['checked'] == 'True':  
				checkedFont=QFont()
				checkedFont.setStrikeOut(True)
				checkedFont.setItalic(True)
				return checkedFont

	def flags(self, index):												# method that allows views to know how to treat each item, eg: if it should be enabled, editable, selectable etc
		return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable		# add QtCore.Qt.ItemIsEditable to edit item

	def sort(self, Ncol, order):										# sort function called when the user clicks on a header
		
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		array = []
		
		if Ncol == 0 or Ncol == 3:										# if sorting by IP address (and by default)
			for i in range(len(self.__hosts)):
				array.append(IP2Int(self.__hosts[i]['ip']))

		elif Ncol == 1:													# if sorting by OS
			for i in range(len(self.__hosts)):
				
				os_string = self.__hosts[i]['os_match']
				if os_string == '':
					array.append('')
									
				elif re.search('[lL]inux', os_string, re.I):
					array.append('Linux')
				
				elif re.search('[wW]indows', os_string, re.I):
					array.append('Windows')
					
				elif re.search('[cC]isco', os_string, re.I):
					array.append('Cisco')
					
				elif re.search('HP ', os_string, re.I):
					array.append('Hp')

				elif re.search('[vV]x[wW]orks', os_string, re.I):
					array.append('Hp')
					
				elif re.search('[vV]m[wW]are', os_string, re.I):
					array.append('Vmware')
					
				else:
					array.append('')

		sortArrayWithArray(array, self.__hosts)							# sort the array of OS

		if order == Qt.AscendingOrder:									# reverse if needed
			self.__hosts.reverse()

		self.emit(SIGNAL("layoutChanged()"))							# update the UI (built-in signal)

	### getter functions ###

	def getHostIPForRow(self, row):
		return self.__hosts[row]['ip']

	def getHostIdForRow(self, row):
		return self.__hosts[row]['id']
		
	def getHostCheckStatusForRow(self, row):
		return self.__hosts[row]['checked']

	def getHostCheckStatusForIp(self, ip):
		for i in range(len(self.__hosts)):
			if str(self.__hosts[i]['ip']) == str(ip):
				return self.__hosts[i]['checked']
			
	def getRowForIp(self, ip):
		for i in range(len(self.__hosts)):
			if self.__hosts[i]['ip'] == ip:
				return i
