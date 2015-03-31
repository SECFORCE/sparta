#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2015 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os, sys, urllib2, socket, time, datetime, locale, webbrowser, re	# for webrequests, screenshot timeouts, timestamps, browser stuff and regex
from PyQt4 import QtGui, QtCore
from PyQt4.QtCore import *												# for QProcess
import errno															# temporary for isHttpd
import subprocess														# for screenshots with cutycapt
import string															# for input validation

# bubble sort algorithm that sorts an array (in place) based on the values in another array
# the values in the array must be comparable and in the corresponding positions
# used to sort objects by one of their attributes.
def sortArrayWithArray(array, arrayToSort):
	for i in range(0, len(array) - 1):
		swap_test = False
		for j in range(0, len(array) - i - 1):
			if array[j] > array[j + 1]:
				array[j], array[j + 1] = array[j + 1], array[j] 		# swap
				arrayToSort[j], arrayToSort[j + 1] = arrayToSort[j + 1], arrayToSort[j]
			swap_test = True
		if swap_test == False:
			break

# converts an IP address to an integer (for the sort function)
def IP2Int(ip):
	ip = ip.split("/")[0]			# bug fix: remove slash if it's a range
	o = map(int, ip.split('.'))
	res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
	return res

# old function, replaced by isHttps (checking for https first is better)
def isHttp(url):
	try:
		req = urllib2.Request(url)
		req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
		r = urllib2.urlopen(req, timeout=10)
		#print 'response code: ' + str(r.code)
		#print 'response content: ' + str(r.read())
		return True
		
	except urllib2.HTTPError, e:
		reason = str(sys.exc_info()[1].reason)
		# print reason
		if reason == 'Unauthorized' or reason == 'Forbidden':
			return True
		return False
		
	except:
		return False

def isHttps(ip, port):
	try:
		req = urllib2.Request('https://'+ip+':'+port)
		req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:22.0) Gecko/20100101 Firefox/22.0 Iceweasel/22.0')
		r = urllib2.urlopen(req, timeout=5)
#		print '\nresponse code: ' + str(r.code)
#		print '\nresponse content: ' + str(r.read())
		return True

	except:	
		reason = str(sys.exc_info()[1].reason)
#		print reason
#		if 'Interrupted system call' in reason:
#			print 'caught exception. retry?'
			
		if reason == 'Forbidden':
			return True	
		return False

		
def getTimestamp(human=False):
	t = time.time()
	if human:
		timestamp = datetime.datetime.fromtimestamp(t).strftime("%d %b %Y %H:%M:%S").decode(locale.getlocale()[1])
	else:
		timestamp = datetime.datetime.fromtimestamp(t).strftime('%Y%m%d%H%M%S')
	return timestamp

# used by the settings dialog when a user cancels and the GUI needs to be reset
def clearLayout(layout):
    if layout is not None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            else:
                clearLayout(item.layout())

# this function sets a table view's properties
def setTableProperties(table, headersLen, hiddenColumnIndexes = []):

	table.verticalHeader().setVisible(False)							# hide the row headers
	table.setShowGrid(False)											# hide the table grid
	table.setSelectionBehavior(QtGui.QTableView.SelectRows)				# select entire row instead of single cell
	table.setSortingEnabled(True)										# enable column sorting
	table.horizontalHeader().setStretchLastSection(True)				# header behaviour
	table.horizontalHeader().setSortIndicatorShown(False)				# hide sort arrow from column header
	table.setWordWrap(False)											# row behaviour
	table.resizeRowsToContents()

	for i in range(0, headersLen):										# reset all the hidden columns
			table.setColumnHidden(i, False)

	for i in hiddenColumnIndexes:										# hide some columns
		table.setColumnHidden(i, True)
	
	table.setContextMenuPolicy(Qt.CustomContextMenu)					# create the right-click context menu
	
def checkHydraResults(output):
	usernames = []
	passwords = []
	string = '\[[0-9]+\]\[[a-z-]+\].+'									# when a password is found, the line contains [port#][plugin-name]		
	results = re.findall(string, output, re.I)
	if results:
		for line in results:
			login = re.search('(login:[\s]*)([^\s]+)', line)
			if login:
				print 'Found username: ' + login.group(2)
				usernames.append(login.group(2))
			password = re.search('(password:[\s]*)([^\s]+)', line)
			if password:
				#print 'Found password: ' + password.group(2)

				passwords.append(password.group(2))	
		return True, usernames, passwords								# returns the lists of found usernames and passwords
	return False, [], []

def exportNmapToHTML(filename):
	try:
		command = 'xsltproc -o ' + str(filename)+'.html ' + str(filename)+ '.xml'
		p = subprocess.Popen(command, shell=True)
		p.wait()
	
	except:
		print '[-] Could not convert nmap XML to HTML. Try: apt-get install xsltproc'

# this class is used for example to store found usernames/passwords	
class Wordlist():
	def __init__(self, filename):										# needs full path
		self.filename = filename
		self.wordlist = []
		with open(filename, 'a+') as f:									# open for appending + reading
			self.wordlist = f.readlines()
			print '[+] Wordlist was created/opened: ' + str(filename)

	def setFilename(self, filename):
		self.filename = filename
	
	# adds a word to the wordlist (without duplicates)	
	def add(self, word):
		with open(self.filename, 'a') as f:
			if not word+'\n' in self.wordlist:
				#print('[+] Adding '+word+' to the wordlist..')
				self.wordlist.append(word+'\n')
				f.write(word+'\n')

# Custom QProcess class
class MyQProcess(QProcess):
	sigHydra = QtCore.pyqtSignal(QObject, list, list, name="hydra") 	# signal to indicate Hydra found stuff

	def __init__(self, name, tabtitle, hostip, port, protocol, command, starttime, outputfile, textbox):
		QProcess.__init__(self)
		self.id	= -1
		self.name = name
		self.tabtitle = tabtitle
		self.hostip = hostip
		self.port = port
		self.protocol = protocol		
		self.command = command
		self.starttime = starttime		
		self.outputfile = outputfile
		self.display = textbox 											# has its own display widget to be able to display its output in the GUI

	@pyqtSlot()															# this slot allows the process to append its output to the display widget
	def readStdOutput(self):
		output = QString(self.readAllStandardOutput())
		#self.display.appendPlainText(unicode(output, 'utf-8').strip())
		self.display.appendPlainText(unicode(output).strip())

		if self.name == 'hydra':										# check if any usernames/passwords were found (if so emit a signal so that the gui can tell the user about it)
			found, userlist, passlist = checkHydraResults(output)
			if found:													# send the brutewidget object along with lists of found usernames/passwords
				self.sigHydra.emit(self.display.parentWidget(), userlist, passlist)
			
		stderror = QString(self.readAllStandardError())

		if len(stderror) > 0:
			#self.display.appendPlainText(unicode(stderror, 'utf-8').strip())	# append standard error too
			self.display.appendPlainText(unicode(stderror).strip())				# append standard error too

# browser opener class with queue and semaphores
class BrowserOpener(QtCore.QThread):
	done = QtCore.pyqtSignal(name="done")								# signals that we are done opening urls in browser
	
	def __init__(self):
		QtCore.QThread.__init__(self, parent=None)
		self.urls = []
		self.processing = False

	def addToQueue(self, url):
		self.urls.append(url)

	def run(self):
		while self.processing == True:
			self.sleep(1)												# effectively a semaphore
			
		self.processing = True		
		for i in range(0, len(self.urls)):
			try:
				url = self.urls.pop(0)
				print '[+] Opening url in browser: '+url
				if isHttps(url.split(':')[0],url.split(':')[1]):
					webbrowser.open_new_tab('https://'+url)
				else:
					webbrowser.open_new_tab('http://'+url)
				if i == 0:
					self.sleep(3)										# fixes bug in Kali. have to sleep on first url so the next ones don't open a new browser instead of adding a new tab
				else:
					self.sleep(1)										# fixes bug when several calls to urllib occur too fast (interrupted system call)
			
			except:
				print '\t[-] Problem while opening url in browser. Moving on..'
				continue
				
		self.processing = False
		if not len(self.urls) == 0:										# if meanwhile urls were added to the queue, start over
			self.run()
		else:
			self.done.emit()

class Screenshooter(QtCore.QThread):
	done = QtCore.pyqtSignal(str, str, str, name="done")				# signal sent after each individual screenshot is taken
	
	def __init__(self, timeout):
		QtCore.QThread.__init__(self, parent=None)
		self.urls = []
		self.processing = False
		self.timeout = timeout											# screenshooter timeout (ms)

	def addToQueue(self, url):
		self.urls.append(url)
		
	# this function should be called when the project is saved/saved as as the tool-output folder changes
	def updateOutputFolder(self, screenshotsFolder):
		self.outputfolder = screenshotsFolder

	def run(self):
		
		while self.processing == True:
			self.sleep(1)												# effectively a semaphore
	
		self.processing = True

		for i in range(0, len(self.urls)):
			try:
				url = self.urls.pop(0)
				outputfile = getTimestamp()+'-screenshot-'+url.replace(':', '-')+'.png'
				ip = url.split(':')[0]
				port = url.split(':')[1]
#				print '[+] Taking screenshot of '+url
				# add to db
				
				if isHttps(ip,port):
					self.save("https://"+url, ip, port, outputfile)
				else:
					self.save("http://"+url, ip, port, outputfile)

			except:
				print '\t[-] Unable to take the screenshot. Moving on..'
				continue				
				
		self.processing = False
		
		if not len(self.urls) == 0:										# if meanwhile urls were added to the queue, start over unless we are in pause mode
			self.run()

		print '\t[+] Finished.'

	def save(self, url, ip, port, outputfile):
		print '[+] Saving screenshot as: '+str(outputfile)
		command = "cutycapt --max-wait="+str(self.timeout)+" --url="+str(url)+"/ --out=\""+str(self.outputfolder)+"/"+str(outputfile)+"\""
#		print command
		p = subprocess.Popen(command, shell=True)
		p.wait()														# wait for command to finish
		self.done.emit(ip,port,outputfile)								# send a signal to add the 'process' to the DB

# This class handles what is to be shown in each panel
class Filters():
	def __init__(self):
																		# host filters
		self.checked = True
		self.up = True
		self.down = False
																		# port/service filters
		self.tcp = True
		self.udp = True
		self.portopen = True
		self.portclosed = False
		self.portfiltered = False
		self.keywords = []
				
	def apply(self, up, down, checked, portopen, portfiltered, portclosed, tcp, udp,  keywords = []):
		self.checked = checked
		self.up = up
		self.down = down
		self.tcp = tcp
		self.udp = udp
		self.portopen = portopen
		self.portclosed = portclosed
		self.portfiltered = portfiltered
		self.keywords = keywords

	def setKeywords(self, keywords):
		print str(keywords)
		self.keywords = keywords

	def getFilters(self):
		return [self.up, self.down, self.checked, self.portopen, self.portfiltered, self.portclosed, self.tcp, self.udp, self.keywords]

	def display(self):
		print 'Filters are:'
		print 'Show checked hosts: ' + str(self.checked)
		print 'Show up hosts: ' + str(self.up)
		print 'Show down hosts: ' + str(self.down)
		print 'Show tcp: ' + str(self.tcp)
		print 'Show udp: ' + str(self.udp)
		print 'Show open ports: ' + str(self.portopen)
		print 'Show closed ports: ' + str(self.portclosed)
		print 'Show filtered ports: ' + str(self.portfiltered)
		print 'Keyword search:'
		for w in self.keywords:
			print w


### VALIDATION FUNCTIONS ###
# TODO: should probably be moved to a new file called validation.py

def sanitise(string):													# this function makes a string safe for use in sql query. the main point is to prevent sparta from breaking, not so much SQLi as such.
	s = string.replace('\'', '\'\'')
	return s
	
def validateNmapInput(text):											# validate nmap input entered in Add Hosts dialog
	if re.search('[^a-zA-Z0-9\.\/\-\s]', text) is not None:
		return False
	return True

def validateCredentials(text):
	return True
	
def validateCommandFormat(text):										# used by settings dialog to validate commands
	if text is not '' and text is not ' ':
		return True
	return False

def validateNumeric(text):												# only allows numbers
	if text.isdigit():
		return True
	return False

def validateString(text):												# only allows alphanumeric characters, '_' and '-'
	if text is not '' and re.search("[^A-Za-z0-9_-]+", text) is None:
		return True
	return False

def validateStringWithSpace(text):										# only allows alphanumeric characters, '_', '-' and space
	if text is not '' and re.search("[^A-Za-z0-9_() -]+", text) is None:
		return True
	return False

def validateNmapPorts(text):											# only allows alphanumeric characters and the following: ./-'"*,:[any kind of space]
	if re.search('[^a-zA-Z0-9\.\/\-\'\"\*\,\:\s]', text) is not None:
		return False
	return True

def validatePath(text):													# only allows valid paths which exist in the OS
	if os.path.isdir(text):
		return True
	return False

def validateFile(text):													# only allows valid files which exist in the OS
	if os.path.isfile(text):
		return True
	return False
