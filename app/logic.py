#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2015 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os, tempfile, ntpath, shutil										# for creation of temp files and file operations
import logging		# test
import subprocess	# for CWD
from parsers.Parser import *
from db.database import *
from app.auxiliary import *

class Logic():
	def __init__(self):		
		self.cwd = subprocess.check_output("echo $OLDPWD", shell=True)[:-1]+'/'
		self.createTemporaryFiles()										# creates temporary files/folders used by SPARTA
																		# other variables initialised elsewhere: self.projectname, self.outputfolder, self.runningfolder, self.db, self.istemp
	def createTemporaryFiles(self):
		try:
			print '[+] Creating temporary files..'
			
			self.istemp = True											# indicates that file is temporary and can be deleted if user exits without saving
						
			tf = tempfile.NamedTemporaryFile(suffix=".sprt",prefix="sparta-", delete=False)			# to store the database file
			self.outputfolder = tempfile.mkdtemp(suffix="-tool-output",prefix="sparta-")			# to store tool output of finished processes
			self.runningfolder = tempfile.mkdtemp(suffix="-running",prefix="sparta-")				# to store tool output of running processes
			os.makedirs(self.outputfolder+'/screenshots')											# to store screenshots
			os.makedirs(self.runningfolder+'/nmap')													# to store nmap output
			os.makedirs(self.runningfolder+'/hydra')												# to store hydra output			
			self.usernamesWordlist = Wordlist(self.outputfolder + '/sparta-usernames.txt')			# to store found usernames
			self.passwordsWordlist = Wordlist(self.outputfolder + '/sparta-passwords.txt')			# to store found passwords
			self.projectname = tf.name
			self.db = Database(self.projectname)
			
		except:
			print '\t[-] Something went wrong creating the temporary files..'
			print "[-] Unexpected error:", sys.exc_info()[0]

	def removeTemporaryFiles(self):
		print '[+] Removing temporary files and folders..'
		try:
			if not self.istemp:											# if current project is not temporary
				if not self.storeWordlists:								# delete wordlists if necessary
					print '[+] Removing wordlist files.'
					os.remove(self.usernamesWordlist.filename)
					os.remove(self.passwordsWordlist.filename)
				
			else:
				os.remove(self.projectname)
				shutil.rmtree(self.outputfolder)
			
			shutil.rmtree(self.runningfolder)

		except:
			print '\t[-] Something went wrong removing temporary files and folders..'
			print "[-] Unexpected error:", sys.exc_info()[0]

	def createFolderForTool(self, tool):
		if 'nmap' in tool:
			tool = 'nmap'		
		path = self.runningfolder+'/'+re.sub("[^0-9a-zA-Z]", "", str(tool))
		if not os.path.exists(path):
			os.makedirs(path)

	# this flag is matched to the conf file setting, so that we know if we need to delete the found usernames/passwords wordlists on exit
	def setStoreWordlistsOnExit(self, flag=True):
		self.storeWordlists = flag

	# this function moves the specified tool output file from the temporary 'running' folder to the 'tool output' folder
	def moveToolOutput(self, outputFilename):
		try:
			# first create the tool folder if it doesn't already exist
			tool = ntpath.basename(ntpath.dirname(str(outputFilename)))
			path = self.outputfolder+'/'+str(tool)
			if not os.path.exists(str(path)):
				os.makedirs(str(path))
			
			# check if the outputFilename exists, if not try .xml and .txt extensions (different tools use different formats)
			if os.path.exists(str(outputFilename)) and os.path.isfile(str(outputFilename)):
				shutil.move(str(outputFilename), str(path))
			# move all the nmap files (not only the .xml)
			elif os.path.exists(str(outputFilename)+'.xml') and os.path.exists(str(outputFilename)+'.nmap') and os.path.exists(str(outputFilename)+'.gnmap') and os.path.isfile(str(outputFilename)+'.xml') and os.path.isfile(str(outputFilename)+'.nmap') and os.path.isfile(str(outputFilename)+'.gnmap'):
				try:
					exportNmapToHTML(str(outputFilename))
					shutil.move(str(outputFilename)+'.html', str(path))
				except:
					pass

				shutil.move(str(outputFilename)+'.xml', str(path))
				shutil.move(str(outputFilename)+'.nmap', str(path))
				shutil.move(str(outputFilename)+'.gnmap', str(path))
			elif os.path.exists(str(outputFilename)+'.xml') and os.path.isfile(str(outputFilename)+'.xml'):
				shutil.move(str(outputFilename)+'.xml', str(path))
			elif os.path.exists(str(outputFilename)+'.txt') and os.path.isfile(str(outputFilename)+'.txt'):
				shutil.move(str(outputFilename)+'.txt', str(path))							
		except:
			print '[-] Something went wrong moving the tool output file..'
			print "[-] Unexpected error:", sys.exc_info()[0]

	def copyNmapXMLToOutputFolder(self, file):
		try:
			path = self.outputfolder+"/nmap"
			filename = ntpath.basename(str(file))
			if not os.path.exists(str(path)):
				os.makedirs(str(path))

			shutil.copy(str(file), str(path))	# will overwrite if file already exists
		except:
			print '[-] Something went wrong copying the imported XML to the project folder.'
			print "[-] Unexpected error:", sys.exc_info()[0]			

	def openExistingProject(self, filename):
		try:
			print '[+] Opening project..'
			self.istemp = False											# indicate the file is NOT temporary and should NOT be deleted later
			
			self.projectname = str(filename)							# set the new projectname and outputfolder vars
			if not str(filename).endswith('.sprt'):			
				self.outputfolder = str(filename)+'-tool-output'		# use the same name as the file for the folder (without the extension)
			else:
				self.outputfolder = str(filename)[:-5]+'-tool-output'

			self.usernamesWordlist = Wordlist(self.outputfolder + '/sparta-usernames.txt')			# to store found usernames
			self.passwordsWordlist = Wordlist(self.outputfolder + '/sparta-passwords.txt')			# to store found passwords			
			
			self.runningfolder = tempfile.mkdtemp(suffix="-running",prefix="sparta-")				# to store tool output of running processes
			self.db = Database(self.projectname)						# use the new db
			self.cwd = ntpath.dirname(str(self.projectname))+'/'		# update cwd so it appears nicely in the window title
		
		except:
			print '\t[-] Something went wrong while opening the project..'
			print "[-] Unexpected error:", sys.exc_info()[0]
		
	# this function copies the current project files and folder to a new location
	# if the replace flag is set to 1, it overwrites the destination file and folder
	def saveProjectAs(self, filename, replace=0):
		try:
			# the folder name must be : filename-tool-output (without the .sprt extension)
			if not str(filename).endswith('.sprt'):
				foldername = str(filename)+'-tool-output'
				filename = str(filename) + '.sprt'
			else:
				foldername = filename[:-5]+'-tool-output'

			# check if filename already exists (skip the check if we want to replace the file)
			if replace == 0 and os.path.exists(str(filename)) and os.path.isfile(str(filename)):
				return False

			shutil.copyfile(self.projectname, str(filename))
			os.system('cp -r "'+self.outputfolder+'/." "'+str(foldername)+'"')
			
			if self.istemp:												# we can remove the temp file/folder if it was temporary
				print '[+] Removing temporary files and folders..'
				os.remove(self.projectname)
				shutil.rmtree(self.outputfolder)

			self.db.openDB(str(filename))								# inform the DB to use the new file
			self.cwd = ntpath.dirname(str(filename))+'/'				# update cwd so it appears nicely in the window title
			self.projectname = str(filename)
			self.outputfolder = str(foldername)

			self.usernamesWordlist = Wordlist(self.outputfolder + '/sparta-usernames.txt')			# to store found usernames
			self.passwordsWordlist = Wordlist(self.outputfolder + '/sparta-passwords.txt')			# to store found passwords	
			
			self.istemp = False											# indicate that file is NOT temporary anymore and should NOT be deleted later
			return True

		except:
			print '\t[-] Something went wrong while saving the project..'
			print "\t[-] Unexpected error:", sys.exc_info()[0]
			return False

	def isHostInDB(self, host):											# used we don't run tools on hosts out of scope
		tmp_query = 'SELECT host.ip FROM db_tables_nmap_host AS host WHERE host.ip == ? OR host.hostname == ?'
		result = metadata.bind.execute(tmp_query, str(host), str(host)).fetchall()
		if result:
			return True
		return False

	def getHostsFromDB(self, filters):
		tmp_query = 'SELECT * FROM db_tables_nmap_host AS hosts WHERE 1=1'

		if filters.down == False:
			tmp_query += ' AND hosts.status!=\'down\''
		if filters.up == False:
			tmp_query += ' AND hosts.status!=\'up\''
		if filters.checked == False:
			tmp_query += ' AND hosts.checked!=\'True\''
		for word in filters.keywords:
			tmp_query += ' AND (hosts.ip LIKE \'%'+sanitise(word)+'%\' OR hosts.os_match LIKE \'%'+sanitise(word)+'%\' OR hosts.hostname LIKE \'%'+sanitise(word)+'%\')'

		return metadata.bind.execute(tmp_query).fetchall()

	# get distinct service names from DB
	def getServiceNamesFromDB(self, filters):
		tmp_query = ('SELECT DISTINCT service.name FROM db_tables_nmap_service as service ' +
					'INNER JOIN db_tables_nmap_port as ports ' +
					'INNER JOIN db_tables_nmap_host AS hosts ' + 
					'ON hosts.id = ports.host_id AND service.id=ports.service_id WHERE 1=1')
					
		if filters.down == False:
			tmp_query += ' AND hosts.status!=\'down\''
		if filters.up == False:
			tmp_query += ' AND hosts.status!=\'up\''
		if filters.checked == False:
			tmp_query += ' AND hosts.checked!=\'True\''
		for word in filters.keywords:
			tmp_query += ' AND (hosts.ip LIKE \'%'+sanitise(word)+'%\' OR hosts.os_match LIKE \'%'+sanitise(word)+'%\' OR hosts.hostname LIKE \'%'+sanitise(word)+'%\')'
		if filters.portopen == False:
			tmp_query += ' AND ports.state!=\'open\' AND ports.state!=\'open|filtered\''
		if filters.portclosed == False:
			tmp_query += ' AND ports.state!=\'closed\''
		if filters.portfiltered == False:
			tmp_query += ' AND ports.state!=\'filtered\' AND ports.state!=\'open|filtered\''
		if filters.tcp == False:
			tmp_query += ' AND ports.protocol!=\'tcp\''
		if filters.udp == False:
			tmp_query += ' AND ports.protocol!=\'udp\''				
					
		tmp_query += ' ORDER BY service.name ASC'
							
		return metadata.bind.execute(tmp_query).fetchall()

	# get notes for given host IP
	def getNoteFromDB(self, hostId):
		return note.query.filter_by(host_id=str(hostId)).first()

	# get script info for given host IP
	def getScriptsFromDB(self, hostIP):
		tmp_query = ('SELECT host.id,host.script_id,port.port_id,port.protocol FROM db_tables_nmap_script AS host ' +
					'INNER JOIN db_tables_nmap_host AS hosts ON hosts.id = host.host_id ' +
					'LEFT OUTER JOIN db_tables_nmap_port AS port ON port.id=host.port_id ' +
					'WHERE hosts.ip=?')

		return metadata.bind.execute(tmp_query, str(hostIP)).fetchall()
		
	def getScriptOutputFromDB(self, scriptDBId):
		tmp_query = ('SELECT script.output FROM db_tables_nmap_script as script WHERE script.id=?')
		return metadata.bind.execute(tmp_query, str(scriptDBId)).fetchall()

	# get port and service info for given host IP
	def getPortsAndServicesForHostFromDB(self, hostIP, filters):
		tmp_query = ('SELECT hosts.ip,ports.port_id,ports.protocol,ports.state,ports.host_id,ports.service_id,services.name,services.product,services.version,services.extrainfo,services.fingerprint FROM db_tables_nmap_port AS ports ' +
			'INNER JOIN db_tables_nmap_host AS hosts ON hosts.id = ports.host_id ' +
			'LEFT OUTER JOIN db_tables_nmap_service AS services ON services.id=ports.service_id ' +
			'WHERE hosts.ip=?')
		
		if filters.portopen == False:
			tmp_query += ' AND ports.state!=\'open\' AND ports.state!=\'open|filtered\''
		if filters.portclosed == False:
			tmp_query += ' AND ports.state!=\'closed\''
		if filters.portfiltered == False:
			tmp_query += ' AND ports.state!=\'filtered\' AND ports.state!=\'open|filtered\''
		if filters.tcp == False:
			tmp_query += ' AND ports.protocol!=\'tcp\''
		if filters.udp == False:
			tmp_query += ' AND ports.protocol!=\'udp\''

		return metadata.bind.execute(tmp_query, str(hostIP)).fetchall()

	# used to check if there are any ports of a specific protocol for a given host
	def getPortsForHostFromDB(self, hostIP, protocol):
		tmp_query = ('SELECT ports.port_id FROM db_tables_nmap_port AS ports ' +
			'INNER JOIN db_tables_nmap_host AS hosts ON hosts.id = ports.host_id ' +
			'WHERE hosts.ip=? and ports.protocol=?')
			
		return metadata.bind.execute(tmp_query, str(hostIP), str(protocol)).first()

	# used to get the service name given a host ip and a port when we are in tools tab (left) and right click on a host
	def getServiceNameForHostAndPort(self, hostIP, port):
		tmp_query = ('SELECT services.name FROM db_tables_nmap_service AS services ' +
			'INNER JOIN db_tables_nmap_host AS hosts ON hosts.id = ports.host_id ' +
			'INNER JOIN db_tables_nmap_port AS ports ON services.id=ports.service_id ' +
			'WHERE hosts.ip=? and ports.port_id=?')
			
		return metadata.bind.execute(tmp_query, str(hostIP), str(port)).first()
	
	# used to delete all port/script data related to a host - to overwrite portscan info with the latest scan	
	def deleteAllPortsAndScriptsForHostFromDB(self, hostID, protocol):
		ports_for_host = nmap_port.query.filter(nmap_port.host_id == hostID, nmap_port.protocol == str(protocol)).all()
				
		for p in ports_for_host:
			scripts_for_ports = nmap_script.query.filter(nmap_script.port_id == p.id).all()
			for s in scripts_for_ports:
				s.delete()				
		
		for p in ports_for_host:
			p.delete()
					
		self.db.commit()

	def getHostInformation(self, hostIP):
		return nmap_host.query.filter_by(ip=str(hostIP)).first()

	def getPortStatesForHost(self,hostID):
		tmp_query = ('SELECT port.state FROM db_tables_nmap_port as port WHERE port.host_id=?')
		return metadata.bind.execute(tmp_query, str(hostID)).fetchall()

	def getHostsAndPortsForServiceFromDB(self, serviceName, filters):
		
		tmp_query = ('SELECT hosts.ip,ports.port_id,ports.protocol,ports.state,ports.host_id,ports.service_id,services.name,services.product,services.version,services.extrainfo,services.fingerprint FROM db_tables_nmap_port AS ports ' +
			'INNER JOIN db_tables_nmap_host AS hosts ON hosts.id = ports.host_id ' +
			'LEFT OUTER JOIN db_tables_nmap_service AS services ON services.id=ports.service_id ' +
			'WHERE services.name=?')

		if filters.down == False:
			tmp_query += ' AND hosts.status!=\'down\''
		if filters.up == False:
			tmp_query += ' AND hosts.status!=\'up\''
		if filters.checked == False:
			tmp_query += ' AND hosts.checked!=\'True\''
		if filters.portopen == False:
			tmp_query += ' AND ports.state!=\'open\' AND ports.state!=\'open|filtered\''
		if filters.portclosed == False:
			tmp_query += ' AND ports.state!=\'closed\''
		if filters.portfiltered == False:
			tmp_query += ' AND ports.state!=\'filtered\' AND ports.state!=\'open|filtered\''
		if filters.tcp == False:
			tmp_query += ' AND ports.protocol!=\'tcp\''
		if filters.udp == False:
			tmp_query += ' AND ports.protocol!=\'udp\''	
		for word in filters.keywords:
			tmp_query += ' AND (hosts.ip LIKE \'%'+sanitise(word)+'%\' OR hosts.os_match LIKE \'%'+sanitise(word)+'%\' OR hosts.hostname LIKE \'%'+sanitise(word)+'%\')'

		return metadata.bind.execute(tmp_query, str(serviceName)).fetchall()

	# this function returns all the processes from the DB
	# the showProcesses flag is used to ensure we don't display processes in the process table after we have cleared them or when an existing project is opened.
	# to speed up the queries we replace the columns we don't need by zeros (the reason we need all the columns is we are using the same model to display process information everywhere)
	def getProcessesFromDB(self, filters, showProcesses=''):
		if showProcesses == '':											# we do not fetch nmap processes because these are not displayed in the host tool tabs / tools
			tmp_query = ('SELECT "0", "0", "0", process.name, "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0" FROM db_tables_process AS process WHERE process.closed="False" AND process.name!="nmap" group by process.name')
			result = metadata.bind.execute(tmp_query).fetchall()

		elif showProcesses == False:									# when opening a project, fetch only the processes that have display=false and were not in tabs that were closed by the user
			tmp_query = ('SELECT process.id, process.hostip, process.tabtitle, process.outputfile, poutput.output FROM db_tables_process AS process '
			'INNER JOIN db_tables_process_output AS poutput ON process.id = poutput.process_id '
			'WHERE process.display=? AND process.closed="False" order by process.id desc')
			result = metadata.bind.execute(tmp_query, str(showProcesses)).fetchall()

		else:															# show all the processes in the (bottom) process table (no matter their closed value)
			tmp_query = ('SELECT * FROM db_tables_process AS process WHERE process.display=? order by id desc')
			result = metadata.bind.execute(tmp_query, str(showProcesses)).fetchall()

		return result

	def getHostsForTool(self, toolname, closed='False'):
		if closed == 'FetchAll':
			tmp_query = ('SELECT "0", "0", "0", "0", "0", process.hostip, process.port, process.protocol, "0", "0", process.outputfile, "0", "0", "0" FROM db_tables_process AS process WHERE process.name=?')
		else:
			tmp_query = ('SELECT process.id, "0", "0", "0", "0", process.hostip, process.port, process.protocol, "0", "0", process.outputfile, "0", "0", "0" FROM db_tables_process AS process WHERE process.name=? and process.closed="False"')
			
		return metadata.bind.execute(tmp_query, str(toolname)).fetchall()

	def getProcessStatusForDBId(self, dbid):
		tmp_query = ('SELECT process.status FROM db_tables_process AS process WHERE process.id=?')
		p = metadata.bind.execute(tmp_query, str(dbid)).fetchall()
 		if p:
 			return p[0][0]
		return -1
		
	def getPidForProcess(self, procid):
		tmp_query = ('SELECT process.pid FROM db_tables_process AS process WHERE process.id=?')
		p = metadata.bind.execute(tmp_query, str(procid)).fetchall()		
		if p:
			return p[0][0]
		return -1

	def toggleHostCheckStatus(self, ipaddr):
		h = nmap_host.query.filter_by(ip=ipaddr).first()
		if h:
			if h.checked == 'False':
				h.checked = 'True'
			else:
				h.checked = 'False'
			self.db.commit()

	# this function adds a new process to the DB
	def addProcessToDB(self, proc):
		p_output = process_output()										# add row to process_output table (separate table for performance reasons)
		p = process(str(proc.pid()), str(proc.name), str(proc.tabtitle), str(proc.hostip), str(proc.port), str(proc.protocol), unicode(proc.command), proc.starttime, "", str(proc.outputfile), 'Waiting', p_output)
		self.db.commit()
		proc.id = p.id
		return p.id
	
	def addScreenshotToDB(self, ip, port, filename):
		p_output = process_output()										# add row to process_output table (separate table for performance reasons)
		p = process("-2", "screenshooter", "screenshot ("+str(port)+"/tcp)", str(ip), str(port), "tcp", "", getTimestamp(True), getTimestamp(True), str(filename), "Finished", p_output)
		self.db.commit()
		return p.id
		
	# is not actually a toggle function. it sets all the non-running processes display flag to false to ensure they aren't shown in the process table 
	# but they need to be shown as tool tabs. this function is called when a user clears the processes or when a project is being closed.
	def toggleProcessDisplayStatus(self, resetAll=False):
		proc = process.query.filter_by(display='True').all()
		if resetAll == True:
			for p in proc:
				if p.status != 'Running':
					p.display = 'False'
		else:
			for p in proc:
				if p.status != 'Running' and p.status != 'Waiting':
					p.display = 'False'
		self.db.commit()
		
	# this function updates the status of a process if it is killed
	def storeProcessKillStatusInDB(self, procId):
		proc = process.query.filter_by(id=procId).first()
		if proc and not proc.status == 'Finished':
			proc.status = 'Killed'
			proc.endtime = getTimestamp(True)	# store end time
			self.db.commit()

	def storeProcessCrashStatusInDB(self, procId):
		proc = process.query.filter_by(id=procId).first()
		if proc and not proc.status == 'Killed' and not proc.status == 'Cancelled':
			proc.status = 'Crashed'
			proc.endtime = getTimestamp(True)	# store end time
			self.db.commit()
			
	# this function updates the status of a process if it is killed
	def storeProcessCancelStatusInDB(self, procId):
		proc = process.query.filter_by(id=procId).first()
		if proc:
			proc.status = 'Cancelled'
			proc.endtime = getTimestamp(True)	# store end time
			self.db.commit()

	def storeProcessRunningStatusInDB(self, procId, pid):
		proc = process.query.filter_by(id=procId).first()
		if proc:
			proc.status = 'Running'
			proc.pid = str(pid)
			self.db.commit()

	# change the status in the db as closed
	def storeCloseTabStatusInDB(self, procId):
		proc = process.query.filter_by(id=int(procId)).first()
		if proc:
			proc.closed = 'True'
			self.db.commit()
	
	# this function stores a finished process' output to the DB and updates it status
	def storeProcessOutputInDB(self, procId, output):
		proc = process.query.filter_by(id=procId).first()
		if proc:
			proc_output = process_output.query.filter_by(process_id=procId).first()
			if proc_output:
				proc_output.output=unicode(output)

			proc.endtime = getTimestamp(True)	# store end time

			if proc.status == "Killed" or proc.status == "Cancelled" or proc.status == "Crashed":	# if the process has been killed don't change the status to "Finished"
				self.db.commit() 										# new: this was missing but maybe this is important here to ensure that we save the process output no matter what
				return True							
			else:
				proc.status = 'Finished'
				self.db.commit()

	def storeNotesInDB(self, hostId, notes):
		note = self.getNoteFromDB(hostId)
		note.text = unicode(notes)
		self.db.commit()
		
	def isKilledProcess(self, procId):
		tmp_query = ('SELECT process.status FROM db_tables_process AS process WHERE process.id=?')
		proc = metadata.bind.execute(tmp_query, str(procId)).fetchall()
		if not proc or str(proc[0][0]) == "Killed":
			return True
		return False
		
	def isCanceledProcess(self, procId):
		tmp_query = ('SELECT process.status FROM db_tables_process AS process WHERE process.id=?')
		proc = metadata.bind.execute(tmp_query, str(procId)).fetchall()
		if not proc or str(proc[0][0]) == "Cancelled":
			return True
		return False
		
class NmapImporter(QtCore.QThread):
	tick = QtCore.pyqtSignal(int, name="changed")						# New style signal
	done = QtCore.pyqtSignal(name="done")								# New style signal
	schedule = QtCore.pyqtSignal(object, bool, name="schedule")			# New style signal

	def __init__(self):
		QtCore.QThread.__init__(self, parent=None)
		self.output = ''

	def setDB(self, db):
		self.db = db

	def setFilename(self, filename):
		self.filename = filename
		
	def setOutput(self, output):
		self.output = output

	def run(self):														# it is necessary to get the qprocess because we need to send it back to the scheduler when we're done importing
		try:
			print "[+] Parsing nmap xml file: " + self.filename
			starttime = time.time()
			
			try:
				parser = Parser(self.filename)
			except:
				print '\t[-] Giving up on import due to previous errors.'
				print "\t[-] Unexpected error:", sys.exc_info()[0]
				self.done.emit()
				return
				
			self.db.dbsemaphore.acquire()								# ensure that while this thread is running, no one else can write to the DB
			s = parser.get_session()									# nmap session info
			if s:
				nmap_session(self.filename, s.start_time, s.finish_time, s.nmap_version, s.scan_args, s.total_hosts, s.up_hosts, s.down_hosts)
			hostCount = len(parser.all_hosts())
			if hostCount==0:											# to fix a division by zero if we ran nmap on one host
				hostCount=1
			progress = 100.0 / hostCount
			totalprogress = 0
			self.tick.emit(int(totalprogress))
	
			for h in parser.all_hosts():								# create all the hosts that need to be created
				db_host = nmap_host.query.filter_by(ip=h.ip).first()
				
				if not db_host:											# if host doesn't exist in DB, create it first
					hid = nmap_host('', '', h.ip, h.ipv4, h.ipv6, h.macaddr, h.status, h.hostname, h.vendor, h.uptime, h.lastboot, h.distance, h.state, h.count)
					note(hid, '')

			session.commit()
			
			for h in parser.all_hosts():								# create all OS, service and port objects that need to be created

				db_host = nmap_host.query.filter_by(ip=h.ip).first()	# fetch the host
				
				os_nodes = h.get_OS()									# parse and store all the OS nodes
				for os in os_nodes:
					db_os = nmap_os.query.filter_by(host_id=db_host.id).filter_by(name=os.name).filter_by(family=os.family).filter_by(generation=os.generation).filter_by(os_type=os.os_type).filter_by(vendor=os.vendor).first()
					
					if not db_os:
						nmap_os(os.name, os.family, os.generation, os.os_type, os.vendor, os.accuracy, db_host)

				for p in h.all_ports():									# parse the ports
					s = p.get_service()

					if not (s is None):									# check if service already exists to avoid adding duplicates
						db_service = nmap_service.query.filter_by(name=s.name).filter_by(product=s.product).filter_by(version=s.version).filter_by(extrainfo=s.extrainfo).filter_by(fingerprint=s.fingerprint).first()
						
						if not db_service:
							db_service = nmap_service(s.name, s.product, s.version, s.extrainfo, s.fingerprint)

					else:												# else, there is no service info to parse
						db_service = None					
																		# fetch the port
					db_port = nmap_port.query.filter_by(host_id=db_host.id).filter_by(port_id=p.portId).filter_by(protocol=p.protocol).first()
					
					if not db_port:		
						db_port = nmap_port(p.portId, p.protocol, p.state, db_host, db_service)

			session.commit()
			
			totalprogress += progress
			self.tick.emit(int(totalprogress))

			for h in parser.all_hosts():								# create all script objects that need to be created
				
				db_host = nmap_host.query.filter_by(ip=h.ip).first()
				
				for p in h.all_ports():
					for scr in p.get_scripts():
												
						db_port = nmap_port.query.filter_by(host_id=db_host.id).filter_by(port_id=p.portId).filter_by(protocol=p.protocol).first()
						db_script = nmap_script.query.filter_by(script_id=scr.scriptId).filter_by(port_id=db_port.id).first()

						if not db_script:								# if this script object doesn't exist, create it
							nmap_script(scr.scriptId, scr.output, db_port, db_host)
					
				for hs in h.get_hostscripts():
					db_script = nmap_script.query.filter_by(script_id=hs.scriptId).filter_by(host_id=db_host.id).first()
					if not db_script:
						nmap_script(hs.scriptId, hs.output, None, db_host)					
					
			session.commit()
					
			for h in parser.all_hosts():								# update everything

				db_host = nmap_host.query.filter_by(ip=h.ip).first()	# get host from DB (if any with the same IP address)
				
				if db_host.ipv4 == '' and not h.ipv4 == '':
					db_host.ipv4 = h.ipv4
				if db_host.ipv6 == '' and not h.ipv6 == '':
					db_host.ipv6 = h.ipv6
				if db_host.macaddr == '' and not h.macaddr == '':
					db_host.macaddr = h.macaddr
				if not h.status == '':
					db_host.status = h.status
				if db_host.hostname == '' and not h.hostname == '':
					db_host.hostname = h.hostname
				if db_host.vendor == '' and not h.vendor == '':
					db_host.vendor = h.vendor
				if db_host.uptime == '' and not h.uptime == '':
					db_host.uptime = h.uptime
				if db_host.lastboot == '' and not h.lastboot == '':
					db_host.lastboot = h.lastboot
				if db_host.distance == '' and not h.distance == '':
					db_host.distance = h.distance
				if db_host.state == '' and not h.state == '':
					db_host.state = h.state
				if db_host.count == '' and not h.count == '':
					db_host.count = h.count
						
				tmp_name = ''
				tmp_accuracy = '0' 										# TODO: check if better to convert to int for comparison
				
				os_nodes = h.get_OS()
				for os in os_nodes:
					db_os = nmap_os.query.filter_by(host_id=db_host.id).filter_by(name=os.name).filter_by(family=os.family).filter_by(generation=os.generation).filter_by(os_type=os.os_type).filter_by(vendor=os.vendor).first()
					
					db_os.os_accuracy = os.accuracy						# update the accuracy
							
					if not os.name == '':								# get the most accurate OS match/accuracy to store it in the host table for easier access
						if os.accuracy > tmp_accuracy:
							tmp_name = os.name
							tmp_accuracy = os.accuracy

				if os_nodes:											# if there was operating system info to parse
					
					if not tmp_name == '' and not tmp_accuracy == '0':	# update the current host with the most accurate OS match
						db_host.os_match = tmp_name
						db_host.os_accuracy = tmp_accuracy
								
				for p in h.all_ports():		
					s = p.get_service()
					if not (s is None):
																		# fetch the service for this port
						db_service = nmap_service.query.filter_by(name=s.name).filter_by(product=s.product).filter_by(version=s.version).filter_by(extrainfo=s.extrainfo).filter_by(fingerprint=s.fingerprint).first()
					else:
						db_service = None						
																		# fetch the port
					db_port = nmap_port.query.filter_by(host_id=db_host.id).filter_by(port_id=p.portId).filter_by(protocol=p.protocol).first()					
					db_port.state = p.state
					
					if not (db_service is None):						# if there is some new service information, update it
						db_port.service_id = db_service.id
				
					for scr in p.get_scripts():							# store the script results (note that existing script outputs are also kept)	
						db_script = nmap_script.query.filter_by(script_id=scr.scriptId).filter_by(port_id=db_port.id).first()

						if not scr.output == '':
							db_script.output = scr.output
				
				totalprogress += progress
				self.tick.emit(int(totalprogress))		

			session.commit()
			self.db.dbsemaphore.release()								# we are done with the DB
			print '\t[+] Finished in '+ str(time.time()-starttime) + ' seconds.'
			self.done.emit()
			self.schedule.emit(parser, self.output == '')				# call the scheduler (if there is no terminal output it means we imported nmap)
			
		except:
			print '\t[-] Something went wrong when parsing the nmap file..'
			print "\t[-] Unexpected error:", sys.exc_info()[0]
			self.done.emit()
