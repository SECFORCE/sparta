#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2014 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from elixir import metadata, Entity, Field
from elixir import create_all, setup_all, session
from elixir import Unicode, UnicodeText
from PyQt4.QtCore import QSemaphore
from tables import *
import time

class Database:
	# TODO: sanitise dbfilename
	def __init__(self, dbfilename):
		try:
			self.name = dbfilename
			self.dbsemaphore = QSemaphore(1)							# to control concurrent write access to db
			metadata.bind = 'sqlite:///'+dbfilename
	#		metadata.bind.echo = True									# uncomment to see detailed database logs
			setup_all()
			create_all()
		except:
			print '[-] Could not create database. Please try again.'

	def openDB(self, dbfilename):
		try:
			self.name = dbfilename
			metadata.bind = 'sqlite:///'+dbfilename
	#		metadata.bind.echo = True									# uncomment to see detailed database logs
			setup_all()
		except:
			print '[-] Could not open database file. Is the file corrupted?'

	# this function commits any modified data to the db, ensuring no concurrent write access to the DB (within the same thread)
	# if you code a thread that writes to the DB, make sure you acquire/release at the beginning/end of the thread (see nmap importer)
	def commit(self):
		self.dbsemaphore.acquire()
		session.commit()
		self.dbsemaphore.release()


if __name__ == "__main__":

	db = Database('myDatabase')
    
	# insert stuff
	nmap_session('~/Documents/tools/sparta/tests/nmap-scan-1', 'Wed Jul 10 14:07:36 2013', 'Wed Jul 10 14:29:36 2013', '6.25', 'nmap -sS -A -T5 -p- -oX a-full.xml -vvvvv 172.16.16.0/24', '256', '25', '231')
	nmap_session('~/Documents/tools/sparta/tests/nmap-scan-2', 'Wed Jul 15 14:07:36 2013', 'Wed Jul 20 14:29:36 2013', '5.44', 'nmap -sT -A -T3 -p- -oX a-full.xml -vvvvv 172.16.16.0/24', '256', '26', '230')   
	session.commit()
	
