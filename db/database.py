#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2020 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.ext.declarative import declarative_base
from PyQt5.QtCore import QSemaphore
#from tables import *
import time
# temp
import threading

Base = declarative_base()

class Database:
    def __init__(self, dbfilename):
        
        try:
            self.connect(dbfilename)
            #setup_all()
            #create_all()
        
        except Exception as e:
            print('[-] Could not create database. Please try again.')
            print(e)

    def openDB(self, dbfilename):
        
        try:
            self.connect(dbfilename)
            #setup_all()
        
        except Exception as e:
            print('[-] Could not open database file. Is the file corrupted?')
            print(e)

    def connect(self, dbfilename):
        self.name = dbfilename
        self.dbsemaphore = QSemaphore(1)                            # to control concurrent write access to db
        self.engine = create_engine('sqlite:///'+dbfilename, connect_args={"check_same_thread": False})
        self.session = scoped_session(sessionmaker())
        self.session.configure(bind=self.engine, autoflush=False)
        self.metadata = Base.metadata
        self.metadata.create_all(self.engine)
        self.metadata.echo = True
        self.metadata.bind = self.engine


    # this function commits any modified data to the db, ensuring no concurrent write access to the DB (within the same thread)
    # if you code a thread that writes to the DB, make sure you acquire/release at the beginning/end of the thread (see nmap importer)
    def commit(self):
        self.dbsemaphore.acquire()

        try:
            session = self.session
            session.commit()
        
        except Exception as e:
            print("[-] Could not commit to DB.")
            print(e)

        self.dbsemaphore.release()
