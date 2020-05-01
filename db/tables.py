#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2020 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from sqlalchemy import Column, String, Unicode, Integer, ForeignKey
from sqlalchemy.orm import relationship
from db.database import Base as Base

# This class holds various info about an nmap scan
class nmap_session(Base):
    __tablename__='nmap_session'
    id=Column(Integer, primary_key=True)
    filename=Column(String)
    start_time=Column(String)
    finish_time=Column(String)
    nmap_version=Column(String)
    scan_args=Column(String)
    total_hosts=Column(String)
    up_hosts=Column(String)
    down_hosts=Column(String)

    def __init__(self, filename, start_time, finish_time, nmap_version='', scan_args='', total_hosts='0', up_hosts='0', down_hosts='0'):
        self.filename=filename
        self.start_time=start_time
        self.finish_time=finish_time
        self.nmap_version=nmap_version
        self.scan_args=scan_args
        self.total_hosts=total_hosts
        self.up_hosts=up_hosts
        self.down_hosts=down_hosts

class nmap_os(Base):
    __tablename__='nmap_os'
    id=Column(Integer, primary_key=True)
    name=Column(String)
    family=Column(String)
    generation=Column(String)
    os_type=Column(String)
    vendor=Column(String)
    accuracy=Column(String)
    host_id = Column(String, ForeignKey('nmap_host.id'))
    
    def __init__(self, name, family, generation, os_type, vendor, accuracy, host_id):
        self.name=name
        self.family=family
        self.generation=generation
        self.os_type=os_type
        self.vendor=vendor
        self.accuracy=accuracy
        self.host_id=host_id
    
class nmap_port(Base):
    __tablename__='nmap_port'
    id=Column(Integer, primary_key=True)
    port_id=Column(String)
    protocol=Column(String)
    state=Column(String)
    host_id=Column(String, ForeignKey('nmap_host.id'))
    service_id=Column(String, ForeignKey('nmap_service.id'))
    script_id=Column(String, ForeignKey('nmap_script.id'))
    
    def __init__(self, port_id, protocol, state, host, service=''):
        self.port_id=port_id
        self.protocol=protocol
        self.state=state
        self.host_id=host
        self.service_id=service

class nmap_service(Base):
    __tablename__='nmap_service'
    id=Column(Integer, primary_key=True)
    name=Column(String)
    product=Column(String)
    version=Column(String)
    extrainfo=Column(String)
    fingerprint=Column(String)
    port=relationship(nmap_port)
    
    def __init__(self, name='', product='', version='', extrainfo='', fingerprint=''):
        self.name=name
        self.product=product
        self.version=version
        self.extrainfo=extrainfo
        self.fingerprint=fingerprint

class nmap_script(Base):
    __tablename__='nmap_script'
    id=Column(Integer, primary_key=True)
    script_id=Column(String)
    output=Column(Unicode)
    port_id=Column(String, ForeignKey('nmap_port.id'))
    host_id=Column(String, ForeignKey('nmap_host.id'))
    
    def __init__(self, script_id, output, port_id, host_id):
        self.script_id=script_id
        self.output=str(output)
        self.port_id=port_id
        self.host_id=host_id

class nmap_host(Base):
    __tablename__='nmap_host'
    id=Column(Integer, primary_key=True)
    # host attributes
    checked=Column(String)
    os_match=Column(String)
    os_accuracy=Column(String)
    ip=Column(String)
    ipv4=Column(String)
    ipv6=Column(String)
    macaddr=Column(String)
    status=Column(String)
    hostname=Column(String)
    vendor=Column(String)
    uptime=Column(String)
    lastboot=Column(String)
    distance=Column(String)
    state=Column(String)
    count=Column(String)    
    
    # host relationships
    os=relationship(nmap_os)
    ports=relationship(nmap_port)

    def __init__(self, os_match='', os_accuracy='', ip='', ipv4='', ipv6='', macaddr='', status='', hostname='', vendor='', uptime='', lastboot='', distance='', state='', count=''):
        self.checked='False'
        self.os_match=os_match
        self.os_accuracy=os_accuracy
        self.ip=ip
        self.ipv4=ipv4
        self.ipv6=ipv6
        self.macaddr=macaddr
        self.status=status
        self.hostname=hostname
        self.vendor=vendor
        self.uptime=uptime
        self.lastboot=lastboot
        self.distance=distance
        self.state=state
        self.count=count        

class process_output(Base):
    __tablename__='process_output'
    id=Column(Integer, primary_key=True)
    output=Column(String)
    process_id=Column(Integer, ForeignKey('process.id'))
    
    def __init__(self):
        self.output=str('')

# this class represents the DB table that will hold information about a process
class process(Base):
    __tablename__='process'
    id=Column(Integer, primary_key=True)
    display=Column(String)
    pid=Column(String)
    name=Column(String)
    tabtitle=Column(String)
    hostip=Column(String)
    port=Column(String)
    protocol=Column(String) 
    command=Column(String)
    starttime=Column(String)
    endtime=Column(String)
    outputfile=Column(String)
    output=relationship(process_output)
    status=Column(String)
    closed=Column(String)
    
    def __init__(self, pid, name, tabtitle, hostip, port, protocol, command, starttime, endtime, outputfile, status, processOutputId):
        self.display='True'
        self.pid=pid
        self.name=name
        self.tabtitle=tabtitle
        self.hostip=hostip
        self.port=port
        self.protocol=protocol      
        self.command=command
        self.starttime=starttime
        self.endtime=endtime
        self.outputfile=outputfile
        self.output=processOutputId
        self.status=status
        self.closed='False'

class note(Base):
    __tablename__='note'
    id = Column(Integer, primary_key=True)
    host_id=Column(Integer, ForeignKey('nmap_host.id'))
    text=Column(String)
    
    def __init__(self, host_id, text):
        self.text=str(text)
        self.host_id=host_id
