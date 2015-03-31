#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2015 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from elixir import metadata, Entity, Field
from elixir import Unicode, UnicodeText, Integer, String
from elixir import OneToMany, ManyToMany, ManyToOne, OneToOne

# This class holds various info about an nmap scan
class nmap_session(Entity):
	filename=Field(String)
	start_time=Field(String)
	finish_time=Field(String)
	nmap_version=Field(String)
	scan_args=Field(String)
	total_hosts=Field(String)
	up_hosts=Field(String)
	down_hosts=Field(String)

	def __init__(self, filename, start_time, finish_time, nmap_version='', scan_args='', total_hosts='0', up_hosts='0', down_hosts='0'):
		self.filename=filename
		self.start_time=start_time
		self.finish_time=finish_time
		self.nmap_version=nmap_version
		self.scan_args=scan_args
		self.total_hosts=total_hosts
		self.up_hosts=up_hosts
		self.down_hosts=down_hosts

class nmap_os(Entity):
	name=Field(String)
	family=Field(String)
	generation=Field(String)
	os_type=Field(String)
	vendor=Field(String)
	accuracy=Field(String)
	host=ManyToOne('nmap_host')
	
	def __init__(self, name, family, generation, os_type, vendor, accuracy, hostId):
		self.name=name
		self.family=family
		self.generation=generation
		self.os_type=os_type
		self.vendor=vendor
		self.accuracy=accuracy
		self.host=hostId
	
class nmap_port(Entity):
	port_id=Field(String)
	protocol=Field(String)
	state=Field(String)
	host=ManyToOne('nmap_host')
	service=ManyToOne('nmap_service')
	script=ManyToMany('nmap_script')
	
	def __init__(self, port_id, protocol, state, host, service=''):
		self.port_id=port_id
		self.protocol=protocol
		self.state=state
		self.host=host
		self.service=service

class nmap_service(Entity):
	name=Field(String)
	product=Field(String)
	version=Field(String)
	extrainfo=Field(String)
	fingerprint=Field(String)
	port=OneToMany('nmap_port')
	
	def __init__(self, name='', product='', version='', extrainfo='', fingerprint=''):
		self.name=name
		self.product=product
		self.version=version
		self.extrainfo=extrainfo
		self.fingerprint=fingerprint

class nmap_script(Entity):
	script_id=Field(String)
	output=Field(Unicode)
	port=ManyToOne('nmap_port')
	host=ManyToOne('nmap_host')
	
	def __init__(self, script_id, output, portId, hostId):
		self.script_id=script_id
		self.output=unicode(output)
		self.port=portId
		self.host=hostId

class nmap_host(Entity):

	# host attributes
	checked=Field(String)
	os_match=Field(String)
	os_accuracy=Field(String)
	ip=Field(String)
	ipv4=Field(String)
	ipv6=Field(String)
	macaddr=Field(String)
	status=Field(String)
	hostname=Field(String)
	vendor=Field(String)
	uptime=Field(String)
	lastboot=Field(String)
	distance=Field(String)
	state=Field(String)
	count=Field(String)	
	
	# host relationships
	os=ManyToMany('nmap_os')
	ports=ManyToMany('nmap_port')

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

# this class represents the DB table that will hold information about a process
class process(Entity):
	display=Field(String)
	pid=Field(String)
	name=Field(String)
	tabtitle=Field(String)
	hostip=Field(String)
	port=Field(String)
	protocol=Field(String)	
	command=Field(String)
	starttime=Field(String)
	endtime=Field(String)
	outputfile=Field(String)
	output=OneToOne('process_output', inverse='process')
	status=Field(String)
	closed=Field(String)
	
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

class process_output(Entity):
	output=Field(Unicode)
	process=ManyToOne('process')
	
	def __init__(self):
		self.output=unicode('')

class note(Entity):
	host=ManyToOne('nmap_host')
	text=Field(Unicode)
	
	def __init__(self, hostId, text):
		self.text=unicode(text)
		self.host=hostId
