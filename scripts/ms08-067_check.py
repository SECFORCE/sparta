#!/usr/bin/env python

'''
Name: Microsoft Server Service Remote Path Canonicalization Stack Overflow Vulnerability

Description:
Anonymously check if a target machine is affected by MS08-067 (Vulnerability in Server Service Could Allow Remote Code Execution)

Author: Bernardo Damele A. G. <bernardo.damele@gmail.com>

License: Modified Apache 1.1

Version: 0.6

References:
* BID: 31874
* CVE: 2008-4250
* MSB: MS08-067
* VENDOR: http://blogs.technet.com/swi/archive/2008/10/25/most-common-questions-that-we-ve-been-asked-regarding-ms08-067.aspx
* VENDOR: http://www.microsoft.com/technet/security/advisory/958963.mspx
* MISC: http://www.phreedom.org/blog/2008/decompiling-ms08-067/
* MISC: http://metasploit.com/dev/trac/browser/framework3/trunk/modules/exploits/windows/smb/ms08_067_netapi.rb
* MISC: http://blog.threatexpert.com/2008/10/gimmiva-exploits-zero-day-vulnerability.html
* MISC: http://blogs.securiteam.com/index.php/archives/1150

Tested:
* Windows 2000 Server Service Pack 0
* Windows 2000 Server Service Pack 4 with Update Rollup 1
* Microsoft 2003 Standard Service Pack 1
* Microsoft 2003 Standard Service Pack 2 Full Patched at 22nd of October 2008, before MS08-067 patch was released

Notes:
* On Windows XP SP2 and SP3 this check might lead to a race condition and
  heap corruption in the svchost.exe process, but it may not crash the
  service immediately: it can trigger later on inside any of the shared
  services in the process.
'''


import socket
import sys

from optparse import OptionError
from optparse import OptionParser
from random import choice
from string import letters
from struct import pack
from threading import Thread
from traceback import format_exc

try:
    from impacket import smb
    from impacket import uuid
    from impacket.dcerpc import dcerpc
    from impacket.dcerpc import transport
except ImportError, _:
    print 'ERROR: this tool requires python-impacket library to be installed, get it '
    print 'from http://oss.coresecurity.com/projects/impacket.html or apt-get install python-impacket'
    sys.exit(1)

try:
    from ndr import *
except ImportError, _:
    print 'ERROR: this tool requires python-pymsrpc library to be installed, get it '
    print 'from http://code.google.com/p/pymsrpc/'
    sys.exit(1)


CMDLINE = False
SILENT  = False


class connectionException(Exception):
    pass


class MS08_067(Thread):
    def __init__(self, target, port=445):
        super(MS08_067, self).__init__()

        self.__port   = port
        self.target   = target
        self.status   = 'unknown'


    def __checkPort(self):
        '''
        Open connection to TCP port to check if it is open
        '''

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((self.target, self.__port))
            s.close()

        except socket.timeout, _:
            raise connectionException, 'connection timeout'

        except socket.error, _:
            raise connectionException, 'connection refused'


    def __connect(self):
        '''
        SMB connect to the Computer Browser service named pipe
        Reference: http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_browser.html
        '''

        try:
            self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)
            self.__trans.connect()

        except smb.SessionError, _:
            raise connectionException, 'access denied (RestrictAnonymous is probably set to 2)'

        except:
            #raise Exception, 'unhandled exception (%s)' % format_exc()
            raise connectionException, 'unexpected exception'


    def __bind(self):
        '''
        DCERPC bind to SRVSVC (Server Service) endpoint
        Reference: http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_srvsvc.html
        '''

        try:
            self.__dce = self.__trans.DCERPC_class(self.__trans)

            self.__dce.bind(uuid.uuidtup_to_bin(('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))

        except socket.error, _:
            raise connectionException, 'unable to bind to SRVSVC endpoint'

        except:
            #raise Exception, 'unhandled exception (%s)' % format_exc()
            raise connectionException, 'unexpected exception'


    def __forgePacket(self):
        '''
        Forge the malicious NetprPathCompare packet

        Reference: http://msdn.microsoft.com/en-us/library/cc247259.aspx

        long NetprPathCompare(
          [in, string, unique] SRVSVC_HANDLE ServerName,
          [in, string] WCHAR* PathName1,
          [in, string] WCHAR* PathName2,
          [in] DWORD PathType,
          [in] DWORD Flags
        );
        '''

        self.__path = ''.join([choice(letters) for _ in xrange(0, 3)])

        self.__request  = ndr_unique(pointer_value=0x00020000, data=ndr_wstring(data='')).serialize()
        self.__request += ndr_wstring(data='\\%s\\..\\%s' % ('A'*5, self.__path)).serialize()
        self.__request += ndr_wstring(data='\\%s' % self.__path).serialize()
        self.__request += ndr_long(data=1).serialize()
        self.__request += ndr_long(data=0).serialize()


    def __compare(self):
        '''
        Compare NetprPathCompare response field 'Windows Error' with the
        expected value (WERR_OK) to confirm the target is vulnerable
        '''

        self.__vulnerable = pack('<L', 0)

        # The target is vulnerable if the NetprPathCompare response field
        # 'Windows Error' is WERR_OK (0x00000000)
        if self.__response == self.__vulnerable:
            self.status = 'VULNERABLE'
        else:
            self.status = 'not vulnerable'

        self.result()


    def result(self):
        if CMDLINE == True and self.status in ('VULNERABLE', 'not vulnerable'):
           print '%s: %s' % (self.target, self.status)
        elif CMDLINE == True and SILENT != True:
           print '%s: %s' % (self.target, self.status)


    def run(self):
        try:
            self.__checkPort()
            self.__connect()
            self.__bind()
        except connectionException, e:
            self.status = e
            self.result()
            return None

        # Forge and send the NetprPathCompare operation malicious packet
        self.__forgePacket()
        self.__dce.call(32, self.__request)

        # Get back the NetprPathCompare response and check if it is vulnerable
        self.__response = self.__dce.recv()
        self.__compare()


if __name__ == '__main__':
    CMDLINE = True

    usage = '%s [option] {-t <target>|-l <iplist.txt>}' % sys.argv[0]
    parser  = OptionParser(usage=usage, version='0.4')
    targets = set()

    # Create command line options
    try:
        parser.add_option('-d', dest='descr', action='store_true', help='show description and exit')

        parser.add_option('-t', dest='target', help='target IP or hostname')

        parser.add_option('-l', dest='list', help='text file with list of targets')

        parser.add_option('-s', dest='silent', action='store_true', help='be silent')

        (args, _) = parser.parse_args()

        if not args.descr and not args.target and not args.list:
            print usage
            sys.exit(1)

    except (OptionError, TypeError), e:
        parser.error(e)

    descr  = args.descr
    target = args.target
    tList  = args.list

    SILENT = args.silent

    if descr:
        print __doc__
        sys.exit(0)

    if tList:
        try:
            fd = open(tList, 'r')
        except IOError:
            print 'ERROR: unable to read targets list file \'%s\'' % tList
            sys.exit(1)

        for line in fd.readlines():
            target = line.replace('\n', '').replace('\r', '')
            targets.add(target)
    else:
        targets.add(target)

    if not targets:
        print 'ERROR: no targets specified'
        sys.exit(1)

    targets = list(targets)
    targets.sort()

    if not SILENT:
        print
        print '***********************************************************************'
        print '* On Windows XP SP2 and SP3 this check might lead to a race condition *'
        print '* and heap corruption in the svchost.exe process, but it may not      *'
        print '* crash the service immediately, it can trigger later on inside any   *'
        print '* of the shared services in the process.                              *'
        print '***********************************************************************'
        print
        answer = raw_input('Do you want to continue? [Y/n] ')

        if answer and answer[0].lower() != 'y':
            sys.exit(1)

    for target in targets:
        current = MS08_067(target)
        current.start()
