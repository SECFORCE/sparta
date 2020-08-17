#!/usr/bin/python

__author__ =  'yunshu(wustyunshu@hotmail.com)'
__version__=  '0.2'
__modified_by = 'ketchup'

import parsers.Service as Service
import parsers.Script as Script
import parsers.OS as OS
import parsers.Port as Port

class Host:
    ipv4 = ''
    ipv6 = ''
    macaddr = ''
    status = 'none'
    hostname = ''
    vendor = ''
    uptime = ''
    lastboot = ''
    distance = 0
    state = ''
    count = ''

    def __init__( self, HostNode ):
        self.host_node = HostNode
        self.status = HostNode.getElementsByTagName('status')[0].getAttribute('state')
        for e in HostNode.getElementsByTagName('address'):
            if e.getAttribute('addrtype') == 'ipv4':
                self.ipv4 = e.getAttribute('addr')
            elif e.getAttribute('addrtype') == 'ipv6':
                self.ipv6 = e.getAttribute('addr')
            elif e.getAttribute('addrtype') == 'mac':
                self.macaddr = e.getAttribute('addr')
                self.vendor = e.getAttribute('vendor')
        #self.ip = HostNode.getElementsByTagName('address')[0].getAttribute('addr');
        self.ip = self.ipv4 # for compatibility with the original library
        if len(HostNode.getElementsByTagName('hostname')) > 0:
            self.hostname = HostNode.getElementsByTagName('hostname')[0].getAttribute('name')
        if len(HostNode.getElementsByTagName('uptime')) > 0:
            self.uptime = HostNode.getElementsByTagName('uptime')[0].getAttribute('seconds')
            self.lastboot = HostNode.getElementsByTagName('uptime')[0].getAttribute('lastboot')
        if len(HostNode.getElementsByTagName('distance')) > 0:
            self.distance = int(HostNode.getElementsByTagName('distance')[0].getAttribute('value'))
        if len(HostNode.getElementsByTagName('extraports')) > 0:
            self.state = HostNode.getElementsByTagName('extraports')[0].getAttribute('state')
            self.count = HostNode.getElementsByTagName('extraports')[0].getAttribute('count')

    def get_OS(self):
        oss = []

        for OS_node in self.host_node.getElementsByTagName('osclass'):
            os = OS.OS(OS_node)
            oss.append(os)

        for OS_node in self.host_node.getElementsByTagName('osmatch'):
            os = OS.OS(OS_node)
            oss.append(os)

        return oss

    def all_ports( self ):
        
        ports = [ ]

        for port_node in self.host_node.getElementsByTagName('port'):
            p = Port.Port(port_node)
            ports.append(p)

        return ports

    def get_ports( self, protocol, state ):
        '''get a list of ports which is in the special state'''

        open_ports = [ ]

        for port_node in self.host_node.getElementsByTagName('port'):
            if port_node.getAttribute('protocol') == protocol and port_node.getElementsByTagName('state')[0].getAttribute('state') == state:
                open_ports.append( port_node.getAttribute('portid') )

        return open_ports

    def get_scripts( self ):

        scripts = [ ]

        for script_node in self.host_node.getElementsByTagName('script'):
            scr = Script.Script(script_node)
            scripts.append(scr)

        return scripts
        
    def get_hostscripts( self ):

        scripts = [ ]
        for hostscript_node in self.host_node.getElementsByTagName('hostscript'):
            for script_node in hostscript_node.getElementsByTagName('script'):
                scr = Script.Script(script_node)
                scripts.append(scr)

        return scripts

    def get_service( self, protocol, port ):
        '''return a Service object'''

        for port_node in self.host_node.getElementsByTagName('port'):
            if port_node.getAttribute('protocol') == protocol and port_node.getAttribute('portid') == port:
                if (len(port_node.getElementsByTagName('service'))) > 0:
                    service_node = port_node.getElementsByTagName('service')[0]
                    service = Service.Service( service_node )
                    return service
        return None
