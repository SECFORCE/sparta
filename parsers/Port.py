#!/usr/bin/python

__author__ =  'SECFORCE'
__version__=  '0.1'

import parsers.Service as Service
import parsers.Script as Script

class Port:
    portId = ''
    protocol= ''
    state=''

    def __init__( self, PortNode ):
        if not (PortNode is None):
            self.port_node = PortNode
            self.portId = PortNode.getAttribute('portid')
            self.protocol = PortNode.getAttribute('protocol')
            self.state = PortNode.getElementsByTagName('state')[0].getAttribute('state')

    def get_service( self ):

        service_node = self.port_node.getElementsByTagName('service')
        
        if len(service_node) > 0:
            return Service.Service(service_node[0])

        return None

    def get_scripts( self ):

        scripts = [ ]

        for script_node in self.port_node.getElementsByTagName('script'):
            scr = Script.Script(script_node)
            scripts.append(scr)

        return scripts
