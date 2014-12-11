#!/usr/bin/python

__author__ =  'yunshu(wustyunshu@hotmail.com)'
__version__=  '0.2'
__modified_by = 'ketchup'

import sys
import xml.dom.minidom

class Service:
    extrainfo = ''
    name = ''
    product = ''
    fingerprint = ''
    version = ''

    def __init__( self, ServiceNode ):
        self.extrainfo = ServiceNode.getAttribute('extrainfo')
        self.name = ServiceNode.getAttribute('name')
        self.product = ServiceNode.getAttribute('product')
        self.fingerprint = ServiceNode.getAttribute('servicefp')
        self.version = ServiceNode.getAttribute('version')


if __name__ == '__main__':

    dom = xml.dom.minidom.parse('i.xml')

    service_nodes = dom.getElementsByTagName('service')
    if len(service_nodes) == 0:
        sys.exit()

    node = dom.getElementsByTagName('service')[0]

    s = Service( node )
    print s.name
    print s.product
    print s.version
    print s.extrainfo
    print s.fingerprint
