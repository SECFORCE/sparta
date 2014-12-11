#!/usr/bin/python

__author__ =  'ketchup'
__version__=  '0.1'
__modified_by = 'ketchup'

import sys
import xml.dom.minidom

class OS:
    name = ''
    family = ''
    generation = ''
    os_type = ''
    vendor = ''
    accuracy = 0

    def __init__( self, OSNode ):
        if not (OSNode is None):
            self.name = OSNode.getAttribute('name')
            self.family = OSNode.getAttribute('osfamily')
            self.generation = OSNode.getAttribute('osgen')
            self.os_type = OSNode.getAttribute('type')
            self.vendor = OSNode.getAttribute('vendor')
            self.accuracy = OSNode.getAttribute('accuracy')

if __name__ == '__main__':

    dom = xml.dom.minidom.parse('test.xml')

    osclass = dom.getElementsByTagName('osclass')[0]

    osmatch = dom.getElementsByTagName('osmatch')[0]


    os = OS( osclass )
    print os.name
    print os.family
    print os.generation
    print os.os_type
    print os.vendor
    print str(os.accuracy)

    os = OS( osmatch )
    print os.name
    print os.family
    print os.generation
    print os.os_type
    print os.vendor
    print str(os.accuracy)
