#!/usr/bin/python

__author__ =  'ketchup'
__version__=  '0.1'
__modified_by = 'ketchup'

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
