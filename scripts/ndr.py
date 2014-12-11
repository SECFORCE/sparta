#!/usr/bin/env python

'''
    This file is part of the PyMSRPC project and is licensed under the
    project license.

    ndr.py
    
    This are the functions that provide all the NDR data types.  It handles
    serialization and everything.  I have spent a shit load of time on this and
    yet they are not 100%.  This is usually due to structure padding or array
    serialization but honestly debugging it is such a beating so this is what
    I have for now.
    
    (c) 2007 Cody Pierce - BSD License - See LICENSE.txt
'''

import sys, struct, random, re, copy

DEBUG = False

#######################################################################
#
# Opcodes
#
#######################################################################

class ndr_opcode:
    def __init__(self, **kwargs):
        self.opnum = kwargs.get('opnum', 0x0)
        self.address = kwargs.get('address', 0x00000000)
        self.elements = kwargs.get('elements', [])
        self.out = kwargs.get('out', None)
        self.align_byte = kwargs.get('align_byte', "\xaa")
        
    def align(self, data):
        return self.align_byte * ((4 - (len(data) & 3)) & 3)
    
    # Allows us to set a context handle for [in] params
    def set_context_handle(self, handle):
        for elem in self.elements:
            if isinstance(elem, ndr_context_handle):
                elem.data = handle
                return True
        
        return False
                
    def serialize(self):
        serialdata = ""
        
        for elem in self.elements:
            s = elem.serialize()
            serialdata += s + self.align(s)

        return serialdata

#######################################################################
#
#    NDR Parent Classes
#
#######################################################################

class ndr_primitive(object):
    def align(self, data):
        return self.align_byte * ((4 - (len(data) & 3)) & 3)
    
    def serialize(self):
        raise NotImplementedError
        
class ndr_container(object):
    def align(self, data):
        return self.align_byte * ((4 - (len(data) & 3)) & 3)
    
    def add_static(self, obj):
        if DEBUG: print "[*] add_static",
            
        if not self.parent:
            if DEBUG: print "self"
            self.s.append(obj)
        else:
            if DEBUG: print "parent"
            self.parent.add_static(obj)
    
    def add_deferred(self, obj):
        if DEBUG: print "[*] add_deferred",
        
        if not self.parent:
            if DEBUG: print "self"
            self.d.append(obj)
        else:
            if DEBUG: print "parent"
            self.parent.add_deferred(obj)
                    
    def serialize(self):
        raise NotImplementedError
    
#######################################################################
#
#    Primitives
#
#######################################################################

class ndr_pad(ndr_primitive):
    '''
        pad placeholder
    '''
    def __init__(self):
        pass
    
class ndr_byte(ndr_primitive):
    '''
        encode: byte element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x06)
        self.signed = kwargs.get('signed', False)
        self.name = kwargs.get('name', "")
        self.size = 1
    
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        if self.signed:
            return struct.pack("<b", self.data)
        else:
            return struct.pack("<B", self.data)

class ndr_small(ndr_primitive):
    '''
        encode: small element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x00)
        self.signed = kwargs.get('signed', False)
        self.name = kwargs.get('name', "")
        self.size = 1
    
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        if self.signed:
            return struct.pack("<b", self.data)
        else:
            return struct.pack("<B", self.data)
        
class ndr_char(ndr_primitive):
    '''
        encode: char [*] element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x03)
        self.signed = kwargs.get('signed', False)
        self.name = kwargs.get('name', "")
        self.size = 1
        
        if self.signed:
            raise Exception
    
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
               
    def serialize(self):
        return chr(self.data)
        
class ndr_wchar(ndr_primitive):
    '''
        encode: wchar element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x42)
        self.signed = kwargs.get('signed', False)
        self.name = kwargs.get('name', "")
        self.size = 2
        
        if self.signed:
            raise Exception
    
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
               
    def serialize(self):
        return chr(self.data).encode("utf-16le")

class ndr_void(ndr_primitive):
    '''
        encode: void *element_1
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "")
        self.name = kwargs.get('name', "")
        self.size = 4
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        return self.data

class ndr_user_marshal(ndr_primitive):
    '''
        encode: [user_marshal(4)] struct struct_12 * elem_24;
        Untested/Unsupported because technically ths calls a
        user function
    '''
    def __init__(self, **kwargs):
        self.num = kwargs.get('num', 0x4)
        self.data = kwargs.get('data', "")
        self.name = kwargs.get('name', "")
        self.size = 0
    
    def get_size(self):
        return self.size
        
    def get_packed(self):
        return struct.pack("<L", self.num)
        
class ndr_range(ndr_primitive):
    '''
        encode: [range(0,1000)] long elem_1;
    '''
    def __init__(self, low=0x0, high=0xffffffff, data=""):
        self.low = kwargs.get('low', 0x0)
        self.high = kwargs.get('high', 0xffffffff)
        self.data = kwargs.get('data', "")
        self.size = 0
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_size(self):
        return self.size
        
    def serialize(self):
        if not self.data:
            self.data = ndr_long(data=random.randint(self.low, self.high))
        else:
            if self.data.get_data() > self.high:
                self.data.data = self.high
            elif self.data.get_data() < self.low:
                self.data.data = self.low
                
        return self.data.serialize()

class ndr_enum16(ndr_primitive):
    '''
        encode: /* enum16 */ short element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x0004)
        self.signed = kwargs.get('signed', True)
        self.name = kwargs.get('name', "")
        self.size = 2
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        if self.signed:
            return struct.pack("<H", self.data)
        else:
            return struct.pack("<h", self.data)
                    
class ndr_short(ndr_primitive):
    '''
        encode: short element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x0004)
        self.signed = kwargs.get('signed', True)
        self.name = kwargs.get('name', "")
        self.size = 2
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        if self.signed:
            return struct.pack("<H", self.data)
        else:
            return struct.pack("<h", self.data)

class ndr_interface(ndr_primitive):
    '''
        encode: interface(0000000c-0000-0000-c000-000000000046)
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "\x89" * 20)
        self.name = kwargs.get('name', "")
        self.size = 20
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
            
    def serialize(self):
        return self.data

class ndr_long(ndr_primitive):
    '''
        encode: long element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x00000002)
        self.signed = kwargs.get('signed', True)
        self.name = kwargs.get('name', "")
        self.size = 4
        
    def set_data(self, new_data):
        self.data = new_data
            
    def get_data(self):
        return self.data
    
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
            
    def serialize(self):
        if self.signed:
            return struct.pack("<l", self.data)
        else:
            return struct.pack("<L", self.data)

class ndr_hyper(ndr_primitive):
    '''
        encode: hyper (aka 64bit) element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x0000000000000005)
        self.signed = kwargs.get('signed', True)
        self.name = kwargs.get('name', "")
        self.size = 8
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        if self.signed:
            return struct.pack("<q", self.data)
        else:
            return struct.pack("<Q", self.data)

class ndr_empty(ndr_primitive):
    '''
        used for default or empty cases in unions/unknown stuff
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "")
        self.name = kwargs.get('name', "")
        self.size = 0
    
    def get_data(self):
        return self.data
        
    def get_name(self):
        return self.name
        
    def get_size(self):
        return self.size
        
    def serialize(self):
        return ""
        
class ndr_float(ndr_primitive):
    '''
        encode: float element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0.0)
        self.name = kwargs.get('name', "")
        self.size = 4
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        return struct.pack("<f", self.data)

class ndr_double(ndr_primitive):
    '''
        encode: double element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0.0)
        self.name = kwargs.get('name', "")
        self.size = 8
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
        
    def serialize(self):
        return struct.pack("<d", self.data)
        
class ndr_string(ndr_primitive):
    '''
        encode: char *element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "Administrator")
        self.name = kwargs.get('name', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        self.size = 0
        
    def pad(self, data):
        return self.align_byte * ((4 - (len(data) & 3)) & 3)
    
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return len(self.get_packed())
        
    def serialize(self):
        # We add our null because it gets counted
        self.data += "\x00"

        length = len(self.data)
        
        # Conformance varying information
        return struct.pack("<L", length)   \
               + struct.pack("<L", 0)      \
               + struct.pack("<L", length) \
               + self.data                 \
               + self.pad(self.data)       \
        
class ndr_wstring(ndr_primitive):
    '''
        encode: wchar *element_1;
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "\\\\EXCHANGE2K3")
        self.name = kwargs.get('name', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        self.size = 0
        
    def pad(self, data):
        return self.align_byte * ((4 - (len(data) & 3)) & 3)
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_data(self):
        return self.data
    
    def get_name(self):
        return self.name
    
    def get_size(self):
        return len(self.get_packed())   
        
    def serialize(self):
        # Add our wide null because it gets counted
        data = self.data.encode("utf-16le") + "\x00\x00"
    
        length = len(data) / 2
        return struct.pack("<L", length)   \
               + struct.pack("<L", 0)      \
               + struct.pack("<L", length) \
               + data                      \
               + self.pad(data)

class ndr_string_nonconformant(ndr_primitive):
    '''
        encode: [string] char element_1[3];
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "ABCDEFG")
        self.name = kwargs.get('name', "")
        self.size = kwargs.get('size', 0)
        self.align_byte = kwargs.get('align_byte', "\xaa")
        
    def pad(self, data):
        return self.align_byte * ((4 - (len(data) & 3)) & 3)
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_data(self):
        return self.data
    
    def get_name(self):
        return self.name
    
    def get_size(self):
        return len(self.get_packed())
        
    def serialize(self):
        # Make sure we stick to our size
        if len(self.data) < self.size:
            self.size = len(self.data)
            data = self.data
        else:
            data = self.data[:self.size - 1]
            
        # Add our null
        data += "\x00"
    
        return struct.pack("<L", 0)           \
               + struct.pack("<L", self.size) \
               + data                         \
               + self.pad(data)

class ndr_wstring_nonconformant(ndr_primitive):
    '''
        encode: [string] wchar_t element_1[3];
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "ABCDEFG")
        self.name = kwargs.get('name', "")
        self.size = kwargs.get('size', 0)
        self.align_byte = kwargs.get('align_byte', "\xaa")
        
    def pad(self, data):
        return self.align_byte * ((4 - (len(data) & 3)) & 3)
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_data(self):
        return self.data
    
    def get_name(self):
        return self.name
    
    def get_size(self):
        return len(self.get_packed())
        
    def serialize(self):
        # Make sure we stick to our size
        if len(self.data) < self.size:
            self.size = len(self.data) / 2
            data = self.data
        else:
            data = self.data[:self.size - 1]
        
        # Add our wide null
        data = data.encode("utf-16le") + "\x00\x00"
    
        return struct.pack("<L", 0)           \
               + struct.pack("<L", self.size) \
               + data                         \
               + self.pad(data)
        
class ndr_error_status(ndr_primitive):
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x00000000)
        self.name = kwargs.get('name', "")
        self.size = 4
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
            
    def serialize(self):
        return struct.pack("<L", self.data)
        
class ndr_callback(ndr_primitive):
    '''
        encodes size_is(callback_0x12345678)
        Unsupported because it calls a user function
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', 0x00000000)
        self.name = kwargs.get('name', "")
        self.size = 4
        
    def get_data(self):
        return self.data
    
    def set_data(self, new_data):
        self.data = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
            
    def serialize(self):
        return struct.pack("<L", self.data)
        
class ndr_context_handle(ndr_primitive):
    '''
        encodes: [in] context_handle arg_1
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "\x88" * 20)
        self.name = kwargs.get('name', "")
        self.size = 20
        
    def get_data(self):
        return self.data
    
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
            
    def serialize(self):
        return self.data

class ndr_pipe(ndr_primitive):
    '''
        I need an example plz2u
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "\x8a" * 20)
        self.name = kwargs.get('name', "")
        self.size = 20
    
    def get_data(self):
        return self.data
    
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
        
    def serialize(self):
        return self.data

class ndr_handle_t(ndr_primitive):
    '''
        encode: handle_t element_1 (not sent on network)
    '''
    def __init__(self, **kwargs):
        self.data = kwargs.get('data', "")
        self.name = kwargs.get('name', "")
        self.size = 0
        
    def get_data(self):
        return self.data
    
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
            
    def serialize(self):
        return ""

#######################################################################
#
# Unions
#
#######################################################################

class ndr_union:
    '''
    NDR Union: data will be a tuple list of (case, ndr_type)
    '''
    
    def __init__(self, **kwargs):
        self.elements = kwargs.get('elements', {})
        self.switch_dep = kwargs.get('switch_dep', "")
        self.name = kwargs.get('name', "")
        self.defname = kwargs.get('defname', "")
        self.size = 0
        
    def get_data(self):
        return self.elements
        
    def set_data(self, new_data):
        self.elements = new_data
        
    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
    
    def add_element(self, case, element):
        self.elements[case] = element
        
    def serialize(self):
        serialdata = ""
        
        switch = self.switch_dep.get_data()
        if self.elements.has_key(switch):
            serialdata += self.switch_dep.serialize()
        
            # Pack our requested enum
            serialdata += self.elements[switch].serialize()
        else:
            # This allows us to pick a switch for the user
            newswitch = self.elements.keys()[0]
            
            # We need to update our original switch_dep so it passes correlation checks
            self.switch_dep.set_data(newswitch)
            
            serialdata += ndr_long(data=newswitch).serialize()
            serialdata += self.elements[newswitch].serialize()

        return serialdata

#######################################################################
#
# Pointers
#
#######################################################################
class ndr_unique(ndr_container):
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', "")
        self.data = kwargs.get('data', "")
        self.type = kwargs.get('type', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        self.pointer_value = kwargs.get('pointer_value', 0x41424344)
        self.size = 4
        self.alignment = 4
        
        self.parent = None
        self.s = []
        self.d = []
        
    def get_name(self):
        return self.name
        
    def get_size(self):
        return self.size
    
    def get_data(self):
        return self.data
            
    def set_data(self, new_data):
        # We have to use the objects set_data if its a unique/array
        self.data.set_data(new_data)
        
    def serialize(self):
        self.add_static(ndr_long(data=self.pointer_value))
        
        if isinstance(self.data, ndr_container):
            self.data.parent = self
        
        self.add_deferred(self.data)
        
        if not self.parent:
            while len(self.d):
                d = self.d.pop(0)
                if isinstance(d, ndr_container):
                    d.serialize()
                else:
                    self.add_static(d)
            
            serialdata = ""
            for s in self.s:
                if isinstance(s, ndr_pad):
                    serialdata += self.align(serialdata)
                else:
                    serialdata += s.serialize()
            
            self.parent = None
            self.s = []
            self.d = []
            
            return serialdata
            
class ndr_full(ndr_container):
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', "")
        self.data = kwargs.get('data', "")
        self.type = kwargs.get('type', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        self.pointer_value = kwargs.get('pointer_value', 0x41424344)
        self.size = 4
        self.alignment = 4
        
        self.parent = None
        self.s = []
        self.d = []
        
    def get_name(self):
        return self.name
        
    def get_size(self):
        return self.size
    
    def get_data(self):
        return self.data
            
    def set_data(self, new_data):
        # We have to use the objects set_data if its a unique/array
        self.data.set_data(new_data)
        
    def serialize(self):
        self.add_static(ndr_long(data=self.pointer_value))
        
        if isinstance(self.data, ndr_container):
            self.data.parent = self
        
        self.add_deferred(self.data)
        
        if not self.parent:
            while len(self.d):
                d = self.d.pop(0)
                if isinstance(d, ndr_container):
                    d.serialize()
                else:
                    self.add_static(d)
            
            serialdata = ""
            for s in self.s:
                if isinstance(s, ndr_pad):
                    serialdata += self.align(serialdata)
                else:
                    serialdata += s.serialize()
            
            self.parent = None
            self.s = []
            self.d = []
                
            return serialdata
            
#######################################################################
#
# Structures
#
#######################################################################

class ndr_struct(ndr_container):
    def __init__(self, **kwargs):
        self.elements = kwargs.get('elements', [])
        self.name = kwargs.get('name', "")
        self.defname = kwargs.get('defname', "")
        self.type = kwargs.get('type', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        
        self.size = 0
        self.alignment = 4
        
        self.parent = None
        self.s = []
        self.d = []
        
    def get_data(self):
        return self.elements
        
    def set_data(self, new_data):
        self.elements = new_data
        
    def add_element(self, element):
        self.elements.append(element)
    
    def del_element(self, eid):
        del(self.elements[eid])
        
        return True
        
    def get_element_by_id(self, eid=0):
        return self.elements[eid]
    
    def get_element_by_name(self, name):
        for element in self.elements:
            try:
                if element.name == name:
                    return element
            except:
                if DEBUG: print "[*] Couldnt get name of element"
        
        return False

    def get_name(self):
        return self.name
    
    def get_size(self):
        return self.size
    
    def serialize(self):
        if DEBUG: print "[*] Serializing ndr_struct"
            
        # First we take care of our list serializing all containers first, and adding primitives verbatim
        for e in self.elements:
            if isinstance(e, ndr_container):
                e.parent = self
                e.serialize()
            else:
                self.add_static(e)
        
        # If we are the top-most structure lets package it all
        if not self.parent:
            if DEBUG: print "[*] Packaging top most struct %s" % self.name
                            
            self.add_static(ndr_pad())
            
            while len(self.d):
                d = self.d.pop(0)
                if isinstance(d, ndr_container):
                    d.serialize()
                else:
                    self.add_static(d)
            
            serialdata = ""
            for s in self.s:
                if isinstance(s, ndr_pad):                    
                    serialdata += self.align(serialdata)
                else:
                    serialdata += s.serialize()
            
            self.parent = None
            self.s = []
            self.d = []
            
            return serialdata

#######################################################################
#
# Arrays
#
#######################################################################

class ndr_array(ndr_container):
    def array_serialize(self, count):
        for c in range(count):
            if isinstance(self.basetype, ndr_container):
                self.basetype.parent = self
                self.basetype.serialize()
            else:
                self.add_static(self.basetype)
        
        if not self.parent:
            if DEBUG: print "[*] Packaging top most array %s" % self.name
                
            while len(self.d):
                d = self.d.pop(0)
                if isinstance(d, ndr_container):
                    d.serialize()
                else:
                    self.add_static(d)
            
            serialdata = ""
            for s in self.s:
                if isinstance(s, ndr_pad):
                    serialdata += self.align(serialdata)
                else:
                    serialdata += s.serialize()
            
            self.parent = None
            self.s = []
            self.d = []
            
            return serialdata + self.align(serialdata)
        else:
            self.add_static(ndr_pad())
                        
class ndr_array_fixed(ndr_array):
    def __init__(self, **kwargs):
        self.basetype = kwargs.get('basetype', ndr_empty())
        self.elements = kwargs.get('elements', [])
        self.count = kwargs.get('count', 0x0)
        self.cmod= kwargs.get('cmod', ())
        self.cptr = kwargs.get('cptr', 0x0)
        self.name = kwargs.get('name', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        self.size = 0

        self.parent = None
        self.s = []
        self.d = []
        
    def set_data(self, new_data):
        # We have to use the objects set_data if its a pointer
        self.basetype.set_data(new_data)
    
    def get_size(self):
        return self.size
            
    def get_count(self):
        return self.count

    def serialize(self):
        if DEBUG: print "[*] Serializing ndr_array"
        
        if self.cptr == 1:
            self.add_static(ndr_long(data=0x41424344))
            
        return self.array_serialize(self.count)

class ndr_array_conformant(ndr_array):    
    def __init__(self, **kwargs):
        self.basetype = kwargs.get('basetype', ndr_empty())
        self.elements = kwargs.get('elements', [])
        self.count = kwargs.get('count', 0x0)
        self.cmod= kwargs.get('cmod', ())
        self.cptr = kwargs.get('cptr', 0x0)
        self.name = kwargs.get('name', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        self.packed_count = False
        self.size = 0
    
        self.parent = None
        self.s = []
        self.d = []
        
    def set_data(self, new_data):
        # We have to use the objects set_data if its a pointer
        self.basetype.set_data(new_data)
    
    def get_size(self):
        return self.size
    
    def serialize(self):
        if DEBUG: print "[*] Serializing ndr_array_conformant"
        
        if self.cptr == 1:
            self.add_static(ndr_long(data=0x41424344))
        
        # Pack our count
        if isinstance(self.count, int):
            num = self.count
            
            self.add_static(ndr_long(data=num))
            
        # If we used a ascii rep of size pack it
        # YYY: callback_0x12345678 will fail here
        elif isinstance(self.count, str):
            num = int(self.count)
            
            self.add_static(ndr_long(data=num))
        # else we have a ndr object to pack
        else:
            # We have to handle the math operators i.e. [size_is(arg1 / 2)]
            num = self.count.get_data()
            if self.cmod:
                if self.cmod[0] == "/":
                    num /= self.cmod[1]
                elif self.cmod[0] == "*":
                    num *= self.cmod[1]
                else:
                    print "[!] Problem with operator %s" % self.cmod[0]
                    sys.exit(-1)
                      
            self.add_static(ndr_long(data=num))
        # End pack count
        
        return self.array_serialize(num)

class ndr_array_varying(ndr_array):
    def __init__(self, **kwargs):
        self.basetype = kwargs.get('basetype', ndr_empty())
        self.elements = kwargs.get('elements', [])
        self.count = kwargs.get('count', 0x0)
        self.cmod= kwargs.get('cmod', ())
        self.cptr = kwargs.get('cptr', 0x0)
        self.name = kwargs.get('name', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        
        self.packed_count = False
        self.size = 0

        self.parent = None
        self.s = []
        self.d = []
        
    def set_data(self, new_data):
        # We have to use the objects set_data if its a pointer
        self.basetype.set_data(new_data)
    
    def get_size(self):
        return self.size

    def serialize(self):
        # Pack offset
        self.add_static(ndr_long(data=0x0))
        
        # Need example of the cptr stuff
        if self.cptr == 1:
            self.add_static(ndr_long(data=0x41424344))
            
        if isinstance(self.count, int):
            num = self.count
        elif isinstance(self.count, str):
            num = int(self.count)
        else:
            num = self.count.get_data()
            if self.cmod:
                if self.cmod[0] == "/":
                    num /= self.cmod[1]
                elif self.cmod[0] == "*":
                    num *= self.cmod[1]
                else:
                    print "[!] Problem with operator %s" % self.cmod[0]
                    sys.exit(-1)
        
        # Pack our array count    
        self.add_static(ndr_long(data=num))
        
        return self.array_serialize(num)

class ndr_array_conformant_varying(ndr_array):
    def __init__(self, **kwargs):
        self.basetype = kwargs.get('basetype', ndr_empty())
        self.elements = kwargs.get('elements', [])
        
        self.maxcount = kwargs.get('maxcount', 0x0)
        self.mmod= kwargs.get('mmod', ())
        self.mptr = kwargs.get('mptr', 0x0)
        
        self.passed = kwargs.get('passed', 0x0)
        self.pmod= kwargs.get('pmod', ())
        self.pptr = kwargs.get('pptr', 0x0)
        
        self.name = kwargs.get('name', "")
        self.align_byte = kwargs.get('align_byte', "\xaa")
        
        self.packed_count = True
        self.size = 0
        
        self.parent = None
        self.s = []
        self.d = []
        
    def set_data(self, new_data):
        # We have to use the objects set_data if its a pointer
        self.basetype.set_data(new_data)
    
    def get_size(self):
        return self.size

    def serialize(self):
        # Need example of the mptr stuff
        if self.mptr == 1:
            self.add_static(ndr_long(data=0x41424344))
        
        # Do conformant stuff
        if isinstance(self.maxcount, int):
            mnum = self.maxcount
        elif isinstance(self.maxcount, str):
            mnum = int(self.maxcount)
        else:                
            mnum = self.maxcount.get_data()
            if self.mmod:
                if self.mmod[0] == "/":
                    mnum /= self.mmod[1]
                elif self.mmod[0] == "*":
                    mnum *= self.mmod[1]
                else:
                    print "[!] Problem with operator %s" % self.mmod[0]
                    sys.exit(-1)
    
        # Pack conformant info
        self.add_static(ndr_long(data=mnum))
                            
        # Offset
        self.add_static(ndr_long(data=0x0))
        
        # Need example of the pptr stuff
        if self.pptr == 1:
            self.add_static(ndr_long(data=0x41424344))
            
        # Do varying stuff
        if isinstance(self.passed, int):
            pnum = self.passed
        elif isinstance(self.passed, str):
            pnum = int(self.passed)
        else:
            pnum = self.passed.get_data()
            if self.pmod:
                if self.pmod[0] == "/":
                    pnum /= self.pmod[1]
                elif self.pmod[0] == "*":
                    pnum *= self.pmod[1]
                else:
                    print "[!] Problem with operator %s" % self.pmod[0]
                    sys.exit(-1)
        
        # Add varying count
        self.add_static(ndr_long(data=pnum))
        
        return self.array_serialize(pnum)
