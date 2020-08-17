#!/usr/bin/python

'''this module used to parse nmap xml report'''
__author__ =  'yunshu(wustyunshu@hotmail.com)'
__version__=  '0.2'
__modified_by = 'ketchup'
__modified_by = 'SECFORCE'

import parsers.Session as Session
import parsers.Host as Host
import xml.dom.minidom

class Parser:

    '''Parser class, parse a xml format nmap report'''
    def __init__( self, xml_input ):
        '''constructor function, need a xml file name as the argument'''
        try:
            self.__dom = xml.dom.minidom.parse(xml_input)
            self.__session = None
            self.__hosts = { }
            for host_node in self.__dom.getElementsByTagName('host'):
                __host =  Host.Host(host_node)
                self.__hosts[__host.ip] = __host
        except Exception as ex:
            print("\t[-] Parser error! Invalid nmap file!")
            print(ex)
            raise

    def get_session( self ):
        '''get this scans information, return a Session object'''
        run_node = self.__dom.getElementsByTagName('nmaprun')[0]
        hosts_node = self.__dom.getElementsByTagName('hosts')[0]

        finish_time = self.__dom.getElementsByTagName('finished')[0].getAttribute('timestr')

        nmap_version = run_node.getAttribute('version')
        start_time =  run_node.getAttribute('startstr')
        scan_args = run_node.getAttribute('args')

        total_hosts = hosts_node.getAttribute('total')
        up_hosts = hosts_node.getAttribute('up')
        down_hosts = hosts_node.getAttribute('down')

        MySession = { 'finish_time': finish_time,
                        'nmap_version' : nmap_version,
                        'scan_args' : scan_args,
                        'start_time' : start_time,
                        'total_hosts' : total_hosts,
                        'up_hosts' : up_hosts,
                        'down_hosts' : down_hosts }

        self.__session = Session.Session( MySession )

        return self.__session

    def get_host( self, ipaddr ):

        '''get a Host object by ip address'''

        return self.__hosts.get(ipaddr)

    def all_hosts( self, status = '' ):

        '''get a list of Host object'''

        if( status == '' ):
            return self.__hosts.values( )

        else:
            __tmp_hosts = [ ]

            for __host in self.__hosts.values( ):

                if __host.status == status:
                    __tmp_hosts.append( __host )

            return __tmp_hosts

    def all_ips( self, status = '' ):

        '''get a list of ip address'''
        __tmp_ips = [ ]

        if( status == '' ):
            for __host in self.__hosts.values( ):

                __tmp_ips.append( __host.ip )

        else:
            for __host in self.__hosts.values( ):

                if __host.status == status:
                    __tmp_ips.append( __host.ip )

        return __tmp_ips
