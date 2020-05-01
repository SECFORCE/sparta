#!/usr/bin/python

__author__ =  'yunshu(wustyunshu@hotmail.com)'
__version__=  '0.2'

class Session:
    def __init__( self, SessionHT ):
        self.start_time = SessionHT.get('start_time', '')
        self.finish_time = SessionHT.get('finish_time', '')
        self.nmap_version = SessionHT.get('nmap_version', '')
        self.scan_args = SessionHT.get('scan_args', '')
        self.total_hosts = SessionHT.get('total_hosts', '')
        self.up_hosts = SessionHT.get('up_hosts', '')
        self.down_hosts = SessionHT.get('down_hosts', '')
