#!/usr/bin/env python

import cgi
import pcap
import socket
import struct
import sys
import threading
import time

from threading import Thread

class Scrobbify(Thread):
    protocols={
        socket.IPPROTO_TCP:'tcp',
        socket.IPPROTO_UDP:'udp',
        socket.IPPROTO_ICMP:'icmp'
    }
    
    expr = 'host post.audioscrobbler.com and port 80'
    
    def __init__(self, callback, interface='en0'):
        super(Scrobbify, self).__init__()
        self._stop = threading.Event()
        
        self.callback = callback
        
        self.p = pcap.pcapObject()
        net, mask = pcap.lookupnet(interface)
        self.p.open_live(interface, 1600, 0, 100)
        self.p.setfilter(self.expr, 0, 0)
    
    def stop(self):
        self._stop.set()
    
    def run(self):
        # Failure to shut down cleanly can result in the interface not being 
        # taken out of promisc. mode
        while not self._stop.isSet():
            self.p.dispatch(1, self.handle_packet)
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % self.p.stats()
    
    def decode_ip_packet(self, s):
        d={}
        d['version']=(ord(s[0]) & 0xf0) >> 4
        d['header_len']=ord(s[0]) & 0x0f
        d['tos']=ord(s[1])
        d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
        d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
        d['flags']=(ord(s[6]) & 0xe0) >> 5
        d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
        d['ttl']=ord(s[8])
        d['protocol']=ord(s[9])
        d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
        d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
        d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
        if d['header_len']>5:
            d['options']=s[20:4*(d['header_len']-5)]
        else:
            d['options']=None
        d['data']=s[4*d['header_len']:]
        return d
    
    def handle_packet(self, pktlen, data, timestamp):
        if not data:
            return
            
        if not data[12:14] == '\x08\x00':
            return
            
        decoded = self.decode_ip_packet(data[14:])
        s = str(decoded['data'].encode('hex')).decode('hex')
        
        if not (s.find('POST /np_1.2') > -1 and s.find('User-Agent: Spotify') > -1):
            return
         
        self.now_playing = cgi.parse_qs(s.splitlines()[-1])
        self.callback(self.now_playing, s)
    


if __name__ == "__main__":
    def cb(now_playing, data):
        sys.stdout.write("Now playing: '%s' by '%s'.\n" % (now_playing['t'][0], now_playing['a'][0]))
        sys.stdout.flush()
    scrob = Scrobbify(cb, interface='en1')
    scrob.start()
    try:
        while True:
            time.sleep(2**20)
    except (KeyboardInterrupt, SystemExit):
        scrob.stop()
