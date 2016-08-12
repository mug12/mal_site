#!/usr/bin/python
from scapy.all import *
from scapy.layers import http

f = open("/root/scapy/mal_site.txt",'r')
arr = []
while 1 :
	line = f.readline().splitlines()
	if not line : break
	print(line)
	arr.append(line)


def process_tcp_packet(packet):
    '''
    Processes a TCP packet, and if it contains an HTTP request, it prints it.
    '''
    if not packet.haslayer(http.HTTPRequest):
        # This packet doesn't contain an HTTP request so we skip it
        return
    http_layer = packet.getlayer(http.HTTPRequest)
    ip_layer = packet.getlayer(IP)
    if str('{1[Host]}'.format(ip_layer.fields, http_layer.fields).splitlines()) in str(arr): print "hello"
        

# Start sniffing the network.
sniff(filter='tcp', prn=process_tcp_packet)


