#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy
from scapy.all import *
import socket
import b64

def get_ip_address():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect (('8.8.8.8',80))
    return s.getsockname()[0]

def monitor_callback(packet):
    nic_ip=get_ip_address()
    if DNS in packet and packet[IP].dst == nic_ip and( packet[DNS].qd[DNSQR].qname[0:8] == "12345678" or packet[DNS].qd[DNSQR].qname[0:8] == "87654321"):
            print "pacote recibido..."
            f = open('received.txt', 'a')
            data = packet[DNS].qd[DNSQR].qname[8:]
            print >>f, data,
            f.close()

            print data


print "Esperando la llegada de los paquetes..."
#pkts = sniff(iface="en1", prn=monitor_callback)
pkts = sniff(prn=monitor_callback)
