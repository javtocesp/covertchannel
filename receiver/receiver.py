#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy
from scapy.all import *
import socket
import base64

file_to_ensamble=''

def get_ip_address():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect (('8.8.8.8',80))
    return s.getsockname()[0]

def convert_b64_to_file(file_in_b64,path_to_save='/home/javier/Pictures/skydiving-katrina-from-base64.jpg'):
    print path_to_save
    file_new=open(path_to_save,'wb+')
    file_new.write(file_in_b64.decode('base64'))
    file_new.close()


def monitor_callback(packet):
    global file_to_ensamble
    nic_ip=get_ip_address()
    if DNS in packet and packet[IP].dst == nic_ip and( packet[DNS].qd[DNSQR].qname[0:8] == "12345678" or packet[DNS].qd[DNSQR].qname[0:8] == "87654321"):
            print "pacote recibido..."
            f = open('received.txt', 'a')
            data = packet[DNS].qd[DNSQR].qname[8:]
            data=data.replace('.','')
            file_to_ensamble=file_to_ensamble+data
            if (packet[DNS].qd[DNSQR].qname[0:8] == "87654321"):
                convert_b64_to_file(file_to_ensamble,'/tmp/file.jpg')                    
            print >>f, data,
            f.close()

            print data


print "Esperando la llegada de los paquetes..."
#pkts = sniff(iface="en1", prn=monitor_callback)
pkts = sniff(prn=monitor_callback)
