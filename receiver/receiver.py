#!/usr/bin/python
# pcc (portantier covert channel) - receiver

# definimos que solamente se debe alertar ante un error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy
# importamos las librerias necesarias
from scapy.all import *
import socket
#import b64

# definimos la funcion que se va a llamar en la llegada de cada paquete
def get_ip_address():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect (('8.8.8.8',80))
    return s.getsockname()[0]

def monitor_callback(packet):
    nic_ip=get_ip_address()
    if DNS in packet and packet[IP].dst == nic_ip and( packet[DNS].qd[DNSQR].qname[0:8] == "12345678" or packet[DNS].qd[DNSQR].qname[0:8] == "87654321"):
            # abrimos el archivo 'received.txt' y escribimos los datos recibidos
            print "pacote recibido..."
            f = open('received.txt', 'a')
            data = packet[DNS].qd[DNSQR].qname[8:]
            print >>f, data,
            f.close()

            print data

# termina la definicion de la funcion, y empieza el programa principal

print "Esperando la llegada de los paquetes..."

# empezamos a escuchar en la interfaz definida en 'eth0'
# la interfaz deberemos ajustarla de acuerdo a nuestro sistema
#pkts = sniff(iface="en1", prn=monitor_callback)
pkts = sniff(prn=monitor_callback)
