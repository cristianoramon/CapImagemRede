#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Created on Tue Mar 31 08:29:30 2015
@author: ramon
"""
import argparse
import re
import zlib
#import cv2
from scapy import  *

import time
from datetime import date,datetime



from threading import Thread
from Queue import Queue, Empty
from scapy.all import *

#interface
#m_iface = "wlan0"
m_finished = False
m_dst = "192.168.0.1"

#diretorio onde vai salvar as imagens capturadas
pictures_directory = "imagens"
faces_directory    = "faces"
pcap_file          = "bhp.pcap"

# our packet callback
def packet_callback(packet):
    print(packet.show())

def http_assembler(pcap_file):

    carved_images   = 0
    faces_detected  = 0

    a = pcap_file
    sessions      = a.sessions()
    for session in sessions:
        http_payload = ""

        qt = 0;

        for packet in sessions[session]:

                qt+=1
                try:

                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:

                        http_payload += str(packet[TCP].payload)
                except:
                   pass

                headers = get_http_headers(http_payload)

                if headers is None:
                    continue

        image,image_type = extract_image(headers,http_payload)



        if image is not None and image_type is not None:

            now = datetime.today()
            ano   = now.year
            mes   = now.month
            dia   = now.day
            hora  = now.hour
            minu  = now.minute
            seg   = now.second
            dataFormatada = str(dia) + "_"+str(mes)+"_"+str(ano)+"_hora_"+str(hora)+"_"+str(minu)+"_"+str(seg)
            print("\n pic_carver_%s_%d.%s" % (dataFormatada,carved_images,image_type))
            file_name = "pic_carver_%s_%d.%s" % (dataFormatada,carved_images,image_type)
            fd = open("%s/%s" %(pictures_directory,file_name),"wb")
            fd.write(image)
            fd.close()
            carved_images += 1



    return carved_images


def get_http_headers(http_payload):
    try:

        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]

        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n",headers_raw))
    except:
        return None
    if "Content-Type" not in headers:
        return None
    return headers

def extract_image(headers,http_payload):
    image      = None
    image_type = None
    try:
        if "image" in headers['Content-Type']:

            image_type = headers['Content-Type'].split("/")[1]
            image = http_payload[http_payload.index("\r\n\r\n")+4:]
            #
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None,None

    return image,image_type


def print_summary(pkt):

    # escrever a captura do pacote
    wrpcap(pcap_file,pkt)

    print("\n Pacote ")
    print("\n")
    carved_images = http_assembler(pkt)
    print("Extraindo : %d images" % carved_images)

def menu():

    parser = argparse.ArgumentParser(
        description='Captura de Imagens na rede ')

    parser.add_argument(
        '-i', '--interface', type=str, help='Especificar a interface', required=True)

    args = parser.parse_args()
    m_iface = args.interface

    return m_iface


def iniciaSniffer():

   #m_iface = "at0"
    m_finished = False

    try:
        qtPacote = 0

        while True:

            print("\n Iniciando a captura de pacote qt =%d" % qtPacote )
            pkt = sniff(iface = m_iface, count = 100, filter = "")
            print("\n Termino da captura e iniciando a gravacao do pacote ")
            wrpcap(pcap_file,pkt)
            print("\n Leitura do pacote ")
            pkt = rdpcap(pcap_file)
            print("\n gravando as imagens")
            carved_images = http_assembler(pkt)
            qtPacote+=1

    except KeyboardInterrupt:
        print("\n\nn\ok")
        carved_images = http_assembler(pkt)
    print("Extraindo: %d images" % carved_images)

m_iface = menu()

if m_iface:
    iniciaSniffer()