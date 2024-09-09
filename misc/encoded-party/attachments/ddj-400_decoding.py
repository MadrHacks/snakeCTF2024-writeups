#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.usb import *

d = {
    #DECK_1
    b'\x96\x46': 'A',  # -> LOAD
    b'\x90\x0b': 'B',  # -> PLAY
    b'\x90\x0c': 'C',  # -> CUE
    b'\x90\x58': 'D',  # -> BEAT SYNC
    b'\x90\x10': 'E',  # -> LOOP IN/4BEAT
    b'\x90\x11': 'F',  # -> LOOP OUT
    b'\x90\x4d': 'G',  # -> RELOOP/EXIT
    b'\x90\x3f': 'H',  # -> SHIFT
    b'\x97\x00': 'I',  # -> PAD1 HOT CUE MODE
    b'\x97\x60': 'J',  # -> PAD1 BEAT LOOP MODE
    b'\x97\x20': 'K',  # -> PAD1 BEAT JUMP MODE
    b'\x97\x30': 'L',  # -> PAD1 SAMPLER MODE
    b'\x97\x01': 'M',  # -> PAD2 HOT CUE MODE
    b'\x97\x61': 'N',  # -> PAD2 BEAT LOOP MODE
    b'\x97\x21': 'O',  # -> PAD2 BEAT JUMP MODE
    b'\x97\x31': 'P',  # -> PAD2 SAMPLER MODE
    b'\x97\x02': 'Q',  # -> PAD3 HOT CUE MODE
    b'\x97\x62': 'R',  # -> PAD3 BEAT LOOP MODE
    b'\x97\x22': 'S',  # -> PAD3 BEAT JUMP MODE
    b'\x97\x32': 'T',  # -> PAD3 SAMPLER MODE
    b'\x97\x03': 'U',  # -> PAD4 HOT CUE MODE
    b'\x97\x63': 'V',  # -> PAD4 BEAT LOOP MODE
    b'\x97\x23': 'W',  # -> PAD4 BEAT JUMP MODE
    b'\x97\x33': 'X',  # -> PAD4 SAMPLER MODE
    b'\x97\x04': 'Y',  # -> PAD5 HOT CUE MODE
    b'\x97\x64': 'Z',  # -> PAD5 BEAT LOOP MODE
    b'\x97\x24': '=',  # -> PAD5 BEAT JUMP MODE
    b'\x97\x05': '2',  # -> PAD6 HOT CUE MODE
    b'\x97\x65': '3',  # -> PAD6 BEAT LOOP MODE
    b'\x97\x25': '4',  # -> PAD6 BEAT JUMP MODE
    b'\x97\x35': '5',  # -> PAD6 SAMPLER MODE
    b'\x97\x06': '6',  # -> PAD7 HOT CUE MODE
    b'\x97\x66': '7',  # -> PAD7 BEAT LOOP MODE
    #DECK_2
    b'\x96\x47': 'A',  # -> LOAD
    b'\x91\x0b': 'B',  # -> PLAY
    b'\x91\x0c': 'C',  # -> CUE
    b'\x91\x58': 'D',  # -> BEAT SYNC
    b'\x91\x10': 'E',  # -> LOOP IN/4BEAT
    b'\x91\x11': 'F',  # -> LOOP OUT
    b'\x91\x4d': 'G',  # -> RELOOP/EXIT
    b'\x91\x3f': 'H',  # -> SHIFT
    b'\x99\x00': 'I',  # -> PAD1 HOT CUE MODE
    b'\x99\x60': 'J',  # -> PAD1 BEAT LOOP MODE
    b'\x99\x20': 'K',  # -> PAD1 BEAT JUMP MODE
    b'\x99\x30': 'L',  # -> PAD1 SAMPLER MODE
    b'\x99\x01': 'M',  # -> PAD2 HOT CUE MODE
    b'\x99\x61': 'N',  # -> PAD2 BEAT LOOP MODE
    b'\x99\x21': 'O',  # -> PAD2 BEAT JUMP MODE
    b'\x99\x31': 'P',  # -> PAD2 SAMPLER MODE
    b'\x99\x02': 'Q',  # -> PAD3 HOT CUE MODE
    b'\x99\x62': 'R',  # -> PAD3 BEAT LOOP MODE
    b'\x99\x22': 'S',  # -> PAD3 BEAT JUMP MODE
    b'\x99\x32': 'T',  # -> PAD3 SAMPLER MODE
    b'\x99\x03': 'U',  # -> PAD4 HOT CUE MODE
    b'\x99\x63': 'V',  # -> PAD4 BEAT LOOP MODE
    b'\x99\x23': 'W',  # -> PAD4 BEAT JUMP MODE
    b'\x99\x33': 'X',  # -> PAD4 SAMPLER MODE
    b'\x99\x04': 'Y',  # -> PAD5 HOT CUE MODE
    b'\x99\x64': 'Z',  # -> PAD5 BEAT LOOP MODE
    b'\x99\x24': '=',  # -> PAD5 BEAT JUMP MODE
    b'\x99\x05': '2',  # -> PAD6 HOT CUE MODE
    b'\x99\x65': '3',  # -> PAD6 BEAT LOOP MODE
    b'\x99\x25': '4',  # -> PAD6 BEAT JUMP MODE
    b'\x99\x35': '5',  # -> PAD6 SAMPLER MODE
    b'\x99\x06': '6',  # -> PAD7 HOT CUE MODE
    b'\x99\x66': '7',  # -> PAD7 BEAT LOOP MODE
}

pcap = PcapReader("party_info.pcap")
flag_base32 = ''
pkt_n = 0
for pkt in pcap:
    pkt_n += 1
    if pkt.haslayer(USBpcap):
        if pkt[USBpcap].endpoint != 0 and pkt_n >= 4550:
            if pkt.haslayer(Raw):
                if pkt[Raw].load[-1] == b'\x7f'[0]:  # Button pressed
                    if pkt[Raw].load[1:3] in d:
                        flag_base32 += d[pkt[Raw].load[1:3]]
print(flag_base32)