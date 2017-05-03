#!/usr/bin/env python
from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

def createAP(iface, ssid):
	dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
	addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
	beacon = Dot11Beacon(cap='ESS+privacy')
	essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
	rsn = Dot11Elt(ID='RSNinfo', info=(
	'\x01\x00'                 #RSN Version 1
	'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
	'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
	'\x00\x0f\xac\x04'         #AES Cipher
	'\x00\x0f\xac\x02'         #TKIP Cipher
	'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
	'\x00\x0f\xac\x02'         #Pre-Shared Key
	'\x00\x00'))               #RSN Capabilities (no extra capabilities)

	frame = RadioTap()/dot11/beacon/essid/rsn

	frame.show()
	print("\nHexdump of frame:")
	hexdump(frame)
	raw_input("\nPress enter to start\n")

	sendp(frame, iface=iface, inter=0.100, loop=1)

if __name__ == '__main__':
    parser = ArgumentParser('RogueAP', description='Create a rogue access point',
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--interface', default='wlan0', required=False, help='Interface to used')
    parser.add_argument('-s', '--ssid', default='testSSID', required=False, help='SSID to create')
    args = parser.parse_args()

    createAP(args.interface, args.ssid)
 
