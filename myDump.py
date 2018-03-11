from __future__ import print_function
from scapy.all import *
import re
import time
import datetime

 
## Create a Packet Counter
counter = 0


## Define our myDump function
def myDump(packet):
    global counter
    
    while counter <999:
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        counter += 1

## for TCP Packets
        if (packet.haslayer(TCP) == 1):
            if (packet.haslayer(Raw) == 1):
                payload = packet[TCP].load
                payload.replace("\\","\\\\")
                tcp = 'TCP'
#'{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} TCP load \n {}'

                print (st, counter, packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst, tcp)
                return payload
            else:
                return '{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} TCP no payload'.format(st, counter, packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst)

## for UDP Packets
        if (packet.haslayer(UDP) == 1):
            if (packet.haslayer(Raw) == 1):
                return '{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} UDP load \n {}'.format(st, counter, packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst, str(packet[0].load))
            else:
                return '{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} UDP no payload'.format(st, counter, packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst)

## for ICMP Packets
        if (packet.haslayer(ICMP) == 1):
            if (packet.haslayer(Raw) == 1):
#'{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} ICMP load \n {}'
                icmp = 'ICMP'
                payload = packet[ICMP].load
                payload.replace("\\","\\")
                print (st, counter, packet[0].src, packet[0][1].src, packet[0].dst, icmp, packet[0][1].dst, payload)
            else:
                return '{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} ICMP no payload'.format(st, counter, packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst)

## for OTHER Packets
        else:
            if (packet.haslayer(Raw) == 1):
                return '{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} OTHER load \n {}'.format(st, counter, packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst, str(packet[0].load))
            else:
		## For ARP since there is no src but a psrc
                if (packet.haslayer(ARP) ==1):
                    return '{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} OTHER no payload'.format(st, counter, packet[0].src, packet[0][1].psrc, packet[0].dst, packet[0][1].pdst)
                else:
                    return '{} Packet #{}: srcMAC {} srcIP {} ==> dstMAC {} dstIP {} OTHER no payload'.format(st, counter, packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst)



    sys.exit()
#haslayer
#print(str(sys.argv[1]))
if len(sys.argv) > 1:
    if str(sys.argv[1]) == "-i":
        interf = str(sys.argv[2])
        if str(sys.argv[3]) == "-s":
            filt = str(sys.argv[4])
            sniff(filter=filt, prn=myDump, iface=interf)
        else:
            sniff(prn=myDump, iface=interf)
    elif (sys.argv[1]) == "-s":
        filt = str(sys.argv[2])
        sniff(filter=filt, prn=myDump)
else:
    sniff(prn=myDump)






