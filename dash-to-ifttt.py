import requests
from scapy.all import *

def record():
        r = requests.post('https://maker.ifttt.com/trigger/<TRIGGER>/with/key/<YOUR IFTTT MAKER KEY>')
        #print r.text

def arp_display(pkt):
  if pkt.haslayer(ARP):
        if pkt[ARP].op == 1: #who-has (request)
                if pkt[ARP].hwsrc == 'DASH_MAC_ADDRESS':
                                print "Pushed Button"
                                record()
        else:
                print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(prn=arp_display, filter="arp", store=0, count=0)

