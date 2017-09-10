import requests
from scapy.all import *

DASH_MAC_ADRESS = '<SET_VALUE_HERE>'
IFTTT_TRIGGER_NAME = '<SET TRIGGER NAME>'
IFTTT_KEY = '<SET KEY>'

def record():
        r = requests.post('https://maker.ifttt.com/' + IFTTT_TRIGGER_NAME + '/with/key/' + IFTTT_KEY)
        #print r.text

def arp_display(pkt):
  if pkt.haslayer(ARP):
        if pkt[ARP].op == 1: #who-has (request)
                if pkt[ARP].hwsrc == DASH_MAC_ADDRESS:
                                print "Pushed Button"
                                record()
        else:
                print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(prn=arp_display, filter="arp", store=0, count=0)

