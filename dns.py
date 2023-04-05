#!/usr/bin/env python
### adapted from : http://thepacketgeek.com/scapy-p-09-scapy-and-dns/
### further adapted from: https://github.com/emileaben/scapy-dns-ninja
### sudo iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
from scapy.all import *
import sys
import os.path
import struct
from cachetools import TTLCache

requestcache = TTLCache(maxsize=10000, ttl=3600) #10k items with 1 hour life
parentdomain = b".example.com"
checksub = b"check"
testsub = b"test"
# if request query ends with ".test.example.com" then store IP
# if request query ends with ".check.example.com" then respond with last lookup address for present, 127.0.0.1 for missing.

def generate_response( pkt, dest, proto ):
   ptype='A'
   if proto=='v6':
      ptype='AAAA'
   elif proto=='cnames':
      ptype='CNAME'
   resp = Ether( #src=pkt[Ether].dst, dst=pkt[Ether].src \
      )/IP(dst=pkt[IP].src, id=pkt[IP].id, src=pkt[IP].dst)\
      /UDP(dport=pkt[UDP].sport, sport=53)\
      /DNS( id=pkt[DNS].id,
            aa=1, #we are authoritative
            qr=1, #it's a response
            rd=pkt[DNS].rd, # copy recursion-desired
            qdcount=pkt[DNS].qdcount, # copy question-count
            qd=pkt[DNS].qd, # copy question itself
            ancount=1, #we provide a single answer
            an=DNSRR(rrname=pkt[DNS].qd.qname, type=ptype, ttl=1, rdata=dest ),
      )
   return resp

def DNS_Responder(conf,lists):
    print("dns")
    def getResponse(pkt):
        print("dns caught!")
        try:
          print("qname:", pkt[DNS].qd.qname, ", opcode:", pkt[DNS].opcode,", ancount:", pkt[DNS].ancount,", qtype:", pkt[DNS].qd.qtype)
        except AttributeError as e:
          return
        #pkt.show()
        global dest_idx
        if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[IP].src != "8.8.8.8"):
            print("entering checks")
            pkt.show()
            resp=""
            try:
               pkt_proto = None
               if pkt[DNS].qd.qtype == 1:
                  pkt_proto='v4'  
               elif pkt[DNS].qd.qtype == 28:
                  pkt_proto='v6'
                  resp = generate_response(pkt, b"0:0:0:0:0:0:0:1", pkt_proto)
               else: ### won't respond to non A or AAAA packet
                  return
               print("1")
               if pkt[DNS].qd.qname.endswith(testsub+parent_domain+b".") and pkt_proto == "v4":
                  print("packet is doing a :", pkt[DNS].qd.qname.split(b".")[0])
                  requestcache[pkt[DNS].qd.qname.split(b".")[0]]=pkt[IP].src
                  print("cache length:", len(requestcache))
                  resp = generate_response( pkt, b"127.0.0.1", pkt_proto )
               elif pkt[DNS].qd.qname.endswith(checksub+parent_domain+b".") and pkt_proto == "v4":
                  print("packet is checking for a hit on sub:", pkt[DNS].qd.qname.split(b".")[0])
                  ip=b"127.0.0.1"
                  try:
                    ip = requestcache[pkt[DNS].qd.qname.split(b".")[0]]
                    print(ip)
                  except:
                    pass
                  resp = generate_response( pkt, ip, pkt_proto )
                  print("response:")
                  resp.show()
               sendp(resp,verbose=0,iface="eth0")
            except Exception as e:
              print("exception", e)
    return getResponse

#print >>sys.stderr, "config loaded, starting operation"
filter = "udp port 53"
sniff(filter=filter,store=0,prn=DNS_Responder("",""))
