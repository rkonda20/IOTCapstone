# NetworkStaicScanner.py



import scapy.all as scapy
from mac_vendor_lookup import MacLookup
import time
import nmap3

def nmap_details(ip):
    nmap = nmap3.Nmap()
    results = nmap.nmap_version_detection(ip)
    return results


def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    return answered_list[0][1].hwsrc

def network_scan(iprange):
    request = scapy.ARP()

    request.pdst = iprange
    broadcast = scapy.Ether()

    broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    request_broadcast = broadcast / request
    clients = scapy.srp(request_broadcast, timeout=1)[0]
    for element in clients:
        print(element[1].psrc + "      " + element[1].hwsrc)
        print(MacLookup().lookup(element[1].hwsrc))
        print(nmap_details(element[1].psrc))



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    #print(get_mac('192.168.1.1'))
    network_scan('192.168.1.1/24')