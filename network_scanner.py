#! /usr/bin/env python

import scapy.all as scapy
import optparse

def get_args():
    parser=optparse.OptionParser()
    parser.add_option("--target", "-t", dest="ip", help="Enter Targets IP which is to be scanned")
    (options, arguments)=parser.parse_args()
    if not options.ip:
        print("[-] Please Enter IP, use --help for info")
    return options

def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_pack=broadcast/arp_request
    answered_list=scapy.srp(arp_pack, timeout=1, verbose=False)[0]

    client_list=[]
    for elements in answered_list:
        client_dict={"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(list):
    print("IP\t\t\tMAC ADDRESS\n--------------------------------------------")
    for clients in list:
        print(clients["ip"]+"\t\t"+clients["mac"])

ui=get_args()
scan_result=scan(ui.ip)
print_result(scan_result)