#!/usr/bin/python3

from scapy.all import *

arpDict = {}


def main():
    interface = ""
    passive = False
    active = False
    number_of_arguments = len(sys.argv)

    if number_of_arguments - 1 == 0:
        help()
    else:
        try:
            opts, args = getopt.getopt(sys.argv[1:], "hi:pa", ["help", "iface=", "passive", "active"])
            for opt, arg in opts:
                if opt in ('-h', "--help"):
                    help()
                elif opt in ('-i', "--iface"):
                    interface = arg
                    if not valid_interface(interface):
                        print(interface + " is not a known interface")
                        sys.exit()
                elif opt in ('-p', "--passive"):
                    passive = True
                elif opt in ('-a', "--active"):
                    active = True

            if interface:
                if passive and active:
                    print("Please specify only one mode")
                elif passive:
                    passive_scan(interface)
                elif active:
                    active_recon(interface)
                else:
                    print("Mode not specified")
            else:
                print("Interface not specified")
        except getopt.GetoptError as e:
            print(e)


def passive_scan(interface):
    print("Passive Mode on interface " + interface)
    sniff(prn=print_arp, iface=interface, filter="arp")


def active_recon(interface):
    online_ips = []
    interface_ip = get_if_addr(interface)
    ip_base = interface_ip[0: (interface_ip.rfind('.'))]
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_base + ".0/24"), timeout=2, verbose=0)
    for answer in ans:
        ip_address = answer[1].psrc
        reply = sr1(IP(src=interface_ip, dst=ip_address, ttl=64) / ICMP(), timeout=2, verbose=0)
        if not (reply is None):
            online_ips.append(reply.src)

    if not online_ips:
        print("No replies received")
    else:
        print("Replies received from : " + str(online_ips)[1:-1])


def valid_interface(interface):
    interfaces = get_if_list()
    return interface in interfaces


def print_arp(pkt):
    arp_packet = pkt[ARP]
    if arp_packet.op == 2:
        ip = arp_packet.psrc
        mac = arp_packet.hwsrc
        if ip in arpDict:
            list_of_macs = arpDict[ip]
            if mac.lower() not in list_of_macs:
                arpDict[ip].append(mac.lower())
                #  TODO: What does this mean ->
                #   If an IP address has already been stored but a different MAC address is seen then the script should
                #   also store this additional MAC address.
        else:
            arpDict[ip] = [mac]

        return f"Source IP: {ip},\t Source MAC: {mac}"


def help():
    print("-i or --iface for network interface name\n-p or --passive for passive mode\n-a or --active for active mode")
    sys.exit()


if __name__ == "__main__":
    main()
