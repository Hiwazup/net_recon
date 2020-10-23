#!/usr/bin/python3

from scapy.all import *
import concurrent.futures

arpDict = {}
icmp_replies = []
INTERFACE_IP = ""
BASE_IP = ""


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
    sniff(prn=handle_arp_packet, iface=interface, filter="arp")


def active_recon(interface):
    global INTERFACE_IP
    INTERFACE_IP = get_if_addr(interface)
    global BASE_IP
    BASE_IP = INTERFACE_IP[0: (INTERFACE_IP.rfind('.') + 1)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=255) as executor:
        executor.map(send_icmp_request, range(1, 255))

    if not icmp_replies:
        print("No replies received")
    else:
        print("Replies received from : " + str(icmp_replies)[1:-1])


def send_icmp_request(ip):
    reply = sr1(IP(src=INTERFACE_IP, dst=BASE_IP + str(ip), ttl=64) / ICMP(), timeout=1, verbose=0)
    if reply is not None:
        icmp_replies.append(reply.src)


def valid_interface(interface):
    interfaces = get_if_list()
    return interface in interfaces


def handle_arp_packet(pkt):
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

        return f"Source IP: {ip}\t Source MAC: {mac}"


def help():
    print("-i or --iface for network interface name\n-p or --passive for passive mode\n-a or --active for active mode")
    sys.exit()


if __name__ == "__main__":
    main()
