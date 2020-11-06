#!/usr/bin/python3

from scapy.all import *
import concurrent.futures


def main():
    interface = ""
    passive = False
    active = False
    number_of_arguments = len(sys.argv)

    if number_of_arguments - 1 == 0 or number_of_arguments > 4:
        help()
    else:
        for argument in sys.argv[1:]:
            if argument == "-i" or argument == "--iface":
                pass
            elif argument == "-p" or argument == "--passive":
                passive = True
            elif argument == "-a" or argument == "--active":
                active = True
            else:
                interface = argument
                if not is_valid_interface(interface):
                    print(argument + " is not a known interface")
                    sys.exit()

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


def passive_scan(interface):
    arp_dict = {}
    sniff(prn=filter_packets(arp_dict), iface=interface, filter="arp")


def active_recon(interface):
    interface_ip = get_if_addr(interface)
    base_ip = interface_ip[0: (interface_ip.rfind('.') + 1)]
    replies_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=254) as executor:
        executor.map(send(interface_ip, base_ip, replies_list), range(1, 255))

    if not replies_list:
        print("No replies received")
    else:
        print("Replies received from : " + str(replies_list)[1:-1])


def send(interface_ip, base_ip, replies_list):
    def send_icmp_request(ip):
        destination = base_ip + str(ip)
        reply = sr1(IP(src=interface_ip, dst=destination, ttl=64) / ICMP(), timeout=1, verbose=0)
        if reply is not None:
            replies_list.append(reply.src)

    return send_icmp_request


def is_valid_interface(interface):
    interfaces = get_if_list()
    return interface in interfaces


def filter_packets(arp_dict):
    def arp_packets_handler(pkt):
        arp_packet = pkt[ARP]
        if arp_packet.op == 2:
            ip = arp_packet.psrc
            mac = arp_packet.hwsrc
            if ip in arp_dict:
                list_of_macs = arp_dict[ip]
                if mac.lower() not in list_of_macs:
                    arp_dict[ip].append(mac.lower())
            else:
                arp_dict[ip] = [mac]

            return f"Source IP: {ip}\t Source MAC: {mac}"

    return arp_packets_handler


def help():
    print("-i or --iface for network interface name\n-p or --passive for passive mode\n-a or --active for active mode")
    sys.exit()


if __name__ == "__main__":
    main()
