#!/usr/bin/python3

from scapy.all import *
import concurrent.futures


# Main function that handles the received command line arguments and verifies that they're allowed.
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


# Scans for arp packets on the specified interface and sends each packet to filter_packets
def passive_scan(interface):
    arp_dict = {}
    sniff(prn=filter_packets(arp_dict), iface=interface, filter="arp")


# Returns a reference to arp_packets_handler.
def filter_packets(arp_dict):
    # Stores the details of an ARP Packet if it's opcode is 2. arp_dict contains all found IP MAC Address pairings. If
    # a packet comes in with the same IP as a stored IP but a different MAC Address then this new MAC Address is
    # appended as a value to the IP key.
    def arp_packet_handler(pkt):
        if ARP in pkt:
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

    return arp_packet_handler


# Gets the IP Address of the interface, extracts the base IP from the interface IP i.e. XXX.YYY.ZZZ. and sends an Echo
# Request to each possible IP in the /24 Network from 1 to 254 with the base IP i.e XXX.YYY.ZZZ.1 -> XXX.YYY.ZZZ.254.
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


# Returns a reference to send_icmp_request
def send(interface_ip, base_ip, replies_list):
    # Sends an Echo Request to the Networks base IP concatenated with a particular IP for the final octet.
    # The interface_ip is set in the Echo Request as the source. If an Echo Reply is not received in 1 second then the
    # request times out.
    def send_icmp_request(ip):
        destination = base_ip + str(ip)
        reply = sr1(IP(src=interface_ip, dst=destination, ttl=64) / ICMP(), timeout=1, verbose=0)
        if reply is not None:
            replies_list.append(reply.src)

    return send_icmp_request


# Returns True if the provided interface is in the if list. False otherwise.
def is_valid_interface(interface):
    interfaces = get_if_list()
    return interface in interfaces


# Prints out the commands that are allowed to be used in the application
def help():
    print("-i or --iface for network interface name\n-p or --passive for passive mode\n-a or --active for active mode")
    sys.exit()


if __name__ == "__main__":
    main()
