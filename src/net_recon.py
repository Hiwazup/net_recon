#!/usr/bin/python3

from scapy.all import *
import concurrent.futures

conf.verb = 0


# Main function that ensures enough command line arguments have been provided.
def main():
    number_of_arguments = len(sys.argv) - 1
    if number_of_arguments == 3:
        validate_and_run_operation(sys.argv[1:])
    else:
        help("Incorrect number of arguments provided")


# Validates the provided command line arguments and performs the desired operation.
def validate_and_run_operation(arguments):
    if ("-p" in arguments and "--passive" in arguments) or ("-a" in arguments and "--active" in arguments) or \
            ("-i" in arguments and "--iface" in arguments):
        help("Duplicate arguments provided")

    passive = ("-p" in arguments or "--passive" in arguments)
    active = ("-a" in arguments or "--active" in arguments)
    if passive and active:
        help("Please specify only one mode")

    interface = get_interface(arguments)

    if passive:
        passive_scan(interface)
    elif active:
        active_recon(interface)
    else:
        help("Invalid arguments specified")


# Gets and verifies the interface provided
def get_interface(arguments):
    index = 0
    missing_interface_message = "Missing interface"

    if "-i" in arguments:
        index = arguments.index("-i")
    elif "--iface" in arguments:
        index = arguments.index("--iface")
    else:
        help("Missing interface option")

    if index >= (len(arguments) - 1):
        help(missing_interface_message)

    interface = arguments[index + 1]
    if "-" in interface:
        help(missing_interface_message)
    elif not is_valid_interface(interface):
        print(interface + " is not a known interface")
        exit()

    return interface


# Scans for arp packets on the specified interface and sends each packet to filter_packets.
def passive_scan(interface):
    arp_dict = {}
    setup_passive_scan_reminder_thread()
    sniff(prn=filter_packets(arp_dict), iface=interface, filter="arp")


# Sets up the reminder thread.
def setup_passive_scan_reminder_thread():
    reminder_thread = threading.Thread(target=print_passive_scan_reminder, name="Passive Scan Reminder Thread")
    reminder_thread.daemon = True
    reminder_thread.start()


# Prints a message every minute reminding the user how to terminate the scan.
def print_passive_scan_reminder():
    while True:
        print("**You can use Ctrl-C at any time to terminate the passive scan**")
        time.sleep(60)


# Returns a reference to arp_packet_handler.
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
                    mac_lowercase = mac.lower()
                    if mac_lowercase not in list_of_macs:
                        arp_dict[ip].append(mac_lowercase)
                else:
                    arp_dict[ip] = [mac]

                print(ip + "\t" + ", ".join(arp_dict[ip]))

    return arp_packet_handler


# Gets the IP Address of the interface, extracts the base IP from the interface IP i.e. XXX.YYY.ZZZ. and sends an Echo
# Request to each possible IP in the /24 Network from 1 to 254 with the base IP i.e XXX.YYY.ZZZ.1 -> XXX.YYY.ZZZ.254.
def active_recon(interface):
    print("Executing active recon. Please wait...")
    interface_ip = get_if_addr(interface)
    base_ip = interface_ip[0: (interface_ip.rfind('.') + 1)]
    replies_list = []

    # Calls the send function over 25 threads. The range option will provide the final octet value for the ping request.
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        executor.map(send(interface_ip, base_ip, replies_list), range(1, 255))

    if not replies_list:
        print("No replies received")
    else:
        print("Replies received from : ", ", ".join(replies_list))


# Returns a reference to send_icmp_request
def send(interface_ip, base_ip, replies_list):
    # Sends an Echo Request to the Networks base IP concatenated with a particular IP for the final octet.
    # The interface_ip is set in the Echo Request as the source. If an Echo Reply is not received in 4 seconds then the
    # request times out.
    def send_icmp_request(ip):
        destination = base_ip + str(ip)
        reply = sr1(IP(src=interface_ip, dst=destination, ttl=64) / ICMP(), timeout=4)
        if reply is not None:
            replies_list.append(reply.src)

    return send_icmp_request


# Returns True if the provided interface is in the if list. False otherwise.
def is_valid_interface(interface):
    return interface in get_if_list()


# Prints out the commands that are allowed to be used in the application
def help(error_message):
    print(error_message + "\n")
    print("Usage")
    print("\tnet_recon --iface <interface>")
    print("\t\t--active")
    print("\t\t--passive")
    print("Arguments")
    print("\t-i or --iface for network interface name")
    print("\t-p or --passive for passive mode")
    print("\t-a or --active for active mode")
    exit()


if __name__ == "__main__":
    main()
