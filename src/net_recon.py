#!/usr/bin/python3
import getopt
import sys


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
                elif opt in ('-p', "--passive"):
                    passive = True
                elif opt in ('-a', "--active"):
                    active = True

            if interface:
                if passive and active:
                    print("Please specify one mode")
                elif passive:
                    passive_scan(interface)
                elif active:
                    active_scan(interface)
                else:
                    print("Mode not specified")
            else:
                print("Interface not specified")
        except getopt.GetoptError as e:
            print(e)


def passive_scan(interface):
    print("Passive Mode on interface " + interface)
    # TODO Scapy sniff -> Passive


def active_scan(interface):
    print("Active Mode on interface " + interface)
    # TODO Scapy sniff -> Active


def help():
    print("-i or --iface for network interface name\n-p or --passive for passive mode\n-a or --active for active mode")
    sys.exit()


if __name__ == "__main__":
    main()
