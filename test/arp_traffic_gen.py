#!/usr/bin/python3

from scapy.all import *
from time import sleep

#
# This script generates ARP traffic for the purpose of testing the functionality of assingment 1
#

reqHostIPs = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"]
reqHostMacs = ["08:09:10:aa:aa:aa", "08:09:10:bb:bb:bb", "08:09:10:cc:cc:cc", "08:09:10:dd:dd:dd", "08:09:10:ee:ee:ee", "08:09:10:ff:ff:ff"]

resHostIPs = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"]
resHostMacs = ["10:11:12:ab:ab:ab", "10:11:12:bc:bc:bc", "10:11:12:cd:cd:cd", "10:11:12:de:de:de", "10:11:12:ef:ef:ef", "10:11:12:f0:f0:f0"]

for i in range(0, len(reqHostIPs)):
  sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=reqHostMacs[i])/ARP(op=1, psrc=reqHostIPs[i], pdst=resHostIPs[i], hwsrc=reqHostMacs[i]), iface="enp0s3")
  sleep(1)
  sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=reqHostMacs[i])/ARP(op=2, psrc=resHostIPs[i], pdst=reqHostIPs[i], hwsrc=resHostMacs[i], hwdst=reqHostMacs[i]), iface="enp0s3")

sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=reqHostMacs[0])/ARP(op=2, psrc=resHostIPs[0], pdst=reqHostIPs[0], hwsrc="de:ad:be:ef:de:ad", hwdst=reqHostMacs[0]), iface="enp0s3")