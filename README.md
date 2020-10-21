<b>Assignment Summary</b>

The net_recon.py script/tool allows a user to passively or actively detect hosts on their network. This
tool takes in two arguments; A network interface name (e.g. “enp0s3”) and an indicator for active or
passive mode. The network interface should be specified using “-i” or “--iface”.

A user who launches the tool with the “-p” or “—passive” argument will launch the tool in passive
mode, where the script will monitor ARP traffic on the given interface and use this traffic to detect IP
address and MAC address pairings. IP and MAC addresses collected by the script are printed out to
the terminal while the script is running. The passive scan will continue until the user stops the script
using ctrl+c.

A user who launches the tool with the “-a” or “—active” argument will launch the tool in active
mode. In active mode the tool will perform a ping sweep. The tool should ping every address in the
network and detect if a reply was received to determine if that address is active in the network.

<hr> 
<b>Part 1 – Set-up (20%) </b>

Create a script called “net_recon.py”.

Add a main function which contains code to read the arguments passed in by the user from the
command line when the script was launched.

Add a function help(), which will print out the usage of the tool. If the user launches the script
without the necessary arguments, this function should be called and should print out the arguments
which a user can include when running the script.

<hr>

<b>Part 2 – Passive Recon (40%)</b>

Add a function passive_scan() which is called if the user includes the “-p” or “—passive” augments
when launching the tool.

This function should use the Scapy sniff() function to listen for traffic at the interface provided by the
user. Include any function(s) necessary to handle traffic picked up by the sniff() function.

ARP traffic with an op code of 2 or “is-at” should be parsed and the source IP address and source
MAC address stored. If an IP address has already been stored but a different MAC address is seen
then the script should also store this additional MAC address.

The user should see a list of hosts appear in the terminal while the script is running.

<hr>

<b>Part 3 – Active Recon (40%)</b>

Add a function active_recon() which is called if the user includes the “-a” or “—active” arguments
when launching the tool.

This function should fetch the IP address for the given network interface. It should then send an
ICMP request to every host in the same network (you may assume it is a /24 network). The tool
should detect if an ICMP reply was returned. When the script has finished sending ICMP requests it
should output a list of addresses for which a reply was received.

<hr>

<b>Testing your Scripts</b>

A script “arp_traffic_gen.py” is available on Canvas with the assignment brief. This script will
generate ARP traffic to test the passive reconnaissance functionality of your script.
To test the active reconnaissance functionality, you can use Wireshark to observe ICMP requests
being sent on the network. If you have not modified any of the Virtual Machines networking details
then you should receive some responses. You could also modify the script to ping hosts in your
home’s LAN.
