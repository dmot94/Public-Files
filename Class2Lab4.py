
import socket
import time
import scapy.layers.l2
from scapy.all import *

"""This is the ARP scanner lab solution that I came up with after some googling.
This will take at over 2 minutes to complete. It will then print the results when it finishes.
It may appear to not be working. Through googling, I found ARP scanners often request for the interface to be specified
This was defaulting to my VirtualBox NIC so you may run into this same error. 
Disabling the VirtualBox NIC solves this and will have the generated ARP table better reflect the arp -a command in CMD. 
(You will need to do this if it appears as if fewer devices are on the generated arp table)
Finally there are commented out lines. Uncomment them to see live progress.

I did not do the last item on the lab that was concerned with coding flow."""

#Obtains network information, then outputs the first 3 octets as octets123: "000.000.000."
def identifyHost():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print("Local IP: "+local_ip)
    ip_octets = local_ip.split('.')
    octets123 = ip_octets[0]+"."+ip_octets[1]+"."+ip_octets[2]+"."
    return octets123

#Uses network information to send ARP requests through the entire network
def scanARP(network):
    networkHosts=[]
    for host in range(1, 255):     #Each iteration of the for loop, increases the host ip that is being send an arp request.
        hostaddress = network +str(host)
        arp = ARP(pdst=hostaddress)       #ARP protocol specified and IP set
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")         #Specify MAC address as broadcast
        packet= broadcast/arp                              #Packet is formed, 2nd level then 3rd level
        arpRequest = srp1(packet, timeout=1, verbose=0)    #Packet is sent

        # print("Current targeted host: "+hostaddress)     #Uncomment this line to watch each host have a packet sent

        if arpRequest:         #If there is a response, receive them and store in networkHosts
            networkHosts.append({'ip': arpRequest.psrc, 'mac': arpRequest.hwsrc})
            print("Host found: "+hostaddress)   #Uncomment this line for hosts that respond in real-time
            time.sleep(0.5)

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for networkHost in networkHosts:               #Prints arp scan results all at once
        print("{:16}    {}".format(networkHost['ip'], networkHost['mac']))


targetNetwork = identifyHost()
scanARP(targetNetwork)
