
import socket
import time
import scapy.layers.l2
from scapy.all import *

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
    for host in range(255):
        hostaddress = network +str(host)
        arp = ARP(pdst=hostaddress)  #ARP protocol specified and destination set
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")     #Specify packet to broadcast
        packet= broadcast/arp                          #Packet is formed
        arpRequest = srp1(packet, timeout=1, verbose=0)

        if arpRequest:         #If there is a response, receive them and store in list
            networkHosts.append({'ip': arpRequest.psrc, 'mac': arpRequest.hwsrc})
            time.sleep(0.5)

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for networkHost in networkHosts:
        print("{:16}    {}".format(networkHost['ip'], networkHost['mac']))


targetNetwork = identifyHost()
scanARP(targetNetwork)
