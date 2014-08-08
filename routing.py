from pox.core import core
import pox.openflow.libopenflow_01 as of
#from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
import networkx as nx
import matplotlib.pyplot as plt
from pox.lib.packet import *
import pox.lib.packet as pkt
from pox.lib.addresses import *
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
#import sys
#sys.path.append("/mininet/custom")
import sys
sys.path.append('/home/mininet/mininet/custom')
from Wide_Area_Network import *
#from LinksToGraph import *
#from NodesToDict import *
#from My_Network import *
#print dpid_NextHopIP_PortNum
#print switchMac
#Need to get the object of the Graph G.
#get the nodes and all their IP addresses.
#for i in nodes.iteritems():
#print i
HipMac = {}
'''
for key in nodes:
    if key == 'h1':
        HipMac[nodes[key][0]] = "00:00:00:00:00:01"
    if key == 'h2':
        HipMac[nodes[key][0]] = "00:00:00:00:00:02"
    if key == 'h3':
        HipMac[nodes[key][0]] = "00:00:00:00:00:03"
    if key == 'h4':
        HipMac[nodes[key][0]] = "00:00:00:00:00:04"
    if key == 'h5':
	HipMac[nodes[key][0]] = "00:00:00:00:00:05"
    if key == 'h6':
	HipMac[nodes[key][0]] = "00:00:00:00:00:06"
'''
#print connections
#print link1.getNextHopPort(('s1','s2'))

class MiniNetwork:
    #one topology of the mininet is one Graph object
    #switches = []#All the switches in this network
    #hosts = []#All the hosts in this network
    #srcSwitchdstIPportNumMac = {}#With the source switch and destination IP, return nextHop port number and dst MAC address  
    #NextHopIP_PortNum = {} #Next Hop Name and which port number to send to
    #HipMac = {} #Get the host IP address and MAC address
    def __init__(self,graph,links): #Try to get all the combination of switches and destination hosts. 
        self.switches = [] 
        self.hosts = []
        self.srcSwitchdstIPportNumMac = {}
        self.NextHopIP_PortNum = {}
        self.HipMac = {}
        self.graph = graph
        self.links = links
        temp = self.graph.nodes()
        temp.sort()
	for node in temp:
	    if 'h' in node:
		self.hosts.append(node)
	    elif 's' in node:
		self.switches.append(node)
        for key in temp:
            if key == 'h1':
                self.HipMac[key] = "00:00:00:00:00:01"
            if key == 'h2':
                self.HipMac[key] = "00:00:00:00:00:02"
            if key == 'h3':
                self.HipMac[key] = "00:00:00:00:00:03"
            if key == 'h4':
                self.HipMac[key] = "00:00:00:00:00:04"
	    if key == 'h5':
		self.HipMac[key] = "00:00:00:00:00:05"
	    if key == 'h6':
		self.HipMac[key] = "00:00:00:00:00:06"
    	for switch in self.switches:
            for host in self.hosts:
                ipSeries = nx.dijkstra_path(graph,switch,host)
                nextHop = ipSeries[1]
		#print self.links.getNextHopPort((switch,nextHop))
                self.srcSwitchdstIPportNumMac[(switch,host)] = (self.links.getNextHopPort((switch,nextHop)), self.HipMac[host]) 
                
    def GetPortNumAndMacAddr(self, sourceSwitch, dstIPaddr):
        return self.srcSwitchdstIPportNumMac[sourceSwitch,dstIPaddr]
        
    #def GetPortNumberAndMacAddr(self, sourceSwitch, dstIPaddr) #This method returns the next hop port number as well as the destination's MAC address
'''
class switches:
    def __init__(self,dpid):
	self.dpid = dpid
	self.arpTable = {}    
'''
arpTable = {}
for list in SwitchIntfsWithHost.values():
    for dstIPAddr in list:
	arpTable[dstIPAddr] = EthAddr("96:d7:9d:87:60:10")
#print arpTable

def find_route_using_dijkstra(src,dst):

    return nx.dijkstra_path(G,src,dst)

def getNextHopAddr(i,j): #take IP address of current router and destination address 
        
    Ipseries = nx.dijkstra_path(G,i,j)
    
    return Ipseries[1] #This is the next hop IP address, have to find a way to combine this IP address to a port, maybe use a Dictionary which gives {NextHop:PortNumber}
    
def getKey(value):   #from the IP address, get the hosts/switches name according to File.
    for name,ip in nodes.iteritems():
        if ip[0] == value:
            return name
            
def getValue(key):
    return nodes.get(key)
    
#nested dictionary to store DPID and destination IP address with next Port number. 
#dpid_NextHopIP_PortNum = {1:{'h1':1, 'h2':2,'s2':3, 's3':4}, 2:{'s1':1,'s3':2,'s4':3,'s5':4}, 3:{'s1':1,'s2':2,'s4':3,'s5':4},4:#{'s2':1,'s3':2,'s5':3,'s6':4}, 5:{'s2':1,'s3':2,'s4':3,'s6':4}, 6:{'s4':1,'s5':2,'h3':3,'h4':4}}
    

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

# This table maps (router,IP.dstip) pairs to the port on 'router' at
# which we last saw a packet *from* 'IP address'.
Mac_To_Port = {} #The destination address and the port number
'''
nodes = G.nodes()
nodes.sort()
count = 0
switches = []
for i in G.nodes():
    if 's' in i:
	switches.append(i)
for j in switches:
    count += 1
print count
'''
Dpid_To_Ip = {1:"s1", 2:"s2", 3:"s3", 4:"s4", 5:"s5", 6:"s6", 7:"s7", 8:"s8"} #Install the current switch ip address where the packet is now, and dpid shows which switch is connecting to the controller then get the ip address of that switch.


def send_Packet(buffer_id, raw_data, out_port, in_port): #get the packetIn message, send it to the correct port
# Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    # Send message to switch
    connection.send(msg)

'''           
def act_like_router(packet, packet_in):
    ip = packet.find('ipv4') #get the ip from the packet sent from the switch that the controller is connecting to.
    IP_to_port[ip.srcip]=packet_in.in_port #bind the source IP address and the port within that switch 
                                                    #get the destination IP address, then get the port number accordingly, then send the port number as one of the parameters
    if IP_to_port.get(ip.dstip)!=None:
        # Send packet out the associated port
        send_packet(packet_in.buffer_id, packet_in.data,IP_to_port[ip.srcip], packet_in.in_port)

def get_PortNumber(event): #extract the destination IP address, find out the port number for destination IP address
    
'''
'''
def RespondToARP(packet,match,event):
    #reply to ARP request
    #print event.port
    r = arp(opcode=arp.REPLY,            #Create the arp reply content
        hwsrc=EthAddr("00:00:00:00:00:02"),
        hwdst=match.dl_src,
        protosrc = IPAddr("192.168.10.2"),
        protodst = match.nw_src)
    e = ethernet(type = packet.ARP_TYPE, src = r.hwsrc, dst = r.hwdst)     
    e.set_payload(r)
    log.debug("%i %i answering ARP for %s" %
     ( event.dpid, event.port,
       str(r.protosrc)))
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT)) #tell the host the answer(MAC address) for the IP address it asked for
    msg.in_port = event.port
    event.connection.send(msg)
'''
'''
def RespondToPing(self, ping, match, event):
    p = ping
    # we know this is an ICMP Echo packet, so loop through
    # maybe this needs a try... except?
    while not isinstance(p, echo):
        p = p.next
    
    r = echo(id=p.id, seq=p.seq)
    r.set_payload(p.next)
    i = icmp(type=0, code=0)
    i.set_payload(r)
    ip = ipv4(protocol=ipv4.ICMP_PROTOCOL,
              srcip=IPAddr("192.168.10.1"),
              dstip=match.nw_src)
    ip.set_payload(i)
    e = ethernet(type=ping.IP_TYPE,
                 src=match.dl_dst,
                 dst=match.dl_src)
    e.set_payload(ip)
    log.debug("%i %i answering PING for %s" % (
              event.dpid, event.port,
              str(match.nw_src)))
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port =
                                          of.OFPP_IN_PORT))
    msg.in_port = event.port
    event.connection.send(msg)
'''
network1 = MiniNetwork(G,link1)
linkTopo = {}
for i in range(len(linkBwSwitches)):
    print linkBwSwitches[i]
    original = linkAndWeight[linkBwSwitches[i]]
    linkAndWeight[linkBwSwitches[i]] = max_link_weight
    G2 = nx.Graph()
    print linkAndWeight
    for key,value in linkAndWeight.iteritems():
	G2.add_weighted_edges_from([(key[0],key[1],int(value))])
    linkTopo[linkBwSwitches[i]] = MiniNetwork(G2,link1)
    linkAndWeight[linkBwSwitches[i]] = original
#network2 = MiniNetwork(G2,link1) #s1 and s2 break, pop(2)


#networkList = []
#networkList.append(network2)

#linkTopo = {}
#for i in range(len(linkAndWeightNoHosts)):
#    if (i == 0):
#    	linkTopo[linkAndWeightNoHosts[i][0]] = networkList[i]
print linkTopo
def _handle_ConnectionUp(event):
    currSwitch = Dpid_To_Ip[event.dpid]
    for host in network1.hosts:
        pair = network1.GetPortNumAndMacAddr(currSwitch,host)
        portNum = pair[0]
        MacAddr = pair[1]
        msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x800
        msg.match.nw_dst = IPAddr(getValue(host)[0])
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(MacAddr)))
        msg.actions.append(of.ofp_action_output(port = portNum))
        event.connection.send(msg)
       
def _handle_PortStatus(event):
    #print event.dpid, event.port
    #print event.added, event.deleted, event.modified
    #print event.dpid, event.port, type(event.ofp.desc.state),type(of.OFPPC_PORT_DOWN) 
    if event.ofp.desc.state == 1 and of.OFPPC_PORT_DOWN == 1: #a link goes down
	downSwitch = 's' + str(event.dpid)
	downPort = event.port
	brokenLink = DpidPortLink[(downSwitch, downPort)]
	#print linkTopo[brokenLink]
	if brokenLink not in linkTopo:
	    return 
	print "Warning: port failure happening on port" + str(event.port) + " on switch " + str(event.dpid) + " -- Updating flow rules."
	#print DpidPortLink[(downSwitch, downPort)]
 	#linkTopo[brokenLink]
        #if (event.dpid == 1 and event.port == 3):            
        #    print "Warning: port failure happening on port 3 on switch 1 -- Updating flow rules"
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        for connection in core.openflow.connections:
            connection.send(msg)
        for connection in core.openflow.connections:
            currSwitch = Dpid_To_Ip[connection.dpid]
	    print brokenLink, linkTopo[brokenLink]
            for host in linkTopo[brokenLink].hosts:
                pair = linkTopo[brokenLink].GetPortNumAndMacAddr(currSwitch,host)#get the destination IP address of the host, get its MAC address 
                portNum = pair[0]                                    #from the arpTable.
		print pair[0] 
                MacAddr = arpTable[getValue(host)[0]]
                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x800
                msg.match.nw_dst = IPAddr(getValue(host)[0])
                msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(MacAddr)))
                msg.actions.append(of.ofp_action_output(port = portNum))
                connection.send(msg)
	#if (event.dpid == 1 and event.port == 4):
    

    elif event.ofp.desc.state == 0 and of.OFPPC_PORT_DOWN == 1: #a link goes up
            #print event.dpid, event.port 
        print "Warning: port failure from port " + str(event.port) + " on switch " + str(event.dpid) + " is recovered! -- resume to normal flow rules"
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        for connection in core.openflow.connections:
            connection.send(msg)
        for connection in core.openflow.connections:
            currSwitch = Dpid_To_Ip[connection.dpid]
        for host in network1.hosts:
            pair = network1.GetPortNumAndMacAddr(currSwitch,host)
            portNum = pair[0]
            MacAddr = arpTable[getValue(host)[0]]
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x800
            msg.match.nw_dst = IPAddr(getValue(host)[0])
            msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(MacAddr)))
            msg.actions.append(of.ofp_action_output(port = portNum))
            connection.send(msg)

lost_packets = {}

def _send_paused_traffic(dpid,ipaddr,port):
    if (dpid,ipaddr) in lost_packets:
	bucket = lost_packets[(dpid,ipaddr)]
	del lost_packets[(dpid,ipaddr)]
	for buffer_id,in_port in bucket:
	    po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
	    po.actions.append(of.ofp_action_dl_addr.set_dst(arpTable[ipaddr]))
	    po.actions.append(of.ofp_action_output(port = port))
	    core.openflow.sendToDPID(dpid,po)
    
def _handle_PacketIn (event): # after receive the PacketIn message, handle it. get the information about the packet, get the
    #Learn the desintation IP address and fill up routing table, according to my store of edge list, get the port number
    #I need to handle the ARP request from each subnet first.
    packet = event.parsed

    #print packet.src
    if packet.type ==  ethernet.IPV6_TYPE:
	return
    srcSwitch = "s" + str(event.dpid)
    print srcSwitch
    print packet.type,event.port
    #match = of.ofp_match.from_packet(packet)
    if isinstance(packet.next, arp):  #This solves the problem of turning every ARP into IP packets
        a = packet.next
        #destinationIP = a.protodst
	#dstIPtest = getKey(destinationIP)
	#test = network1.GetPortNumAndMacAddr(srcSwitch, dstIPtest)
	if a.prototype == arp.PROTO_TYPE_IP:
	    if a.hwtype == arp.HW_TYPE_ETHERNET:
		if a.protosrc != 0:
		    arpTable[str(a.protosrc)] = packet.src
		    print arpTable
		    _send_paused_traffic(event.dpid,str(a.protosrc),event.port)
        	    if a.opcode == a.REQUEST:
			if str(a.protodst) in arpTable:
			    
            		    r = pkt.arp()
            		    r.hwtype = a.hwtype
            		    r.prototype = a.prototype
            		    r.hwlen = a.hwlen
            		    r.protolen = a.protolen
            		    r.opcode = a.REPLY
            		    r.hwdst = a.hwsrc
            #r.hwsrc = switchMac[a.protodst]
            		    r.hwsrc = arpTable[str(a.protodst)]
            		    r.protodst = a.protosrc
            #print a.protodst.toRaw
            #print (r.protodst.toStr == "192.168.70.2")
            #if(r.protodst == IPAddr("192.168.70.2")):
            #if(r.protodst == IPAddr("192.168.10.1")):
            #r.hwsrc = EthAddr("52:fa:e1:4c:d1:6c")
            		    r.protosrc = a.protodst #a.protodst is the destination IP addresses
            		    e = pkt.ethernet(type=packet.type, src=r.hwsrc, dst=a.hwsrc)
            		    e.payload = r
            		    msg = of.ofp_packet_out()
            		    msg.data = e.pack()
            		    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            		    msg.in_port = event.port
            		    event.connection.send(msg)
			else:
			    msg = of.ofp_packet_out(in_port = event.port, action = of.ofp_action_output(port = of.OFPP_IN_PORT))
			    event.connection.send(msg)
	#destinationIP = a.protodst
	#dstIPtest = getKey(destinationIP)
	#print dstIPtest
	#test = network1.GetPortNumAndMacAddr(srcSwitch,dstIPtest)
	#msg = of.ofp_packet_out(action = of.ofp_action_output(port = of.OFPP_FLOOD))
	#event.connection.send(msg)
    elif isinstance(packet.next, ipv4): #begin to receive IP packets, from each switch, controller needs to make the right move to send the packet into the right port. 
   	arpTable[str(packet.next.srcip)] = packet.src
        dstIp = packet.next.dstip #get the packet's destination IP address
        desHost = getKey(dstIp)
	#print srcSwitch
	pair = network1.GetPortNumAndMacAddr(srcSwitch,desHost)
	#print pair
	#_send_paused_traffic(event.dpid, str(packet.next.srcip), event.port)
	if str(dstIp) in arpTable:
	    #desHost = getKey(dstIp)
            #pair = network1.GetPortNumAndMacAddr(srcSwitch,desHost)
	    NextPort = pair[0]
	    DstMAC = arpTable[str(dstIp)]
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x800
            msg.match.nw_dst = dstIp #destination IP address
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_dl_addr.set_dst(DstMAC))
            msg.actions.append(of.ofp_action_output(port = NextPort))
            event.connection.send(msg)
	else:
	    if (event.dpid,str(dstIp)) not in lost_packets:
		lost_packets[(event.dpid,str(dstIp))] = []
	    bucket = lost_packets[(event.dpid,str(dstIp))]
	    entry = (event.ofp.buffer_id,event.port)
	    bucket.append(entry)
	    while len(bucket) > 5: del bucket[0]


	    if srcSwitch in SwitchNameWithConnectingHosts:
		if str(dstIp) in SwitchNameWithConnectingHosts[srcSwitch]:
	    #ARPnextPort = pair[0]
	    #print ARPnextPort
	    	    r = arp()
	    	    r.hwtype = r.HW_TYPE_ETHERNET
	    	    r.prototype = r.PROTO_TYPE_IP
	    	    r.hwlen = 6
	    	    r.protolen = r.protolen
	    	    r.opcode = r.REQUEST
   	    	    r.hwdst = ETHER_BROADCAST
	    	    r.protodst = dstIp
	    	    r.hwsrc = packet.src
	    	    r.protosrc = packet.next.srcip
	    	    e = ethernet(type = ethernet.ARP_TYPE, src = packet.src, dst = ETHER_BROADCAST)
	    	    e.set_payload(r)
	    	    msg = of.ofp_packet_out()
	    	    msg.data = e.pack()
	    	    msg.actions.append(of.ofp_action_output(port = pair[0]))
	    	    msg.in_port = event.port
	     	    event.connection.send(msg)
		else:
		    NextPortNum = pair[0]
		    msg = of.ofp_flow_mod()
		    msg.match.dl_type = 0x800
		    msg.match.nw_dst = dstIp
		    msg.data = event.ofp
		    msg.actions.append(of.ofp_action_output(port = NextPortNum))
	   	    event.connection.send(msg)
            else:
		NextPortNum2 = pair[0]
		msg = of.ofp_flow_mod()
		msg.match.dl_type = 0x800
	  	msg.match.nw_dst = dstIp
		msg.data = event.ofp
		msg.actions.append(of.ofp_action_output(port = NextPortNum2))
		event.connection.send(msg)
'''
        if (i.dstip == "192.168.10.2"):
            msg = of.ofp_flow_mod()     #add a flow entry
            msg.match.in_port = 4
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port = 1))   #do the action
            event.connection.send(msg)
        if (i.dstip == "192.168.10.1"):
            msg = of.ofp_flow_mod()     #add a flow entry
            msg.match.in_port = 1
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port = 4))   #do the action
            event.connection.send(msg)
    
    
            msg2 = of.ofp_flow_mod()
            msg2.data = event.ofp
            msg2.match.nw_dst = IPAddr("192.168.10.1")
            print msg2
            msg2.actions.append(of.ofp_action_output(port = 4))
            event.connection.send(msg)

            #Reply to pings
            #Make the ping reply, create ICMP data,payload
            icmp = pkt.icmp()
            icmp.type = pkt.TYPE_ECHO_REPLY
            icmp.payload = packet.find("icmp").payload
            #make the IP packet
            ipp = pkt.ipv4()
            ipp.protocol = ipp.ICMP_PROTOCOL
            ipp.srcip = packet.find("ipv4").dstip
            ipp.dstip = packet.find("ipv4").srcip
            #Ethernet around that
            e = pkt.ethernet()
            e.src = packet.dst
            e.dst = packet.src
            e.type = e.IP_TYPE
            #Put them together
            ipp.payload = icmp
            e.payload = ipp
            msg2 = of.ofp_packet_out()
            msg2.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
            msg2.data = e.pack()
            msg2.in_port = event.port
            event.connection.send(msg2)
           
            
    packet_in = event.ofp
    Mac_To_Port[packet.src] = packet_in.in_port
    ip = packet.find('icmp')
    print ip
    #print ip.dstip
    if(ip.dstip == "192.168.10.2"):
        msg = of.ofp_flow_mod()     #add a flow entry
        #msg.match.nw_dst = IPAddr("192.168.10.2")
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = 1))   #do the action
        event.connection.send(msg)
        
    
    print Mac_To_Port
    print packet.type
    print ethernet.IP_TYPE
    
    
    ip = packet.find('ipv4')
    if ip != None:
        if ip.dstip == "192.168.10.2":
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.actions.append(of.ofp_action_output(port = 1))
            msg.data = event.ofp
            event.connection.send(msg)
    
    
    match = of.ofp_match.from_packet(packet)
    if (match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST and match.nw_dst == IPAddr("192.168.10.2")):
        RespondToARP(packet,match,event)
    if (match.dl_type == packet.IP_TYPE):
        if (match.nw_dst == IPAddr("192.168.10.2")):
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port = 1))
            print msg
            event.connection.send(msg)
          
    #when the packet goes out of their subnet. from routers to routers.
    #get the packet.type
    #if packet.type == packet.ARP_TYPE
    
    table[(event.connection,packet.src)] = event.port
    dst_port = table.get((event.connection,packet.dst))
    
    
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return
    if packet.type == packet.IP_TYPE:
        ip = packet.payload
        dst_ip = ip.dstip
        print dst_ip
    
    
        #get the reference of one switch 
        if(dpid == 1):
        #ip_address = "192.168.10.0"
            if (ip.dstip == "192.168.60.1"):
                action = of.ofp_action_output(port = 3)
                msg.actions.append(action)
                # Send message to switch
                connection.send(msg)
        if(dpid == 2):
            if (ip.dstip == "192.168.60.1"):
                action = of.ofp_action_output(port = 3)
                msg.actions.append(action)
                # Send message to switch
                connection.send(msg)
        if(dpid == 5):
            if (ip.dstip == "192.168.60.1"):
                action = of.ofp_action_output(port = 4)
                msg.actions.append(action)
                # Send message to switch
                connection.send(msg)
        if(dpid == 6):
            if (ip.dstip == "192.168.60.1"):
                action = of.ofp_action_output(port = 3)
                msg.actions.append(action)
                # Send message to switch
                connection.send(msg)
    
     
    IP_to_port[(event.connection,packet.src)] = event.port #a table of destination iddress and port.
    dst_port = IP_to_port.get((event.connection,packet.dst)) 
    packet = event.parsed
    if not packet.parsed:
        log.warning("Ignoring incomplete packet")
        return
    packet_in = event.ofp #The actual ofp_packet_in message.
    if packet.type == packet.IP_TYPE:
        ip = packet.payload
        print "Source IP:", ip.srcip
        #act_like_router(packet,packet_in)     
'''                 
def launch ():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    #core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PortStatus", _handle_PortStatus)

if __name__ == '__main__':
    setLogLevel( 'info' )
    net = emptyNet()
