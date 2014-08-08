"""
Create an empty Mininet object (without a topology object, from scratch) and add nodes to the network manually
"""
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Intf
#from pox.core import core
import networkx as nx
import matplotlib.pyplot as plt
import time
import threading
from operator import itemgetter
#Store the file into a dictionary with lists.
nodes = {}
global switchMac
switchMac = {}
max_link_weight = '10000'
print max_link_weight
with open("WAN.txt") as f:  
    for line in f: 
        if (line.split(' ')[0] not in nodes): # for column 0 and 2, store them into nodes
            nodes[line.split(' ')[0]] = [(line.split(' ')[2].strip('\n'))]
            if (line.split(' ')[1] not in nodes): # for column 1 and 3, store them into nodes
                nodes[line.split(' ')[1]] = [(line.split(' ')[3].strip('\n'))]
            else:
                nodes[line.split(' ')[1]].append(line.split(' ')[3].strip('\n'))
        else:
            nodes[line.split(' ')[0]].append(line.split(' ')[2].strip('\n'))
            if (line.split(' ')[1] not in nodes): # for column 1 and 3, store them into nodes
                nodes[line.split(' ')[1]] = [(line.split(' ')[3].strip('\n'))]
            else:
                nodes[line.split(' ')[1]].append(line.split(' ')[3].strip('\n'))
'''
with open("WAN.txt") as f:             
    for line in f:
        if (line.split(' ')[1] not in nodes): # for column 1 and 3, store them into nodes
            nodes[line.split(' ')[1]] = [(line.split(' ')[3].strip('\n'))]
        else:
            nodes[line.split(' ')[1]].append(line.split(' ')[3].strip('\n'))
'''
#print nodes.keys()
#Store the connections between nodes into Graph.     
with open("WAN.txt") as f:
    connections = [tuple((line.split()[0], line.split()[1], line.split()[4].strip('\n'))) for line in f.readlines()]
#connections = [tuple((line.split(' ')[0], line.split(' ')[1], line.split(' ')[4].strip('\n'))) for line in f.readlines()]
#print connections

#get a dictionary where key is host, value is its IP address
HostIP = {}
SwitchIntfsWithHost = {}
with open("WAN.txt") as f:
    information = [tuple((line.split()[0], line.split()[1], line.split()[2], line.split()[3])) for line in f.readlines()]
SwitchNameWithConnectingHosts = {}
for i in information:
    for j in i:
	if 'h' in j:
	    index = i.index(j)
	    if (index == 0):
		index2 = index + 1
		if i[index2] in SwitchIntfsWithHost:
		    SwitchIntfsWithHost[i[index2]].append(i[index2 + 2])
		    SwitchNameWithConnectingHosts[i[index2]].append(i[index2 + 1])
		else:
		    SwitchIntfsWithHost[i[index2]] = [i[index2 + 2]]
		    SwitchNameWithConnectingHosts[i[index2]] = [i[index2 + 1]]
	    if (index == 1):
		index2 = index - 1
		if i[index2] in SwitchIntfsWithHost:
		    SwitchIntfsWithHost[i[index2]].append(i[index2 + 2])
		    SwitchNameWithConnectingHosts[i[index2]].append(i[index2 + 3])
		else:
		    SwitchIntfsWithHost[i[index2]] = [i[index2 + 2]]
		    SwitchNameWithConnectingHosts[i[index2]] = [i[index2 + 3]]
	    HostIP[j] = i[index+2] #next next index
	
#print SwitchNameWithConnectingHosts

G = nx.Graph()

linkAndWeight = {}
for each in connections:
    linkAndWeight[(each[0],each[1])] = each[2]


for key,value in linkAndWeight.iteritems():   #add network nodes and links with weight links
    #print j[0],j[1],j[2]
    G.add_weighted_edges_from([(key[0],key[1],int(value))])


with open("WAN.txt") as f:
    links = [tuple((line.split(' ')[0], line.split(' ')[1])) for line in f.readlines()]


class PortReference:#two attributes: two dictionaries
    def __init__(self,links): #when an instance is created, one link list is passed to the instance
	self.node_ports = {} #how many ports a switch already has
	self.node_port_numbers = {}
        self.links = links
        for i in self.links:
		self.node_ports[i[0]] = self.node_ports.get(i[0],0) + 1
		self.node_ports[i[1]] = self.node_ports.get(i[1],0) + 1
                self.node_port_numbers[i] = self.node_ports[i[0]]
                temp = (i[1],i[0])
 	 	self.node_port_numbers[temp] = self.node_ports[temp[0]]
    def getNextHopPort(self, pair):#return next port number by getting a tuple of switches
	return self.node_port_numbers.get(pair)



#-------------------------------break one link in turn-------------------------------------------#
#link s1 and s2 break
global link1
link1 = PortReference(links)



DpidPortLink = {} #This is used for store the pair between information from port status event and getting the link.
temp = link1.node_port_numbers
for key,value in temp.iteritems():
    DpidPortLink[(key[0],value)] = key
#print DpidPortLink

linkBwSwitches = []
for key,value in linkAndWeight.iteritems():
    if value != '0':
	linkBwSwitches.append(key)

#first link failure
#original =  linkAndWeight[list[0]]
#linkAndWeight[list[0]] = max_link_weight

def emptyNet():

    "Create an empty network and add nodes to it."
    global net    
    global commandLine
    net = Mininet(controller = RemoteController,autoSetMacs = False )
    #print net.controller
    #net.autoPinCpus = True
    
    info('*** Adding controller\n' )
    net.addController( 'c0', controller = RemoteController)
    
    info( '*** Adding hosts\n' )
    node = G.nodes()
    node.sort()
    for key in node:                   
        if 'h' in key:    #Add the hosts
            net.addHost(key)
            #h.setIP(h,nodes[key],24)
        else: #Add the switches
            net.addSwitch(key)
            #neighbors = G.neighbors(key)
            #neighbors.sort()
            #dpid_NextHopIP_PortNum[key] = neighbors     
    
    info( '*** Creating links\n' )
    
    '''
    links = G.edges()
    print links
    links = sorted(links,key = lambda x:x[1])
    print links
    '''
    
    links = [] #get a list of links between interfaces in my network
    
    for i in connections:
        net.addLink(net.getNodeByName(i[0]),net.getNodeByName(i[1])) #Add the links as the same sequence as in the file 
    
    info( '*** Starting network\n')
    net.start()
        
    # for all the switches in the net  
    for switch in net.switches: # for each switch
        intfName = switch.intfList()[1:] #intfName is a list of interfaces on that switch, except the l0 interface
        #print 'Switch' + name + '  ' + str(switch.intfList()[1:])
        for i in range(len(intfName)):
            #print nodes[str(switch)][i]
            intfName[i].setIP(nodes[str(switch)][i], prefixLen = 24) #set IP address for that specific interface of this switch
            #print intfName[i].ifconfig
	    #print intfName[i], intfName[i].MAC() #may put them into a dictionary
            #print intfName[i].IP(), intfName[i].MAC()
            switchMac[intfName[i].IP()] = intfName[i].MAC()
            
#Add 1 interface for hosts
    for host in net.hosts:
        #host.setDefaultRoute(intf = "via 192.168.10.10")
        #print interface
        interface = host.intf()
        host.setIP(nodes[str(host)][0],prefixLen = 24)
	#print host.intfIsUp()
	#host.setDefaultRoute(interface)
        host.cmd("sudo route add default netmask 0.0.0.0 gw " + str(interface.link.intf1.IP()))
        #interface.cmd("route del -net ")
        #host.cmd("sudo arp -s " + str(interface.link.intf1.IP()), str(interface.link.intf1.MAC()))
        
                
        
        
        #I want to add ARP table and Routing Table in my hosts. could possibly set a dictionary storing interface name and interface IP address / MAC address. 
        #print host.IP()
    
        #print nodes[str(switch)]
    #print links
    
           
    info( '*** Running CLI\n' )
    
    CLI(net)
    #print commandLine
    #print 'what do you want?'
    #print 'h1'
    return net
    
    
    info( '*** Stopping network' )
    net.stop()

def test1():
    for switch in net.switches:
        if str(switch) == 's1':
            print str(switch.intfList()[3])
            switch.intfList()[3].delete()
            print switch.intfIsUp(switch.intfList()[3])
            time.sleep(5)
            switch.attach(switch.intfList()[3])
            print switch.intfIsUp(switch.intfList()[3])
            #switch.intfList()[3].ifconfig('up')
        #if str(switch) == 's2':
            #switch.detach(switch.intfList()[1]) 	   
def test2():
    for switch in net.switches:
        if str(switch) == 's1':
            intfName = switch.intfList()[1:]
            #switch.intfList()[3].delete()
 	    intfName[2].ifconfig("down")
            #switch.detach(switch.intfList()[3])
            #switch.detach("s2-eth1")
            print intfName[2].isUp()
            time.sleep(8)
            intfName[2].ifconfig("up")
            print intfName[2].isUp()
	    time.sleep(10)
            #interface2 = intfName[2].link.intf2
            #print switch.intfIsUp(switch.intfList()[3])
            #time.sleep(5)
            #intfName[2].link.makeIntfPair(str(intfName[2]),str(interface2))
	if str(switch) == 's2':
	    intfName = switch.intfList()[1:]
	    intfName[2].ifconfig("down")
	    print intfName[2].isUp()
	    time.sleep(8)
	    intfName[2].ifconfig("up")
	    print intfName[2].isUp()        
            #net.addLink(net.getNodeByName(connections[2][0]), net.getNodeByName(connections[2][1]))

def test3():
    while(True):
        net.iperf([net.getNodeByName('h1'), net.getNodeByName('h3')],l4Type='UDP',udpBw='10M')
 	#net.pingFull([net.getNodeByName('h1'), net.getNodeByName('h3')])

def test5():
    while(True):
	net.iperf([net.getNodeByName('h1'), net.getNodeByName('h4')],l4Type='UDP',udpBw='10M')

def test6():
    while(True):
        net.pingFull([net.getNodeByName('h2'), net.getNodeByName('h3')])

def test7():
    while(True):
        net.iperf([net.getNodeByName('h2'), net.getNodeByName('h4')],l4Type='UDP',udpBw='10M')

def test4():
    print connections[2][0],connections[2][1]
    for switch in net.switches:
        if str(switch) == 's1':
            intfName = switch.intfList()[1:]
            net.addLink(intfName[2].link)

def test8():
    #print 'hi'
    cli.do_link('link s1 s2 down')

def test9():
    for host in net.hosts:        
        if str(host) == 'h2':
	    host.cmd("ping 192.168.60.1")
	if str(host) == 'h3':
	    host.cmd("ping 192.168.10.1")
	if str(host) == 'h1':
	    host.cmd("iperf -s &")
	if str(host) == 'h4':
	    host.cmd("iperf -c 192.168.10.1")

if __name__ == '__main__':
    setLogLevel( 'info' )
    threading.Thread(target = emptyNet).start()
    time.sleep(20)
    #threading.Thread(target = test1).start()
    t1 = threading.Thread(target = test2)
    t1.start()
    #t1.join()
    #t1._stop()
    #time.sleep()
    
    #threading.Thread(target = test5).start()
    #time.sleep(2)
    #threading.Thread(target = test3)._stop()
    #t2 = threading.Thread(target = test6)
    #t2.start()
    #t2.join()
    #time.sleep(2)
    #threading.Thread(target = test7).start()
    
    
    
    
    
    
    
    
    
    
    
