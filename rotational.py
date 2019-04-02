
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
import random
from netmiko import ConnectHandler
from netaddr import IPNetwork, IPAddress
import os
import json
import thread
import threading
import time
import socket

class Loadbalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        #self.virtual_ip = "10.0.0.100"
        #self.virtual_mac = "AA:AA:AA:AA:AA:AA"
        #self.servers_list = ["10.0.0.1","10.0.0.2","10.0.0.3"]
        #self.server1_connection = ConnectHandler(**{"username": "dashi", "ip": "192.168.0.1", "secret": "dashi", "password": "dashi", "device_type": "linux"})
        #self.server2_connection = ConnectHandler(**{"username": "dashi", "ip": "192.168.0.2", "secret": "dashi", "password": "dashi", "device_type": "linux"})
        with open ('controller_config.txt') as json_file:               #Extracting startup config from the file
            data = json.load(json_file)
            print(data)
            self.master = data['master']                                #List of primary and secondary servers
            self.worker = data['worker']
            self.remote_controller = data['remote_controller']
            self.master_worker_controller_details = data['master_worker_controller_details']
            self.master_to_worker = data['master_to_worker']
        self.ip_to_local_mac = {}                                       #Local IPs are mapped with ovs port numbers and mac addresses
        self.master_status={}
        self.worker_status={}
        self.remote_controller_status={}
        self.datapath = ""
        self.outside_port = 5
	self.ovs_password = ""
        self.down_server = {}
        self.connections = {}
        self.primary_mapping = {}
        self.subnet_to_cpe_mac = {}
        self.active_active_customers = []
        self.port_to_ip = {}

         
        self.url_ip_to_mac = {}
        self.statefulmapping = {"10.0.2.1":{"name":"www.customer1.com","port":30002,"vlan":2, "subnet": "10.0.2.0/24",
            "selection":"active-active-multiple-server", "name": "Customer1", "netmask":"255.255.255.0","gateway":"10.0.2.100"},
                                "10.0.3.1":{"name":"www.customer2.com","port":30003,"vlan":3, "subnet": "10.0.3.0/24",
                                    "selection":"active-active-one-server", "name": "Customer2", "netmask":"255.255.255.0", "gateway": "10.0.3.100"}}      #Dictionary consisiting of details about all the customers
        self.initialize_customer_details()
        super(Loadbalancer, self).__init__(*args, **kwargs)
    
    def initialize_customer_details(self, updates=None):
	
        if not updates:
            customer_dictionary = self.statefulmapping
        else:
            customer_dictionary = updates
            
        for i in customer_dictionary:
            if self.master[0] not in self.primary_mapping:
                self.primary_mapping[self.master[0]] = []
            self.primary_mapping[self.master[0]].append(i)
            self.statefulmapping[i]["primary"] = self.master[0]
            self.statefulmapping[i]["secondary"] = self.master[1]
            if 'active-active-multiple-server' in self.statefulmapping[i]['selection']:
                self.active_active_customers.append(i)
            if self.statefulmapping[i]['subnet'] not in self.subnet_to_cpe_mac:
                self.subnet_to_cpe_mac[self.statefulmapping[i]['subnet']] = {}
            self.subnet_to_cpe_mac[self.statefulmapping[i]['subnet']] = {"ip": i, "mac_of_cpe": ""}
            if not self.statefulmapping[i]['port'] in self.port_to_ip:
                self.port_to_ip[self.statefulmapping[i]['port']] = ""
            self.port_to_ip[self.statefulmapping[i]['port']] = i
            if not updates:
                self.statefulmapping[i] = customer_dictionary[i]
            self.rotate()
        print(self.primary_mapping)
        print(self.active_active_customers)
        print(self.subnet_to_cpe_mac)
        print(self.port_to_ip)
        print(self.statefulmapping)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
	'''Initial flows are installed in switch features'''
        self.datapath = ev.msg.datapath
        datapath = self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(priority=0, match=match, actions=actions, datapath=datapath)
        

        for i in self.master_worker_controller_details:
            self.add_arp_flows(i)
            self.add_ip_and_tcp_flows(i, 6)
        
       	for i in self.statefulmapping:
            	self.install_namespace_and_veth_for_customer(self.connections["OVS"], i)
       
        

    def install_namespace_and_veth_for_customer(self, net_connect, customer):
	'''create veth interfaces for the url created for the customer to return ping and arp requests
	'''
        net_connect.send_command_timing("sudo ip netns {}".format(customer['name']))
        net_connect.send_command_timing(self.OVS_password)
        cmd_list.append("sudo ip link add {}_url type veth peer name {}_ovs".format(customer['name'], customer['name']))
        cmd_list.append("sudo ip link set {}_url netns {}".format(customer['name'], customer['name']))
        cmd_list.append("sudo ifconfig {}_ovs up".format(customer['name']))
        cmd_list.append("sudo ovs-vsctl add-port br0 {}_ovs".format(customer['name']))
        cmd_list.append("sudo ip netns exec {} ifconfig {}_url {} netmask {} address {} up".format(cusotmer['name'], customer['name'], customer['netmask'], self.create_unique_mac(customer['ip']))) 
        cmd_list.append("sudo ip netns exec {} ip route add default via {}".format(customer['name'], customer['gateway']))
        net_connect.send_config_set(cmd_list)

    def create_unique_mac(self, ip):
	'''Create unique mac for the url ip veth interface created for arp reply.
	'''
        x = ip.split('.')
        int_of_ip=""
        for i in x:
            if len(i)<3:
                for j in range(3-len(i)):
                    int_of_ip = int_of_ip + "0"
            int_of_ip = int_of_ip + str(i)
        t = iter(int_of_ip)
        mac_address = ':'.join(a+b for a,b in zip(t, t))
        return(mac_address)
       


    def add_ip_and_tcp_flows(self, ip_addr, ip_proto=None, out_port=None, match=None, actions=None, priority=100):
        ''' 
        Install IP and TCP Flows for an IP address 
        Create match and action to use in the function add_flow()
        IP and TCP flows will only be installed when ip_proto = 6
        IP flows will be installed when ip_proto is not provided 
        '''
        parser = self.datapath.ofproto_parser
        if not match:
            match = parser.OFPMatch(ipv4_dst=ip_addr, eth_type=2048)
        if not actions:
            actions = [parser.OFPActionOutput(self.master_worker_controller_details[ip_addr][1])]
        self.add_flow(priority=100, match=match, actions=actions)
        if ip_proto:
            match = parser.OFPMatch(ipv4_dst=ip_addr, eth_type=2048, ip_proto=6)
            actions = [parser.OFPActionOutput(self.master_worker_controller_details[ip_addr][1])]
            self.add_flow(priority=100, match=match, actions=actions)
        
    def add_arp_flows(self, ip_addr, out_port=None):
        '''
        Install arp flows for a particular IP Address 
        Create match and action to use in the function add_flow()
        '''
	
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=2054,arp_tpa=ip_addr)
	actions = [parser.OFPActionOutput(self.master_worker_controller_details[ip_addr][1])]
        self.add_flow(priority=100, match=match, actions=actions)
      

          


    
    
    def check_if_primary_server_is_up(self):
	'''Check if primary server is up
	It can be found out by checking the connection_status.txt file that is being created from the check_connection.py
	If connection to master1 or worker1 goes down, the entire master1 can be considered down.
	Similar for worker2 and master2.
	If the primary server goes down, the primary server has to be swapped with the secondary server and flows have to be reinstalled.
	'''
	with open ('connection_status.txt') as json_file:
		connections = json.load(json_file)
	
        while True:
            
                
            for i in connections:
                if connections[i] == self.master[0] or connections[i] == self.worker[0]:
                    print("{} is down so changing the server to {}".format(self.master[0],self.master[1]))
                    primary = self.master[0]

                elif connections[i] == connections[1] or self.down_server[i] == self.worker[1]:
                    print("{} is down so changing the server to {}".format(self.master[1],self.master[0]))
                    primary = self.master[1]
            
                for x in self.primary_mapping[primary]:
                    temp = self.statefulmapping[x]['primary']
                    self.statefulmapping[x]['primary'] = self.statefulmapping[x]['secondary']
                    self.statefulmapping[x]['secondary'] = temp
                    self.install_primary_server_flow(x)


    def add_flow(self, priority=0, match=None, actions=None, buffer_id=None, datapath=None, inst=None, table_id=0, cookie=0):
        '''
        Used to install flows in the switch using flow mod
        If user provides match and action an instruction will be created which will be provided to flowmod
        If user does not provide match and action, user has the option to provide instruction which will be used in flowmod
        If datapath is not provided, class variable, self.datapath will be used which was created during feature handling.
        '''

        if not datapath:
            datapath = self.datapath
                
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if not inst:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(cookie=cookie,datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(cookie=cookie,datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)
    
    def add_cpe_to_ovs_flow(self, msg, ipv4frame, etherframe, CIDR):
        '''
        Used to add flows for the packet that comes from CPE to OVS.
        2 flows are installed simultaneously:
        1. For a packet coming from CPE to OVS, the VLAN is popped.
        2. For a packet going from OVS to CPE, the VLAN of customer is pushed and destination mac address is set to the SVI of CPE.
        '''
        

        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        match = ofp_parser.OFPMatch(ip_proto=6, eth_type=2048, ipv4_src=ipv4frame.src)
        actions = [
                    ofp_parser.OFPActionPopVlan(),
                ]
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions), ofp_parser.OFPInstructionGotoTable(table_id=2)]
        self.add_flow(priority=100, match=match, actions=actions, inst=inst)
        match = ofp_parser.OFPMatch(ip_proto=6, eth_type=2048, ipv4_dst=CIDR)
        actions = [
                    ofp_parser.OFPActionPushVlan(ethertype=self.statefulmapping[self.subnet_to_cpe_mac[CIDR]['ip']]['vlan']),
                    ofp_parser.OFPActionSetField(eth_dst=self.subnet_to_cpe_mac[CIDR]['mac_of_cpe'])
                ]
        self.add_flow(priority=100, match=match, actions=actions, table_id=1)

        
    
    def add_server_to_ovs_flow(self, ip_addr, msg=None, pkt=None):
        '''
        Used to add flows for the packet that comes from the Master Node to OVS.
        2 flows are installed simultaneously.
        1. For the packet coming from Master node to OVS, change the source IP address to the URL ip address, 
        source port to 80 and source mac address to the mac address of the veth interface representing the URL.
        2. For the packet going from OVS to Master node, change the destination ip address to the address of the primary server,
        destination mac address to the mac address of the primary server and destination port to the 30000 port associated with the customer service.
        '''

        priority = 1
        if msg:
            datapath = msg.datapath
        else:
            datapath = self.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        #tcpframe = pkt.get_protocol(tcp.tcp)
        ip_addr="10.0.2.1"
        ipv4frame = pkt.get_protocol(ipv4.ipv4)
        etherframe = pkt.get_protocol(ethernet.ethernet)
        match = ofp_parser.OFPMatch(ip_proto=6, eth_type=2048, tcp_src=self.statefulmapping[ip_addr]['port'])
        actions = [
                    ofp_parser.OFPActionSetField(ipv4_src=ip_addr),
                    ofp_parser.OFPActionSetField(tcp_src=80),
                    ofp_parser.OFPActionSetField(eth_src=self.url_ip_to_mac[ip_addr][0]),
                ]
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions), ofp_parser.OFPInstructionGotoTable(table_id=1)]

        self.add_flow(priority=100, match=match, actions=actions, inst=inst)
    
    def install_primary_server_flow(self, ip_addr, msg=None, pkt=None):
	'''
	The functions is used to specifically install flows that direct to the primary server.
	'''
        match = ofp_parser.OFPMatch(ip_proto=6, eth_type=2048, ipv4_dst=ip_addr)
        actions = [
                    ofp_parser.OFPActionSetField(ipv4_dst=self.statefulmapping[ip_addr]['primary']),
                    ofp_parser.OFPActionSetField(tcp_dst=self.statefulmapping[ip_addr]['port']),
                    ofp_parser.OFPActionSetField(eth_dst=self.server_details[self.statefulmapping[ip_addr]['primary']][0]),
                ]
        self.add_flow(priority=100, match=match, actions=actions, table_id=2, cookie=int(ip_addr.replace(".","")))
    

    def get_mac_of_cpe(self, msg, pkt, port):
	'''
	The function is used to obtain the mac address of SVI of CPE
	'''
        ipv4frame = pkt.get_protocol(ipv4.ipv4)
        etherframe = pkt.get_protocol(ethernet.ethernet)
        self.server_details[ipv4frame.src]=[etherframe.src,port]
        for i in self.subnet_to_cpe_mac:
            if not IPAddress(ipv4frame.src) in IPNetwork(i):
                continue
            self.subnet_to_cpe_mac[i]["mac_of_cpe"] = etherframe.src
            break
        self.add_cpe_to_ovs_flow(msg, ipv4frame, etherframe, i)    
    
    

    def rotate(self, n=1):
        self.master = self.master[n:] + self.master[:n]
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        
        
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        port_to_cpe = 1
        port = msg.match['in_port']
        print(port) 
        if port == port_to_cpe:
            self.get_mac_of_cpe(msg, pkt, port)
        #print (pkt.get_protocol(ethernet.ethernet).src)
        '''
        x = pkt.get_protocol(ethernet.ethernet)
        if pkt.get_protocol(tcp.tcp):
            tcpframe = pkt.get_protocol(tcp.tcp)
            self.handle_tcp_packet(msg, pkt)

        elif pkt.get_protocol(icmp.icmp):
            self.handle_icmp_packet(msg, pkt)

        elif pkt.get_protocol(ethernet.ethernet):
            etherframe = pkt.get_protocol(ethernet.ethernet)
            if etherframe.ethertype == ether.ETH_TYPE_ARP:
                arpPacket = pkt.get_protocol(arp.arp)
                if arpPacket.opcode == 1:
                    self.send_arp_reply(msg, etherframe, arpPacket, pkt)
        '''    

