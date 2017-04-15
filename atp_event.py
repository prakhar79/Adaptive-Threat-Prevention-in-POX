'''
This code will handle events raised by atp class. 
'''

import pox  
import pox.openflow.libopenflow_01 as of  
from pox.core import core  
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer


from pox.openflow.of_json import *
log = core.getLogger()

HOST_IP = IPAddr('10.0.0.5')

'''
This module has all the necessary event handling functions of ATP algorithm.
This modules does following tasks.

1. _handle_GoingUpEvent : This event will start listing to various events coming 
from openflow and pox core.

2. _handle_check_packetIn : This is check_packetIn event handler. This will handle check_packetIn
event raised by atp module. Basically, this will create entries in new and reg lists.

3. _handle_flowStatsEvent : This will handle flowStates events called by the atp module. This module will
send flow stats reqest to open flow switches.

4. _handle_FlowStatsReceived : This will handle FlowStatsReceived event raised by the open flow switch. 
This will get flow stats and get packets counts from the entries.     
'''

class atp_events(EventMixin):

	avgCount = 2
	avgRequestPktCount = 3
	minRequestThreshold = 2
	maxRequestThreshold = 5
	newIPTable = {}
	validIPTable = {IPAddr('10.0.0.2') : [0,0], IPAddr('10.0.0.3') : [0,0]}
	regularIPCount = len(validIPTable)

	def __init__(self):
		self.listenTo(core)
		self.requestPackets = 0
		self.dataPackets = 1	
		self.idleTimeoutAttacker = 30
		self.hardTimeoutAttacker = 3600
		self.idleTimeoutRegular = 10
		self.hardTimeoutRegular = 30
		self.regReq = 3
	
	def dropIP (self,event):
		packet = event.parsed
		msg = of.ofp_flow_mod()
		
		msg.command = of.OFPFC_DELETE
		msg.match.nw_src = packet.next.srcip
		msg.match.nw_dst = packet.next.dstip
		msg.match.dl_type = ethernet.IP_TYPE
		event.connection.send(msg)

		log.info("Delete %s with %s and %s."
			%(packet.type,packet.next.protocol,packet.next.srcip))

		msg = of.ofp_flow_mod()
		msg.priority = 100
		msg.command = of.OFPFC_ADD
		msg.match.nw_src = packet.next.srcip
		msg.match.nw_proto = packet.next.protocol
		msg.match.dl_type = ethernet.IP_TYPE
		msg.actions = []

		msg.idle_timeout = self.idleTimeoutAttacker
		msg.hard_timeout = self.hardTimeoutAttacker

		msg.flags=of.OFPFF_SEND_FLOW_REM
		
		event.connection.send(msg)
		log.info("Issusing Drop Entry.")

	def issueNormalEntry(self,event):
		inport = event.port
		packet = event.parsed
		msg = of.ofp_flow_mod()
		msg.command = of.OFPFC_MODIFY
		msg.match = of.ofp_match.from_packet(packet,
			inport)
		msg.idle_timeout = self.idleTimeoutRegular
		msg.hard_timeout = self.hardTimeoutRegular
		event.connection.send(msg)

	#start when event goes up.
	def _handle_GoingUpEvent(self,event):
		self.listenTo(core.openflow)
		self.listenTo(core.adaptiveThreatPrevention)

	def _handle_check_packetIn(self,event):
		
		#parsing the pakcet to get necessary data.
		packet = event.event.parsed
		srcIP = packet.next.srcip

		if(srcIP == HOST_IP):
			return

		if(srcIP in self.validIPTable.keys()):
			'''
			#src is registered as regular IP.
			1. Issue a normal entry.
			2. srcIP reqPacketcount ++.
			'''

			self.issueNormalEntry(event.event)
			self.validIPTable[srcIP][self.requestPackets] += 1

			'''
			#Check its reqPacket count.
			1. If reqPacket count > maxReqCount
				It's DoS attacker.
			'''

			if(self.validIPTable[srcIP][self.requestPackets] > self.maxRequestThreshold):
				#It will be considered as a DoS attacker.

				#check data packets.
				if(self.validIPTable[srcIP][self.dataPackets] < (3*self.validIPTable[srcIP][self.requestPackets])):
					#definately DoS attacker.

					#remove from database.
					del self.validIPTable[srcIP]

					#issues drop for long time.
					self.dropIP(event.event)

		else:
			if(srcIP not in self.newIPTable.keys()):
				self.newIPTable[srcIP] = [1,0]

			#issue new short entry.
			self.newIPTable[srcIP][self.requestPackets] += 1

			if(self.newIPTable[srcIP][self.requestPackets] > self.minRequestThreshold):

				#get status from the switch.
				if(self.newIPTable[srcIP][self.dataPackets] < self.avgCount):
					#Its a DDoS attacker.
					#issue drop for long time
					#remove from database.
					del self.newIPTable[srcIP]
					self.dropIP(event.event)
			

				else:
					#add to reg database.
					self.validIPTable[srcIP] = self.newIPTable[srcIP]
					del self.newIPTable[srcIP]


	#Sending flow state messages to switch.
	def _handle_flowStatsEvent(self,event):
		for connection in core.openflow._connections.values():
			connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

	#Handling flow states received event.
	def _handle_FlowStatsReceived(self,event):
		stats = flow_stats_to_list(event.stats)
		packet_count = 0
		flow_count = 0

		for f in event.stats:
			flow_count += 1
			packet_count += f.packet_count
		log.info("Flow are %s and Total packets = %s" % (flow_count,packet_count))
	
	#To get the packet count from a given IP address. 
	def _handle_FlowRemoved(self,event):
		msg = event.ofp
		f_ip = msg.match.nw_src
	
		if(f_ip in self.newIPTable.keys()):
			self.newIPTable[f_ip][self.dataPackets] = self.newIPTable[f_ip][self.dataPackets] + msg.packet_count
		elif (f_ip in self.validIPTable.keys()):
			self.validIPTable[f_ip][self.dataPackets] = self.validIPTable[f_ip][self.dataPackets] + msg.packet_count

def launch():
	core.registerNew(atp_events)

