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

	def __init__(self):

		self.listenTo(core)
		self.reqPackets = 0
		self.dataPackets = 1
		self.avgCount = 2
		self.minReqCount = 5
		self.maxReqCount = 20
		self.newHardTimeout = 5
		self.idleTimeout = 5
		self.RegHardTimeout = 15
		self.regReq = 3

	newList = {}
	regList = {IPAddr('10.0.0.2') : [0,0], IPAddr('10.0.0.3') : [0,0]}

	def dropIP (self,event):
		packet = event.parsed
		msg = of.ofp_flow_mod()
		msg.command = of.OFPFC_DELETE
		msg.nw_src = (packet.next.srcip,32)

		log.info("Issusing Drop Entry.")
		msg = of.ofp_flow_mod()
		msg.command = of.OFPFC_ADD
		msg.nw_src = (packet.next.srcip,32)
		action = of.ofp_action_output(port = of.OFPP_NONE)
		msg.actions.append(action)          
		msg.idle_timeout = 30
		msg.hard_timeout = 3600
		msg.flags=of.OFPFF_SEND_FLOW_REM
		
		event.connection.send(msg)

	def issueNormalEntry(self,event):
		inport = event.port
		packet = event.parsed
		#log.info("Issusing Normal Entry for %s." % packet.next.srcip)
		msg = of.ofp_flow_mod()
		msg.command = of.OFPFC_MODIFY
		msg.match = of.ofp_match.from_packet(packet,
			inport)
		msg.idle_timeout = 10
		msg.hard_timeout = 30
		event.connection.send(msg)

	def _handle_GoingUpEvent(self,event):
		self.listenTo(core.openflow)
		self.listenTo(core.adaptiveThreatPrevention)

	def _handle_check_packetIn(self,event):
		
		#parsing the pakcet to get necessary data.
		packet = event.event.parsed
		srcIP = packet.next.srcip

		if(srcIP == HOST_IP):
			return

		if(srcIP in self.regList.keys()):
			'''
			#src is registered as regular IP.
			1. Issue a normal entry.
			2. srcIP reqPacketcount ++.
			'''

			self.issueNormalEntry(event.event)
			self.regList[srcIP][self.reqPackets] += 1

			'''
			#Check its reqPacket count.
			1. If reqPacket count > maxReqCount
				It's DoS attacker.
			'''

			if(self.regList[srcIP][self.reqPackets] > self.maxReqCount):
				#It will be considered as a DoS attacker.

				#check data packets.
				if(self.regList[srcIP][self.dataPackets] < (3*self.regList[srcIP][self.reqPackets])):
					#definately DoS attacker.

					#delete all entries.

					#issues drop for long time.
					self.dropIP(event.event)

					#remove from database.
					del self.regList[srcIP]
		
		elif (srcIP in self.newList.keys()):

			#issue new short entry.
			#issueNewEntry(event)
			#print("New Entry for %s." % srcIP)
			self.newList[srcIP][self.reqPackets] += 1

			if(self.newList[srcIP][self.reqPackets] > self.minReqCount):

				#get status from the switch.
				if(self.newList[srcIP][self.dataPackets] < self.avgCount):
					#Its a DDoS attacker.

					#remove all entries.

					#issue drop for long time

					#remove from database.
					del self.newList[srcIP]

				else:
					#add to reg database.
					self.regList[srcIP] = self.newList[srcIP]
					del self.newList[srcIP]

		else :	

			#issue Normal entry.

			#add to new list.
			self.newList[srcIP] = [1,0]


	def _handle_flowStatsEvent(self,event):
		#log.info(self.newList)
		for connection in core.openflow._connections.values():
			connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

	def _handle_FlowStatsReceived(self,event):
		pass
		

	
	#To get the packet count from a given IP address. 
	def _handle_FlowRemoved(self,event):
		msg = event.ofp
		f_ip = msg.match.nw_src
		#print (msg.idle_timeout)
		if(f_ip in self.newList.keys()):
			self.newList[f_ip][self.dataPackets] = self.newList[f_ip][self.dataPackets] + msg.packet_count
		elif (f_ip in self.regList.keys()):
			self.regList[f_ip][self.dataPackets] = self.regList[f_ip][self.dataPackets] + msg.packet_count


def launch():
	core.registerNew(atp_events)

