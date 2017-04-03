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
		self.newList = {}
		self.regList = {}
		self.ip_count = 0
		self.ip_req = 1
		self.avg_count = 100
		self.AvgMinCount = 2
		self.AvgMaxCount = 20
		self.newHardTimeout = 5
		self.idleTimeout = 5
		self.RegHardTimeout = 15
		self.regReq = 3
		self.listenTo(core.openflow)
		self.listenTo(core.adaptiveThreatPrevention)

	def _handle_check_packetIn(self,event):
		packet = event.event.parsed
		print (self.newList)
		if isinstance(packet.next, ipv4):
	
			s_ip = packet.next.srcip
			print(str(packet.next.srcip) + " " +  str(packet.next.dstip) + " " + str(packet.next.id))
			if(s_ip in self.regList.keys()):
				
				'''
				check packet count..

				get status from switches.

				if it is in sending normal packets Issue normal entry

				if not then remove from reglist

				delete entry for long time push rule to switch blocking such entry 
				'''
				self.regList[s_ip][self.ip_count] += 1

				if(self.regList[s_ip][self.ip_count] < self.AvgMaxCount):
					#issue regular entry
					log.info("Packet from %s are %s" % (s_ip,self.regList[s_ip][self.ip_count]))
				else:
					#delete all entries.

					#remvove all entries from switches.

					#block for long time.

					#remove from the database.
					#log.info("Blocking %s. as it is making %s requests." % (s_ip,self.regList[s_ip][self.ip_count]))
					del self.regList[s_ip]


			elif (s_ip in self.newList.keys()):

				'''
				check new packets counts 

				gets stats from switches

				if okay then check number of entry... 

				if entry is more than 5 then move to regualar list.

				'''
				self.newList[s_ip][self.ip_count] += 1

				#Update flow entry request count
				self.newList[s_ip][self.ip_req] = self.newList[s_ip][self.ip_req] + 1
				#log.info(self.newList[s_ip])

				#check packet count from switches. 

				if(self.newList[s_ip][self.ip_count] > self.AvgMinCount):
					#issue new entry.
					log.info("Packet from %s are %s" % (s_ip,self.newList[s_ip][self.ip_count]))

					#check if its regular list eligible for reg list or not.
					if (self.newList[s_ip][self.ip_req] > self.regReq):
						log.info("Moving to reg.")
						self.regList[s_ip] = [0,1]
						self.regList[s_ip][self.ip_count] = self.newList[s_ip][self.ip_count]
						self.regList[s_ip][self.ip_req] = self.newList[s_ip][self.ip_req]
						del self.newList[s_ip]
				else:
					#remove all entries in switches. 

					#block for long time with high hardtimeout.

					#remove from newList.
					#log.info("Blocking %s. as it is making %s requests." % (s_ip,self.newList[s_ip][self.ip_count]))
					del self.newList[s_ip]

			else:
				'''
				Add to newlist and issue a normal entry.
				'''

				self.newList[s_ip] = [0,1]

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
		if(f_ip in self.newList.keys()):
			self.newList[f_ip][self.ip_count] = self.newList[f_ip][self.ip_count] + msg.packet_count
		elif (f_ip in self.regList.keys()):
			self.newList[f_ip][self.ip_count] = self.regList[f_ip][self.ip_count] + msg.packet_count



		log.info(msg.packet_count)


def launch():
	core.registerNew(atp_events)

