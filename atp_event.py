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
		self.min_count = 0
		self.max_count = 100
		self.newHardTimeout = 5
		self.idleTimeout = 5
		self.RegHardTimeout = 15
		

	def _handle_GoingUpEvent (self, event):
		self.listenTo(core.openflow)
		self.listenTo(core.adaptiveThreatPrevention)

	def _handle_check_packetIn(self,event):
		packet = event.event.parsed

		if (packet.type == ethernet.IP_TYPE):
			s_ip = packet.next.srcip
			if(s_ip in self.regList.keys()):
				
				'''
				check packet count..

				get status from switches.

				if it is in sending normal packets Issue normal entry

				if not then remove from reglist

				delete entry for long time push rule to switch blocking such entry 
				'''

			elif (s_ip in self.newList.keys()):

				'''
				check new packets counts 

				gets stats from switches

				if okay then check number of entry... 

				if entry is more than 5 then move to regualar list.

				'''
				self.newList[s_ip][self.ip_req] = self.newList[s_ip][self.ip_req] + 1
				log.info(self.newList[s_ip])
			else:
				'''
				Add to newlist and issue a normal entry.
				'''

				self.newList[s_ip] = [0,1]

	def _handle_flowStatsEvent(self,event):
		log.info(self.newList)
		for connection in core.openflow._connections.values():
			connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

	def _handle_FlowStatsReceived(self,event):
		stats = flow_stats_to_list(event.stats)
		for f in event.stats:
			f_ip = f.match.nw_src 
			if(f_ip in self.newList.keys()):
				self.newList[f_ip][self.ip_count] = self.newList[f_ip][self.ip_count] + f.packet_count

def launch():
	core.registerNew(atp_events)

