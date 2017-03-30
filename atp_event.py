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

global i

class atp_events(EventMixin):

	def __init__(self):
		self.listenTo(core)
		self.newList = {}
		self.ip_count = 0
		self.ip_req = 1


	def _handle_GoingUpEvent (self, event):
		self.listenTo(core.openflow)
		self.listenTo(core.adaptiveThreatPrevention)
		

	def _handle_check_packetIn(self,event):
		packet = event.event.parsed
		if isinstance(packet.next, ipv4):
			if (packet.type == ethernet.IP_TYPE):
				if(packet.next.srcip not in self.newList.keys()):
					self.newList[packet.next.srcip] = [0,1]
				else :
					self.newList[packet.next.srcip][self.ip_req] = self.newList[packet.next.srcip],
					[self.ip_req] + 1
			

	def _handle_flowStatsEvent(self,event):
		for connection in core.openflow._connections.values():
			connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

	def _handle_FlowStatsReceived(self,event):
		stats = flow_stats_to_list(event.stats)
		for f in event.stats:
			if(f.match.nw_src == '10.0.0.2'):
				log.info(f.packet_count)

def launch():
	core.registerNew(atp_events)
	#core.openflow.addListenerByName("FlowStatsReceived",_handle_flowstats_received)

