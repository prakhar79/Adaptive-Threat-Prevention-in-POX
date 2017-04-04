'''
Adaptive threat Prevention for preventing DoS attacks in 
convergent SDN networks.
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
import pox
from pox.lib.recoco import Timer
from pox.lib.packet.ipv4 import ipv4
log = core.getLogger()

class check_packetIn(Event):
	def __init__(self,event):
		Event.__init__(self)
		self.event = event

class flowStatsEvent(Event):
	def __init__(self):
		Event.__init__(self)


class adaptiveThreatPrevention (EventMixin):

	_eventMixin_events = set([check_packetIn,flowStatsEvent,])

	def __init__ (self):
		self.listenTo(core)
		log.info("Enabling Adaptive Threat Prevention Module.")

	def _handle_GoingUpEvent (self, event):
		self.listenTo(core.openflow)    
		Timer(5, self._timely_flow_stats, recurring=True)

	def _handle_PacketIn (self,event):
		packet = event.parsed
		
		if isinstance(packet.next, ipv4):
			self.raiseEvent(check_packetIn,event)

	def _timely_flow_stats (self):
		self.raiseEvent(flowStatsEvent)

def launch():
	core.registerNew(adaptiveThreatPrevention)
