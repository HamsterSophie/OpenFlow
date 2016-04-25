from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr

log = core.getLogger()



class Router1 (object):
	"""
	A Router1 object is created for each switch that connects.
	A Connection object for that switch is passed to the __init__ function.
	"""
	arpcache = {}
	
	def __init__ (self, connection):
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		# This binds our PacketIn event listener
		connection.addListeners(self)

		# Use this table to keep track of which ethernet address is on
		# which switch port (keys are MACs, values are ports).
		self.mac_to_port = {}
		self.ip_to_port = {"10.0.1.1":1,"10.0.2.1":2,"10.0.3.1":3}
		self.routing_table = {'10.0.1.0/24': ['10.0.1.100', 's1-eth1', '10.0.1.1', 1, '00:00:00:00:00:01'],
							  '10.0.2.0/24': ['10.0.2.100', 's1-eth2', '10.0.2.1', 2, '00:00:00:00:00:02'], 
							  '10.0.3.0/24': ['10.0.3.100', 's1-eth3', '10.0.3.1', 3, '00:00:00:00:00:03']}

	
	def FlowMode(self, packet, packet_in):
		log.debug("Flow Mode install  Successfully")
		msg = of.ofp_flow_mod()
		msg.match = of.ofp_match.from_packet(packet)
		msg.idle_timeout = 20
		msg.hard_timeout = 30
		msg.buffer_id = packet_in.buffer_id
		msg.data = packet_in
			
		action = of.ofp_action_output(port = packet_in.in_port)
		msg.actions.append(action)
	
	
	def arp_reply_msg (self, packet, packet_in, mac_addr):
		arp_reply = pkt.arp()
		arp_reply.hwsrc = mac_addr  #mac address of the router
		arp_reply.hwdst = packet.src
		arp_reply.opcode = pkt.arp.REPLY
		arp_reply.protosrc = packet.payload.protodst  #ip address of the router
		arp_reply.protodst = packet.payload.protosrc
		ether = pkt.ethernet()
		ether.type = pkt.ethernet.ARP_TYPE
		ether.dst = packet.src
		ether.src = mac_addr
		ether.payload = arp_reply
		
		msg = of.ofp_packet_out()
		msg.data = ether.pack()
		
		action = of.ofp_action_output(port = packet_in.in_port)
		msg.actions.append(action)
		log.debug("msg is :")
		log.debug(msg)
		
		self.connection.send(msg)
		log.debug("arp reply !")
	
	def act_like_router (self, packet, packet_in):
		self.mac_to_port[packet.src] = packet_in.in_port
		if packet.type == packet.ARP_TYPE:
			# ARP request
			if packet.payload.opcode == pkt.arp.REQUEST:
				log.debug("An arp request coming in!")
				self.arp_reply_msg(packet, packet_in, adr.EthAddr("40:10:40:10:40:10"))		
				log.debug("An arp reply is going out!")	
			# ARP reply
			elif packet.payload.opcode == arp.REPLY:
				log.debug("An arp reply coming in!")
				arpcache[packet.src] = packet.payload.protosrc
				self.mac_to_port[packet.src] = packet_in.in_port
				
		# static routing
		elif packet.type == pkt.ethernet.IP_TYPE:
			log.debug("An ip packet coming in!")
			ip_packet = packet.payload
			if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
				icmp_packet = ip_packet.payload 				
	
				if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
					log.debug("ICMP request received")
					src_ip = ip_packet.srcip
					dst_ip = ip_packet.dstip						
					k = 0
					for key in self.routing_table.keys():
						if dst_ip.inNetwork(key):
							k = key
							break
					if k != 0:
						
						log.debug("network containing host:"+k)
						ech = pkt.echo()
						ech.seq = icmp_packet.payload.seq + 1
						ech.id = icmp_packet.payload.id
						
						icmp_reply = pkt.icmp()
						icmp_reply.type = pkt.TYPE_ECHO_REPLY
						icmp_reply.payload = ech
						
						ip_p = pkt.ipv4()
						ip_p.srcip = dst_ip
						ip_p.dstip = src_ip
						ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
						ip_p.payload = icmp_reply
						
						eth_p = pkt.ethernet()
						eth_p.type = pkt.ethernet.IP_TYPE
						eth_p.dst = packet.src
						eth_p.src = packet.dst
						eth_p.payload = ip_p
						
						msg = of.ofp_packet_out()
						msg.data = eth_p.pack()
						
						action = of.ofp_action_output(port = packet_in.in_port)
						msg.actions.append(action)
						
						self.connection.send(msg)
						log.debug("ICMP reply sent")
					
					else:
						log.debug("ICMP destination unreachable")
						unr = pkt.unreach()
						unr.payload = ip_packet
						
						icmp_reply = pkt.icmp()
						icmp_reply.type = pkt.TYPE_DEST_UNREACH
						icmp_reply.payload = unr
						
						ip_p = pkt.ipv4()
						ip_p.srcip = dst_ip
						ip_p.dstip = src_ip
						ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
						ip_p.payload = icmp_reply
						
						eth_p = pkt.ethernet()
						eth_p.type = pkt.ethernet.IP_TYPE
						eth_p.dst = packet.src
						eth_p.src = packet.dst
						eth_p.payload = ip_p
						
						msg = of.ofp_packet_out()
						msg.data = eth_p.pack()
						
						action = of.ofp_action_output(port = packet_in.in_port)
						msg.actions.append(action)
						
						self.connection.send(msg)
						log.debug("ICMP unreachable reply sent")
   				
			else:
				log.debug("A regular packet is received!")
				src_ip = ip_packet.srcip
				dst_ip = ip_packet.dstip
				log.debug("src_ip: %s, dst_ip: %s", src_ip, dst_ip)
				k = 0
				for key in self.routing_table.keys():
					if dst_ip.inNetwork(key):
						k = key
						break
				if k != 0:
					port1 = self.routing_table[k][3]
					dsteth = adr.EthAddr(self.routing_table[k][4])
					
					msg = of.ofp_packet_out()
					
					packet.src = packet.dst
					packet.dst = dsteth
					log.info("src addr %s , dest addr %s", packet.src, packet.dst)
					msg.data = packet.pack()
					
					action = of.ofp_action_output(port = port1)
					msg.actions.append(action)
					self.connection.send(msg)
					log.info(msg)
					log.debug("A regular packet is foward!")
			self.FlowMode(packet, packet_in)
	
	
		
	def _handle_PacketIn (self, event):
		"""
		Handles packet in messages from the switch.
		"""

		packet = event.parsed # This is the parsed packet data.
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return
		
		packet_in = event.ofp # The actual ofp_packet_in message.
		log.debug("packet_in: in_port: %d", packet_in.in_port)
		# newly added from wiki
		
		# Comment out the following line and uncomment the one after
		# when starting the exercise.
		#self.act_like_hub(packet, packet_in)
		#self.act_like_switch(packet, packet_in)
		self.act_like_router(packet, packet_in)



def launch ():
	"""
	Starts the component
	"""
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Router1(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
