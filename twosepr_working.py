from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr


log = core.getLogger()



class Router1:
	"""
	A Router1 object is created for each switch that connects.
	A Connection object for that switch is passed to the __init__ function.
	"""
	arpcache = {}
	
	def __init__ (self, connection, dpid):
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		# This binds our PacketIn event listener
		connection.addListeners(self)

		# Use this table to keep track of which ethernet address is on
		# which switch port (keys are MACs, values are ports).
		
		
		#self.ip_to_port = {"10.0.1.2":1,"10.0.1.3":2}
		#self.port_to_mac = {1:'00:00:00:00:00:01', 2:'00:00:00:00:00:02'}
		
		#ip with network prefix, ip of host, interface name, interface address, switch port
		if dpid == "00-00-00-00-00-01":
			self.macaddr = adr.EthAddr("00:00:00:00:01:01")
			self.mac_to_port = {'00:00:00:00:00:01': 1,
								'00:00:00:00:00:02': 2}
			self.ip_to_macandport = {'10.0.1.2':['00:00:00:00:00:01', 1],
									 '10.0.1.3':['00:00:00:00:00:02', 2]}			
			self.routing_table = {'10.0.1.0/24': [0, '00:00:00:00:00:00'],
								  '10.0.2.0/24': [3, '00:00:00:00:01:02'],
				      			  '10.0.3.0/24': [3, '00:00:00:00:01:02']}
		else:
			self.macaddr = adr.EthAddr("00:00:00:00:01:02") 
			
			self.mac_to_port = {'00:00:00:00:00:03': 2,
								'00:00:00:00:00:04': 3,
								'00:00:00:00:00:05': 4}
			self.ip_to_macandport = {'10.0.2.2':['00:00:00:00:00:03', 2],
									 '10.0.2.3':['00:00:00:00:00:04', 3],
								 	 '10.0.2.4':['00:00:00:00:00:05', 4]}		
			self.routing_table = {'10.0.1.0/24': [1, '00:00:00:00:01:01'],
								   '10.0.2.0/24': [0, '00:00:00:00:00:00'],
							       '10.0.3.0/24': [1, '00:00:00:00:01:01']}

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

	def icmp_reply(self, packet, packet_in):
		icmp_packet = packet.payload.payload 
		src_ip = packet.payload.srcip
		dst_ip = packet.payload.dstip
		
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
	
	def icmp_unreach (self, packet, packet_in):
		ip_packet = packet.payload 
		unr = pkt.unreach()
		unr.payload = ip_packet
		src_ip = packet.payload.srcip
		dst_ip = packet.payload.dstip
		
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

	
	
	def act_like_router (self, packet, packet_in):
		if packet.type == packet.ARP_TYPE:
			# ARP request
			src_ip = packet.payload.protosrc
			dst_ip = packet.payload.protodst
			log.debug("a new ARP request: src_ip: %s  dst_ip = %s", src_ip, dst_ip)
			if packet.payload.opcode == pkt.arp.REQUEST:
				#in the same network
				if src_ip in self.ip_to_macandport.keys() and  dst_ip in self.ip_to_macandport.keys():
					log.debug("ARP:src and dst are in the same network")
					arp_reply = pkt.arp()					
					arp_reply.hwsrc = adr.EthAddr(self.ip_to_macandport[str(dst_ip)][0])  #mac address of the router
					arp_reply.hwdst = packet.src
					arp_reply.opcode = pkt.arp.REPLY
					arp_reply.protosrc = dst_ip  #ip address of the router
					arp_reply.protodst = src_ip
					ether = pkt.ethernet()
					ether.type = pkt.ethernet.ARP_TYPE
					ether.dst = packet.src
					ether.src = self.macaddr
					ether.payload = arp_reply
					
					msg = of.ofp_packet_out()
					msg.data = ether.pack()
					
					action = of.ofp_action_output(port = packet_in.in_port)
					msg.actions.append(action)
					self.connection.send(msg)

				#reply be the router
				else:				
					arp_reply = pkt.arp()					
					arp_reply.hwsrc = self.macaddr  #mac address of the router
					#log.debug("this is which router: %s", arp_reply.hwsrc)
					arp_reply.hwdst = packet.src
					arp_reply.opcode = pkt.arp.REPLY
					arp_reply.protosrc = dst_ip  #ip address of the router
					arp_reply.protodst = src_ip
					ether = pkt.ethernet()
					ether.type = pkt.ethernet.ARP_TYPE
					ether.dst = packet.src
					ether.src = self.macaddr
					ether.payload = arp_reply
					
					msg = of.ofp_packet_out()
					msg.data = ether.pack()
					
					action = of.ofp_action_output(port = packet_in.in_port)
					msg.actions.append(action)
					self.connection.send(msg)
					log.debug("Arp replied by the router %s", arp_reply.hwsrc)
			
			# ARP reply
			elif packet.payload.opcode == arp.REPLY:
				log.debug("a new Arp REPLY: from %s, to %s", src_ip, dst_ip)
				arpcache[packet.src] = src_ip
				self.mac_to_port[packet.src] = packet_in.in_port
				if dst_ip in self.ip_to_macandport.keys():
					log.debug("arp reply recieved by router %s and forward to the host", self.macaddr)
					packet.dst = adr.EthAddr(self.ip_to_macandport[dst_ip][0])
					msg = of.ofp_packet_out()
					msg.data = packet.pack()
					action = of.ofp_action_output(port = self.ip_to_macandport[str(dst_ip)][1])
					msg.actions.append(action)
					self.connection.send(msg)
					
				
		# static routing
		elif packet.type == pkt.ethernet.IP_TYPE:
			ip_packet = packet.payload
			if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
				icmp_packet = ip_packet.payload 
				
				src_ip = ip_packet.srcip
				dst_ip = ip_packet.dstip
				
				if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
					#log.debug("ICMP request received")						
					k = 0
					for key in self.routing_table.keys():
						if dst_ip.inNetwork(key):
							k = key
							break
					if k != 0:
						#log.debug("ICMP reply sent")
						#log.debug("network containing host:"+k)
						self.icmp_reply(packet, packet_in)
					
					else:
						#log.debug("ICMP destination unreachable")
						self.icmp_unreach(packet, packet_in)
						   			#regular packet is received
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
					log.debug("in port: %d", packet_in.in_port)
					log.debug("key is : %s", k)
					#src and dst are in the same network
					if self.routing_table[k][0] == 0:
						self.mac_to_port[packet.src] = packet_in.in_port
						if dst_ip in self.ip_to_macandport.keys():
							packet.src = packet.dst
							packet.dst = adr.EthAddr(self.ip_to_macandport[str(dst_ip)][0])
							
							msg = of.ofp_packet_out()
							msg.data = packet.pack()
							action = of.ofp_action_output(port = self.ip_to_macandport[str(dst_ip)][1])
							msg.actions.append(action)
							self.connection.send(msg)
							log.info("within the same network:")
							log.info(msg)
							#log.info(packet)
													
					else:	
						port1 = self.routing_table[k][0]
						dsteth = adr.EthAddr(self.routing_table[k][1])
																
						packet.src = packet.dst
						packet.dst = dsteth
						log.info("src addr %s , dest addr %s", packet.src, packet.dst)
						msg = of.ofp_packet_out()
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
		Router1(event.connection, dpid_to_str(event.dpid))
	core.openflow.addListenerByName("ConnectionUp", start_switch)
