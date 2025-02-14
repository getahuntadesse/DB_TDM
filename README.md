Overall Goal:
The goal is to allow the controller to enforce a distance bound (maximum hop count) from the controller to switches in the network. Packets from switches exceeding this bound are dropped, providing a security or policy enforcement mechanism. The implementation includes dynamic adjustment of the Round Trip Time (RTT) threshold to account for network latency.

1. Algorithm in `switches.py`:

This app is responsible for the following:

LLDP-based Topology Discovery:Discovering the network topology using LLDP packets.
RTT Measurement: Periodically sending LLDP packets with timestamps to measure the RTT to each switch.
Dynamic RTT Threshold Calculation: Calculating a dynamic RTT threshold based on recent RTT history for each switch.
Packet-In Validation:Determining whether incoming packets from switches should be processed or dropped based on the RTT threshold.
Link Fabrication Detection : Provides the basis for preventing malicious attack on the network

Steps Performed:

1.  Initialization:
       The `Switches` class initializes data structures to store:
           `dps`: Datapaths (switches) in the network.
           `port_state`: Ports on each switch.
           `ports`: `PortData` objects, containing information about each port (including RTT).
           `links`: Links between switches.
           `rtt_thresholds`: RTT threshold for each switch.
           `rtt_histories`: Recent RTT history for each switch, used to calculate the dynamic threshold.
      Starts threads for LLDP discovery (`lldp_loop`), link timeout checking (`link_loop`), and RTT measurement (`rtt_measurement_loop`).
2.  LLDP Loop (`lldp_loop`):
      Periodically sends LLDP packets on all active ports.
      The `send_lldp_packet` function creates the LLDP packet (using `LLDPPacket.lldp_packet`) and sends it out.
3. RTT Measurement Loop (`rtt_measurement_loop`):
    Periodically sends LLDP packets with a timestamp (`is_rtt_measurement=True`) to measure the RTT to each switch.
    The `send_lldp_packet` function includes a `SendTime` TLV in the LLDP packet.
4.  Packet-In Processing (`lldp_packet_in_handler`):
       Receives LLDP packets.
       Calls `LLDPPacket.lldp_parse` to extract the source DPID, port, and send time (if present).
       Calculates the RTT (if a `SendTime` TLV is present).
       Updates the `rtt` attribute of the `PortData` object for the receiving port.
       Updates the `rtt_histories` for the switch.
       Calls `update_rtt_threshold` to adjust the RTT threshold for the switch.
5. Dynamic RTT Threshold Calculation (`update_rtt_threshold`):
      Calculates the average RTT based on the recent RTT history (`rtt_histories`).
      Sets the RTT threshold (`rtt_thresholds`) for the switch to a multiple (defined by `RTT_THRESHOLD_MULTIPLIER`) of the average RTT.
6. Packet-In Validation (`is_valid_packet_in`):
      Called by `simple_switch_13.py` before processing any incoming packet.
        Retrieves the RTT for the port from which the packet was received.
        Retrieves the RTT threshold for the switch.
        If the RTT exceeds the threshold, the function returns `False` (indicating that the packet should be dropped); otherwise, it returns `True`.

2. Algorithm in `simple_switch_13.py`:

This app is a simple L2 learning switch that integrates with `switches.py` for distance-bound enforcement.

Packet Forwarding:  Learns MAC address-to-port mappings and forwards packets accordingly.
Distance-Bound Enforcement: Uses the `switches.py` app to check if packets should be forwarded or dropped based on the RTT threshold.

Steps Performed:

1.  Initialization:
    The `SimpleSwitch13` class initializes a MAC address table (`mac_to_port`).
    It obtains a reference to the `Switches` app.
2.  Packet-In Handling (`_packet_in_handler`):
       Receives incoming packets.
       Distance-Bound Check: Calls `self.switches_app.is_valid_packet_in(msg)` to determine if the packet should be processed based on the RTT threshold.
       If `is_valid_packet_in` returns `False`, the packet is dropped (the function returns).
       If `is_valid_packet_in` returns `True`, the packet is processed as usual (MAC learning and forwarding).
3.  Web API
       A web API has been created, so you can get the RTT threshold by calling the endpoint.

Key Algorithm Parts I modified
switches.py` - `is_valid_packet_in`:

    
    def is_valid_packet_in(self, msg):
        """
        Check if a packet_in message should be processed based on RTT.
        """
        dpid = msg.datapath.id
        in_port = msg.match['in_port'] if hasattr(msg.match, '__getitem__') and 'in_port' in msg.match else msg.in_port

        port = self._get_port(dpid, in_port)
        if not port:
            LOG.warning("Port %s not found on switch %s", in_port, dpid)
            return False

        rtt = self.ports.get_rtt(port)
        threshold = self.rtt_thresholds.get(dpid)

        if threshold is None:
            LOG.warning("RTT threshold not set for switch %s", dpid)
            return True  # Allow if no threshold is set

        if rtt is None:
            LOG.debug("RTT not measured for switch %s, port %s", dpid, in_port)
            return True  # modified to avoid dropping packets while the RTT is being measured

        if rtt > threshold:
            LOG.warning(
                "Packet-in from switch %s, port %s exceeds RTT threshold (RTT: %s, Threshold: %s). Dropping packet.",
                dpid, in_port, rtt, threshold)
            return False

        return True
  

simple_switch_13.py` - `_packet_in_handler`:

    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Check RTT threshold before processing
        if self.switches_app:
            if not self.switches_app.is_valid_packet_in(msg):
                return  # Drop the packet
        else:
            self.logger.warning("Switches app not found. Forwarding all packets.")

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

NB: RTT Threshold Adjustment: The `RTT_THRESHOLD_MULTIPLIER` constant is crucial. A higher value makes the threshold more lenient, while a lower value makes it more strict. 
