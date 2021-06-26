from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.topology.api import get_link
from ryu.lib.packet import ether_types
from ryu.app.wsgi import  WSGIApplication
from collections import defaultdict
import network_monitor
import time
import threading

class dynamic_rules(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Monitor": network_monitor.Network_Monitor,
        "wsgi": WSGIApplication
    }
    
    def __init__(self, *args, **kwargs):
        super(dynamic_rules, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.mac_to_dpid = {}  # {mac:(dpid,port)}

        self.datapaths = defaultdict(lambda: None)
        self.topology_api_app = self
        self.src_links = defaultdict(lambda: defaultdict(lambda: None))

        self.check_ip_dpid = defaultdict(list)

        self.qos_ip_bw_list = []

        self.network_monitor = kwargs["Network_Monitor"]

        
        self.ip_to_switch = {}
        self.port_name_to_num = {}

        self.ip_to_port = {}  #{ip:(dpid,port)}
        #promise me, use it well :)
        self.lock = threading.RLock()
        self.path_mod = defaultdict(int)
        self.route_list = defaultdict(list)
        self.path = None
        self.path_list = defaultdict(list)
        self.count = 0
        # self.flag_list = defaultdict(bool)
        # self.path_set = [[(1, 1), (1, 3), (4, 1), (4, 2), (5, 3), (5, 1)], [(1, 1), (1, 2), (2, 1), (2, 2), (3, 1), (3, 2), (5, 2), (5, 1)], 
        #                 [(5, 1), (5, 3), (4, 2), (4, 1), (1, 3), (1, 1)], [(5, 1), (5, 2), (3, 2), (3, 1), (2, 2), (2, 1), (1, 2), (1, 1)]]

        
              

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # in rest_topology, self.mac_to_port is for the find for host
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # arp handle
        if pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)

            if pkt_arp.dst_ip in self.ip_to_mac:
                #self.logger.info("[PACKET] ARP packet_in.")
                self.handle_arpre(datapath=datapath, port=in_port,
                                  src_mac=self.ip_to_mac[pkt_arp.dst_ip],
                                  dst_mac=src, src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip)
            else:
                # to avoid flood when the dst ip not in the network
                if datapath.id not in self.check_ip_dpid[pkt_arp.dst_ip]:
                    self.check_ip_dpid[pkt_arp.dst_ip].append(datapath.id)
                    out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
            return

        elif pkt_arp and pkt_arp.opcode == arp.ARP_REPLY:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)
            dst_mac = self.ip_to_mac[pkt_arp.dst_ip]
            (dst_dpid, dst_port) = self.mac_to_dpid[dst_mac]
            self.handle_arpre(datapath=self.datapaths[dst_dpid], port=dst_port, src_mac=src, dst_mac=dst_mac,
                              src_ip=pkt_arp.src_ip, dst_ip=pkt_arp.dst_ip)
            return

        if pkt_ipv4 and (self.ip_to_port.get(pkt_ipv4.dst)) and (self.ip_to_port.get(pkt_ipv4.src)):
            (src_dpid, src_port) = self.ip_to_port[pkt_ipv4.src]  # src dpid and port
            (dst_dpid, dst_port) = self.ip_to_port[pkt_ipv4.dst]  # dst dpid and port
            localtime = time.asctime( time.localtime(time.time()) )
            self.logger.info(localtime)
            self.install_path(src_dpid=src_dpid, dst_dpid=dst_dpid, src_port=src_port, dst_port=dst_port,
                              ev=ev, src=src, dst=dst, pkt_ipv4=pkt_ipv4, pkt_tcp=pkt_tcp)
                              
    def send_pkt(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arpre(self, datapath, port, src_mac, dst_mac, src_ip, dst_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        self.send_pkt(datapath, port, pkt)
        
    def install_path(self, src_dpid, dst_dpid, src_port, dst_port, ev, src, dst, pkt_ipv4, pkt_tcp):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if len(self.route_list[(src_dpid, dst_dpid)])==0:
            self.logger.info("count : %s", self.count)
            self.count+=1
            self.get_all_route(src_dpid, dst_dpid, [src_dpid])
            self.get_all_path(src_dpid, dst_dpid)
        
        
       
        mid_path = None

        mid_path = self.path_list[(src_dpid, dst_dpid)][self.path_mod[(src_dpid, dst_dpid)]]
        self.path_mod[(src_dpid, dst_dpid)] = (self.path_mod[(src_dpid, dst_dpid)] + 1) % len(self.path_list[(src_dpid, dst_dpid)])
        #mid_path = self.short_path(src=src_dpid, dst=dst_dpid)
        #if mid_path is None:
        #    return
        
        
        #self.path = None
        self.path = [(src_dpid, src_port)] + mid_path + [(dst_dpid, dst_port)]

        self.logger.info("path : %s", str(self.path))
        
        for i in range(len(self.path) - 2, -1, -2):
            datapath_path = self.datapaths[self.path[i][0]]
            match = parser.OFPMatch(in_port=self.path[i][1], eth_src=src, eth_dst=dst, eth_type=0x0800,
                                    ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst)

            if i < (len(self.path) - 2):
                actions = [parser.OFPActionOutput(self.path[i + 1][1])]
            else:
                actions = [parser.OFPActionSetField(eth_dst=self.ip_to_mac.get(pkt_ipv4.dst)),
                            parser.OFPActionOutput(self.path[i + 1][1])]
            
            self.add_flow(datapath_path, 100, match, actions, idle_timeout=0, hard_timeout=5)
        # time_install = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        # self.logger.info("time_install: %s", time_install)
    
    def get_all_route(self, src, dst, route):
        last = route[-1]
        if last == dst:
            temp_route = []
            for switch in route:
                temp_route.append(switch)
                if temp_route not in self.route_list[(src, dst)]:
                    self.route_list[(src, dst)].append(temp_route)
            return
        
        for (temp_src, temp_dst) in self.src_links[last]:
            if temp_dst not in route:
                self.get_all_route(src, dst, route + [temp_dst])
    
    def get_all_path(self, src, dst):
        for route in self.route_list[(src, dst)]:
            path = []
            for i in range(len(route) - 1):
                temp_src = route[i]
                temp_dst = route[i + 1]
                src_port = self.src_links[temp_src][(temp_src, temp_dst)][0]
                dst_port = self.src_links[temp_src][(temp_src, temp_dst)][1]
                path = path + [(temp_src, src_port)] + [(temp_dst, dst_port)]

            self.path_list[(src, dst)].append(path)
            



    # def dynamic_path(self, src, dst):
    #     path = []     

    #     if src == 1 and dst == 5:
    #         if self.path_mod[0] == 0:
    #             path = self.path_set[0]
    #         else:
    #             path = self.path_set[1]
    #         self.path_mod[0] = 1 - self.path_mod[0]
    #     else: 
    #         if src == 5 and dst == 1:
    #             if self.path_mod[1] == 0:
    #                 path = self.path_set[2]
    #             else:
    #                 path = self.path_set[3]
    #             self.path_mod[1] = 1 - self.path_mod[1]
        
    #     return path

    
    # this function might be useful, but who knows anyway
    # def long_path(self, src, dst, bw=0):

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
        #self.logger.info("datapaths : %s", self.datapaths)
    
    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave, event.EventPortAdd, event.EventPortDelete,
        event.EventPortModify, event.EventLinkAdd, event.EventLinkDelete])        
    def get_topology(self, ev):
        links_list = get_link(self.topology_api_app, None)
        self.src_links.clear()
        for link in links_list:
            sw_src = link.src.dpid
            sw_dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            src_port_name = link.src.name
            dst_port_name = link.dst.name
            self.port_name_to_num[src_port_name] = src_port
            self.port_name_to_num[dst_port_name] = dst_port
            self.src_links[sw_src][(sw_src, sw_dst)] = (src_port, dst_port)
            self.src_links[sw_dst][(sw_dst, sw_src)] = (dst_port, src_port)
            #self.logger.info("****src_port_name : %s", str(src_port_name))
            #self.logger.info("src_links : %s", str(self.src_links))
            #self.logger.info("port_name_to_num : %s", str(self.port_name_to_num))

    # these two functions need to be coded in your own way
    
    #def delete_flow(self, datapath, priority, match, actions, idle_timeout=10, hard_timeout=60):

    #@set_ev_cls(ofp_event.EventOFPPortStatus, [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER])
    #def get_OFPPortStatus_msg(self, ev):
