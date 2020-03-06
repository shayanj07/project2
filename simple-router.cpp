/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

static uint16_t IP_ID = 0;

namespace simple_router {



//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

//std::shared_ptr<ArpRequest> insertArpEntry(const Buffer& mac, uint32_t ip);

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) 
  {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }


  const ethernet_hdr *ehdr = (const ethernet_hdr *)packet.data();
  const uint8_t broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


  // Check if router dest addr is MAC addr or broadcast addr
  Buffer destMAC(ETHER_ADDR_LEN);
  Buffer broadAddr(ETHER_ADDR_LEN);


  memcpy(destMAC.data(), ehdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(broadAddr.data(), broadcast, sizeof(broadcast));

  bool MAC_ok = true;
  bool broad_ok = true;


  for (int i = 0; i < ETHER_ADDR_LEN; i++) 
  {
    if (destMAC[i] != iface->addr[i])
      MAC_ok = false;
  }
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    if (destMAC[i] != broadAddr[i])
      broad_ok = false;
  }

  if (!broad_ok && !MAC_ok) 
  {
    std::cerr << "wrong broadcast and MAC address. ignoring" << std::endl;
    return;
  }

  	uint16_t ether_type = ethertype(packet.data());
    /* Need to extract the header from the Ethernet frame */
   	std::vector<unsigned char> payload(packet.begin() + sizeof(ethernet_hdr), packet.end());

  switch(ether_type)
  {
  /*
   * Handle ARP request  
   */
    case ethertype_arp:
    {
      std::cerr << "ARP--RIGHT!" << std::endl;
      // arp_hdr *arphdr = (arp_hdr *) payload.data();
      arp_hdr *arphdr = (arp_hdr *) (packet.data() + sizeof(ethernet_hdr));

      if (ntohs(arphdr->arp_op) == arp_op_request)
      {
      	std::cerr << "Received ARP request!" << std::endl;


      	if (iface->ip == arphdr->arp_tip)	/* target address matches our own address */
      	{

          /////////
        	Buffer response (sizeof(ethernet_hdr) + sizeof(arp_hdr));
        	ethernet_hdr *ethhdr = (ethernet_hdr *) response.data(); 
        	arp_hdr *arphdres = (arp_hdr *) (response.data() + sizeof(ethernet_hdr));

	        /* length/format of addresses is the same */
	        arphdres->arp_hrd = arphdr->arp_hrd;
	        arphdres->arp_pro = arphdr->arp_pro;
	        arphdres->arp_hln = arphdr->arp_hln;
	        arphdres->arp_pln = arphdr->arp_pln;

	        /* this should be a reply, not request */
	        arphdres->arp_op = htons(arp_op_reply);

	        /* reverse the direction towards sender */
	        arphdres->arp_sip = arphdr->arp_tip; 
	        arphdres->arp_tip = arphdr->arp_sip;

	        memcpy(arphdres->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
	        memcpy(arphdres->arp_tha, arphdr->arp_sha, ETHER_ADDR_LEN);

	        /* fill out the ethernet header as well */
	        memcpy(ethhdr->ether_shost, arphdres->arp_sha, ETHER_ADDR_LEN );
	        memcpy(ethhdr->ether_dhost, arphdres->arp_tha, ETHER_ADDR_LEN );
	        ethhdr->ether_type = htons(ethertype_arp);

	        sendPacket(response, iface->name);
	        std::cerr << "ARP request sent" << std::endl;
      	}
      	else
      	{
      		std::cerr << "ARP request dropped" << std::endl;
      	}


      }
      else if (ntohs(arphdr->arp_op) == arp_op_reply)
      {
      	std::cerr << "Received ARP reply!" << std::endl;

      	if (iface->ip == arphdr->arp_tip)	/* target address matches our own address */
      	{

      	fprintf(stderr, "This is ARP reply\n");
      	Buffer mac_buf(ETHER_ADDR_LEN);  // Piazza @48
      	memcpy(mac_buf.data(), arphdr->arp_sha, ETHER_ADDR_LEN); 

      // record IP-MAC mapping in ARP cache
      std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(mac_buf, arphdr->arp_sip);   
      if (req == nullptr) {
        fprintf(stderr, "Null packet\n");
        return;
      }
        
         // we need to send packets on the req->packets link list
          for (auto pkt : req->packets) 
          {
            Buffer PACK = pkt.packet;

            ethernet_hdr* new_eth_hdr = (ethernet_hdr*)(PACK.data());
            memcpy(new_eth_hdr->ether_dhost, arphdr->arp_sha, ETHER_ADDR_LEN);
            memcpy(new_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

  		     std::cerr << "ARP reply sent" << std::endl;

          // Send cached packet
            sendPacket(PACK, iface->name);
           }
          m_arp.removeRequest(req);
      	}
      	else
      	{
      		std::cerr << "ARP reply dropped" << std::endl;
      	}

      }

      else
      {
      	std::cerr << "Unrecognized arp oper" << std::endl;
      }
      break;
  	}
  /*
   * Handle IPv4 request  
   */
    case ethertype_ip:
    {

    /* VERIFICATION */
    const ip_hdr* iphdr = (ip_hdr*) (packet.data() + sizeof(ethernet_hdr));

    // checking the length of the packet
    if (ntohs(iphdr->ip_len) < sizeof(ip_hdr)) 
    { 
      std::cerr << "Invalid packet: exceeds max size, discarding" << std::endl;
      return;
    }
    // verifying the checksum
    else if (ntohs(cksum(iphdr, sizeof(*iphdr)) != 0xFFFF)) 
    {
      std::cerr << "Invalid packet: corrupted checksum, discarding" << std::endl;
      return;
    }
    /* END OF VERIFICATION */

    // Check destination IP
    if (findIfaceByIp(iphdr->ip_dst) != nullptr)
     {
      /* ICMP packet */

      if (iphdr->ip_p != ip_protocol_icmp)
       {
        std::cerr << "Not ICMP, igonring" << std::endl;
        /**************************************************************/


        /* SEND ICMP3 PORT UNREACHABLE */

  		  ethernet_hdr *eth_hdr = (ethernet_hdr *) packet.data(); 
  		  ip_hdr *ip_Hdr = (ip_hdr *) (packet.data() + sizeof(ethernet_hdr));

  		  Buffer resp (sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));

  		  ethernet_hdr *resp_eth_hdr = (ethernet_hdr *) resp.data(); 
  		  ip_hdr *resp_ip_hdr = (ip_hdr *) (resp.data() + sizeof(ethernet_hdr));
  		  icmp_t3_hdr *resp_icmp_hdr = (icmp_t3_hdr *) (resp.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

  		  /* eth header */
  		  memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
  		  memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
  		  resp_eth_hdr->ether_type = htons(ethertype_ip);

  		  /* icmp header */
  		  resp_icmp_hdr->icmp_type = 3;
  		  resp_icmp_hdr->icmp_code = 3;
  		  resp_icmp_hdr->unused = 0; /* these two fields aren't used */
  		  resp_icmp_hdr->next_mtu = 0; /* fill with 0's to standardize */

  		   // the data field of the icmp contains the entire IP header and
  		   // * first 8 bytes of the payload that caused the error message 
  		  memcpy( resp_icmp_hdr->data, ((uint8_t *) ip_Hdr), ICMP_DATA_SIZE );

  		  /* ip header */
  		  resp_ip_hdr->ip_v = 4; /* IPv4 */
  		  resp_ip_hdr->ip_hl = 5; /* minimum header length */
  		  resp_ip_hdr->ip_tos = ip_Hdr->ip_tos; 
  		  resp_ip_hdr->ip_off = htons(IP_DF);
  		  resp_ip_hdr->ip_len = htons((uint16_t) sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  		  resp_ip_hdr->ip_id = htons(IP_ID++);
  		  resp_ip_hdr->ip_ttl = 64;
  		  resp_ip_hdr->ip_p = ip_protocol_icmp;
  		  resp_ip_hdr->ip_src = ip_Hdr->ip_dst;
  		  resp_ip_hdr->ip_dst = ip_Hdr->ip_src;

  		  /* icmp cksum is it's entire header (including data field) */
  		  resp_icmp_hdr->icmp_sum = 0;
  		  resp_icmp_hdr->icmp_sum = cksum( resp_icmp_hdr, sizeof(icmp_t3_hdr) );

  		  /* ip cksum is it's header */
  		  resp_ip_hdr->ip_sum = 0;
  		  resp_ip_hdr->ip_sum = cksum( resp_ip_hdr, sizeof(ip_hdr) );

  		  sendPacket(resp, iface->name);
        /**************************************************************/



        return;
      }
      
      const icmp_hdr* icmphdr = (icmp_hdr*)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      const size_t icmp_len = packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr);

      if (ntohs(cksum(icmphdr, icmp_len)) != 0xFFFF) 
      {
        std::cerr << "Invalid ICMP packet: corrupted checksum, discarding" << std::endl;
        return;
      }

      // Create ICMP echo reply
      if (icmphdr->icmp_type == 8) 
      {
        // ethernet_hdr *eth_hdr = (ethernet_hdr *) packet.data(); 
        // ip_hdr *iphdr = (ip_hdr *) (packet.data() + sizeof(ethernet_hdr));

        // Buffer resp (sizeof(ethernet_hdr) + ntohs(iphdr->ip_len));
        // ethernet_hdr *resp_eth_hdr = (ethernet_hdr *) resp.data(); 
        // ip_hdr *resp_ip_hdr = (ip_hdr *) (resp.data() + sizeof(ethernet_hdr));
        // icmp_hdr *resp_icmp_hdr = (icmp_hdr *) (resp.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

        // /* eth header */
        // memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
        // memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
        // resp_eth_hdr->ether_type = htons(ethertype_ip);

        // /* ip header */
        // resp_ip_hdr->ip_v = 4; /* IPv4 */
        // resp_ip_hdr->ip_hl = 5; /* minimum header length */
        // resp_ip_hdr->ip_tos = iphdr->ip_tos; 
        // resp_ip_hdr->ip_off = htons(IP_DF);
        // resp_ip_hdr->ip_len = htons((uint16_t) sizeof(ip_hdr) + icmp_len); 
        // resp_ip_hdr->ip_id = htons(IP_ID++);
        // resp_ip_hdr->ip_ttl = 64;
        // resp_ip_hdr->ip_p = ip_protocol_icmp;
        // resp_ip_hdr->ip_src = iphdr->ip_dst;
        // resp_ip_hdr->ip_dst = iphdr->ip_src;

        // /* icmp packet should be exactly the same */
        // resp_icmp_hdr->icmp_type = 0;
        // resp_icmp_hdr->icmp_code = 0;
        // /* place the old payload in the new one */ 
        // memcpy(((uint8_t *) resp_icmp_hdr) + sizeof(icmp_hdr), 
        //        ((uint8_t *) icmphdr) + sizeof(icmp_hdr),
        //        icmp_len - sizeof(icmp_hdr));

        // /* calculate checksums */
        // resp_ip_hdr->ip_sum = 0;
        // resp_ip_hdr->ip_sum = cksum(resp_ip_hdr, sizeof(ip_hdr));
        // resp_icmp_hdr->icmp_sum = 0;
        // resp_icmp_hdr->icmp_sum = cksum(resp_icmp_hdr, icmp_len);

        // std::cerr << "ICMP echo reply sent" << std::endl;
        // sendPacket(resp, iface->name);
        // return;

        std::cout << "Type 8: ICMP echo message received. sending echo reply" << std::endl;
        /* creating a copy of the packet */
        Buffer echo_reply = packet;
        ethernet_hdr* ethhdr = (ethernet_hdr*)(echo_reply.data());

        memcpy(ethhdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethhdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

        ip_hdr* new_ip_hdr = (ip_hdr*)(echo_reply.data() + sizeof(ethernet_hdr));
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(*new_ip_hdr));
        new_ip_hdr->ip_dst = iphdr->ip_src;
        new_ip_hdr->ip_src = iphdr->ip_dst;

        icmp_hdr* new_icmp_hdr = (icmp_hdr*)(echo_reply.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        new_icmp_hdr->icmp_type = 0;
        new_icmp_hdr->icmp_sum = 0;
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, icmp_len);

        std::cout << "ICMP echo reply sent" << std::endl;
        // Send ICMP echo_reply
        sendPacket(echo_reply, iface->name);
        return;
      }
    }  // end IP

    else 
    {
      /*****************************************************************************/
    	/* we need to forward the packet */

      // make a copy of the packet and update the fields 
      ip_hdr* new_iphdr = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));

      if (--new_iphdr->ip_ttl <= 0) 
      {
        std::cerr << "TTL expired, sending ICMP Time Exceeded" << std::endl;

        ethernet_hdr *eth_hdr = (ethernet_hdr *) packet.data(); 

        Buffer resp (sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        ethernet_hdr *resp_eth_hdr = (ethernet_hdr *) resp.data(); 
        ip_hdr *resp_ip_hdr = (ip_hdr *) (resp.data() + sizeof(ethernet_hdr));
        icmp_t3_hdr *resp_icmp_hdr = (icmp_t3_hdr *) (resp.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

        /* eth header */
        memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
        memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
        resp_eth_hdr->ether_type = htons(ethertype_ip);

        /* icmp header */
        resp_icmp_hdr->icmp_type = 11;
        resp_icmp_hdr->icmp_code = 0;
        resp_icmp_hdr->unused = 0; /* these two fields aren't used */
        resp_icmp_hdr->next_mtu = 0; /* fill with 0's to standardize */

        /* the data field of the icmp contains the entire IP header and
         * first 8 bytes of the payload that caused the error message */
        memcpy( resp_icmp_hdr->data, (uint8_t *)new_iphdr, ICMP_DATA_SIZE );

        /* ip header */
        resp_ip_hdr->ip_v = 4; /* IPv4 */
        resp_ip_hdr->ip_hl = 5; /* minimum header length */
        resp_ip_hdr->ip_tos = new_iphdr->ip_tos; 
        resp_ip_hdr->ip_off = htons(IP_DF);
        resp_ip_hdr->ip_len = htons((uint16_t) sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        resp_ip_hdr->ip_id = htons(IP_ID++);
        resp_ip_hdr->ip_ttl = 64;
        resp_ip_hdr->ip_p = ip_protocol_icmp;
        // resp_ip_hdr->ip_src = new_iphdr->ip_dst;
        resp_ip_hdr->ip_src = iface->ip;
        resp_ip_hdr->ip_dst = new_iphdr->ip_src;

        /* icmp cksum is it's entire header (including data field) */
        resp_icmp_hdr->icmp_sum = 0;
        resp_icmp_hdr->icmp_sum = cksum(resp_icmp_hdr, sizeof(icmp_t3_hdr) );

        /* ip cksum is it's header */
        resp_ip_hdr->ip_sum = 0;
        resp_ip_hdr->ip_sum = cksum( (uint8_t *)resp_ip_hdr, sizeof(ip_hdr) );
        sendPacket(resp, iface->name);

        return;
      }

      // new_iphdr->ip_ttl--; 
      new_iphdr->ip_sum = 0;
      new_iphdr->ip_sum = cksum(new_iphdr, sizeof(*new_iphdr));

      // Lookup routing table and find next hop
      RoutingTableEntry next_hop = m_routingTable.lookup(iphdr->ip_dst);  // RoutingTableEntry: dest, gw, mask, ifName

      if (next_hop.dest == 0 && next_hop.gw == 0 && next_hop.mask == 0)
      {
        ethernet_hdr *eth_hdr = (ethernet_hdr *) packet.data(); 
        ip_hdr *ip_Hdr = (ip_hdr *) (packet.data() + sizeof(ethernet_hdr));

        Buffer resp (sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr));

        ethernet_hdr *resp_eth_hdr = (ethernet_hdr *) resp.data(); 
        ip_hdr *resp_ip_hdr = (ip_hdr *) (resp.data() + sizeof(ethernet_hdr));
        icmp_t3_hdr *resp_icmp_hdr = (icmp_t3_hdr *) (resp.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

        /* eth header */
        memcpy( resp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN ); 
        memcpy( resp_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN ); 
        resp_eth_hdr->ether_type = htons(ethertype_ip);

        /* icmp header */
        resp_icmp_hdr->icmp_type = 3;
        resp_icmp_hdr->icmp_code = 0;
        resp_icmp_hdr->unused = 0; /* these two fields aren't used */
        resp_icmp_hdr->next_mtu = 0; /* fill with 0's to standardize */

        /* the data field of the icmp contains the entire IP header and
         * first 8 bytes of the payload that caused the error message */
        memcpy( resp_icmp_hdr->data, ((uint8_t *) ip_Hdr), ICMP_DATA_SIZE );

        /* ip header */
        resp_ip_hdr->ip_v = 4; /* IPv4 */
        resp_ip_hdr->ip_hl = 5; /* minimum header length */
        resp_ip_hdr->ip_tos = ip_Hdr->ip_tos; 
        resp_ip_hdr->ip_off = htons(IP_DF);
        resp_ip_hdr->ip_len = htons((uint16_t) sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
        resp_ip_hdr->ip_id = htons(IP_ID++);
        resp_ip_hdr->ip_ttl = 64;
        resp_ip_hdr->ip_p = ip_protocol_icmp;
        resp_ip_hdr->ip_src = ip_Hdr->ip_dst;
        resp_ip_hdr->ip_dst = ip_Hdr->ip_src;

        /* icmp cksum is it's entire header (including data field) */
        resp_icmp_hdr->icmp_sum = 0;
        resp_icmp_hdr->icmp_sum = cksum( resp_icmp_hdr, sizeof(icmp_t3_hdr) );

        /* ip cksum is it's header */
        resp_ip_hdr->ip_sum = 0;
        resp_ip_hdr->ip_sum = cksum( resp_ip_hdr, sizeof(ip_hdr) );

        sendPacket(resp, iface->name);
        return; 
      }

      const Interface* next_hop_iface = findIfaceByName(next_hop.ifName);
      ethernet_hdr* ethhdr = (ethernet_hdr*)(packet.data());
      ethhdr->ether_type = htons(ethertype_ip);
      memcpy(ethhdr->ether_shost, next_hop_iface->addr.data(), ETHER_ADDR_LEN); 
      // Lookup ARP cache
      std::shared_ptr<ArpEntry> nextHopArp = m_arp.lookup(next_hop.gw);  // gw: next-hop IP addr (of next router's interface)

      if (nextHopArp == nullptr) 
      {
        // if the ARP entry is not found we need to cache the packet and send an ARP request
        std::shared_ptr<ArpRequest> queue_req = m_arp.queueRequest(next_hop.gw, packet, next_hop.ifName);

        if(queue_req->packets.size() > 1) 
        {
            std::cerr << "more than one packet. ignoring" << std::endl; 
            return; 
        }
        if (queue_req->nTimesSent <= 0)
        {
        queue_req->nTimesSent++;
        queue_req->timeSent = steady_clock::now();

        // Create new ARP request
        Buffer arpreq(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        ethernet_hdr* new_eth_hdr = (ethernet_hdr *)arpreq.data();
        memcpy(new_eth_hdr->ether_dhost, broadcast, sizeof(broadcast));
        memcpy(new_eth_hdr->ether_shost, next_hop_iface->addr.data(), ETHER_ADDR_LEN);
        
        new_eth_hdr->ether_type = htons(ethertype_arp);

        arp_hdr* arphdr = (arp_hdr *)(arpreq.data() + sizeof(ethernet_hdr));

        memcpy( new_eth_hdr->ether_shost, arphdr->arp_sha, ETHER_ADDR_LEN );

		    arphdr->arp_hln = ETHER_ADDR_LEN;
        arphdr->arp_pln = 0x04;

        arphdr->arp_op = htons(arp_op_request);

        memcpy(arphdr->arp_tha, broadcast, ETHER_ADDR_LEN);

        arphdr->arp_tip = iphdr->ip_dst;

        memcpy(arphdr->arp_sha, next_hop_iface->addr.data(), ETHER_ADDR_LEN);

        arphdr->arp_sip = next_hop_iface->ip;
        arphdr->arp_pro = htons(ethertype_ip);
        arphdr->arp_hrd = htons(arp_hrd_ethernet);

        sendPacket(arpreq, next_hop_iface->name);
      }
        //return;
      }
      else
      {
        // ARP entry found. Forwarding
        memcpy(ethhdr->ether_dhost, nextHopArp->mac.data(), ETHER_ADDR_LEN);
        sendPacket(packet, next_hop_iface->name);
      }


    }
      break;
    }
    default:
      std::cerr << "Unrecognized Ethernet type" << std::endl; 
      break;
  }
  
  std::cerr << getRoutingTable() << std::endl;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
