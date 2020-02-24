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

// #include "arp-cache.hpp"


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
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  	print_hdr_eth(packet.data());
	std::cerr << "MAC IS " << macToString(packet) << std::endl;


//////////////////////////////////////////////////////////////////////////	
   /* 
   TODO:
   1. check if findIfaceByMac(packet) behaves correctly 
   without using a broadcasting address
   2. ("FF" vs "ff"?) - Done
   3. also need to drop packages with destination hardware address that is 
   not the corresponding MAC address of the interface
	*/
	const Interface* mac = findIfaceByMac(packet);

  	if (mac == nullptr && macToString(packet) != "ff:ff:ff:ff:ff:ff") 
  	{
    	std::cerr << "Received packet, but MAC is unknown, ignoring" << std::endl;
    	return;
  	}
//////////////////////////////////////////////////////////////////////////


  //static_assert(std::is_same<unsigned char, uint8_t>::value, "uint8_t is not unsigned char");

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
      arp_hdr *arphdr = (arp_hdr *) payload.data();

      if (ntohs(arphdr->arp_op) == arp_op_request)
      {
      	std::cerr << "Received ARP request!" << std::endl;


      	if (iface->ip == arphdr->arp_tip)	/* target address matches our own address */
      	{
      		// uint8_t *response = (uint8_t *) malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      		// Buffer* response = (Buffer *) malloc(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      		Buffer response(sizeof(ethernet_hdr) + sizeof(arp_hdr));

      		/* the size of the frame is the ethernet header + the ARP payload */
      		ethernet_hdr *ethhdr = (ethernet_hdr *) response.data();
      		std::vector<unsigned char> arp_and_eth(response.begin() + sizeof(ethernet_hdr), response.end());
      		arp_hdr *arphdres = (arp_hdr *) (arp_and_eth.data());
      		// arp_hdr *arphdres = (arp_hdr *) (response + sizeof(ethernet_hdr));

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

      		std::vector<unsigned char> mac(packet.at(6), packet.at(11));
      	   /*
      	   	* TODO: fix the scope situation for the insertArpEntry function call 
      	   	* what about ::ArpCache::insertArpEntry...?
      		*/
      		std::shared_ptr<ArpRequest> arp_rep = m_arp.insertArpEntry(mac, ntohl(arphdr->arp_sip));

	        //sendPacket(response, iface->name);
	        std::cerr << "ARP reply sent" << std::endl;
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
      std::cerr << "IPv4--RIGHT!" << std::endl;
     /*
      * need to calculate checksum
      */
      ip_hdr *iphdr = (ip_hdr *) payload.data();
      if (iphdr->ip_sum != cksum(payload.data(), sizeof(payload)))
      	/* or if (!cksum(payload.data(), sizeof(payload))) ? */
      {
      	std::cerr << "Checksum failed, ignoring" << std::endl;
      	return;
      }
      
      break;
    }
    default:
      std::cerr << "Unrecognized Ethernet type" << std::endl; 
      break;
  }
  
  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

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
