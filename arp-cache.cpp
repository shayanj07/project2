/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  for (auto i = m_arpRequests.begin(); i != m_arpRequests.end(); i++) {
    handleRequest(*i);
  }

  for (auto i = m_cacheEntries.begin(); i != m_cacheEntries.end();) {
    if (!(*i)->isValid) 
      i = m_cacheEntries.erase(i);
    else 
      ++i;
  }

}

void
ArpCache::handleRequest(std::shared_ptr<ArpRequest> arpreq) {
  auto now = steady_clock::now();
  if (now - arpreq->timeSent > seconds(1)) {
    if (arpreq->nTimesSent >= MAX_SENT_TIME) {
      removeRequest(arpreq);
    }
    else {
      // Send arp request
      const Interface* next_hop_iface = m_router.findIfaceByName(arpreq->packets.front().iface); //packets: PendingPacket (Buffer, iface)
      if (!next_hop_iface) {
        std::cerr<<"bad iii"<<std::endl;
      }
      Buffer arp_req(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      uint8_t* req_buf = (uint8_t*)arp_req.data();
      ethernet_hdr* new_eth_hdr = (ethernet_hdr *)req_buf;
      const uint8_t broadcast[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      memcpy(new_eth_hdr->ether_dhost, broadcast, sizeof(broadcast));
      memcpy(new_eth_hdr->ether_shost, next_hop_iface->addr.data(), ETHER_ADDR_LEN);
      new_eth_hdr->ether_type = htons(ethertype_arp);

      arp_hdr* new_arp_hdr = (arp_hdr *)(req_buf + sizeof(ethernet_hdr));
      new_arp_hdr->arp_op = htons(arp_op_request);
      memcpy(new_arp_hdr->arp_tha, broadcast, ETHER_ADDR_LEN);
      new_arp_hdr->arp_tip = arpreq->ip;
      memcpy(new_arp_hdr->arp_sha, next_hop_iface->addr.data(), ETHER_ADDR_LEN);
      new_arp_hdr->arp_sip = next_hop_iface->ip;
      new_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
      new_arp_hdr->arp_pro = htons(ethertype_ip);
      new_arp_hdr->arp_hln = 0x06;
      new_arp_hdr->arp_pln = 0x04; 

      std::cout << "ARP REPEAT REQUEST ATTEMPT" << std::endl;
      print_hdrs(arp_req);
      m_router.sendPacket(arp_req, next_hop_iface->name);
      arpreq->nTimesSent++;
      arpreq->timeSent = now;
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
