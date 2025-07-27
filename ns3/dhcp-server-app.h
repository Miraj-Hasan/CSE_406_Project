/* dhcp-server-app.h */

#ifndef DHCP_SERVER_APP_H
#define DHCP_SERVER_APP_H

#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"
#include "ns3/mac48-address.h"
#include <map>

namespace ns3 {

class DhcpServerApp : public Application {
public:
  static TypeId GetTypeId(void);
  DhcpServerApp();
  virtual ~DhcpServerApp();
  void EnableDefense(bool on);

  void Setup(Ipv4Address startIp, uint32_t poolSize, uint16_t port, Time responseDelay);

protected:
  virtual void StartApplication(void);
  virtual void StopApplication(void);

private:
  void HandleRead(Ptr<Socket> socket);
  Ipv4Address AllocateIp();

  Ptr<Packet> BuildDhcpOfferPacket(uint32_t xid, Mac48Address chaddr, Ipv4Address yiaddr);
  Ptr<Packet> BuildDhcpAckPacket(uint32_t xid, Mac48Address chaddr, Ipv4Address yiaddr);

  Ptr<Socket> m_socket;
  Ipv4Address m_currentIp;
  uint32_t m_remaining;
  uint16_t m_port;
  Time m_delay;

  // for defence
  bool m_defenceOn = false; 
  Time m_monitorWindow = Seconds(1);
  uint32_t m_discoverThreshold = 20;
  std::vector<Time> m_recentDiscoverTimes; // timestamps of received DHCPDISCOVER messages
  

  std::map<uint32_t, Ipv4Address> m_leaseTable;  // xid -> offered IP
};

} // namespace ns3

#endif // DHCP_SERVER_APP_H
