#include "ns3/udp-socket-factory.h"
#include "dhcp-server-app.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/simulator.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("DhcpServerApp");
NS_OBJECT_ENSURE_REGISTERED(DhcpServerApp);

TypeId DhcpServerApp::GetTypeId(void) {
  static TypeId tid = TypeId("ns3::DhcpServerApp")
    .SetParent<Application>()
    .SetGroupName("Applications")
    .AddConstructor<DhcpServerApp>();
  return tid;
}

DhcpServerApp::DhcpServerApp() : m_remaining(0) {}

DhcpServerApp::~DhcpServerApp() {
  m_socket = 0;
}

void DhcpServerApp::Setup(Ipv4Address startIp, uint32_t poolSize, uint16_t port, Time delay) {
  m_currentIp = startIp;
  m_remaining = poolSize;
  m_port = port;
  m_delay = delay;
  NS_LOG_INFO("Server has been set up!");
}

void DhcpServerApp::EnableDefense(bool on) {
  m_defenceOn = on;
  if (on) {
    NS_LOG_INFO("DHCP flood defense enabled.");
  } else {
    NS_LOG_INFO("DHCP flood defense disabled.");
  }
}

void DhcpServerApp::StartApplication() {
  m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
  m_socket->SetAllowBroadcast(true);
  InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_port);
  m_socket->Bind(local);
  m_socket->SetRecvCallback(MakeCallback(&DhcpServerApp::HandleRead, this));
  NS_LOG_INFO("Server application has started!");
}

void DhcpServerApp::StopApplication() {
  if (m_socket) {
    m_socket->Close();
  }
}

Ipv4Address DhcpServerApp::AllocateIp() {
  Ipv4Address ip = m_currentIp;
  uint32_t ipNum = ip.Get();
  m_currentIp = Ipv4Address(ipNum + 1);
  m_remaining--;
  return ip;
}

void DhcpServerApp::HandleRead(Ptr<Socket> socket) {
  Address from;
  Ptr<Packet> packet = socket->RecvFrom(from);

  uint8_t data[300];
  packet->CopyData(data, 300);

  if (packet->GetSize() < 240 || data[236] != 99 || data[237] != 130) return;

  uint8_t msgType = 0;
  Ipv4Address requestedIp = Ipv4Address::GetAny();
  for (uint32_t i = 240; i < packet->GetSize();) {
    uint8_t opt = data[i++];
    if (opt == 255) break;
    uint8_t len = data[i++];
    if (opt == 53) msgType = data[i];
    if (opt == 50 && len == 4) {
      uint32_t ip = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];
      requestedIp = Ipv4Address(ip);
    }
    i += len;
  }

  uint32_t xid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
  Mac48Address chaddr;
  chaddr.CopyFrom(&data[28]);

  if (msgType == 1 ) {  // DHCPDISCOVER
    Time now = Simulator::Now();
    if (m_defenceOn) {
      // Maintain a rolling log of DISCOVER timestamps 

      while(!m_recentDiscoverTimes.empty() && (now - m_recentDiscoverTimes.front() > m_monitorWindow)) {
        m_recentDiscoverTimes.erase(m_recentDiscoverTimes.begin());
      }
      m_recentDiscoverTimes.push_back(now);

      if(m_recentDiscoverTimes.size() > m_discoverThreshold) {
        NS_LOG_WARN("DHCP flood detected: too many DISCOVERs (" 
          << m_recentDiscoverTimes.size() << ") in the past "
          << m_monitorWindow.GetSeconds() << "s. Dropping packet from " << chaddr);
        return; // Ignore this request
      }
    }
    if(m_remaining > 0) {
    Ipv4Address offeredIp = AllocateIp();
    m_leaseTable[xid] = offeredIp;
    Time jitter = MilliSeconds(rand() % 2);
    Simulator::Schedule(m_delay + jitter, [=]() {
      Ptr<Packet> offer = BuildDhcpOfferPacket(xid, chaddr, offeredIp);
      socket->SendTo(offer, 0, from);
      NS_LOG_INFO("Sent DHCPOFFER for " << offeredIp);
    });
   }
  
  } else if (msgType == 3) {  // DHCPREQUEST
    Ipv4Address lease = (requestedIp == Ipv4Address::GetAny()) ? m_leaseTable[xid] : requestedIp;

    Simulator::Schedule(m_delay, [=]() {
      Ptr<Packet> ack = BuildDhcpAckPacket(xid, chaddr, lease);
      socket->SendTo(ack, 0, from);
      NS_LOG_INFO("Sent DHCPACK for " << lease);
    });
  }
}

Ptr<Packet> DhcpServerApp::BuildDhcpOfferPacket(uint32_t xid, Mac48Address chaddr, Ipv4Address yiaddr) {
  uint8_t buf[300] = {0};
  buf[0] = 2; // BOOTREPLY
  buf[1] = 1; buf[2] = 6; buf[3] = 0;
  buf[4] = (xid >> 24) & 0xFF;
  buf[5] = (xid >> 16) & 0xFF;
  buf[6] = (xid >> 8) & 0xFF;
  buf[7] = xid & 0xFF;

  uint32_t ip = yiaddr.Get();
  buf[16] = (ip >> 24) & 0xFF;
  buf[17] = (ip >> 16) & 0xFF;
  buf[18] = (ip >> 8) & 0xFF;
  buf[19] = ip & 0xFF;

  chaddr.CopyTo(&buf[28]);
  buf[236] = 99; buf[237] = 130; buf[238] = 83; buf[239] = 99;
  buf[240] = 53; buf[241] = 1; buf[242] = 2; // DHCP Message Type: Offer
  buf[243] = 255;
  return Create<Packet>(buf, 244);
}

Ptr<Packet> DhcpServerApp::BuildDhcpAckPacket(uint32_t xid, Mac48Address chaddr, Ipv4Address yiaddr) {
  uint8_t buf[300] = {0};
  buf[0] = 2; buf[1] = 1; buf[2] = 6; buf[3] = 0;
  buf[4] = (xid >> 24) & 0xFF;
  buf[5] = (xid >> 16) & 0xFF;
  buf[6] = (xid >> 8) & 0xFF;
  buf[7] = xid & 0xFF;

  uint32_t ip = yiaddr.Get();
  buf[16] = (ip >> 24) & 0xFF;
  buf[17] = (ip >> 16) & 0xFF;
  buf[18] = (ip >> 8) & 0xFF;
  buf[19] = ip & 0xFF;

  chaddr.CopyTo(&buf[28]);
  buf[236] = 99; buf[237] = 130; buf[238] = 83; buf[239] = 99;
  buf[240] = 53; buf[241] = 1; buf[242] = 5; // DHCPACK
  buf[243] = 255;
  return Create<Packet>(buf, 244);
}

} // namespace ns3