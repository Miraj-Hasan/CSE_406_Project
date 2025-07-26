/* dhcp-client-app.h */

#ifndef DHCP_CLIENT_APP_H
#define DHCP_CLIENT_APP_H

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/ipv4-address.h"
#include "ns3/mac48-address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"

namespace ns3
{

class DhcpClientApp : public Application
{
  public:
    static int s_rogueAssigned;
    static int s_legitAssigned;

    static TypeId GetTypeId(void);
    DhcpClientApp();
    virtual ~DhcpClientApp();

    void Setup(Address broadcastAddress, uint16_t serverPort);
    Ipv4Address GetAssignedIp() const;
    Address GetServerAddress() const;
    void SetIsAttacker(bool isAttacker);
    void SendSpoofedDiscover(uint32_t index);
    Ptr<Packet> BuildDhcpDiscoverPacketWith(uint32_t xid, Mac48Address mac);
    Mac48Address GenerateSpoofedMac(uint32_t index);

  protected:
    virtual void StartApplication(void);
    virtual void StopApplication(void);

  private:
    void SendDiscover();                 // Send DHCPDISCOVER
    void HandleRead(Ptr<Socket> socket); // Handle OFFER or ACK

    Ptr<Packet> BuildDhcpDiscoverPacket();
    Ptr<Packet> BuildDhcpRequestPacket(Ipv4Address requestedIp);

    Ptr<Socket> m_socket;
    Address m_broadcastAddress;
    Address m_serverAddress;
    Ipv4Address m_assignedIp;
    uint16_t m_port;
    bool m_receivedOffer;

    uint32_t m_xid;     // Transaction ID
    Mac48Address m_mac; // Client MAC address

    bool m_isAttacker = false;
    uint32_t m_numSpoofed = 100;
    ns3::Time m_interval = ns3::MilliSeconds(10);
};

} // namespace ns3

#endif // DHCP_CLIENT_APP_H
