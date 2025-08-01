/* dhcp-client-app.cc */

#include "dhcp-client-app.h"

#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/udp-socket-factory.h"

#include <iomanip> // Required for std::setw and std::setfill

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("DhcpClientApp");
NS_OBJECT_ENSURE_REGISTERED(DhcpClientApp);

int DhcpClientApp::s_rogueAssigned = 0;
int DhcpClientApp::s_legitAssigned = 0;

TypeId
DhcpClientApp::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::DhcpClientApp")
                            .SetParent<Application>()
                            .SetGroupName("Applications")
                            .AddConstructor<DhcpClientApp>();
    return tid;
}

DhcpClientApp::DhcpClientApp()
    : m_socket(0),
      m_port(67),
      m_receivedOffer(false),
      m_xid(0)
{
}

DhcpClientApp::~DhcpClientApp()
{
    m_socket = nullptr;
}

void
DhcpClientApp::Setup(Address broadcastAddress, uint16_t port)
{
    m_broadcastAddress = broadcastAddress;
    m_port = port;

    m_xid = rand(); // generate transaction ID here
}

Ipv4Address
DhcpClientApp::GetAssignedIp() const
{
    return m_assignedIp;
}

Address
DhcpClientApp::GetServerAddress() const
{
    return m_serverAddress;
}

Mac48Address
DhcpClientApp::GenerateSpoofedMac(uint32_t index)
{
    std::ostringstream oss;
    oss << "00:11:22:" << std::hex << std::setw(2) << std::setfill('0') << ((index >> 8) & 0xFF)
        << ":" << std::setw(2) << (index & 0xFF) << ":AA";
    return Mac48Address(oss.str().c_str());
}

void
DhcpClientApp::SendSpoofedDiscover(uint32_t index)
{
    uint32_t spoofedXid = rand();
    Mac48Address spoofedMac = GenerateSpoofedMac(index);
    Ptr<Packet> pkt = BuildDhcpDiscoverPacketWith(spoofedXid, spoofedMac);

    m_socket->SendTo(pkt, 0, InetSocketAddress(Ipv4Address("255.255.255.255"), m_port));
    NS_LOG_INFO("Attacker sent DISCOVER #" << index << " with MAC=" << spoofedMac
                                           << " XID=" << spoofedXid);
}

void
DhcpClientApp::StartApplication()
{
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->SetAllowBroadcast(true);
    m_socket->Bind();
    m_socket->SetRecvCallback(MakeCallback(&DhcpClientApp::HandleRead, this));

    // Now GetNode() is valid
    Ptr<Node> node = GetNode();
    Ptr<NetDevice> dev = node->GetDevice(0);
    m_mac = Mac48Address::ConvertFrom(dev->GetAddress());

    if (m_isAttacker)
    {
        for (uint32_t i = 0; i < m_numSpoofed; ++i)
        {
            Simulator::Schedule(Seconds(1.0) + i * m_interval,
                                &DhcpClientApp::SendSpoofedDiscover,
                                this,
                                i);
        }
    }
    else
    {
        Simulator::Schedule(Seconds(1.0), &DhcpClientApp::SendDiscover, this);
    }
}

void
DhcpClientApp::StopApplication()
{
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
DhcpClientApp::SendDiscover()
{
    Ptr<Packet> packet = BuildDhcpDiscoverPacket();
    m_socket->SendTo(packet, 0, InetSocketAddress(Ipv4Address("255.255.255.255"), m_port));
    NS_LOG_INFO("Client sent DHCPDISCOVER with XID=" << m_xid);
}

void
DhcpClientApp::HandleRead(Ptr<Socket> socket)
{
    Address from;
    Ptr<Packet> packet = socket->RecvFrom(from);
    uint8_t data[300];
    packet->CopyData(data, 300);

    if (packet->GetSize() < 240 || data[236] != 99 || data[237] != 130)
    {
        NS_LOG_INFO("Received non-DHCP packet or malformed");
        return;
    }

    uint8_t msgType = 0;
    for (uint32_t i = 240; i < packet->GetSize();)
    {
        uint8_t opt = data[i++];
        if (opt == 255)
            break;
        uint8_t len = data[i++];
        if (opt == 53)
        {
            msgType = data[i];
        }
        i += len;
    }

    uint32_t xid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (xid != m_xid)
        return; // Ignore packets for other clients

    Ipv4Address serverIp = InetSocketAddress::ConvertFrom(from).GetIpv4(); 

    if(m_spoofingDefenseEnabled && m_whiteListedServers.find(serverIp) == m_whiteListedServers.end())
    {
        NS_LOG_INFO("Received packet from untrusted server: " << serverIp);
        return; // Ignore packets from untrusted servers
    }

    Ipv4Address offeredIp =
        Ipv4Address((data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19]);

    if (msgType == 2 && !m_receivedOffer)
    { // OFFER
        m_receivedOffer = true;
        m_serverAddress = from;
        m_assignedIp = offeredIp;
        NS_LOG_INFO("Client received DHCPOFFER for "
                    << offeredIp << " from " << InetSocketAddress::ConvertFrom(from).GetIpv4());

        Ptr<Packet> request = BuildDhcpRequestPacket(offeredIp);
        m_socket->SendTo(request, 0, from);
        NS_LOG_INFO("Client sent DHCPREQUEST for " << offeredIp);
    }
    else if (msgType == 5)
    { // DHCPACK
        m_assignedIp = offeredIp;
        Ipv4Address serverIp = InetSocketAddress::ConvertFrom(m_serverAddress).GetIpv4();

        if (serverIp == Ipv4Address("10.1.1.142"))
            ++s_rogueAssigned;
        else if (serverIp == Ipv4Address("10.1.1.141"))
            ++s_legitAssigned;

        NS_LOG_INFO("Client got IP " << offeredIp << " from " << serverIp);
    }
}

Ptr<Packet>
DhcpClientApp::BuildDhcpDiscoverPacket()
{
    uint8_t buf[300] = {0};
    buf[0] = 1; // op: BOOTREQUEST
    buf[1] = 1; // htype: Ethernet
    buf[2] = 6; // hlen
    buf[3] = 0; // hops

    buf[4] = (m_xid >> 24) & 0xFF;
    buf[5] = (m_xid >> 16) & 0xFF;
    buf[6] = (m_xid >> 8) & 0xFF;
    buf[7] = m_xid & 0xFF;

    buf[236] = 99; // magic cookie
    buf[237] = 130;
    buf[238] = 83;
    buf[239] = 99;

    // DHCP option 53: DHCPDISCOVER
    buf[240] = 53;
    buf[241] = 1;
    buf[242] = 1;

    // End option
    buf[243] = 255;

    // Set chaddr (client MAC)
    m_mac.CopyTo(&buf[28]);

    return Create<Packet>(buf, 244);
}

Ptr<Packet>
DhcpClientApp::BuildDhcpRequestPacket(Ipv4Address requestedIp)
{
    uint8_t buf[300] = {0};
    buf[0] = 1;
    buf[1] = 1;
    buf[2] = 6;
    buf[3] = 0;

    buf[4] = (m_xid >> 24) & 0xFF;
    buf[5] = (m_xid >> 16) & 0xFF;
    buf[6] = (m_xid >> 8) & 0xFF;
    buf[7] = m_xid & 0xFF;

    buf[236] = 99;
    buf[237] = 130;
    buf[238] = 83;
    buf[239] = 99;

    // DHCP option 53: DHCPREQUEST
    buf[240] = 53;
    buf[241] = 1;
    buf[242] = 3;

    // DHCP option 50: Requested IP
    buf[243] = 50;
    buf[244] = 4;
    uint32_t ip = requestedIp.Get();
    buf[245] = (ip >> 24) & 0xFF;
    buf[246] = (ip >> 16) & 0xFF;
    buf[247] = (ip >> 8) & 0xFF;
    buf[248] = ip & 0xFF;

    // End
    buf[249] = 255;

    m_mac.CopyTo(&buf[28]);

    return Create<Packet>(buf, 250);
}

void
DhcpClientApp::SetIsAttacker(bool isAttacker)
{
    m_isAttacker = isAttacker;
}

Ptr<Packet>
DhcpClientApp::BuildDhcpDiscoverPacketWith(uint32_t xid, Mac48Address mac)
{
    uint8_t buf[300] = {0};
    buf[0] = 1;
    buf[1] = 1;
    buf[2] = 6;
    buf[3] = 0;

    buf[4] = (xid >> 24) & 0xFF;
    buf[5] = (xid >> 16) & 0xFF;
    buf[6] = (xid >> 8) & 0xFF;
    buf[7] = xid & 0xFF;

    buf[236] = 99;
    buf[237] = 130;
    buf[238] = 83;
    buf[239] = 99;
    buf[240] = 53;
    buf[241] = 1;
    buf[242] = 1; // DISCOVER
    buf[243] = 255;

    mac.CopyTo(&buf[28]);
    return Create<Packet>(buf, 244);
}

void
DhcpClientApp::AddTrustedServer(Ipv4Address serverIp)
{
    m_whiteListedServers.insert(serverIp);
    NS_LOG_INFO("Added trusted server: " << serverIp);
}

void
DhcpClientApp::EnableSpoofingDefense(bool enable)
{
    m_spoofingDefenseEnabled = enable;
}



} // namespace ns3
