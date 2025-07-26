#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"

#include "ns3/dhcp-client-app.h"
#include "ns3/dhcp-server-app.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("DhcpAttackSim");

int main(int argc, char *argv[]) {
  LogComponentEnableAll(LOG_PREFIX_TIME); // Optional: shows simulation time

  LogComponentEnable("DhcpClientApp", LOG_LEVEL_INFO);
  LogComponentEnable("DhcpServerApp", LOG_LEVEL_INFO);

  // Number of clients
  uint32_t numClients = 40;

  // Create nodes
  NodeContainer clients;
  clients.Create(numClients);

  NodeContainer legitServer, rogueServer;
  legitServer.Create(1);
  rogueServer.Create(1);

  NodeContainer all;
  all.Add(clients);
  all.Add(legitServer);
  all.Add(rogueServer);

  // Create CSMA network
  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
  csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));

  NetDeviceContainer devices = csma.Install(all);
  csma.EnablePcapAll("dhcp-attack-sim", true);

  // Install Internet stack
  InternetStackHelper stack;
  stack.Install(all);

  // Assign base IPs (not actually used by DHCP apps)
  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");
  address.Assign(devices);

  // Port for DHCP
  uint16_t port = 67;

  // Rogue DHCP Server (responds fast)
  Ptr<DhcpServerApp> rogue = CreateObject<DhcpServerApp>();
  rogue->Setup(Ipv4Address("192.168.100.1"), 100, port, MilliSeconds(1)); // fast
  rogueServer.Get(0)->AddApplication(rogue);
  rogue->SetStartTime(Seconds(0.0));

  // Legitimate DHCP Server (slower)
  Ptr<DhcpServerApp> legit = CreateObject<DhcpServerApp>();
  legit->Setup(Ipv4Address("10.10.10.1"), 100, port, MilliSeconds(3)); // slow
  legitServer.Get(0)->AddApplication(legit);
  legit->SetStartTime(Seconds(0.0));

  std::cout << "Rogue server node IP: " << rogueServer.Get(0)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
  std::cout << "Legit server node IP: " << legitServer.Get(0)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;


  // Attach DHCP Clients
  for (uint32_t i = 0; i < clients.GetN(); ++i) {
    Ptr<DhcpClientApp> client = CreateObject<DhcpClientApp>();
    client->Setup(Ipv4Address("255.255.255.255"), port);
    clients.Get(i)->AddApplication(client);
    client->SetStartTime(Seconds(1.0 + i * 0.1));
  }

  Simulator::Stop(Seconds(20.0));
  Simulator::Run();
  Simulator::Destroy();

  int rogueAssigned = DhcpClientApp::s_rogueAssigned;
  int legitAssigned = DhcpClientApp::s_legitAssigned;
  int total = rogueAssigned + legitAssigned;
  
  std::cout << "========= DHCP Statistics =========" << std::endl;
  std::cout << "Total clients with IP: " << total << std::endl;
  std::cout << "From Rogue Server     : " << rogueAssigned
            << " (" << (total > 0 ? 100.0 * rogueAssigned / total : 0) << "%)" << std::endl;
  std::cout << "From Legit Server     : " << legitAssigned
            << " (" << (total > 0 ? 100.0 * legitAssigned / total : 0) << "%)" << std::endl;
  std::cout << "===================================" << std::endl;
  


  return 0;
}
