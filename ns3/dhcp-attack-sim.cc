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
  uint32_t numClients = 140;

  bool enableStarvatingDefense = false;
  bool enableSpoofingDefense = false;

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
  csma.EnablePcapAll("pcap-files/dhcp-attack-sim", true);

  // Install Internet stack
  InternetStackHelper stack;
  stack.Install(all);

  // Assign base IPs (not actually used by DHCP apps)
  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");
  address.Assign(devices);

  // Port for DHCP
  uint16_t port = 67;

  // Define broadcast address
  Ipv4Address broadcastAddr = Ipv4Address("255.255.255.255");

  int rogue_pool = 250; 
  // Rogue DHCP Server (responds fast)
  Ptr<DhcpServerApp> rogue = CreateObject<DhcpServerApp>();
  rogue->Setup(Ipv4Address("192.168.100.1"), rogue_pool, port, MilliSeconds(1)); // fast
  rogue->SetStartTime(Seconds(3.0));
  rogueServer.Get(0)->AddApplication(rogue);
  

  // Legitimate DHCP Server (slower)
  Ptr<DhcpServerApp> legit = CreateObject<DhcpServerApp>();
  legit->Setup(Ipv4Address("10.10.10.1"), 100, port, MilliSeconds(3)); // slow
  legit->EnableDefense(enableStarvatingDefense); // Enable defense mechanism
  legitServer.Get(0)->AddApplication(legit);
  legit->SetStartTime(Seconds(0.0));

  std::cout << "Rogue server node IP: " << rogueServer.Get(0)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;
  std::cout << "Legit server node IP: " << legitServer.Get(0)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal() << std::endl;

  

  for (uint32_t i = 0; i < numClients; ++i) {
    Ptr<Node> node = clients.Get(i);
    Ptr<DhcpClientApp> client = CreateObject<DhcpClientApp>();
    client->Setup(broadcastAddr, 67);

    if (i == 0) { // only the first node acts as attacker
        client->SetIsAttacker(true);
    }

    if(enableSpoofingDefense) {
        // Add legitimate DHCP server to whitelist
        client->EnableSpoofingDefense(true);
        client->AddTrustedServer(Ipv4Address("10.1.1.141")); // Legitimate server IP
    } else {
        // No spoofing defense, so add rogue server to whitelist
        client->EnableSpoofingDefense(false);
    }

    double jitter = (rand() % 100) / 1000.0; // 0–0.099s
    client->SetStartTime(Seconds(2.0 + i * 0.2 + jitter));
    client->SetStopTime(Seconds(20.0));
    node->AddApplication(client);
}

  double runningTime = 30.0;
  Simulator::Stop(Seconds(runningTime));
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

  // Write results to a file for comparison
  std::ostringstream fname;
  fname << "results/defence_numClients" << numClients << "_runningTime" << runningTime << "_roguePoolSize_"<< rogue_pool <<"_both_defence_off.txt";
  std::ofstream outfile(fname.str()); // overwrite mode
  outfile << "numClients: " << numClients << std::endl;
  outfile << "Total clients with IP: " << total << std::endl;
  outfile << "From Rogue Server     : " << rogueAssigned
          << " (" << (total > 0 ? 100.0 * rogueAssigned / total : 0) << "%)" << std::endl;
  outfile << "From Legit Server     : " << legitAssigned
          << " (" << (total > 0 ? 100.0 * legitAssigned / total : 0) << "%)" << std::endl;
  outfile << "===================================" << std::endl;
  outfile.close();
  
  return 0;
}
