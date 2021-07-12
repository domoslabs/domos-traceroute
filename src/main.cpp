#include "Probe.h"
#include "Traceroute.h"
#include "Utilities.h"
#include <PcapFileDevice.h>
#include <NetworkUtils.h>
#include "Capture.h"
#include <iostream>
#include <unistd.h>
#include <fstream>

const char* target = "google.com";
uint16_t baseSrcPort = 33000;
uint16_t dstPort = 80;
uint16_t n_paths = 1;
uint16_t max_ttl = 15;
uint32_t n_runs = 10;
pcpp::PcapLiveDevice *device;
int main(int argc, char* argv[])
{
    device = findDefaultDevice();
    pcpp::MacAddress gatewayMac = getGatewayMac(device);
    pcpp::IPv4Address targetIp = resolveHostnameToIP(target, device);

    device->open();
    // Populate the flows
    auto flows = new std::unordered_map<uint16_t, std::vector<ProbeRegister*>>();
    for (int srcPort = baseSrcPort; srcPort < baseSrcPort + n_paths; srcPort++) {
        std::vector<ProbeRegister*> flow;
        // Perform the traceroute backwards in order to bypass some weird network behaviour.
        // Because sometimes no SYN-ACK response is given if any of the previous nodes had their TTL reach 0.
        for (uint8_t ttl = max_ttl; ttl > 0; ttl--) {
            auto pr = new ProbeRegister(n_runs);
            flow.push_back(pr);
        }
        flows->insert({srcPort, flow});
    }
    auto *tr = new Traceroute(n_runs, n_paths, max_ttl, ProbeType::TCP, flows);
    auto capture = new Capture(baseSrcPort, dstPort, n_paths, device);

    for(int run_idx = 0; run_idx < n_runs; run_idx++){
        capture->startCapture();
        // Send out the probes, and sleep until we are done capturing
        tr->execute(baseSrcPort, targetIp, dstPort, gatewayMac, device, run_idx);
        // Sleep 2 secs while we capture...
        usleep(2*1000*1000);
        // Stop the capture
        device->stopCapture();
        // Analyze the captured packets
        tr->analyze(capture->getRawPackets(), run_idx);

    }
    device->close();
    std::string out = tr->to_json();
    std::cout << out << std::endl;

    std::ofstream file_id;
    file_id.open("file.txt");

    file_id << out;

    file_id.close();
    return 0;
}
