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
uint16_t n_paths = 10;
uint16_t max_ttl = 15;
uint32_t n_runs = 1;
pcpp::PcapLiveDevice *device;
int main(int argc, char* argv[])
{
    device = findDefaultDevice();
    pcpp::MacAddress gatewayMac = getGatewayMac(device);
    pcpp::IPv4Address targetIp = resolveHostnameToIP(target, device);

    device->open();

    auto capture = new Capture(baseSrcPort, dstPort, n_paths, device);
    capture->startCapture();
    // Send out the probes, and sleep until we are done capturing
    auto *tr = new Traceroute(n_runs, n_paths, max_ttl, ProbeType::TCP);
    tr->execute(baseSrcPort, targetIp, dstPort, gatewayMac, device);
    // Sleep 2 secs while we capture...
    usleep(2*1000*1000);
    // Stop the capture
    device->stopCapture();
    // Analyze the captured packets
    tr->analyze(capture->getRawPackets());
    device->close();
    std::string out = tr->to_json();
    std::cout << out << std::endl;

    std::ofstream file_id;
    file_id.open("file.txt");

    file_id << out;

    file_id.close();
    return 0;
}
