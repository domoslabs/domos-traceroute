#include "Probe.h"
#include "Traceroute.h"
#include "Utilities.h"
#include <PcapFileDevice.h>
#include <NetworkUtils.h>
#include "Capture.h"
#include <iostream>
#include <unistd.h>
const char* target = "google.com";
uint16_t baseSrcPort = 33000;
uint16_t dstPort = 80;
uint16_t n_paths = 1;
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
    auto *tr = new Traceroute(n_paths, 20, ProbeType::TCP);
    tr->execute(baseSrcPort, "142.250.74.142", dstPort, gatewayMac, device);
    usleep(100*1000);
    // Stop the capture
    device->stopCapture();
    // Analyze the captured packets
    tr->analyze(*capture->getRawPackets());
    device->close();
    return 0;
}
