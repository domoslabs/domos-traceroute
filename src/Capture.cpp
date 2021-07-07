//
// Created by vladim0105 on 07.07.2021.
//

#include <iostream>
#include "Capture.h"

Capture::Capture(uint16_t baseSrcPort, uint16_t dstPort, uint16_t n_paths, pcpp::PcapLiveDevice *device) {
    this->device = device;
    // Setup filters
    pcpp::ProtoFilter tcpFilter(pcpp::TCP);
    pcpp::PortRangeFilter portRangeFilter(baseSrcPort, baseSrcPort+n_paths, pcpp::DST);
    pcpp::PortFilter portFilter(dstPort, pcpp::SRC);
    pcpp::AndFilter finalTcpFilter;
    finalTcpFilter.addFilter(&tcpFilter);
    finalTcpFilter.addFilter(&portRangeFilter);
    finalTcpFilter.addFilter(&portFilter);

    pcpp::ProtoFilter icmpFilter(pcpp::ICMP);

    pcpp::OrFilter orFilter;
    orFilter.addFilter(&finalTcpFilter);
    orFilter.addFilter(&icmpFilter);

    device->setFilter(orFilter);
}
pcpp::RawPacketVector *packets = new pcpp::RawPacketVector();
void Capture::onPacketCaptured(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie){
    packets->pushBack(packet);
}
void Capture::startCapture() {
    // Start capturing
    device->startCapture(Capture::onPacketCaptured, this);
    std::cout << "Capturing..." << std::endl;
}

pcpp::RawPacketVector *Capture::getRawPackets() {
    return packets;
}

