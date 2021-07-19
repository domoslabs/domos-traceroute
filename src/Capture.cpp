//
// Created by vladim0105 on 07.07.2021.
//

#include <iostream>
#include <PcapFileDevice.h>
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
static std::vector<std::shared_ptr<pcpp::RawPacket>> packets;
void Capture::onPacketCaptured(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie){
    timespec recv_time{};
    clock_gettime(CLOCK_REALTIME, &recv_time);
    packet->setPacketTimeStamp(recv_time);
    packets.push_back(std::make_shared<pcpp::RawPacket>(*packet));
}
void Capture::startCapture() {
    // Clear the packet array, in order for multiple runs to not include packets from previous runs
    packets.clear();
    // Start capturing
    device->startCapture(Capture::onPacketCaptured, this);
}

std::vector<std::shared_ptr<pcpp::RawPacket>> Capture::getRawPackets() {
    return packets;
}

