//
// Created by vladim0105 on 05.07.2021.
//

#include <DnsLayer.h>
#include <iostream>
#include <PcapLiveDeviceList.h>
#include <NetworkUtils.h>
#include <netinet/in.h>
#include "Probe.h"
Probe::Probe(const std::string &dst_ip, uint16_t srcPort, uint16_t dstPort, uint8_t ttl, pcpp::MacAddress gatewayMac,
             pcpp::PcapLiveDevice *device, ProbeType probe_type) {
    this->device = device;
    this->packet = new pcpp::Packet(100);
    pcpp::EthLayer newEthernetLayer(device->getMacAddress(), gatewayMac);
    this->packet->addLayer(&newEthernetLayer);
    pcpp::IPv4Layer newIPLayer(device->getIPv4Address(), dst_ip);
    this->packet->addLayer(&newIPLayer);
    newIPLayer.getIPv4Header()->timeToLive = ttl;

    if(probe_type == ProbeType::TCP){
        pcpp::TcpLayer newTcpLayer = pcpp::TcpLayer(srcPort, dstPort);
        newTcpLayer.getTcpHeader()->sequenceNumber = htonl((uint32_t)ttl);
        newTcpLayer.getTcpHeader()->synFlag = 1;
        this->packet->addLayer(&newTcpLayer);
        this->packet->computeCalculateFields();// compute all calculated fields
    } else if (probe_type == ProbeType::UDP){
        throw std::runtime_error("UDP Probe not implemented yet!");
        pcpp::UdpLayer newUdpLayer(srcPort, dstPort);
        this->packet->addLayer(&newUdpLayer);
        this->packet->computeCalculateFields();// compute all calculated fields
    } else {
        throw std::runtime_error("Unknown probe type.");
    }
}

pcpp::Packet *Probe::getPacket() {
    return packet;
}

void Probe::send() {
    if(!this->packet){
        throw std::runtime_error("No packet to send!");
    }
    device->sendPacket(*this->packet->getRawPacket());
}


Probe::~Probe(){
    packet = nullptr;
    device = nullptr;
};
