//
// Created by vladim0105 on 05.07.2021.
//

#include <DnsLayer.h>
#include <iostream>
#include <PcapLiveDeviceList.h>
#include <NetworkUtils.h>
#include <netinet/in.h>
#include <PayloadLayer.h>
#include "Probe.h"

Probe::Probe(pcpp::IPv4Address dst_ip, uint16_t srcPort, uint16_t dstPort, uint8_t ttl, pcpp::MacAddress gatewayMac,
             pcpp::PcapLiveDevice *device, ProbeType probe_type, uint32_t n_run) {
    this->device = device;
    this->packet = new pcpp::Packet(100);
    auto newEthernetLayer = new pcpp::EthLayer(device->getMacAddress(), gatewayMac);
    this->packet->addLayer(newEthernetLayer);
    auto newIPLayer = new pcpp::IPv4Layer(device->getIPv4Address(), dst_ip);
    this->packet->addLayer(newIPLayer);
    newIPLayer->getIPv4Header()->timeToLive = ttl;
    newIPLayer->getIPv4Header()->fragmentOffset = PCPP_IP_DONT_FRAGMENT;

    if (probe_type == ProbeType::TCP) {
        auto newTcpLayer = new pcpp::TcpLayer(srcPort, dstPort);
        newTcpLayer->getTcpHeader()->sequenceNumber = htonl(ttl);
        newTcpLayer->getTcpHeader()->synFlag = 1;
        // Important to disable timestamping, so that we receive SYN-ACK from the endpoint, and to avoid weird network behaviour.
        newTcpLayer->addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionType::PCPP_TCPOPT_TIMESTAMP, (uint16_t) false));
        newTcpLayer->addTcpOption(pcpp::TcpOptionBuilder(pcpp::TcpOptionType::PCPP_TCPOPT_SACK, (uint16_t) false));
        this->packet->addLayer(newTcpLayer);

        this->packet->computeCalculateFields();// compute all calculated fields
    } else if (probe_type == ProbeType::UDP) {

        auto newUdpLayer = new pcpp::UdpLayer(srcPort, dstPort);
        this->packet->addLayer(newUdpLayer);

        unsigned char payload[] = {'N', 'S', 'M', 'N', 'C', 0x00, 0x00};
        uint16_t identifier = srcPort + ttl;
        payload[5] = ((unsigned char *) &identifier)[0];
        payload[6] = ((unsigned char *) &identifier)[1];
        auto newPayloadLayer = new pcpp::PayloadLayer(payload, sizeof(payload), false);
        this->packet->addLayer(newPayloadLayer);
        this->packet->computeCalculateFields();// compute all calculated fields
        newIPLayer->getIPv4Header()->ipId = htons(newUdpLayer->calculateChecksum(false));
        this->packet->computeCalculateFields();// compute all calculated fields
    } else {
        throw std::runtime_error("Unknown probe type.");
    }
}

pcpp::Packet *Probe::getPacket() {
    return packet;
}

void Probe::send() {
    if (!this->packet) {
        throw std::runtime_error("No packet to send!");
    }
    device->sendPacket(*this->packet->getRawPacket());
}


Probe::~Probe() {
    packet = nullptr;
    device = nullptr;
};
