//
// Created by vladim0105 on 05.07.2021.
//

#include <unistd.h>
#include <iostream>
#include "Traceroute.h"
#include "Probe.h"
Traceroute::Traceroute(uint8_t n_paths, uint8_t max_ttl, ProbeType probeType) {
    this->n_paths = n_paths;
    this->max_ttl = max_ttl;
    this->probeType = probeType;
};
Traceroute::~Traceroute() = default;

void Traceroute::execute(uint16_t srcBasePort, const std::string &dstIp, uint16_t dstPort, pcpp::MacAddress gatewayMac,
                         pcpp::PcapLiveDevice *device) {
    for(int srcPort = srcBasePort; srcPort < srcBasePort+n_paths; srcPort++){
        for(int ttl = 1; ttl < max_ttl+1; ttl++){
            auto *probe = new Probe(dstIp, srcPort, dstPort, ttl, gatewayMac, device, this->probeType);
            probe->send();
            timespec sent_time{};
        }
        usleep(1000);
    }
}

void Traceroute::analyze(const pcpp::RawPacketVector& rawPackets) {
    for(auto rawPacket : rawPackets){
        pcpp::Packet packet(rawPacket);
        if(packet.isPacketOfType(pcpp::ICMP)){
            analyzeICMP(packet);
        } else if(packet.isPacketOfType(pcpp::TCP)){
            analyzeTCP(*packet.getLayerOfType<pcpp::TcpLayer>());
        } else {
            throw std::runtime_error("Wrong packet captured, this is a bug!");
        }
    }
}

void Traceroute::analyzeICMP(const pcpp::Packet& icmpPacket) {
    if(icmpPacket.isPacketOfType(pcpp::TCP)){
        std::exit(5);
    } else if (icmpPacket.isPacketOfType(pcpp::UDP)){
        throw std::runtime_error("UDP Analysis not yet implemented.");
    }
}

void Traceroute::analyzeTCP(const pcpp::TcpLayer& tcp) {

}
