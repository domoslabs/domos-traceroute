//
// Created by vladim0105 on 05.07.2021.
//

#ifndef DOMOS_TRACEROUTE_TRACEROUTE_H
#define DOMOS_TRACEROUTE_TRACEROUTE_H


#include <cstdint>
#include "Probe.h"
#include <IcmpLayer.h>
#include <unordered_map>
#include "ProbeRegister.h"
class Traceroute {
private:
    uint8_t n_paths;
    uint8_t max_ttl;
    ProbeType probeType;
    std::unordered_map<uint16_t, std::vector<ProbeRegister>> flows;
    void analyzeTCPResponse(pcpp::Packet *tcpPacket);
    void analyzeICMPResponse(pcpp::Packet* icmpPacket);
public:
    Traceroute(uint8_t n_paths, uint8_t max_ttl, ProbeType probeType);
    void execute(uint16_t srcBasePort, pcpp::IPv4Address dstIp, uint16_t dstPort, pcpp::MacAddress gatewayMac,
                 pcpp::PcapLiveDevice *device);
    void analyze(const std::vector<std::shared_ptr<pcpp::RawPacket>>& rawPackets);
    ~Traceroute();

};


#endif //DOMOS_TRACEROUTE_TRACEROUTE_H
