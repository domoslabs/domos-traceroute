//
// Created by vladim0105 on 05.07.2021.
//

#ifndef DOMOS_TRACEROUTE_TRACEROUTE_H
#define DOMOS_TRACEROUTE_TRACEROUTE_H


#include <cstdint>
#include "Probe.h"
#include <IcmpLayer.h>
class Traceroute {
private:
    uint8_t n_paths;
    uint8_t max_ttl;
    ProbeType probeType;
    void analyzeTCP(const pcpp::TcpLayer& tcp);
    void analyzeICMP(const pcpp::Packet& icmpPacket);
public:
    Traceroute(uint8_t n_paths, uint8_t max_ttl, ProbeType probeType);
    void execute(uint16_t srcBasePort, const std::string &dstIp, uint16_t dstPort, pcpp::MacAddress gatewayMac,
                 pcpp::PcapLiveDevice *device);
    void analyze(const pcpp::RawPacketVector& rawPackets);
    ~Traceroute();

};


#endif //DOMOS_TRACEROUTE_TRACEROUTE_H
