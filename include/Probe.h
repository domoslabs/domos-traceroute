//
// Created by vladim0105 on 05.07.2021.
//

#ifndef DOMOS_TRACEROUTE_PROBE_H
#define DOMOS_TRACEROUTE_PROBE_H
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PcapLiveDevice.h>
#include <memory>
enum ProbeType {
    TCP,
    UDP
};
class Probe {
private:
    pcpp::Packet *packet = nullptr;
    pcpp::PcapLiveDevice *device = nullptr;
public:
    Probe(pcpp::IPv4Address dst_ip, uint16_t srcPort, uint16_t dstPort, uint8_t ttl, pcpp::MacAddress gatewayMac,
          pcpp::PcapLiveDevice *device, ProbeType probe_type, uint32_t n_run);
    ~Probe();
    void send();

    pcpp::Packet *getPacket();
};


#endif //DOMOS_TRACEROUTE_PROBE_H
