//
// Created by vladim0105 on 05.07.2021.
//
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <TcpLayer.h>

#ifndef DOMOS_TRACEROUTE_UTILITIES_H
#define DOMOS_TRACEROUTE_UTILITIES_H
struct IncompleteTCP{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
};
pcpp::PcapLiveDevice *findDefaultDevice();
pcpp::MacAddress getGatewayMac(pcpp::PcapLiveDevice *device);
pcpp::IPv4Address resolveHostnameToIP(const char *hostname, pcpp::PcapLiveDevice *device);
pcpp::Packet * parseInnerTcpPacket(uint8_t *tcpData, pcpp::Packet *original);
timespec timespec_diff(timespec start, timespec end);
#endif //DOMOS_TRACEROUTE_UTILITIES_H
