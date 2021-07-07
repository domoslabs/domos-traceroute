//
// Created by vladim0105 on 05.07.2021.
//
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#ifndef DOMOS_TRACEROUTE_UTILITIES_H
#define DOMOS_TRACEROUTE_UTILITIES_H
pcpp::PcapLiveDevice *findDefaultDevice();
pcpp::MacAddress getGatewayMac(pcpp::PcapLiveDevice *device);
pcpp::IPv4Address resolveHostnameToIP(const char *hostname, pcpp::PcapLiveDevice *device);
#endif //DOMOS_TRACEROUTE_UTILITIES_H
