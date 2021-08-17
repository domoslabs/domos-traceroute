//
// Created by vladim0105 on 05.07.2021.
//
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <TcpLayer.h>
#include <sstream>

#ifndef DOMOS_TRACEROUTE_UTILITIES_H
#define DOMOS_TRACEROUTE_UTILITIES_H
struct IncompleteTCP {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
};

pcpp::PcapLiveDevice *findDefaultDevice();

pcpp::MacAddress getGatewayMac(pcpp::PcapLiveDevice *device);

pcpp::IPv4Address resolveHostnameToIP(const char *hostname, pcpp::PcapLiveDevice *device);

pcpp::Packet *parseInnerTcpPacket(uint8_t *tcpData, pcpp::Packet *original);

std::string getHostNameIpAddress(const char *a_domainName);

void compressBZ2(const std::string &data, const char *filename);

timespec timespec_diff(timespec start, timespec end);

template<typename T>
inline std::string array_to_string(std::vector<T> array) {
    std::stringstream ss;
    copy(array.begin(), array.end(), std::ostream_iterator<T>(ss, ","));
    std::string s = ss.str();
    s = s.substr(0, s.length() - 1);  // get rid of the trailing comma
    return s;
}

#endif //DOMOS_TRACEROUTE_UTILITIES_H
