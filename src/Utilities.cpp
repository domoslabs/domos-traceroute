//
// Created by vladim0105 on 05.07.2021.
//

#include "Utilities.h"
#include <NetworkUtils.h>
#include <netinet/in.h>
#include <Probe.h>

pcpp::PcapLiveDevice *findDefaultDevice() {
    auto devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for(auto device : devList){
        if(device->getDefaultGateway().isValid()){
            return device;
        }
    }
    return nullptr;
}

pcpp::MacAddress getGatewayMac(pcpp::PcapLiveDevice *device) {
    double _ = 0;
    return pcpp::NetworkUtils::getInstance().getMacAddress(device->getDefaultGateway(), device, _);
}

pcpp::IPv4Address resolveHostnameToIP(const char *hostname, pcpp::PcapLiveDevice *device) {
    double _ = 0;
    uint32_t _ttl = 0;
    return pcpp::NetworkUtils::getInstance().getIPv4Address(hostname, device, _, _ttl);
}

pcpp::Packet * reconstructIncompleteTcpLayer(uint8_t *tcpData, pcpp::Packet *original) {
    uint16_t src_port = 0;
    memcpy(&src_port, tcpData, sizeof(src_port));
    uint16_t dst_port = 0;
    memcpy(&dst_port, tcpData + sizeof(src_port), sizeof(dst_port ));
    uint32_t seq = 0;
    memcpy(&seq, tcpData + sizeof(src_port) + sizeof(dst_port), sizeof(seq));
    auto originalEth = original->getLayerOfType<pcpp::EthLayer>();
    auto originalIp = original->getLayerOfType<pcpp::IPv4Layer>();
    auto packet = new pcpp::Packet(100);

    auto newEthernetLayer = new pcpp::EthLayer(originalEth->getSourceMac(), originalEth->getDestMac());
    packet->addLayer(newEthernetLayer);

    auto newIPLayer = new pcpp::IPv4Layer(originalIp->getSrcIPv4Address(), originalIp->getDstIPv4Address());
    packet->addLayer(newIPLayer);

    auto newTcpLayer = new pcpp::TcpLayer(ntohs(src_port), ntohs(dst_port));
    newTcpLayer->getTcpHeader()->sequenceNumber = seq;
    packet->addLayer(newTcpLayer);

    packet->computeCalculateFields();// compute all calculated fields
    packet->getRawPacket()->setPacketTimeStamp(original->getRawPacket()->getPacketTimeStamp());
    return packet;
}
timespec timespec_diff(timespec start, timespec end)
{
    timespec temp{};
    if ((end.tv_nsec-start.tv_nsec)<0) {
        temp.tv_sec = end.tv_sec-start.tv_sec-1;
        temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    } else {
        temp.tv_sec = end.tv_sec-start.tv_sec;
        temp.tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return temp;
}
