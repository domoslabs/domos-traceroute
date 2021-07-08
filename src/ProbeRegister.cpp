//
// Created by vladim0105 on 07.07.2021.
//

#include <IPLayer.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <memory>
#include <iostream>
#include <Utilities.h>
#include "ProbeRegister.h"
void ProbeRegister::register_sent(pcpp::Packet &packet, timespec timestamp) {
    this->sent_packet = std::make_shared<pcpp::Packet>(packet);
    this->sent_timestamp = timestamp;
}
void ProbeRegister::register_received(pcpp::Packet &packet, timespec timestamp) {
    this->received_packet = std::make_shared<pcpp::Packet>(packet);
    this->received_timestamp = timestamp;
}

unsigned int ProbeRegister::get_rtt() {
    if(received_packet){
        timespec diff = timespec_diff(sent_timestamp, received_timestamp);
        return diff.tv_sec*1000000000+diff.tv_nsec;
    }
    return 0;
}

uint16_t ProbeRegister::get_flowhash() {
    uint16_t flowhash = 0;
    pcpp::IPv4Layer ip = *sent_packet->getLayerOfType<pcpp::IPv4Layer>();
    flowhash += ip.getIPv4Header()->typeOfService + ip.getIPv4Header()->protocol;
    flowhash += (uint32_t)(ip.getIPv4Header()->ipSrc);
    flowhash += (uint32_t)(ip.getIPv4Header()->ipDst);
    if(sent_packet->isPacketOfType(pcpp::TCP)){
        pcpp::TcpLayer tcp = *sent_packet->getLayerOfType<pcpp::TcpLayer>();
        flowhash += tcp.getTcpHeader()->portSrc + tcp.getTcpHeader()->portDst;
    } else if (sent_packet->isPacketOfType(pcpp::UDP)){
        pcpp::UdpLayer udp = *sent_packet->getLayerOfType<pcpp::UdpLayer>();
        flowhash += udp.getUdpHeader()->portSrc + udp.getUdpHeader()->portDst;
    }
    if (flowhash == 0)
        flowhash = 0xffff;
    return flowhash;
}

std::shared_ptr<pcpp::Packet> ProbeRegister::getSentPacket() const {
    return sent_packet;
}


