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

void ProbeRegister::register_sent(std::shared_ptr<pcpp::Packet> packet, timespec timestamp) {
    this->sent_packet = packet;
    this->sent_timestamp = timestamp;
}
void ProbeRegister::register_received(std::shared_ptr<pcpp::Packet> packet, timespec timestamp) {
    this->received_packet = packet;
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

void ProbeRegister::setIsLast(bool isLast) {
    is_last = isLast;
}

bool ProbeRegister::isLast() const {
    return is_last;
}

Json::Value ProbeRegister::to_json() {
    Json::Value root;
    Json::Value nullvalue;

    // Serialize the sent packet
    root["is_last"] = is_last;
    root["sent"]["timestamp"] = std::to_string(this->sent_timestamp.tv_sec) + "." + std::to_string(this->sent_timestamp.tv_nsec);

    // flow hash
    root["flowhash"] = get_flowhash();

    // IP layer
    auto sent_ip = sent_packet->getLayerOfType<pcpp::IPv4Layer>();
    root["sent"]["ip"]["src"] = sent_ip->getSrcIPv4Address().toString();
    root["sent"]["ip"]["dst"] = sent_ip->getDstIPv4Address().toString();
    root["sent"]["ip"]["ttl"] = sent_ip->getIPv4Header()->timeToLive;


    auto tcp_sent = sent_packet->getLayerOfType<pcpp::TcpLayer>();
    root["sent"]["sport"] = tcp_sent->getSrcPort();
    root["sent"]["dport"] = tcp_sent->getDstPort();


    // If present, serialize the received packet
    if (received_packet) {
        root["rtt_nsec"] = get_rtt();
        root["received"]["timestamp"] = std::to_string(received_timestamp.tv_sec) + "." + std::to_string(received_timestamp.tv_nsec);
        auto tcp_received = sent_packet->getLayerOfType<pcpp::TcpLayer>();
        root["received"]["sport"] = tcp_received->getSrcPort();
        root["received"]["dport"] = tcp_received->getDstPort();

        // IP layer
        auto received_ip = received_packet->getLayerOfType<pcpp::IPv4Layer>();
        root["received"]["ip"]["src"] = received_ip->getSrcIPv4Address().toString();
        root["received"]["ip"]["dst"] = received_ip->getDstIPv4Address().toString();
        root["received"]["ip"]["ttl"] = received_ip->getIPv4Header()->timeToLive;
    } else {
        root["received"] = nullvalue;
        root["rtt_nsec"] = nullvalue;
    }
    return root;
}


