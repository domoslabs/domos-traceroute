//
// Created by vladim0105 on 07.07.2021.
//

#include <IPLayer.h>
#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <memory>
#include <utility>
#include "ProbeRegister.h"

ProbeRegister::ProbeRegister(uint32_t n_runs, uint16_t ttl) {
    this->sent_packets = std::vector<std::shared_ptr<pcpp::Packet>>(n_runs, nullptr);
    this->received_packets = std::vector<std::shared_ptr<pcpp::Packet>>(n_runs, nullptr);
    this->sent_timestamps = std::vector<timespec>(n_runs);
    this->received_timestamps = std::vector<timespec>(n_runs);
    this->ttl = ttl;
}

void ProbeRegister::register_sent(std::shared_ptr<pcpp::Packet> packet, timespec timestamp, uint32_t idx) {
    this->sent_packets.at(idx) = std::move(packet);
    this->sent_timestamps.at(idx) = timestamp;
}

void ProbeRegister::register_received(std::shared_ptr<pcpp::Packet> packet, timespec timestamp, uint32_t idx) {
    this->received_packets.at(idx) = std::move(packet);
    this->received_timestamps.at(idx) = timestamp;
}

std::vector<unsigned int> *ProbeRegister::get_rtt() {
    auto rtts = new std::vector<unsigned int>();
    for (int i = 0; i < sent_packets.size(); i++) {
        auto sent_packet = sent_packets.at(i);
        auto recv_packet = received_packets.at(i);
        if (recv_packet == nullptr) {
            rtts->push_back(0);
            continue;
        }
        timespec diff = timespec_diff(sent_timestamps.at(i), received_timestamps.at(i));
        rtts->push_back(diff.tv_sec * 1000000000 + diff.tv_nsec);
    }

    return rtts;
}

uint16_t ProbeRegister::get_flowhash() {
    uint16_t flowhash = 0;
    pcpp::IPv4Layer ip = *sent_packets.front()->getLayerOfType<pcpp::IPv4Layer>();
    flowhash += ip.getIPv4Header()->typeOfService + ip.getIPv4Header()->protocol;
    flowhash += (uint32_t) (ip.getIPv4Header()->ipSrc);
    flowhash += (uint32_t) (ip.getIPv4Header()->ipDst);
    if (sent_packets.front()->isPacketOfType(pcpp::TCP)) {
        pcpp::TcpLayer tcp = *sent_packets.front()->getLayerOfType<pcpp::TcpLayer>();
        flowhash += tcp.getTcpHeader()->portSrc + tcp.getTcpHeader()->portDst;
    } else if (sent_packets.front()->isPacketOfType(pcpp::UDP)) {
        pcpp::UdpLayer udp = *sent_packets.front()->getLayerOfType<pcpp::UdpLayer>();
        flowhash += udp.getUdpHeader()->portSrc + udp.getUdpHeader()->portDst;
    }
    if (flowhash == 0)
        flowhash = 0xffff;
    return flowhash;
}

std::vector<std::shared_ptr<pcpp::Packet>> ProbeRegister::getSentPackets() {
    return sent_packets;
}

void ProbeRegister::setIsLast(bool isLast) {
    is_last = isLast;
}

bool ProbeRegister::isLast() const {
    return is_last;
}

std::shared_ptr<pcpp::Packet> ProbeRegister::getFirstReceivedPacket() {
    for (auto packet : this->received_packets) {
        if (packet != nullptr) {
            return packet;
        }
    }
    return nullptr;
}

Json::Value ProbeRegister::to_json() {
    Json::Value root;
    Json::Value nullvalue;

    // Serialize the sent packet
    root["is_last"] = is_last;
    //root["sent"]["timestamp"] = std::to_string(this->sent_timestamps.tv_sec) + "." + std::to_string(this->sent_timestamps.tv_nsec);

    // flow hash
    root["flowhash"] = get_flowhash();

    // IP layer
    auto sent_ip = sent_packets.front()->getLayerOfType<pcpp::IPv4Layer>();
    root["sent"]["ip"]["src"] = sent_ip->getSrcIPv4Address().toString();
    root["sent"]["ip"]["dst"] = sent_ip->getDstIPv4Address().toString();
    root["sent"]["ip"]["ttl"] = sent_ip->getIPv4Header()->timeToLive;


    auto tcp_sent = sent_packets.front()->getLayerOfType<pcpp::TcpLayer>();
    auto udp_sent = sent_packets.front()->getLayerOfType<pcpp::UdpLayer>();
    if (tcp_sent) {
        root["sent"]["sport"] = tcp_sent->getSrcPort();
        root["sent"]["dport"] = tcp_sent->getDstPort();
        root["type"] = "tcp";
    } else if (udp_sent) {
        root["sent"]["sport"] = udp_sent->getSrcPort();
        root["sent"]["dport"] = udp_sent->getDstPort();
        root["type"] = "udp";
    }

    Json::Value sent_timespecs = Json::Value(Json::arrayValue);
    for (timespec ts: this->sent_timestamps) {
        sent_timespecs.append(std::to_string(ts.tv_sec) + "." + std::to_string(ts.tv_nsec));
    }
    root["sent"]["timestamp"] = sent_timespecs;
    // If present, serialize the received packet
    auto first_recv = getFirstReceivedPacket();
    if (first_recv != nullptr) {
        Json::Value rtts = Json::Value(Json::arrayValue);
        for (unsigned int rtt : *get_rtt()) {
            if (rtt == 0) {
                rtts.append(-1);
            } else {
                rtts.append(rtt);
            }
        }
        Json::Value recv_timespecs = Json::Value(Json::arrayValue);
        for (int i = 0; i < received_packets.size(); i++) {
            timespec ts = received_timestamps.at(i);
            if (received_packets.at(i) == nullptr) {
                recv_timespecs.append("-1.0");
            } else {
                recv_timespecs.append(std::to_string(ts.tv_sec) + "." + std::to_string(ts.tv_nsec));
            }
        }
        root["received"]["timestamp"] = recv_timespecs;
        root["nsec_rtt"] = rtts;
        auto tcp_received = first_recv->getLayerOfType<pcpp::TcpLayer>();
        auto udp_received = first_recv->getLayerOfType<pcpp::UdpLayer>();
        // Values are switched because we are receiving...
        if (tcp_received) {
            root["received"]["sport"] = tcp_received->getDstPort();
            root["received"]["dport"] = tcp_received->getSrcPort();
        } else if (udp_received) {
            root["received"]["sport"] = udp_received->getDstPort();
            root["received"]["dport"] = udp_received->getSrcPort();
        }

        // IP layer
        auto received_ip = first_recv->getLayerOfType<pcpp::IPv4Layer>();
        root["received"]["ip"]["src"] = received_ip->getSrcIPv4Address().toString();
        root["received"]["ip"]["dst"] = received_ip->getDstIPv4Address().toString();
        root["received"]["ip"]["ttl"] = received_ip->getIPv4Header()->timeToLive;
    } else {
        root["received"] = nullvalue;
        root["nsec_rtt"] = nullvalue;
    }
    return root;
}

uint16_t ProbeRegister::getTTL() {
    return ttl;
}



