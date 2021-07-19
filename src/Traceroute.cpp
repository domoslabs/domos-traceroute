//
// Created by vladim0105 on 05.07.2021.
//

#include <unistd.h>
#include <iostream>
#include <netinet/in.h>
#include <PcapFileDevice.h>
#include <Utilities.h>
#include "Traceroute.h"
#include "Probe.h"

Traceroute::Traceroute(uint32_t n_runs, uint8_t n_paths, uint8_t max_ttl, ProbeType probeType,
                       std::unordered_map<uint16_t, std::vector<ProbeRegister*>> *flows) {
    this->n_runs = n_runs;
    this->n_paths = n_paths;
    this->max_ttl = max_ttl;
    this->probeType = probeType;
    this->flows = flows;
};

Traceroute::~Traceroute() = default;

void Traceroute::execute(uint16_t srcBasePort, pcpp::IPv4Address dstIp, uint16_t dstPort, pcpp::MacAddress gatewayMac,
                         pcpp::PcapLiveDevice *device, uint32_t run_idx) {
    for (int srcPort = srcBasePort; srcPort < srcBasePort + n_paths; srcPort++) {
        std::vector<ProbeRegister*> flow = this->flows->at(srcPort);
        // Perform the traceroute backwards in order to bypass some weird network behaviour.
        // Because sometimes no SYN-ACK response is given if any of the previous nodes had their TTL reach 0.
        for (uint8_t ttl = max_ttl; ttl > 0; ttl--) {
            auto *probe = new Probe(dstIp, srcPort, dstPort, ttl, gatewayMac, device, this->probeType, run_idx);
            probe->send();

            timespec sent_time{};
            clock_gettime(CLOCK_REALTIME, &sent_time);

            auto pr = flow.at(ttl-1);
            pr->register_sent(std::make_shared<pcpp::Packet>(*probe->getPacket()), sent_time, run_idx);
            //Wait some time before sending the next probe, to avoid spamming them all at once.
            usleep(40 * 1000);
        }
    }


}

void Traceroute::analyze(const std::vector<std::shared_ptr<pcpp::RawPacket>> &rawPackets, uint32_t run_idx) {
    for (const auto &rawPacket : rawPackets) {
        pcpp::Packet packet(rawPacket.get());
        if (packet.isPacketOfType(pcpp::ICMP)) {
            if (packet.getLayerOfType<pcpp::IcmpLayer>()->isMessageOfType(pcpp::ICMP_TIME_EXCEEDED)) {
                analyzeICMPResponse(&packet, run_idx);
            }
        } else if (packet.isPacketOfType(pcpp::TCP)) {
            analyzeTCPResponse(&packet, run_idx);
        } else {
            throw std::runtime_error("Wrong packet captured, this is a bug!");
        }
    }
}

void Traceroute::analyzeICMPResponse(pcpp::Packet *receivedICMPPacket, uint32_t run_idx) {
    //IPv4 Layer = 20
    //TCP Layer should also be 20, but is sometimes truncated to only 8, we need to fix that here
    uint8_t *payload = receivedICMPPacket->getLayerOfType<pcpp::IcmpLayer>()->getLayerPayload();
    // TCP data starts at offset 20
    auto innerPacket = parseInnerTcpPacket(payload + 20, receivedICMPPacket);
    auto tcp = innerPacket->getLayerOfType<pcpp::TcpLayer>();
    uint16_t flow_id = tcp->getSrcPort();
    auto &probe_registers = flows->at(flow_id);
    for (auto &probe_register : probe_registers) {
        pcpp::TcpLayer sentTcp = *probe_register->getSentPackets().at(run_idx)->getLayerOfType<pcpp::TcpLayer>();
        uint32_t sentSeq = ntohl(sentTcp.getTcpHeader()->sequenceNumber);
        uint32_t receivedSeq = ntohl(tcp->getTcpHeader()->sequenceNumber);
        if (receivedSeq == sentSeq) {
            probe_register->register_received(std::make_shared<pcpp::Packet>(*innerPacket),
                                             receivedICMPPacket->getRawPacket()->getPacketTimeStamp(), run_idx);
        }
    }
}

void Traceroute::analyzeTCPResponse(pcpp::Packet *tcpPacket, uint32_t run_idx) {
    auto tcp = tcpPacket->getLayerOfType<pcpp::TcpLayer>();
    bool condition = (tcp->getTcpHeader()->rstFlag == 1) || (tcp->getTcpHeader()->ackFlag == 1);
    if (!condition) {
        std::cout << "Unexpected TCP response." << std::endl;
        return;
    }
    uint16_t flow_id = tcp->getDstPort();
    auto &probe_registers = flows->at(flow_id);
    for (auto &probe_register : probe_registers) {
        pcpp::TcpLayer sentTcp = *probe_register->getSentPackets().at(run_idx)->getLayerOfType<pcpp::TcpLayer>();
        uint32_t sentSeq = ntohl(sentTcp.getTcpHeader()->sequenceNumber);
        uint32_t receivedAck = ntohl(tcp->getTcpHeader()->ackNumber);
        if (receivedAck - 1 == sentSeq) {
            probe_register->register_received(std::make_shared<pcpp::Packet>(*tcpPacket),
                                             tcpPacket->getRawPacket()->getPacketTimeStamp(), run_idx);
            probe_register->setIsLast(true);
        }
    }
}
bool sortByTTL(ProbeRegister* a, ProbeRegister* b){
    return (a->getTTL() > b->getTTL());
}
void Traceroute::compress() {
    /**
     * Compress the traceroute graph by removing trailing unknowns at the end
     */
    for (auto &iter: *flows) {
        auto hops = iter.second;
        for (uint32_t i = hops.size()-1; i >= 1; i--) {
            auto hop = hops.at(i);
            auto next_hop = hops.at(i-1);
            if (hop->getFirstReceivedPacket() == nullptr && next_hop->getFirstReceivedPacket() != nullptr) {
                hop->setIsLast(true);
                break;
            }
        }
    }
}
std::string Traceroute::to_json() {
    //compress();
    std::stringstream json;
    Json::Value root;

    for (auto &iter: *this->flows) {

        auto flow_id = std::to_string(iter.first);
        //Necessary since we are tracerouting backwards
        //std::reverse(iter.second.begin(), iter.second.end());
        std::sort(iter.second.begin(), iter.second.end(), sortByTTL);
        Json::Value hops(Json::arrayValue);
        for (auto hop: iter.second) {
            hops.append(hop->to_json());
            if (hop->isLast())
                break;
        }
        root["flows"][flow_id] = hops;
    }

    json << root;
    return json.str();
}
