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

Traceroute::Traceroute(uint8_t n_paths, uint8_t max_ttl, ProbeType probeType,
                       std::unordered_map<uint16_t, std::vector<ProbeRegister *>> *flows) {
    this->n_paths = n_paths;
    this->max_ttl = max_ttl;
    this->probeType = probeType;
    this->flows = flows;
};

Traceroute::~Traceroute() = default;

void Traceroute::execute(uint16_t srcBasePort, pcpp::IPv4Address dstIp, uint16_t dstPort, pcpp::MacAddress gatewayMac,
                         pcpp::PcapLiveDevice *device, uint32_t run_idx, uint32_t interval_delay) {
    for (int srcPort = srcBasePort; srcPort < srcBasePort + n_paths; srcPort++) {
        std::vector<ProbeRegister *> flow = this->flows->at(srcPort);
        // Perform the traceroute backwards in order to bypass some weird network behaviour.
        // Because sometimes no SYN-ACK response is given if any of the previous nodes had their TTL reach 0.
        for (uint8_t ttl = max_ttl; ttl > 0; ttl--) {
            auto *probe = new Probe(dstIp, srcPort, dstPort, ttl, gatewayMac, device, this->probeType, run_idx);
            probe->send();

            timespec sent_time{};
            clock_gettime(CLOCK_REALTIME, &sent_time);

            auto pr = flow.at(ttl - 1);
            pr->register_sent(std::make_shared<pcpp::Packet>(*probe->getPacket()), sent_time, run_idx);
            //Wait some time before sending the next probe, to avoid spamming them all at once.
            usleep(interval_delay * 1000);
        }
    }
}

void Traceroute::analyze(const std::vector<std::shared_ptr<pcpp::RawPacket>> &rawPackets, uint32_t run_idx) {
    for (const auto &rawPacket : rawPackets) {
        pcpp::Packet packet(rawPacket.get());
        if (packet.isPacketOfType(pcpp::ICMP)) {
            auto icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
            if (icmpLayer->isMessageOfType(pcpp::ICMP_TIME_EXCEEDED) ||
                icmpLayer->isMessageOfType(pcpp::ICMP_DEST_UNREACHABLE)) {
                if (probeType == ProbeType::TCP) {
                    analyzeICMPTCPResponse(&packet, run_idx);
                } else if (probeType == ProbeType::UDP) {
                    analyzeICMPUDPResponse(&packet, run_idx);
                }
            }
        } else if (packet.isPacketOfType(pcpp::TCP)) {
            analyzeTCPResponse(&packet, run_idx);
        } else {
            throw std::runtime_error("Wrong packet captured, this is a bug!");
        }
    }
}

void Traceroute::analyzeICMPTCPResponse(pcpp::Packet *receivedICMPPacket, uint32_t run_idx) {
    //IPv4 Layer = 20
    //TCP Layer should also be 20, but is sometimes truncated to only 8, we need to fix that here
    uint8_t *payload = receivedICMPPacket->getLayerOfType<pcpp::IcmpLayer>()->getLayerPayload();
    // TCP data starts at offset 20
    auto innerPacket = parseInnerTcpPacket(payload + 20, receivedICMPPacket);
    auto tcp = innerPacket->getLayerOfType<pcpp::TcpLayer>();
    uint16_t flow_id = tcp->getSrcPort();
    try {
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
    } catch (std::out_of_range &e) {
        //If we get here, means we have intercepted a wrong packet.
        return;
    }

}

void Traceroute::analyzeICMPUDPResponse(pcpp::Packet *receivedICMPPacket, uint32_t run_idx) {

    auto innerUdp = receivedICMPPacket->getLayerOfType<pcpp::UdpLayer>();
    auto innerIP = (pcpp::IPv4Layer *) innerUdp->getPrevLayer();
    uint16_t flow_id = innerUdp->getSrcPort();
    try {
        auto &probe_registers = flows->at(flow_id);
        for (auto &probe_register : probe_registers) {
            pcpp::UdpLayer sentUdp = *probe_register->getSentPackets().at(run_idx)->getLayerOfType<pcpp::UdpLayer>();
            // Here we compare the sent udp checksum with the received inner ip identification.
            // Paris traceroute originally compared udp checksum with udp checksum, but the checksum of the received inner UDP
            // can be rewritten when passing through NAT.
            // Therefore we look at the received inner ip identification, but keep in mind that this is not supported in IPv6.
            if (ntohs(sentUdp.getUdpHeader()->headerChecksum) == ntohs(innerIP->getIPv4Header()->ipId)) {
                probe_register->register_received(std::make_shared<pcpp::Packet>(*receivedICMPPacket),
                                                  receivedICMPPacket->getRawPacket()->getPacketTimeStamp(), run_idx);
                auto icmpLayer = receivedICMPPacket->getLayerOfType<pcpp::IcmpLayer>();
                if (icmpLayer->isMessageOfType(pcpp::ICMP_DEST_UNREACHABLE)) {
                    probe_register->setIsLast(true);
                }
            }
        }
    } catch (std::out_of_range &e) {
        // Sometimes we receive random UDP packets, just ignore them if their ports dont match.
        return;
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

bool sortByTTL(ProbeRegister *a, ProbeRegister *b) {
    return (a->getTTL() > b->getTTL());
}

void Traceroute::compress() {
    /**
     * Compress the traceroute graph by removing trailing unknowns at the end
     */
    for (auto &iter: *flows) {
        auto hops = iter.second;
        for (uint32_t i = hops.size() - 1; i > 0; i--) {
            auto hop = hops.at(i);
            auto next_hop = hops.at(i - 1);
            if (hop->getFirstReceivedPacket() == nullptr && next_hop->getFirstReceivedPacket() != nullptr) {
                hop->setIsLast(true);
                break;
            }
            // No trailing unknowns
            if (hop->getFirstReceivedPacket() != nullptr) {
                break;
            }
        }
    }
}

std::string Traceroute::to_json() {
    compress();
    Json::StreamWriterBuilder builder;
    builder["indentation"] = ""; // If you want whitespace-less output
    Json::Value root;
    for (auto &iter: *this->flows) {
        auto flow_id = std::to_string(iter.first);
        // Not sure if necessary to sort by ttl since I suspect the json already kinda does it, but why not...
        std::sort(iter.second.begin(), iter.second.end(), sortByTTL);
        Json::Value hops(Json::arrayValue);
        for (auto hop: iter.second) {
            hops.append(hop->to_json());
            if (hop->isLast())
                break;
        }
        root["flows"][flow_id] = hops;
    }
    return Json::writeString(builder, root);
}
