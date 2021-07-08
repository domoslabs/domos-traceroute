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
Traceroute::Traceroute(uint8_t n_paths, uint8_t max_ttl, ProbeType probeType) {
    this->n_paths = n_paths;
    this->max_ttl = max_ttl;
    this->probeType = probeType;
};
Traceroute::~Traceroute() = default;

void Traceroute::execute(uint16_t srcBasePort, pcpp::IPv4Address dstIp, uint16_t dstPort, pcpp::MacAddress gatewayMac,
                         pcpp::PcapLiveDevice *device) {
    for(int srcPort = srcBasePort; srcPort < srcBasePort+n_paths; srcPort++){
        std::vector<ProbeRegister> flow;
        for(uint8_t ttl = max_ttl; ttl > 0; ttl--){
            auto *probe = new Probe(dstIp, srcPort, dstPort, ttl, gatewayMac, device, this->probeType);
            probe->send();

            timespec sent_time{};
            clock_gettime(CLOCK_REALTIME, &sent_time);

            ProbeRegister pr = ProbeRegister();
            pr.register_sent(*probe->getPacket(), sent_time);

            flow.push_back(pr);
            //Wait some time before sending the next probe, to avoid spamming them all at once.
            usleep(200*1000);
        }
        this->flows.insert({srcPort, flow});
    }
}

void Traceroute::analyze(const std::vector<std::shared_ptr<pcpp::RawPacket>>& rawPackets) {
    for(const auto& rawPacket : rawPackets){
        pcpp::Packet packet(rawPacket.get());
        if(packet.isPacketOfType(pcpp::ICMP)){
            if(packet.getLayerOfType<pcpp::IcmpLayer>()->isMessageOfType(pcpp::ICMP_TIME_EXCEEDED)){
                analyzeICMPResponse(&packet);
            }
        } else if(packet.isPacketOfType(pcpp::TCP)){
            analyzeTCPResponse(&packet);
        } else {
            throw std::runtime_error("Wrong packet captured, this is a bug!");
        }
    }
}

void Traceroute::analyzeICMPResponse(pcpp::Packet *receivedICMPPacket) {
    // Make sure the ICMP response actually contains a TCP and is not some other random ICMP packet.
    if(receivedICMPPacket->isPacketOfType(pcpp::TCP)){
        //IPv4 Layer = 20
        //TCP Layer should also be 20, but is sometimes truncated to only 8, we need to fix that here
        uint8_t *payload = receivedICMPPacket->getLayerOfType<pcpp::IcmpLayer>()->getLayerPayload();
        // TCP data starts at offset 20
        auto icmpPacket = reconstructIncompleteTcpLayer(payload+20, receivedICMPPacket);
        auto tcp = icmpPacket->getLayerOfType<pcpp::TcpLayer>();
        uint16_t flow_id = tcp->getSrcPort();
        auto probe_registers = flows.at(flow_id);
        for(auto probe_register : probe_registers){
            pcpp::TcpLayer sentTcp = *probe_register.getSentPacket()->getLayerOfType<pcpp::TcpLayer>();
            uint32_t sentSeq = ntohl(sentTcp.getTcpHeader()->sequenceNumber);
            uint32_t receivedSeq = ntohl(tcp->getTcpHeader()->sequenceNumber);
            if(receivedSeq == sentSeq){
                probe_register.register_received(*icmpPacket, icmpPacket->getRawPacketReadOnly()->getPacketTimeStamp());
                std::cout << "ICMP" << std::endl;
                std::cout << probe_register.get_rtt()/1000000.0 << std::endl;
            }
        }
    } else if (receivedICMPPacket->isPacketOfType(pcpp::UDP)){
        throw std::runtime_error("UDP Analysis not yet implemented.");
    }
}

void Traceroute::analyzeTCPResponse(pcpp::Packet *tcpPacket) {
    auto *tcp = tcpPacket->getLayerOfType<pcpp::TcpLayer>();
    bool condition = (tcp->getTcpHeader()->rstFlag == 1) || (tcp->getTcpHeader()->ackFlag == 1);
    if(!condition){
        std::cout << "Unexpected TCP response." << std::endl;
        return;
    }
    uint16_t flow_id = tcp->getDstPort();
    auto probe_registers = flows.at(flow_id);
    for(auto probe_register : probe_registers){
        pcpp::TcpLayer sentTcp = *probe_register.getSentPacket()->getLayerOfType<pcpp::TcpLayer>();
        uint32_t sentSeq = ntohl(sentTcp.getTcpHeader()->sequenceNumber);
        uint32_t receivedAck = ntohl(tcp->getTcpHeader()->ackNumber);
        if(receivedAck-1 == sentSeq){
            std::cout << "TCP" << std::endl;
            probe_register.register_received(*tcpPacket, tcpPacket->getRawPacketReadOnly()->getPacketTimeStamp());
            std::cout << probe_register.get_rtt()/1000000.0 << std::endl;
        }
    }
}
