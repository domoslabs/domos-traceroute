//
// Created by vladim0105 on 07.07.2021.
//

#ifndef DOMOS_TRACEROUTE_PROBEREGISTER_H
#define DOMOS_TRACEROUTE_PROBEREGISTER_H
#include <Packet.h>

class ProbeRegister {
private:
    std::shared_ptr<pcpp::Packet> sent_packet = nullptr;
    std::shared_ptr<pcpp::Packet> received_packet = nullptr;
    timespec sent_timestamp{};
    timespec received_timestamp{};
public:
    void register_sent(pcpp::Packet &packet, timespec timestamp);
    void register_received(pcpp::Packet &packet, timespec timestamp);
    unsigned int get_rtt();
    uint16_t get_flowhash();

    std::shared_ptr<pcpp::Packet> getSentPacket() const;
};


#endif //DOMOS_TRACEROUTE_PROBEREGISTER_H
