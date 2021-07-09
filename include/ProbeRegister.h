//
// Created by vladim0105 on 07.07.2021.
//

#ifndef DOMOS_TRACEROUTE_PROBEREGISTER_H
#define DOMOS_TRACEROUTE_PROBEREGISTER_H
#include <Packet.h>
#include <json/json.h>
class ProbeRegister {
private:
    std::shared_ptr<pcpp::Packet> sent_packet;
    std::shared_ptr<pcpp::Packet> received_packet;
    timespec sent_timestamp{};
    timespec received_timestamp{};
    bool is_last = false;
public:
    void register_sent(std::shared_ptr<pcpp::Packet> packet, timespec timestamp);
    void register_received(std::shared_ptr<pcpp::Packet> packet, timespec timestamp);
    unsigned int get_rtt();
    uint16_t get_flowhash();

    std::shared_ptr<pcpp::Packet> getSentPacket() const;
    Json::Value to_json();

    void setIsLast(bool isLast);

    bool isLast() const;
};


#endif //DOMOS_TRACEROUTE_PROBEREGISTER_H
