//
// Created by vladim0105 on 07.07.2021.
//

#ifndef DOMOS_TRACEROUTE_PROBEREGISTER_H
#define DOMOS_TRACEROUTE_PROBEREGISTER_H
#include <Packet.h>
#include <json/json.h>
#include "Utilities.h"
class ProbeRegister {
private:
    std::vector<std::shared_ptr<pcpp::Packet>> sent_packets;
    std::vector<std::shared_ptr<pcpp::Packet>> received_packets;
    std::vector<timespec> sent_timestamps;
    std::vector<timespec> received_timestamps;
    bool is_last = false;
    std::shared_ptr<pcpp::Packet> getFirstReceivedPacket();
public:
    ProbeRegister(uint32_t n_runs);

    void register_sent(std::shared_ptr<pcpp::Packet> packet, timespec timestamp, uint32_t idx);
    void register_received(std::shared_ptr<pcpp::Packet> packet, timespec timestamp, uint32_t idx);
    std::vector<unsigned int> * get_rtt();
    uint16_t get_flowhash();

    std::vector<std::shared_ptr<pcpp::Packet>> getSentPacket();
    Json::Value to_json();

    void setIsLast(bool isLast);

    bool isLast() const;

};


#endif //DOMOS_TRACEROUTE_PROBEREGISTER_H
