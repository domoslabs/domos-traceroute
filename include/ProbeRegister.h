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
    uint16_t ttl = 0;

public:
    ProbeRegister(uint32_t n_runs, uint16_t ttl);

    void register_sent(std::shared_ptr<pcpp::Packet> packet, timespec timestamp, uint32_t idx);
    void register_received(std::shared_ptr<pcpp::Packet> packet, timespec timestamp, uint32_t idx);
    std::vector<unsigned int> * get_rtt();
    uint16_t get_flowhash();
    std::shared_ptr<pcpp::Packet> getFirstReceivedPacket();
    std::vector<std::shared_ptr<pcpp::Packet>> getSentPackets();
    Json::Value to_json();

    void setIsLast(bool isLast);

    bool isLast() const;

    uint16_t getTTL();
};


#endif //DOMOS_TRACEROUTE_PROBEREGISTER_H
