//
// Created by vladim0105 on 07.07.2021.
//

#ifndef DOMOS_TRACEROUTE_CAPTURE_H
#define DOMOS_TRACEROUTE_CAPTURE_H


#include <Device.h>
#include <PcapLiveDevice.h>
#include <memory>

class Capture {
private:
    pcpp::PcapLiveDevice *device;

    static void onPacketCaptured(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie);

public:
    Capture(uint16_t baseSrcPort, uint16_t dstPort, uint16_t n_paths, pcpp::PcapLiveDevice *device);

    std::vector<std::shared_ptr<pcpp::RawPacket>> getRawPackets();

    void startCapture();
};


#endif //DOMOS_TRACEROUTE_CAPTURE_H
