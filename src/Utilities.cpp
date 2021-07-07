//
// Created by vladim0105 on 05.07.2021.
//

#include "Utilities.h"
#include <NetworkUtils.h>
pcpp::PcapLiveDevice *findDefaultDevice() {
    auto devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    for(auto device : devList){
        if(device->getDefaultGateway().isValid()){
            return device;
        }
    }
    return nullptr;
}

pcpp::MacAddress getGatewayMac(pcpp::PcapLiveDevice *device) {
    double _ = 0;
    return pcpp::NetworkUtils::getInstance().getMacAddress(device->getDefaultGateway(), device, _);
}

pcpp::IPv4Address resolveHostnameToIP(const char *hostname, pcpp::PcapLiveDevice *device) {
    double _ = 0;
    uint32_t _ttl = 0;
    return pcpp::NetworkUtils::getInstance().getIPv4Address(hostname, device, _, _ttl);
}
