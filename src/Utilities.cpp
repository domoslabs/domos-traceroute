//
// Created by vladim0105 on 05.07.2021.
//

#include "Utilities.h"
#include <NetworkUtils.h>
#include <netinet/in.h>
#include <Probe.h>
#include <sstream>
#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <net/if.h>


int getDefaultGatewayAndInterface(in_addr_t *addr, char *interface) {
    long destination, gateway, flags, refcngt, use, metric, mask;
    char iface[IF_NAMESIZE];
    char buf[4096];
    FILE *file;

    memset(iface, 0, sizeof(iface));
    memset(buf, 0, sizeof(buf));

    file = fopen("/proc/net/route", "r");
    if (!file)
        return -1;

    while (fgets(buf, sizeof(buf), file)) {
        int a = sscanf(buf, "%s %lx %lx %lx %lx %lx %lx %lx", iface, &destination, &gateway, &flags, &refcngt, &use, &metric, &mask);
        if (a == 8) {
            if (destination == mask) { /* default */
                *addr = gateway;
                strcpy(interface, iface);
                fclose(file);
                return 0;
            }
        }
    }
    /* default route not found */
    if (file)
        fclose(file);
    return -1;
}

pcpp::PcapLiveDevice *findDefaultDevice() {
    in_addr_t addr = 0;
    char interface[IF_NAMESIZE];
    int res = getDefaultGatewayAndInterface(&addr, interface);
    if (res == -1) {
        std::cerr << "Unable to determine default gateway!" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    auto device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface);
    return device;
}

pcpp::MacAddress getGatewayMac(pcpp::PcapLiveDevice *device) {
    double _ = 0;
    return pcpp::NetworkUtils::getInstance().getMacAddress(device->getDefaultGateway(), device, _);
}


// Not used for now due to taking a long time. See getHostNameIpAddress() instead...
pcpp::IPv4Address resolveHostnameToIP(const char *hostname, pcpp::PcapLiveDevice *device) {
    double _ = 0;
    uint32_t _ttl = 0;
    return pcpp::NetworkUtils::getInstance().getIPv4Address(hostname, device, _, _ttl);
}

std::string getHostNameIpAddress(const char *a_domainName) {
    struct addrinfo hints{}, *res;
    int errcode;
    char addrstr[100];
    void *ptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    errcode = getaddrinfo(a_domainName, NULL, &hints, &res);
    if (errcode != 0) {
        std::cout << "getaddrinfo failed with error: " << errcode << std::endl;
        return "";
    }

    while (res) {
        switch (res->ai_family) {
            case AF_INET:
                ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
                inet_ntop(res->ai_family, ptr, addrstr, 100);
                break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                inet_ntop(res->ai_family, ptr, addrstr, 100);
                break;
        }

        res = res->ai_next;
    }

    return addrstr; // retuns wrong address as it interates past the domain name to the gateway ip
}

pcpp::Packet *parseInnerTcpPacket(uint8_t *tcpData, pcpp::Packet *original) {
    uint16_t src_port = 0;
    memcpy(&src_port, tcpData, sizeof(src_port));
    uint16_t dst_port = 0;
    memcpy(&dst_port, tcpData + sizeof(src_port), sizeof(dst_port));
    uint32_t seq = 0;
    memcpy(&seq, tcpData + sizeof(src_port) + sizeof(dst_port), sizeof(seq));
    auto originalEth = original->getLayerOfType<pcpp::EthLayer>();
    auto originalIp = original->getLayerOfType<pcpp::IPv4Layer>();
    auto packet = new pcpp::Packet(100);

    auto newEthernetLayer = new pcpp::EthLayer(originalEth->getSourceMac(), originalEth->getDestMac());
    packet->addLayer(newEthernetLayer);

    auto newIPLayer = new pcpp::IPv4Layer(originalIp->getSrcIPv4Address(), originalIp->getDstIPv4Address());
    newIPLayer->getIPv4Header()->timeToLive = originalIp->getIPv4Header()->timeToLive;
    packet->addLayer(newIPLayer);

    auto newTcpLayer = new pcpp::TcpLayer(ntohs(src_port), ntohs(dst_port));
    newTcpLayer->getTcpHeader()->sequenceNumber = seq;
    packet->addLayer(newTcpLayer);

    packet->computeCalculateFields();// compute all calculated fields
    packet->getRawPacket()->setPacketTimeStamp(original->getRawPacket()->getPacketTimeStamp());
    return packet;
}

timespec timespec_diff(timespec start, timespec end) {
    timespec temp{};
    if ((end.tv_nsec - start.tv_nsec) < 0) {
        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
        temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    } else {
        temp.tv_sec = end.tv_sec - start.tv_sec;
        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return temp;
}