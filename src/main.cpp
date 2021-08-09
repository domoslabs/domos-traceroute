#include "Probe.h"
#include "Traceroute.h"
#include "Utilities.h"
#include <PcapFileDevice.h>
#include <NetworkUtils.h>
#include "Capture.h"
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <getopt.h>

const char *target = nullptr;
ProbeType probeType = ProbeType::TCP;
uint16_t baseSrcPort = 33000;
uint16_t dstPort = 80;
uint16_t n_paths = 10;
uint16_t max_ttl = 15;
uint32_t n_runs = 3;
uint32_t interval_delay = 50;
uint32_t timeout_delay = 500;
const char *interface = nullptr;
const char *file = nullptr;
pcpp::PcapLiveDevice *device;

void show_help(char *progname) {
    std::cout
            << "\nA traceroute by Domos which can control per flow ECMP, and that way map paths to an endpoint. TCP only for now. \n"
            << std::endl;
    std::cout << "Usage: " << progname
              << " <target_host> [--sport] [--dport] [--ttl] [--n_paths] [--n_runs] [--interface] [--file] [--help]"
              << std::endl;
    std::cout << "target_host                     The hostname or IP of the target host" << std::endl;
    std::cout
            << "-s --sport                      A port which will define source port range used: [sport, sport+n_paths] Default is ("
            << baseSrcPort << ")" << std::endl;
    std::cout
            << "-d --dport                      The target destination port. For TCP, a good port is 80. For UDP a good port is 33434. Default is ("
            << dstPort << ")" << std::endl;
    std::cout << "-u --udp                        Use UDP probes instead. Uses TCP by default." << std::endl;
    std::cout << "-t --ttl                        The time-to-live value to count up to. Default is (" << max_ttl << ")"
              << std::endl;
    std::cout << "-p --n_paths                    Amount of paths to probe. Default is (" << n_paths << ")"
              << std::endl;
    std::cout << "-n --n_runs                     Amount of runs to perform. Default is (" << n_runs << ")"
              << std::endl;
    std::cout << "-I --interval                   Interval between probes (ms). Default is (" << interval_delay << ")"
              << std::endl;
    std::cout << "-T --timeout                    How long to wait for probes to return (ms). Default is ("
              << timeout_delay << ")" << std::endl;
    std::cout
            << "-i --interface                  The interface to use, given by name or IP. Finds and uses a interface with a default gateway by default."
            << std::endl;
    std::cout << "-f --file                       File name to save the results to. Optional." << std::endl;
    std::cout << "-h --help                       Show this message." << std::endl;
}

void parse_args(int argc, char **argv) {
    const char *shortopts = "s:d:ut:p:n:I:T:i:f:h";
    const struct option longopts[] = {
            {"sport",     required_argument, 0, 's'},
            {"dport",     required_argument, 0, 'd'},
            {"udp",       no_argument, 0, 'u'},
            {"ttl",       required_argument, 0, 't'},
            {"n_paths",   required_argument, 0, 'p'},
            {"n_runs",    required_argument, 0, 'n'},
            {"interval",  required_argument, 0, 'I'},
            {"timeout",   required_argument, 0, 'T'},
            {"interface", required_argument, 0, 'i'},
            {"file",      required_argument, 0, 'f'},
            {"help",      no_argument,       0, 'h'},
            {0, 0,                           0, 0},
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1)
        switch (c) {
            case 's':
                baseSrcPort = std::stoul(optarg);
                break;
            case 'd':
                dstPort = std::stoul(optarg);
                break;
            case 'u':
                probeType = ProbeType::UDP;
                break;
            case 't':
                max_ttl = std::stoul(optarg);
                break;
            case 'p':
                n_paths = std::stoul(optarg);
                break;
            case 'n':
                n_runs = std::stoul(optarg);
                break;
            case 'I':
                interval_delay = std::stoul(optarg);
                break;
            case 'T':
                timeout_delay = std::stoul(optarg);
                break;
            case 'i':
                interface = optarg;
                break;
            case 'f':
                file = optarg;
                break;
            case 'h':
                show_help(argv[0]);
                std::exit(EXIT_SUCCESS);
            default:
                std::cerr << "Invalid argument: " << c << ". See --help." << std::endl;
                std::exit(EXIT_FAILURE);
        }
    if (optind == argc) {
        std::cerr << "Missing target. See --help." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    target = argv[optind];
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        std::cerr << "Insufficient privileges, please run as root." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    parse_args(argc, argv);
    std::cout << "Status: Resolving...\r" << std::flush;
    if (interface == nullptr) {
        device = findDefaultDevice();
    } else {
        device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interface);
    }
    pcpp::MacAddress gatewayMac = getGatewayMac(device);
    pcpp::IPv4Address targetIp = pcpp::IPv4Address(target);
    if(!targetIp.isValid()){
        targetIp = resolveHostnameToIP(target, device);
        if (gatewayMac == pcpp::MacAddress::Zero || targetIp == pcpp::IPv4Address::Zero) {
            throw std::runtime_error("Could not resolve gateway mac or target ip.");
        }
    }

    device->open();
    // Populate the flows
    auto flows = new std::unordered_map<uint16_t, std::vector<ProbeRegister *>>();
    for (int srcPort = baseSrcPort; srcPort < baseSrcPort + n_paths; srcPort++) {
        std::vector<ProbeRegister *> flow;
        // Perform the traceroute backwards in order to bypass some weird network behaviour.
        // Because sometimes no SYN-ACK response is given if any of the previous nodes had their TTL reach 0.
        for (uint8_t ttl = max_ttl; ttl > 0; ttl--) {
            auto pr = new ProbeRegister(n_runs, ttl);
            flow.push_back(pr);
        }
        flows->insert({srcPort, flow});
    }
    auto *tr = new Traceroute(n_paths, max_ttl, probeType, flows);
    auto capture = new Capture(baseSrcPort, dstPort, n_paths, device);

    for (int run_idx = 0; run_idx < n_runs; run_idx++) {
        std::cout << "Status: Capturing... (" << run_idx + 1 << "/" << n_runs << ")\r" << std::flush;
        capture->startCapture();
        // Send out the probes, and sleep until we are done capturing
        tr->execute(baseSrcPort, targetIp, dstPort, gatewayMac, device, run_idx, interval_delay);
        // Sleep 1 sec while we capture in the other thread...
        usleep(timeout_delay * 1000);
        // Stop the capture
        device->stopCapture();
        // Analyze the captured packets
        tr->analyze(capture->getRawPackets(), run_idx);
    }
    device->close();
    // Create json
    std::string out = tr->to_json();
    // Write to file if file has been defined, otherwise write to terminal.
    if (file != nullptr) {
        std::ofstream file_id;
        file_id.open(file);

        file_id << out;

        file_id.close();
    } else {
        std::cout << out << std::endl;
    }

    return 0;
}
