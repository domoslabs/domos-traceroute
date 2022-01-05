#include "Probe.h"
#include "Traceroute.h"
#include "Utilities.h"
#include <PcapFileDevice.h>
#include <NetworkUtils.h>
#include "Capture.h"
#include <iostream>
#include <unistd.h>
#include "third-party/random.hpp"
#include "third-party/CLI11.hpp"

using Random = effolkronium::random_static;
struct Args{
    std::string target;
    ProbeType probeType = ProbeType::TCP;
    uint16_t baseSrcPort = Random::get<uint16_t>(33000, 40000);
    uint16_t dstPort = 80;
    uint16_t n_paths = 10;
    uint16_t max_ttl = 20;
    uint32_t n_runs = 3;
    uint32_t interval_delay = 50;
    uint32_t timeout_delay = 500;
    std::string interface;
    std::string file;
    bool quiet = false;
    bool udp = false;
    pcpp::PcapLiveDevice *device = nullptr;
};

Args parse_args(int argc, char **argv) {
    Args args = {};
    CLI::App app{"Domos Traceroute"};
    app.option_defaults()->always_capture_default(true);
    app.add_option("address", args.target, "The hostname or IP of the target host.");
    app.add_option("-s, --sport", args.baseSrcPort, "A port which will define source port range used: [sport, sport+n_paths] Default is random in range [33000, 40000].");
    app.add_option("-d, --dport", args.dstPort, "The target destination port. For TCP, a good port is 80. For UDP a good port is 33434.");
    app.add_flag("-u, --udp", args.udp, "Use UDP probes instead of TCP.");
    app.add_option("-t, --ttl", args.max_ttl, "The time-to-live value to count up to.");
    app.add_option("-p, --paths", args.n_paths,"Amount of paths to probe.");
    app.add_option("-n", args.n_runs,"Amount of runs to perform.");
    app.add_option("-I, --interval", args.interval_delay,"Interval between probes (ms).");
    app.add_option("-T, --timeout", args.timeout_delay,"How long to wait for probes to return (ms).");
    app.add_option("-i, --interface", args.interface, "The interface to use, given by name or IP. Finds and uses a interface with a default gateway by default.");
    app.add_option("-f, --file", args.file, "File name to save the results to. Optional.");
    app.add_flag("-q, --quiet", args.quiet, "Run in quiet mode, meaning only the minimum will be printed.");


    try{
        app.parse(argc, argv);
    }catch(const CLI::ParseError &e) {
        std::exit((app).exit(e));
    }
    if(args.udp){
        args.probeType = ProbeType::UDP;
    }
    if (getuid() != 0) {
        std::cerr << "Insufficient privileges, please run as root." << std::endl;
        std::exit(EXIT_FAILURE);
    }
    return args;
}

int main(int argc, char *argv[]) {
    Args args = parse_args(argc, argv);
    if (!args.quiet)
        std::cout << "Status: Resolving...\r" << std::flush;
    if (args.interface.empty()) {
        args.device = findDefaultDevice();
    } else {
        args.device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(args.interface);
    }
    pcpp::MacAddress gatewayMac = getGatewayMac(args.device);
    auto targetIp = pcpp::IPv4Address(args.target);
    if (!targetIp.isValid()) {
        targetIp = getHostNameIpAddress(args.target.c_str());
        if (gatewayMac == pcpp::MacAddress::Zero || targetIp == pcpp::IPv4Address::Zero) {
            throw std::runtime_error("Could not resolve gateway mac or target ip.");
        }
    }

    args.device->open();
    // Populate the flows
    auto flows = new std::unordered_map<uint16_t, std::vector<ProbeRegister *>>();
    for (int srcPort = args.baseSrcPort; srcPort < args.baseSrcPort + args.n_paths; srcPort++) {
        std::vector<ProbeRegister *> flow;
        // Perform the traceroute backwards in order to bypass some weird network behaviour.
        // Because sometimes no SYN-ACK response is given if any of the previous nodes had their TTL reach 0.
        for (uint8_t ttl = args.max_ttl; ttl > 0; ttl--) {
            auto pr = new ProbeRegister(args.n_runs, ttl);
            flow.push_back(pr);
        }
        flows->insert({srcPort, flow});
    }
    auto *tr = new Traceroute(args.n_paths, args.max_ttl, args.probeType, flows);
    auto capture = new Capture(args.baseSrcPort, args.dstPort, args.n_paths, args.device);

    for (int run_idx = 0; run_idx < args.n_runs; run_idx++) {
        if (!args.quiet)
            std::cout << "Status: Capturing on base port " << std::to_string(args.baseSrcPort) << "... (" << run_idx + 1
                      << "/" << args.n_runs << ")\r" << std::flush;
        capture->startCapture();
        // Send out the probes, and sleep until we are done capturing
        tr->execute(args.baseSrcPort, targetIp, args.dstPort, gatewayMac, args.device, run_idx, args.interval_delay);
        // Sleep 1 sec while we capture in the other thread...
        usleep(args.timeout_delay * 1000);
        // Stop the capture
        args.device->stopCapture();
        // Analyze the captured packets
        tr->analyze(capture->getRawPackets(), run_idx);
    }
    args.device->close();


    // Create json
    std::string out = tr->to_json();
    // Write to file if file has been defined, otherwise write to terminal.
    if (!args.file.empty()) {
            std::ofstream file_id;
            file_id.open(args.file);
            file_id << out;
            file_id.close();
    } else {
        std::cout << out << std::endl;
    }
    return 0;
}
