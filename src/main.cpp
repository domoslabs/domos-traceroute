#include "Probe.h"
#include "Traceroute.h"
#include "Utilities.h"
#include <PcapFileDevice.h>
#include <NetworkUtils.h>
#include "Capture.h"
#include <iostream>
#include <unistd.h>
#include <fstream>
#include "effolkronium/random.hpp"
#include "argparse/argparse.hpp"

using Random = effolkronium::random_static;
// Default values
std::string target;
ProbeType probeType = ProbeType::TCP;
uint16_t baseSrcPort = Random::get<uint16_t>(33000, 40000);
uint16_t dstPort = 80;
uint16_t n_paths = 10;
uint16_t max_ttl = 15;
uint32_t n_runs = 3;
uint32_t interval_delay = 50;
uint32_t timeout_delay = 500;
std::string interface;
std::string file;
bool compress = false;
bool quiet = false;
bool udp = false;
pcpp::PcapLiveDevice *device;


void parse_args(int argc, char **argv) {
    argparse::ArgumentParser program("Domos Traceroute", "1.0.1");
    program.add_argument("target_host")
            .help("The hostname or IP of the target host.");
    program.add_argument("-s", "--sport")
            .help("A port which will define source port range used: [sport, sport+n_paths] Default is random in range [33000, 40000].")
            .scan<'u', uint16_t>();
    program.add_argument("-d", "--dport")
            .help("The target destination port. For TCP, a good port is 80. For UDP a good port is 33434.")
            .scan<'u', uint16_t>()
            .default_value(dstPort);
    program.add_argument("-u", "--udp")
            .help("Use UDP probes instead.")
            .default_value(udp)
            .implicit_value(!udp);
    program.add_argument("-t", "--ttl")
            .help("The time-to-live value to count up to.")
            .scan<'u', uint16_t>()
            .default_value(max_ttl);
    program.add_argument("-p", "--paths")
            .help("Amount of paths to probe.")
            .scan<'u', uint16_t>()
            .default_value(n_paths);
    program.add_argument("-n", "--n_runs")
            .help("Amount of runs to perform.")
            .scan<'i', uint32_t>()
            .default_value(n_runs);
    program.add_argument("-I", "--interval")
            .help("Interval between probes (ms).")
            .scan<'u', uint32_t>()
            .default_value(interval_delay);
    program.add_argument("-T", "--timeout")
            .help("How long to wait for probes to return (ms).")
            .scan<'u', uint32_t>()
            .default_value(timeout_delay);
    program.add_argument("-i", "--interface")
            .help("The interface to use, given by name or IP. Finds and uses a interface with a default gateway by default.");
    program.add_argument("-f", "--file")
            .help("File name to save the results to. Optional.");
    program.add_argument("-c", "--compress")
            .help(" Whether or not to compress the output file as bzip2. Optional.")
            .default_value(compress)
            .implicit_value(!compress);
    program.add_argument("-q", "--quiet")
            .help("Run in quiet mode, meaning only the minimum will be printed.")
            .default_value(quiet)
            .implicit_value(!quiet);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        exit(0);
    }
    target = program.get("target_host");
    if (program.is_used("--sport"))
        baseSrcPort = program.get<uint16_t>("--sport");

    dstPort = program.get<uint16_t>("--dport");
    n_paths = program.get<uint16_t>("--paths");
    max_ttl = program.get<uint16_t>("--ttl");
    n_runs = program.get<uint32_t>("--n_runs");
    interval_delay = program.get<uint32_t>("--interval");
    timeout_delay = program.get<uint32_t>("--timeout");
    if (program.is_used("--interface"))
        interface = program.get("--interface");
    if (program.is_used("--file"))
        file = program.get("--file");
    compress = program.get<bool>("--compress");
    quiet = program.get<bool>("--quiet");
    if (program["--udp"] == true) {
        probeType = ProbeType::UDP;
    }

    if (getuid() != 0) {
        std::cerr << "Insufficient privileges, please run as root." << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]) {
    parse_args(argc, argv);
    if (!quiet)
        std::cout << "Status: Resolving...\r" << std::flush;
    if (interface.empty()) {
        device = findDefaultDevice();
    } else {
        device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interface);
    }
    pcpp::MacAddress gatewayMac = getGatewayMac(device);
    auto targetIp = pcpp::IPv4Address(target);
    if (!targetIp.isValid()) {
        targetIp = getHostNameIpAddress(target.c_str());
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
        if (!quiet)
            std::cout << "Status: Capturing on base port " << std::to_string(baseSrcPort) << "... (" << run_idx + 1
                      << "/" << n_runs << ")\r" << std::flush;
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
    if (!file.empty()) {
        if (compress) {
            std::string compressedFile = file;
            compressedFile += ".bz2";
            compressBZ2(out, compressedFile.c_str());
        } else {
            std::ofstream file_id;
            file_id.open(file);
            file_id << out;
            file_id.close();
        }
    } else {
        std::cout << out << std::endl;
    }
    return 0;
}
