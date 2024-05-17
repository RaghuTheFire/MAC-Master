#include <iostream>
#include <fstream>
#include <regex>
#include <random>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <colorama.h>

using namespace std;

void show_version() 
{
    cout << "MacMaster Version: " << __version__ << endl;
}

void analyze_signal_strength(const char* interface) 
{
    try {
        string iwconfig_output = exec_command("iwconfig " + string(interface));
        // Signal strength and quality regex patterns
        regex signal_strength_pattern("Signal level=(-?\\d+ dBm)");
        regex quality_pattern("Link Quality=(\\d+/\\d+)");

        smatch signal_strength_match;
        smatch quality_match;

        if (regex_search(iwconfig_output, signal_strength_match, signal_strength_pattern)) {
            string signal_strength = signal_strength_match.str(1);
            cout << "Signal Strength on " << interface << ": " << signal_strength << endl;
        } else {
            cout << "Could not determine signal strength on " << interface << "." << endl;
        }

        if (regex_search(iwconfig_output, quality_match, quality_pattern)) {
            string quality = quality_match.str(1);
            cout << "Link Quality on " << interface << ": " << quality << endl;
        } else {
            cout << "Could not determine link quality on " << interface << "." << endl;
        }
    } catch (const exception& e) {
        cout << "Failed to get signal information for " << interface << ". Make sure it's a wireless interface." << endl;
    }
}

void get_ssid(const char* interface) {
    try {
        string ssid_output = exec_command("iwgetid " + string(interface) + " -r");
        string ssid = trim(ssid_output);
        if (!ssid.empty()) {
            cout << "\033[34mConnected SSID on\033[0m " << interface << ": " << ssid << endl;
        } else {
            cout << "No SSID found on " << interface << "." << endl;
        }
    } catch (const exception& e) {
        cout << "\033[31mCould not retrieve SSID for " << interface << ". Make sure it's a wireless interface.\033[0m" << endl;
    }
}

void check_network_security(const char* interface) {
    try {
        string scan_output = exec_command("sudo iwlist " + string(interface) + " scan");
        map<string, string> security_patterns = {
            {"WEP", "Encryption key:on"},
            {"WPA", "WPA Version"},
            {"WPA2", "WPA2 Version"}
        };
        for (const auto& pattern : security_patterns) {
            if (regex_search(scan_output, regex(pattern.second))) {
                cout << pattern.first << " security detected on " << interface << "." << endl;
                return;
            }
        }
        cout << "No recognized security protocols found on " << interface << "." << endl;
    } catch (const exception& e) {
        cout << "\033[31mCould not scan " << interface << " for security protocols. Make sure it's a wireless interface.\033[0m" << endl;
    }
}

void packet_callback(const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header* eth_header = (struct ether_header*)packet;
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    char source_mac[18];
    char destination_mac[18];
    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];

    snprintf(source_mac, sizeof(source_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
             eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    snprintf(destination_mac, sizeof(destination_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
             eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), destination_ip, INET_ADDRSTRLEN);

    cout << "\033[32mSource Mac     :\033[0m " << source_mac << " ==> \033[32mSource IP:\033[0m " << source_ip << endl;
    cout << "\033[32mDestination Mac:\033[0m " << destination_mac << " ==> \033[32mSource IP:\033[0m " << destination_ip << endl;
}

void start_traffic_monitoring(const char* interface) {
    cout << "\033[34mMonitoring network traffic on\033[0m " << "\033[32m" << interface << "...\033[0m" << endl;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char* packet;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cout << "\033[31mFailed to open interface " << interface << " for packet capture.\033[0m" << endl;
        return;
    }

    pcap_loop(handle, -1, packet_callback, NULL);
    pcap_close(handle);
}

void packet_analysis_callback(const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header* eth_header = (struct ether_header*)packet;
    struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];
    char protocol[10];

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), destination_ip, INET_ADDRSTRLEN);

    snprintf(protocol, sizeof(protocol), "%d", ip_header->ip_p);

    if (tcp_header != NULL || udp_header != NULL) {
        cout << "\033[32mPacket: \033[0m" << source_ip << ":" << ntohs(tcp_header->th_sport) << " \033[32m==>\033[0m " << destination_ip << ":" << ntohs(tcp_header->th_dport) << " \033[32m| Protocol: \033[0m" << protocol << endl;
    } else {
        cout << "\033[32mPacket: \033[0m" << source_ip << " \033[32m==>\033[0m " << destination_ip << " \033[32m| Protocol: \033[0m" << protocol << endl;
    }
}

void start_packet_analysis(const char* interface) {
    cout << "\033[34mStarting packet analysis on\033[0m " << "\033[32m" << interface << "...\033[0m" << endl;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char* packet;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cout << "\033[31mFailed to open interface " << interface << " for packet capture.\033[0m" << endl;
        return;
    }

    pcap_loop(handle, -1, packet_analysis_callback, NULL);
    pcap_close(handle);
}

void list_network_interfaces() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cout << "Failed to get network interfaces: " << errbuf << endl;
        return;
    }

    int index = 0;
    cout << "Availables:" << endl;
    for (pcap_if_t* dev = alldevs; dev != NULL; dev = dev->next) {
        index++;
        cout << "\033[36m" << index << ")\033[0m " << dev->name << endl;
    }

    pcap_freealldevs(alldevs);
}

void save_original_mac(const char* interface) {
    string mac_address_file = "/opt/" + string(interface) + "_original_mac.txt";
    ifstream file(mac_address_file);
    if (!file) {
        string original_mac = get_mac(interface);
        ofstream outfile(mac_address_file);
        outfile << original_mac;
        outfile.close();
    }
}

string get_original_mac(const char* interface) {
    string mac_address_file = "/opt/" + string(interface) + "_original_mac.txt";
    ifstream file(mac_address_file);
    if (file) {
        string original_mac;
        getline(file, original_mac);
        file.close();
        return original_mac;
    } else {
        return "";
    }
}

string get_mac(const char* interface) {
    string command = "ifconfig " + string(interface);
    string output = exec_command(command);
    regex mac_regex("([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}");
    smatch mac_match;
    if (regex_search(output, mac_match, mac_regex)) {
        return mac_match.str(0);
    } else {
        return "";
    }
}

string generate_random_mac() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dis(0x00, 0xff);

    stringstream ss;
    ss << hex << setw(2) << setfill('0') << (dis(gen) & 0xfe);  // Make sure the MAC address is unicast
    for (int i = 0; i < 5; i++) {
        ss << ":" << setw(2) << setfill('0') << dis(gen);
    }

    return ss.str();
}

string generate_custom_mac(const string& oui) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dis(0x00, 0xff);

    stringstream ss;
    ss << oui;
    for (int i = 0; i < 3; i++) {
        ss << ":" << setw(2) << setfill('0') << dis(gen);
    }

    return ss.str();
}

bool validate_mac(const string& mac_address) {
    regex mac_regex("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$");
    return regex_match(mac_address, mac_regex);
}

void restart_network_services() {
    cout << "\033[34mRestarting network services...\033[0m" << endl;
    system("sudo service networking restart");
    system("sudo service NetworkManager restart");
    cout << "\033[35mNetwork services have been restarted successfully.\033[0m" << endl;
}

void change_mac(const char* interface, const string& new_mac) {
    string original_mac = get_original_mac(interface);
    cout << "\033[34m\033[1mChanging MAC address\033[0m" << endl;
    cout << "\033[32mInterface: \033[0m" << interface << endl;
    cout << "\033[32mOld Mac  : \033[0m" << original_mac << endl;
    cout << "\033[32mNew Mac  : \033[0m" << new_mac << endl;

    exec_command("sudo ifconfig " + string(interface) + " down");
    exec_command("sudo ifconfig " + string(interface) + " hw ether " + new_mac);
    exec_command("sudo ifconfig " + string(interface) + " up");

    cout << "\033[35mMAC address changed successfully.\033[0m" << endl;
}

bool is_wireless_interface(const char* interface) {
    string iwconfig_output = exec_command("iwconfig " + string(interface) + " 2>&1");
    return iwconfig_output.find("no wireless extensions") == string::npos;
}

bool change_interface_mode(const char* interface, const string& mode) {
    if (!is_wireless_interface(interface)) {
        cout << "\033[31m" << interface << "\033[0m is not a wireless interface or not supported." << endl;
        return false;
    }

    try {
        exec_command("sudo ifconfig " + string(interface) + " down");
        exec_command("sudo iwconfig " + string(interface) + " mode " + mode);
        exec_command("sudo ifconfig " + string(interface) + " up");
        cout << "Interface \033[32m" << interface << "\033[0m has been set to \033[32m" << mode << "\033[0m mode." << endl;
        return true;
    } catch (const exception& e) {
        cout << "\033[31mError occurred while changing mode of " << interface << "\033[0m" << endl;
        return false;
    }
}

bool validate_interface(const char* interface) {
    string command = "ifconfig " + string(interface);
    string output = exec_command(command);
    if (output.find("Device not found") != string::npos) {
        cout << "\033[31mInvalid interface:\033[0m " << interface << endl;  // Bold Red Text
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    string interface;
    bool list_interfaces = false;
    bool show_version = false;
    bool random_mac = false;
    string new_mac;
    string custom_oui;
    bool reset_mac = false;
    string mode;
    bool get_ssid = false;
    bool check_security = false;
    bool analyze_signal = false;
    bool restart_network = false;
    bool monitor_mac_traffic = false;
    bool analyze_packets = false;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "--interface" || arg == "-i") {
            if (i + 1 < argc) {
                interface = argv[i + 1];
                i++;
            } else {
                cout << "Please specify an interface with --interface." << endl;
                return 1;
            }
        } else if (arg == "--list-interfaces" || arg == "-li") {
            list_interfaces = true;
        } else if (arg == "--version" || arg == "-V") {
            show_version = true;
        } else if (arg == "--random" || arg == "-r") {
            random_mac = true;
        } else if (arg == "--newmac" || arg == "-nm") {
            if (i + 1 < argc) {
                new_mac = argv[i + 1];
                i++;
            } else {
                cout << "Please specify a MAC address with --newmac." << endl;
                return 1;
            }
        } else if (arg == "--customoui" || arg == "-co") {
            if (i + 1 < argc) {
                custom_oui = argv[i + 1];
                i++;
            } else {
                cout << "Please specify an OUI with --customoui." << endl;
                return 1;
            }
        } else if (arg == "--reset" || arg == "-rs") {
            reset_mac = true;
        } else if (arg == "--mode") {
            if (i + 1 < argc) {
                mode = argv[i + 1];
                i++;
            } else {
                cout << "Please specify a mode with --mode." << endl;
                return 1;
            }
        } else if (arg == "--get-ssid") {
            get_ssid = true;
        } else if (arg == "--check-security") {
            check_security = true;
        } else if (arg == "--analyze-signal") {
            analyze_signal = true;
        } else if (arg == "--restart-network" || arg == "-rn") {
            restart_network = true;
        } else if (arg == "--monitor-mac-traffic" || arg == "-mmt") {
            monitor_mac_traffic = true;
        } else if (arg == "--analyze-packets" || arg == "-ap") {
            analyze_packets = true;
        }
    }

    if (show_version) {
        show_version();
        return 0;
    }
    if (list_interfaces) {
        list_network_interfaces();
        return 0;
    }
    if (restart_network) {
        restart_network_services();
        return 0;
    }
    if (monitor_mac_traffic) {
        start_traffic_monitoring(interface.c_str());
        return 0;
    }
    if (get_ssid) {
        if (!interface.empty()) {
            get_ssid(interface.c_str());
        } else {
            cout << "Please specify an interface with --interface to get its SSID." << endl;
        }
        return 0;
    }
    if (check_security) {
        if (!interface.empty()) {
            check_network_security(interface.c_str());
        } else {
            cout << "Please specify an interface with --interface to check its security protocol." << endl;
        }
        return 0;
    }
    if (analyze_signal) {
        if (!interface.empty()) {
            analyze_signal_strength(interface.c_str());
        } else {
            cout << "Please specify an interface with --interface to analyze its signal strength." << endl;
        }
        return 0;
    }
    if (analyze_packets) {
        if (!interface.empty()) {
            start_packet_analysis(interface.c_str());
        } else {
            cout << "Please specify an interface with --interface to analyze packets." << endl;
        }
        return 0;
    }

    if (interface.empty()) {
        cout << "Please specify an interface with --interface." << endl;
        return 1;
    }

    validate_interface(interface.c_str());
    save_original_mac(interface.c_str());

    if (random_mac) {
        string random_mac = generate_random_mac();
        change_mac(interface.c_str(), random_mac);
    } else if (!new_mac.empty()) {
        if (validate_mac(new_mac)) {
            change_mac(interface.c_str(), new_mac);
        } else {
            cout << "Invalid MAC address format. Please provide a valid MAC address." << endl;
            return 1;
        }
    } else if (!custom_oui.empty()) {
        if (validate_mac(custom_oui + ":00:00:00")) {
            string custom_mac = generate_custom_mac(custom_oui);
            change_mac(interface.c_str(), custom_mac);
        } else {
            cout << "Invalid OUI format. Please provide a valid OUI." << endl;
            return 1;
        }
    } else if (reset_mac) {
        string original_mac = get_original_mac(interface.c_str());
        if (!original_mac.empty()) {
            change_mac(interface.c_str(), original_mac);
            cout << "MAC address reset to the original value." << endl;
        } else {
            cout << "Unable to reset the MAC address. Original MAC address not found." << endl;
        }
    }

    if (!mode.empty()) {
        bool success = change_interface_mode(interface.c_str(), mode);
        if (success) {
            cout << "Mode change to " << mode << " was successful." << endl;
        } else {
            cout << "Failed to change mode to " << mode << "." << endl;
        }
    }

    return 0;
}


