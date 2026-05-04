#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <chrono>
#include <sstream>
#include <algorithm>

using namespace std;

// Structure for flow features
struct FlowStats {
    string src_ip;
    string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    string protocol;

    double start_time;
    double last_time;
    int fwd_packets = 0;
    int bwd_packets = 0;
    long long fwd_len_total = 0;
    long long bwd_len_total = 0;
    
    vector<int> fwd_lengths;
    vector<int> bwd_lengths;
    
    vector<double> flow_iats;
    vector<double> fwd_iats;
    vector<double> bwd_iats;
    
    double last_fwd_time = 0;
    double last_bwd_time = 0;
    
    long long fwd_header_len = 0;
    long long bwd_header_len = 0;
    
    int fin_flag = 0;
    int syn_flag = 0;
    int rst_flag = 0;
    int psh_flag = 0;
    int ack_flag = 0;

    void add_packet(int size, int header_len, bool is_fwd, double timestamp, int flags) {
        if (fwd_packets + bwd_packets > 0) {
            flow_iats.push_back((timestamp - last_time) * 1e6);
        }
        last_time = timestamp;

        if (is_fwd) {
            if (fwd_packets > 0) {
                fwd_iats.push_back((timestamp - last_fwd_time) * 1e6);
            }
            last_fwd_time = timestamp;
            fwd_packets++;
            fwd_len_total += size;
            fwd_lengths.push_back(size);
            fwd_header_len += header_len;
        } else {
            if (bwd_packets > 0) {
                bwd_iats.push_back((timestamp - last_bwd_time) * 1e6);
            }
            last_bwd_time = timestamp;
            bwd_packets++;
            bwd_len_total += size;
            bwd_lengths.push_back(size);
            bwd_header_len += header_len;
        }

        if (flags & TH_FIN) fin_flag++;
        if (flags & TH_SYN) syn_flag++;
        if (flags & TH_RST) rst_flag++;
        if (flags & TH_PUSH) psh_flag++;
        if (flags & TH_ACK) ack_flag++;
    }
};

// Global map and mutex
unordered_map<string, FlowStats> active_flows;
mutex flow_lock;

// Helper to calculate mean
double calculate_mean(const vector<double>& vec) {
    if (vec.empty()) return 0.0;
    double sum = 0;
    for (double v : vec) sum += v;
    return sum / vec.size();
}

// Evaluator thread function
void flow_evaluator() {
    while (true) {
        this_thread::sleep_for(chrono::seconds(2));
        
        vector<FlowStats> to_export;
        double currentTime = chrono::duration<double>(chrono::system_clock::now().time_since_epoch()).count();

        {
            lock_guard<mutex> lock(flow_lock);
            for (auto it = active_flows.begin(); it != active_flows.end(); ) {
                FlowStats& flow = it->second;
                double idle_time = currentTime - flow.last_time;
                double duration = flow.last_time - flow.start_time;

                // 1. Export if the flow is "mature" (has at least 2 packets)
                if (flow.fwd_packets + flow.bwd_packets >= 2) {
                    to_export.push_back(flow);
                }

                // 2. PRUNING LOGIC:
                // Remove if: It's a TCP flow with a FIN/RST flag OR it's been idle for 15 seconds
                if (flow.fin_flag > 0 || flow.rst_flag > 0 || idle_time > 15.0) {
                    it = active_flows.erase(it);
                } else {
                    it++;
                }
            }
        }

        // 3. Output to Python
        for (const auto& flow : to_export) {
            double duration_us = (flow.last_time - flow.start_time) * 1e6;
            if (duration_us <= 0) duration_us = 1.0;

            int fwd_max = flow.fwd_lengths.empty() ? 0 : *max_element(flow.fwd_lengths.begin(), flow.fwd_lengths.end());
            int fwd_min = flow.fwd_lengths.empty() ? 0 : *min_element(flow.fwd_lengths.begin(), flow.fwd_lengths.end());
            int bwd_max = flow.bwd_lengths.empty() ? 0 : *max_element(flow.bwd_lengths.begin(), flow.bwd_lengths.end());
            int bwd_min = flow.bwd_lengths.empty() ? 0 : *min_element(flow.bwd_lengths.begin(), flow.bwd_lengths.end());

            double flow_bytes_s = (flow.fwd_len_total + flow.bwd_len_total) / (duration_us / 1e6);
            double flow_pkts_s = (flow.fwd_packets + flow.bwd_packets) / (duration_us / 1e6);

            double flow_iat_mean = calculate_mean(flow.flow_iats);
            double fwd_iat_mean = calculate_mean(flow.fwd_iats);
            double bwd_iat_mean = calculate_mean(flow.bwd_iats);

            cout << "{\"src_ip\":\"" << flow.src_ip 
                 << "\",\"dst_ip\":\"" << flow.dst_ip 
                 << "\",\"src_port\":" << flow.src_port 
                 << ",\"dst_port\":" << flow.dst_port 
                 << ",\"protocol\":\"" << flow.protocol 
                 << "\",\"features\":["
                 << duration_us << "," << flow.fwd_packets << "," << flow.bwd_packets << ","
                 << flow.fwd_len_total << "," << flow.bwd_len_total << "," << fwd_max << ","
                 << fwd_min << "," << bwd_max << "," << bwd_min << "," << flow_bytes_s << ","
                 << flow_pkts_s << "," << flow_iat_mean << "," << fwd_iat_mean << ","
                 << bwd_iat_mean << "," << flow.fwd_header_len << "," << flow.bwd_header_len << ","
                 << flow.fin_flag << "," << flow.syn_flag << "," << flow.rst_flag << ","
                 << flow.psh_flag << "," << flow.ack_flag << "]}" << endl;
        }
    }
}

// Packet handler callback
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    const u_char *ip_header_ptr = packet + 14;
    struct ip *ip_hdr = (struct ip *)ip_header_ptr;
    int ip_header_len = ip_hdr->ip_hl * 4;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    uint16_t src_port = 0, dst_port = 0;
    string protocol = "OTHER";
    int header_len = 20; 
    int tcp_flags = 0;

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
        struct tcphdr *tcp_hdr = (struct tcphdr *)(ip_header_ptr + ip_header_len);
        src_port = ntohs(tcp_hdr->th_sport);
        dst_port = ntohs(tcp_hdr->th_dport);
        tcp_flags = tcp_hdr->th_flags;
        header_len += tcp_hdr->th_off * 4;
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
        struct udphdr *udp_hdr = (struct udphdr *)(ip_header_ptr + ip_header_len);
        src_port = ntohs(udp_hdr->uh_sport);
        dst_port = ntohs(udp_hdr->uh_dport);
        header_len += 8;
    } else {
        return;
    }

    double timestamp = pkthdr->ts.tv_sec + (pkthdr->ts.tv_usec / 1000000.0);
    int size = pkthdr->len;

    ostringstream fwd_stream, bwd_stream;
    fwd_stream << src_ip << ":" << src_port << "->" << dst_ip << ":" << dst_port << ":" << protocol;
    bwd_stream << dst_ip << ":" << dst_port << "->" << src_ip << ":" << src_port << ":" << protocol;
    
    string fwd_tuple = fwd_stream.str();
    string bwd_tuple = bwd_stream.str();

    lock_guard<mutex> lock(flow_lock);
    
    if (active_flows.find(fwd_tuple) != active_flows.end()) {
        active_flows[fwd_tuple].add_packet(size, header_len, true, timestamp, tcp_flags);
    } else if (active_flows.find(bwd_tuple) != active_flows.end()) {
        active_flows[bwd_tuple].add_packet(size, header_len, false, timestamp, tcp_flags);
    } else {
        FlowStats flow;
        flow.src_ip = src_ip;
        flow.dst_ip = dst_ip;
        flow.src_port = src_port;
        flow.dst_port = dst_port;
        flow.protocol = protocol;
        flow.start_time = timestamp;
        flow.add_packet(size, header_len, true, timestamp, tcp_flags);
        active_flows[fwd_tuple] = flow;
    }
}

int main(int argc, char *argv[]) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    string filter_exp = "";
    if (argc > 1) {
        dev = argv[1];
    } else {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            cerr << "Couldn't find default device: " << errbuf << endl;
            return 2;
        }
    }
    
    if (argc > 2) {
        for (int i=2; i<argc; i++) {
            filter_exp += argv[i];
            if (i < argc - 1) filter_exp += " ";
        }
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Couldn't open device " << dev << ": " << errbuf << endl;
        return 2;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << endl;
        return 2;
    }

    thread eval_thread(flow_evaluator);
    eval_thread.detach();

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
