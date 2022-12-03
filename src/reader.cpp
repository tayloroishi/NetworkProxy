#include "reader.h"
#include <unistd.h>
#include <netinet/ip.h>
#include <cstring>
#include <string>

namespace PacketCapture {

    int Reader::mDataLinkHdrSize = 0;

    void Reader::Start() {

        char errbuf[PCAP_ERRBUF_SIZE];
        std::string device;
        pcap_if_t* devices = nullptr;
//      struct bpf_program bpf;
        bpf_u_int32 netmask;
        bpf_u_int32 srcip;

        // If no network interface (device) is specfied, get the first one.
        if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
            return;
        }

        strcpy(device.data(), devices[0].name);
        fprintf(stdout, "Device found : %s\n", device.data());

        // Get network device source IP address and netmask.
        if (pcap_lookupnet(device.data(), &srcip, &netmask, errbuf) == PCAP_ERROR) {
            fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
            return;
        }

        // Open the device for live capture.
        mPcapHandler = pcap_open_live(device.data(), BUFSIZ, 1, 1000, errbuf);
        if (mPcapHandler == nullptr) {
            fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
            return;
        }

        // Convert the packet filter epxression into a packet filter binary.
//        if (pcap_compile(mPcapHandler, &bpf, filter, 0, netmask) == PCAP_ERROR) {
//            fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(mPcapHandler));
//            return;
//        }

        // Bind the packet filter to the libpcap handle.
//        if (pcap_setfilter(mPcapHandler, &bpf) == PCAP_ERROR) {
//            fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(mPcapHandler));
//            return;
//        }

        pcap_activate(mPcapHandler);
        SetDataLinkHeaderLength(mPcapHandler);

        mReaderIsStarted = true;
    }

    void Reader::Run() {

        if (!mReaderIsStarted)
        {
            printf("Reader not started properly\n");
            return;
        }

        pcap_set_timeout(mPcapHandler, 100);
        pcap_loop(mPcapHandler, 0, HandlePacket, nullptr);
        printf("Done\n");
    }

    void Reader::SetDataLinkHeaderLength(pcap_t* handler)
    {
        int linktype;

        // Determine the datalink layer type.
        if ((linktype = pcap_datalink(handler)) == PCAP_ERROR) {
            fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handler));
            return;
        }

        // Set the datalink layer header size.
        switch (linktype)
        {
            case DLT_NULL:
                mDataLinkHdrSize = 4;
                break;

            case DLT_EN10MB:
                mDataLinkHdrSize = 14;
                break;

            case DLT_SLIP:
            case DLT_PPP:
                mDataLinkHdrSize = 24;
                break;

            default:
                printf("Unsupported datalink (%d)\n", linktype);
        }
    }

    void Reader::HandlePacket(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
    {
        struct ip* iphdr;
        char iphdrInfo[256];
        char srcip[256];
        char dstip[256];

        // Skip the datalink layer header and get the IP header fields.
        packetptr += mDataLinkHdrSize;
        iphdr = (struct ip*)packetptr;
        strcpy(srcip, inet_ntoa(iphdr->ip_src));
        strcpy(dstip, inet_ntoa(iphdr->ip_dst));
        sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
                ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
                4*iphdr->ip_hl, ntohs(iphdr->ip_len));
        printf(iphdrInfo);
        printf("\n");
    }


}
