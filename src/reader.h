#ifndef PCAP_READER_H
#define PCAP_READER_H


#include <pcap/pcap.h>

namespace PacketCapture {

    class Reader {

    public:
        void Start();
        void Run();

    private:
        static void HandlePacket(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr);
        static void SetDataLinkHeaderLength(pcap_t* handler);

        pcap_t* mPcapHandler;
        bool mReaderIsStarted = false;
        static int mDataLinkHdrSize;
    };

}


#endif //PCAP_READER_H
