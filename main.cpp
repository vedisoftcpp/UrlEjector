#include <stdio.h>
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")
#define HAVE_REMOTE 1
#include <pcap.h>

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;



/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


using std::vector;
//vector<vector<u_char>> ip_packets_buffer;

typedef vector<u_char> ip_packet_t;

using std::map;
map<u_short, vector<ip_packet_t> > ip_packets_buffer;

struct fragmented_ordering
{
    bool operator() (const ip_packet_t& p1, const ip_packet_t& p2) const
    {
        // ip headers
        ip_header* h1 = (ip_header*)&p1[0];
        ip_header* h2 = (ip_header*)&p2[0];

        // fragment offsets
        u_short fo1 = h1->flags_fo >> 3;
        u_short fo2 = h2->flags_fo >> 3;

        return fo1 < fo2;
    }
};


struct tcp_header
{
    u_short src_port;
    u_short dst_port;
    u_int seq_number;
    u_int ask_number;
    u_char stuff;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urg_ptr;
};


int main()
{
pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i=0;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
u_int netmask;
char packet_filter[] = "ip";
struct bpf_program fcode;

    /* Retrieve the device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    scanf_s("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the adapter */
    if ( (adhandle= pcap_open(d->name,  // name of the device
                             65536,     // portion of the packet to capture.
                                        // 65536 grants that the whole packet will be captured on all the MACs.
                             PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
                             1000,      // read timeout
                             NULL,      // remote authentication
                             errbuf     // error buffer
                             ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]),"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
//    struct tm ltime;
//    char timestr[16];
//    ip_header *ih;
//    udp_header *uh;
//    u_int ip_len;
//    u_short sport,dport;
//    time_t local_tv_sec;

//    /*
//     * Unused variable
//     */
//    (VOID)(param);

//    /* convert the timestamp to readable format */
//    local_tv_sec = header->ts.tv_sec;
//    localtime_s(&ltime, &local_tv_sec);
//    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

//    /* print timestamp and length of the packet */
//    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

//    /* retireve the position of the ip header */
//    ih = (ip_header *) (pkt_data +
//        14); //length of ethernet header

//    /* retireve the position of the udp header */
//    ip_len = (ih->ver_ihl & 0xf) * 4;
//    uh = (udp_header *) ((u_char*)ih + ip_len);

//    /* convert from network byte order to host byte order */
//    sport = ntohs( uh->sport );
//    dport = ntohs( uh->dport );

//    /* print ip addresses and udp ports */
//    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
//        ih->saddr.byte1,
//        ih->saddr.byte2,
//        ih->saddr.byte3,
//        ih->saddr.byte4,
//        sport,
//        ih->daddr.byte1,
//        ih->daddr.byte2,
//        ih->daddr.byte3,
//        ih->daddr.byte4,
//        dport);

    ip_header *ih;
    ih = (ip_header *) (pkt_data + 14);

    // check for TCP
    if (ih->proto != 0x06)
        return;

    vector<u_char> ip_packet(ntohs(ih->tlen));
    for (int i = 0; i < ntohs(ih->tlen); ++i)
        ip_packet.push_back( *((u_char*)ih+i) );

    // checking for fragmentation
    u_short DF_flag = (ntohs(ih->flags_fo) >> 13) & 0x02;
    u_short MF_flag = (ntohs(ih->flags_fo) >> 13) & 0x04;

    u_short data_offset = (ih->ver_ihl & 0x0f)*4;
    tcp_header* th = (tcp_header*)((u_char*)ih + data_offset);
    //std::cout << ((th->stuff) & 0x0f) << "\n";
    //std::cout << ntohs(th->src_port) << "\n";

    if (!DF_flag)
    {
        u_short fo = ntohs(ih->flags_fo) & 0x1fff;
        if (!MF_flag && !fo)
            return;

        // have all ip-packets was recived
        map<u_short, vector<ip_packet_t> >::iterator it = ip_packets_buffer.find(ntohs(ih->identification));
        if (it == ip_packets_buffer.end())
        {
//            std::cout << ntohs(ih->identification) << "\n";
//            // check for data in TCP
//            u_short data_offset = (ih->ver_ihl & 0x0f)*4;
//            tcp_header* th = (tcp_header*)((u_char*)ih+data_offset);
//            //std::cout << "tcp data offset: " << (th->stuff >> 4) << "\n";

//            u_short tcp_data_size = ntohs(ih->tlen) -
//                                    (ih->ver_ihl & 0x0f)*4 -
//                                    (th->stuff >> 4)*4;
//            std::cout << "tcp data size: " << tcp_data_size << "\n\n";

            //std::cout << 1 << " " << ip_packets_buffer.size() << "\n\n";
            // there aren't ip-packet with same id in buffer
            vector<ip_packet_t> fragmented_packets;
            fragmented_packets.push_back(ip_packet);
            ip_packets_buffer[ntohs(ih->identification)] = fragmented_packets;
            return;
        }
        else
        {
            std::cout << 5 << "\n";
            // there are ip-packet with same id in buffer

            // fragmented packets (fpackets)
            vector<ip_packet_t>& fpackets = ip_packets_buffer[ntohs(ih->identification)];

            fpackets.push_back(ip_packet);
            std::sort(fpackets.begin(), fpackets.end(), fragmented_ordering());

            // try to merge
            ip_header *first_packet_header = (ip_header*)&(fpackets[0][0]);

            // fragment offset
            u_short firt_packet_fo = ntohs(first_packet_header->flags_fo) & 0x1fff;
            if (firt_packet_fo != 0)
            {
                //std::cout << 2 << "\n";
                // there isn't first packet
                return;
            }

            u_char MF_flag = 0x04;
            u_short first_packet_data_len = ntohs(first_packet_header->tlen) -
                                            (first_packet_header->ver_ihl & 0x0f)*4;
            u_short data_len = first_packet_data_len;
            vector<ip_packet_t>::iterator it;
            for (it = fpackets.begin()+1; it != fpackets.end(); ++it)
            {
                ip_header *packet_header = (ip_header*)&((*it)[0]);
                u_short fo = ntohs(packet_header->flags_fo) & 0X1fff;

                if (fo != data_len/8)
                {
                    //std::cout << 3 << "\n";
                    return;
                }

                data_len += ntohs(packet_header->tlen) -
                            (packet_header->ver_ihl & 0x0f)*4;
                MF_flag *= (ntohs(packet_header->flags_fo) >> 13) & 0x04;
            }
            if (MF_flag != 0)
            {
                //std::cout << 4 << "\n";
                return;
            }

            // we can merge fragmented packets
            first_packet_header->tlen = htons((first_packet_header->ver_ihl & 0x0f)*4 + data_len);
            vector<u_char> data_add(data_len - first_packet_data_len);
            for (it = fpackets.begin()+1; it != fpackets.end(); ++it)
            {
                ip_header* packet_header = (ip_header*)&((*it)[0]);
                u_short offset = (packet_header->ver_ihl & 0x0f)*4;
                for (u_short i = offset; i < ntohs(packet_header->tlen); ++i)
                    data_add.push_back( *((u_char*)packet_header+i) );
            }

            ip_packet_t merged_packet = fpackets[0];
            merged_packet.insert(merged_packet.end(), data_add.begin(), data_add.end());
            ip_packet = merged_packet;
            std::cout << 6 << "\n";

            ip_packets_buffer.erase(ntohs(ih->identification));
        }
    }
    else
    {
        //std::cout << 7 << "\n";
    }



}


