#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>

#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >>4)



/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};




/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};


struct tcpheader {
    u_short tcp_sourceport;
    u_short tcp_destport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};





void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type 이 패킷이 ip패킷인지 검사 
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 


    if (ip->iph_protocol != IPPROTO_TCP){
        return;
    }

    int ip_header_len = ip->iph_ihl *4;  // IHL은 32 비트 워드 단위 이므로 4를 곱해 Byte 길이로 변환

    struct tcpheader *tcp = (struct tcpheader*)((u_char *)ip + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4; //data offset 도 32비트 단위

    // 출력

    printf("=============================\n");
    printf("Ethernet Src MAC: %02x: %02x: %02x: %02x: %02x: %02x \n",
    eth ->ether_shost[0],eth ->ether_shost[1],eth ->ether_shost[2],eth ->ether_shost[3],eth ->ether_shost[4],eth ->ether_shost[5]);
    printf("Ethernet Dst MAC: %02x: %02x: %02x: %02x: %02x: %02x \n",
    eth -> ether_dhost[0],eth -> ether_dhost[1],eth -> ether_dhost[2],eth -> ether_dhost[3],eth -> ether_dhost[4],eth -> ether_dhost[5]);

    printf(" IP Src: %s\n", inet_ntoa(ip->iph_sourceip));
    printf(" IP Dst: %s\n", inet_ntoa(ip->iph_destip));
    printf(" TCP SrcPort: %d\n", ntohs(tcp->tcp_sourceport));
    printf(" TCP DstPort: %d\n", ntohs(tcp->tcp_destport));


    // Http message 

    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;
    u_char *payload = (u_char *)tcp + tcp_header_len;

    if(payload_len >0){
        printf("  message: ");
        for(int i=0; i<payload_len; i++){
            putchar(isprint(payload[i])|| payload[i] == '\n' || payload[i]== '\r' ? payload[i]: '.');
        }
        printf("\n");
    } else{
        printf("   message: (payload 없음)\n");
    }
  }
}



int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC
  handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);  //utm vm으로 인해 


  // compile filterexp -> BPF psuedocode

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if(pcap_setfilter(handle, &fp) != 0){
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }


  // packet capture
  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);

  return 0;
}

