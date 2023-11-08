//compile as follows
//gcc example.cpp -lpcap
//run as follows the
// sudo ./a.out tcp 100  ----- this is to capture 100 tcp packets

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/ethernet.h> 
#include <string.h>
#include <arpa/inet.h>

unsigned long packet_counter = 1;

void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
  //try here the dissection


	/* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
	/*printf("packet portion captured length : %u\n",pkthdr->caplen);
	printf("packet length : %u\n",pkthdr->len);
	printf("Packet timestamp : %s\n",ctime((const time_t *) &(pkthdr->ts.tv_sec)));*/
    //printf("Total packet available: %d bytes\n", header->caplen);
    //printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
	struct ip *ip_hdr = (struct ip*)ip_header;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
	//printf("IP source address = %s\n", inet_ntoa(ip_hdr->ip_src)); 
	//printf("IP Destination address = %s\n", inet_ntoa(ip_hdr->ip_dst)); 

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
	struct tcphdr *tcp_hdr = (struct tcphdr *)tcp_header;
    //printf("TCP header length in bytes: %d\n", tcp_header_length);
	//printf("Source TCP port = %d\n",ntohs(tcp_hdr->source));
	//printf("Destination TCP port = %d\n",ntohs(tcp_hdr->dest));

	
    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    //printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = pkthdr->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    //printf("Payload size: %d bytes\n", payload_length);
	//Get a pointer to the application data offset
   	payload = packet + total_headers_size -1;
    //printf("Memory address where payload begins: %p\n", payload);
    if (payload_length > 0) {
		printf("===============================\n");
		printf("Begin packet (%ld)\n",packet_counter);
		// This means application protocol data is present
		// Get reference to first 4 bytes of application payload (trimmed)
		const u_char *payload_byte1 = payload + 1;
		const u_char *payload_byte2 = payload + 2;
		const u_char *payload_byte3 = payload + 3;
		const u_char *payload_byte4 = payload + 4;
		const u_char *payload_byte5 = payload + 5;
		const u_char *payload_byte6 = payload + 6;
		const u_char *payload_byte7 = payload + 7;
		char *method;
		int is_http_request = 0;

		//We are looking for HTTP request message
		//Check whether the first 3-7 bytes are either of the following
		//GET , PUT , HEAD , POST , PATCH , TRACE , DELETE , CONNECT , OPTIONS
		if ( *payload_byte1 == 'G' && *payload_byte2 == 'E' && *payload_byte3 == 'T') {
			method = "GET";
			is_http_request = 1;
		} else if (*payload_byte1 == 'P' && *payload_byte2 == 'U' && *payload_byte3 == 'T') {
			method = "PUT";
			is_http_request = 1;
		} else if (*payload_byte1 == 'H' && *payload_byte2 == 'E' && *payload_byte3 == 'A' && *payload_byte4 == 'D') {
			method = "HEAD";
			is_http_request = 1;
		} else if (*payload_byte1 == 'P' && *payload_byte2 == 'O' && *payload_byte3 == 'S' && *payload_byte4 == 'T') {
			method = "POST";
			is_http_request = 1;
		} else if (*payload_byte1 == 'P' && *payload_byte2 == 'A' && *payload_byte3 == 'T' && *payload_byte4 == 'C' && *payload_byte4 == 'H') {
			method = "PATCH";
			is_http_request = 1;
		} else if (*payload_byte1 == 'T' && *payload_byte2 == 'R' && *payload_byte3 == 'A' && *payload_byte4 == 'C' && *payload_byte4 == 'E') {
			method = "TRACE";
			is_http_request = 1;
		} else if (*payload_byte1 == 'D' && *payload_byte2 == 'E' && *payload_byte3 == 'L' && *payload_byte4 == 'E' && *payload_byte4 == 'T' 
					&& *payload_byte4 == 'E') {
			method = "DELETE";
			is_http_request = 1;
		} else if (*payload_byte1 == 'C' && *payload_byte2 == 'O' && *payload_byte3 == 'N' && *payload_byte4 == 'N' && *payload_byte4 == 'E' 
					&& *payload_byte4 == 'C' && *payload_byte4 == 'T') {
			method = "CONNECT";
			is_http_request = 1;
		} else if (*payload_byte1 == 'O' && *payload_byte2 == 'P' && *payload_byte3 == 'T' && *payload_byte4 == 'I' && *payload_byte4 == 'O' 
					&& *payload_byte4 == 'N' && *payload_byte4 == 'S') {
			method = "OPTIONS";
			is_http_request = 1;
		}

		/* If HTTP request message, then dump the packet */
		if (is_http_request) {
			printf("HTTP Protocol request message detected. Method : GET\n");
			printf("IP source address = %s\n", inet_ntoa(ip_hdr->ip_src)); 
			printf("IP Destination address = %s\n", inet_ntoa(ip_hdr->ip_dst)); 
			printf("Source TCP port = %d\n",ntohs(tcp_hdr->source));
			printf("Destination TCP port = %d\n",ntohs(tcp_hdr->dest));
			printf("Dumping packet : \n");
        	const u_char *temp_pointer = payload;
        	int byte_count = 0;
        	while (byte_count++ < payload_length + 1) {
            	printf("%c ", *temp_pointer);
            	temp_pointer++;
        	}
		} 
		
		/* Now we are checking for HTTP response messages */
		/* Check if the first 4 payload bytes are HTTP or not */
		if ( *payload_byte1 == 'H' && *payload_byte2 == 'T' && *payload_byte3 == 'T' && *payload_byte4 == 'P') {
			/* Print payload in ascii if 1st 4 bytes (trimmed) are 'H','T','T','P' */
			printf("HTTP response message packet detected.\n");
			printf("IP source address = %s\n", inet_ntoa(ip_hdr->ip_src)); 
			printf("IP Destination address = %s\n", inet_ntoa(ip_hdr->ip_dst)); 
			printf("Source TCP port = %d\n",ntohs(tcp_hdr->source));
			printf("Destination TCP port = %d\n",ntohs(tcp_hdr->dest));
			printf("Dumping packet : \n");
        	const u_char *temp_pointer = payload;
        	int byte_count = 0;
        	while (byte_count++ < payload_length + 1) {
            	printf("%c ", *temp_pointer);
            	temp_pointer++;
			}
		}

		printf("End packet (%ld)\n",packet_counter);
		printf("===============================\n");
	} else {
		printf("No application data in packet (%ld).\n", packet_counter);
	}
	#if 0
    /* Print payload in Hex */
      
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c ", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    #endif
	packet_counter++;
    return;

}

int main(int argc,char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        
    bpf_u_int32 pMask;           
    bpf_u_int32 pNet;             
	char *network;
	char *netmask;
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;

    
    if(argc != 3)
    {
        printf("\nInsufficient Arguments \nUsage: %s [protocol][number-of-packets]\n",argv[0]);
        return 0;
    }


    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }


    printf("\nHere is a list of available devices on your system:\n\n");
    for(d=alldevs; d; d=d->next)
    {
        //try flags and print other device details here
		if (d != NULL) {
            printf("Device name : %s\n",d->name);
			d->description != NULL ? printf("Description : %s\n",d->description) : printf("Description : (None)\n");
			printf("Flags : %d\n", d->flags);
        }
            
        else
        {
            printf(" (Sorry, No description available for this device)\n");
            printf(" (%d) \n", d->flags);
        }
    }

    printf("\nEnter the interface name on which you want to run the packet sniffer : ");
    
    fgets(dev_buff, sizeof(dev_buff)-1, stdin);

    dev_buff[strlen(dev_buff)-1] = '\0';

    if(strlen(dev_buff))
    {
        dev = dev_buff;
        printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...",dev, (atoi)(argv[2]));
    }

	    
    printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...\n",dev, (atoi)(argv[2]));
    if(dev == NULL)
    {
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    int ret = pcap_lookupnet(dev, &pNet, &pMask, errbuf);
	struct in_addr ip_addr;
    //unsigned int mask[4] = {0xff000000, 0x00ff0000, 0x0000ff00, 0x000000ff};
    
	if(ret == -1) {
   		printf("%s\n",errbuf);
   		exit(1);
  	}

    //print network mask and network address here
	if (ret == 0) {
		ip_addr.s_addr = pNet;
		network = inet_ntoa(ip_addr);
		printf("IP Network: %s\n", network);
		ip_addr.s_addr = pMask;
		netmask = inet_ntoa(ip_addr);
		printf("Subnet mask: %s\n", netmask);
	} else {
		printf("Unable to get IP address and netmask.\n");
		printf("Error : %s\n", errbuf);
	}

    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    if(pcap_compile(descr, &fp, argv[1], 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    pcap_loop(descr,atoi(argv[2]), callback, NULL);

    printf("\nDone with packet sniffing!\n");
    return 0;
}
