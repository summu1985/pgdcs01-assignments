/******************************************************************************
 * IITJ PGDCS 01 - Group 7
 * Computer Networking Assigment
 * Authors : Sumit Mukherjee (sumit.mckv@gmail.com)
 *           Vineet Sinha (vineet0506@gmail.com)
 *           Vijay Sharma (vj141418@gmail.com)
 *           Sunil Singh (sunilsinghshiv@gmail.com)
 *           Sunil Kumar (sk2504@gmail.com)
 * Compilation instruction: gcc packet-sniffer.c -l pcap -o packet-sniffer
 * Running instruction: ./packet-sniffer <options> [As root user]
 *                      sudo ./packet-sniffer <options> [As non-root user with
 *                      user in sudoer list]
 *                      To see available options, run with -h option as below
 *                      ./packet-sniffer -h
 *****************************************************************************/           

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
#include <unistd.h>
#include <signal.h>

unsigned long packet_counter = 1;
unsigned long flagged_packets = 0;

/********************************************
 * Default program options and global
 * variables.
 *******************************************/
char *dev = NULL;
pcap_t* descr;
char *transport_protocol = "tcp";
char *application_protocol = NULL;
char *http_request_method = NULL;
int packets_to_capture = 0;

/******************************************************************************
 * This is a helper method. The purpose of the method is to accept the
 * application payload in the captured packet and perform dissection
 * on the packet, assuming it is an HTTP packet. Check the HTTP request
 * method and flag if it matches the requested method on the CLI.
 * HTTP response messages are flagged automatically.
 *****************************************************************************/
 
int parse_http_application_payload(const u_char *payload, const struct ip *ip_hdr, const struct tcphdr *tcp_hdr,
									int payload_length) {

	// Get reference to first 3-6 bytes of application payload (trimmed)
	const u_char *payload_byte1 = payload + 1;
	const u_char *payload_byte2 = payload + 2;
	const u_char *payload_byte3 = payload + 3;
	const u_char *payload_byte4 = payload + 4;
	const u_char *payload_byte5 = payload + 5;
	const u_char *payload_byte6 = payload + 6;
	char *method;
	int is_http_request = 0;

	//We are looking for HTTP request message
	/***********************************************************************
 	 * The logic that we use here is that we first we look at 3-6 bytes of
 	 * the payload and verify whether it is 'GET', 'PUT', 'POST' or 
 	 * 'DELETE'. Then we look at the the HTTP request method command line
 	 * option provided by user.
 	 * If user provided the request method as 'all' i.e. default, then
 	 * as long as the HTTP request method in the packet is either GET, PUT,
 	 * POST or DELETE, we flag the packet and dump the content.
 	 * Otherwise, we flag the packet only if the HTTP request method in the
 	 * packet matches that provided by the user on the CLI.
 	 ***********************************************************************/

	if ( *payload_byte1 == 'G' && *payload_byte2 == 'E' && *payload_byte3 == 'T') {
		method = "get";
		if (strcmp("all",http_request_method) == 0
			|| strcmp(http_request_method, method) == 0) {
			is_http_request = 1;
		}
	} else if (*payload_byte1 == 'P' && *payload_byte2 == 'U' && *payload_byte3 == 'T') {
		method = "put";
		if (strcmp("all",http_request_method) == 0
			|| strcmp(http_request_method, method) == 0) {
			is_http_request = 1;
		}
	} else if (*payload_byte1 == 'P' && *payload_byte2 == 'O' && *payload_byte3 == 'S' && *payload_byte4 == 'T') {
		method = "post";
		if (strcmp("all",http_request_method) == 0
			|| strcmp(http_request_method, method) == 0) {
			is_http_request = 1;
		}
	} else if (*payload_byte1 == 'D' && *payload_byte2 == 'E' && *payload_byte3 == 'L' && *payload_byte4 == 'E' && *payload_byte5 == 'T' 
				&& *payload_byte6 == 'E') {
		method = "delete";
		if (strcmp("all",http_request_method) == 0
			|| strcmp(http_request_method, method) == 0) {
			is_http_request = 1;
		}
	}

	/* If HTTP request method matches that provided as input, then dump the packet */
	if (is_http_request) {
		printf("HTTP Protocol request message detected. Method : %s\n", method);
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
		printf("End packet (%ld)\n",packet_counter);
		printf("===============================\n");
		flagged_packets++;
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
		printf("End packet (%ld)\n",packet_counter);
		printf("===============================\n");
		flagged_packets++;
	}
	return 0;
}

/******************************************************************
 * This is the callback function which we register with pcap
 * library. For every packet captured, this function is called
 * for processing. We validate that each captured packet is of type
 * IP and matches with that of specified transport layer protocol
 * (in this case TCP) and Application layer protocol (in this case 
 * HTTP).
 ******************************************************************/
 
void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
	/* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

	/*************************************************************
     * The total packet length, including all headers
     * and the data payload is stored in
     * header->len and header->caplen. Caplen is
     * the amount actually available, and len is the
     * total packet length even if it is larger
     * than what we currently have captured. If the snapshot
     * length set with pcap_open_live() is too small, you may
     * not have the whole packet.
	**************************************************************/

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
    
	/**************************************************
	 * The second-half of the first byte in ip_header
     * contains the IP header length (IHL).
    ***************************************************/
    ip_header_length = ((*ip_header) & 0x0F);

	/*****************************************************
     * The IHL is number of 32-bit segments. Multiply
     * by four to get a byte count for pointer arithmetic
    ******************************************************/

    ip_header_length = ip_header_length * 4;

	/********************************************************
     * Now that we know where the IP header is, we can 
     * inspect the IP header for a protocol number to 
     * make sure it is TCP before going any further. 
     * Protocol is always the 10th byte of the IP header
    ******************************************************/
    u_char protocol = *(ip_header + 9);

	/**************************************************************************
	 * Only capture those packets whose transport layer protocol matches the 
  	 * one mentioned on the command line.
 	**************************************************************************/

	if (strcmp("tcp",transport_protocol) == 0) {
    	if (protocol != IPPROTO_TCP) {
        	printf("Not a TCP packet. Skipping...\n\n");
        	return;
    	}
	} else if (strcmp("udp", transport_protocol) == 0) {
		if (protocol != IPPROTO_UDP) {
        	printf("Not an UDP packet. Skipping...\n\n");
        	return;
		}	
	} else {
		printf("Unknown transport protocol packet to capture. Exiting.\n");
		exit(0);
	}

	/********************************************************************
 	 * Add the ethernet and ip header length to the start of the packet
     * to find the beginning of the TCP header
	********************************************************************/

    tcp_header = packet + ethernet_header_length + ip_header_length;
 
	/*******************************************************************
   	 *  TCP header length is stored in the first half 
     *  of the 12th byte in the TCP header. Because we only want
     *  the value of the top half of the byte, we have to shift it
     *  down to the bottom half otherwise it is using the most 
     *  significant bits instead of the least significant bits
	*******************************************************************/

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

	/******************************************************************
     *  The TCP header length stored in those 4 bits represents
     *  how many 32-bit words there are in the header, just like
     *  the IP header length. We multiply by four again to get a
     *  byte count.
	*******************************************************************/
    
	tcp_header_length = tcp_header_length * 4;
	struct tcphdr *tcp_hdr = (struct tcphdr *)tcp_header;
	
    /* Add up all the header sizes to find the payload offset */
    
	int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    payload_length = pkthdr->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
	
	//Get a pointer to the application data offset
   	payload = packet + total_headers_size -1;
    if (payload_length > 0) {
	
		/* This means application protocol data is present
		 Parse the application specific data as per application layer protocol */
	
		if (application_protocol != NULL && strcmp("http", application_protocol) == 0) {
			parse_http_application_payload(payload, ip_hdr, tcp_hdr, payload_length);
		}
	
	} else {
		if (application_protocol == NULL )
			printf("No application data in packet (%ld).\n", packet_counter);
	}
	
	packet_counter++;
    return;
}

/***************************************************************
 * This is a helper function. The purpose of this function is
 * to print out the help message displaying all the possible
 * options that this program takes and providing a brief 
 * explanation of the options as well as the default values.
 **************************************************************/

void print_help(const char *progname, const char *additional_msg) {
	static char usage[] = "usage: %s [-i <interface>] [-c <packet_count>] [-t <transport_protocol>] [-a <application_protocol>] "
						  "[-X <http_method>] [-h]\n"
						  "interface            = network interface to start capturing from.\n"
						  "                       If not provided, will be asked to choose from a list.\n"
						  "packet_count         = number of packets to capture.\n"
                          "                       Default value: 0 (capture all packets - ctrl+c to stop).\n"
						  "transport_protocol   = The transport layer protocol packets, that will be captured.\n"
                		  "                       Can be 'tcp'. Default : 'tcp'.\n"
						  "application_protocol = The application layer protocol packets, that will be captured.\n"
						  "                       Can be 'http'. Default: 'http'.\n"
						  "http_method          = If capturing HTTP packets, specify which HTTP method request packet to capture.\n"
						  "                       Can be 'get', 'put', 'post, 'delete', 'all'. Default value : all.\n"
						  "                       Specifying the value of all means packets with any of the above 4 HTTP methods will be flagged.\n" 
						  "-h                   = help. Display this help message and exit.\n";
	if (additional_msg != NULL) {
		printf("%s \n");
		printf(usage,progname);
	} else {
		printf(usage,progname);
	}

	exit(0);
} 

/******************************************************************************
 * This is a helper function. The purpose of this function is to parse the
 * command line options provided by the user while executing and then
 * set global variables accordingly, so that the application can behave
 * as per user expectation.
 * This also helps to weed out incorrect options.
 *****************************************************************************/

void handle_command_line_options(int argc, char **argv) {
	char c;
    int i =0, method_found = 0;
	char http_methods[4][7] = {"get","put","post", "delete"};

	while ((c = getopt(argc, argv, ":i:c:t:a:X:h")) != -1) {
		switch(c) {
			case 'i':
				dev = optarg;
				break;
			case 'c':
				packets_to_capture = atoi(optarg);
				break;
			case 'h':
				print_help(argv[0],NULL);
				break;
			case 't':
				transport_protocol = optarg;
				break;
			case 'a':
				application_protocol = optarg;
				if (strcmp(application_protocol, "http") != 0) {
					print_help(argv[0], "Unsupported application protocol.");
				}
				break;
			case 'X':
				http_request_method = optarg;
				for (i=0; i<4; i++) {
					printf("http_request_method = %s,http_method[%d] = %s",http_request_method,i,http_methods[i]);
					
					if (strcmp(http_methods[i], http_request_method) == 0) {
						method_found = 1;
						break;
					}
				}
				if (!method_found)
					print_help(argv[0], "Unsupported HTTP request method.");
				break;
			case '?':
				char additional_message[80];
				sprintf(additional_message, "Unknown option : '%c'", optopt);
				print_help(argv[0], additional_message);
				break; 
		}
	}
}

void ctrlc_handler(int sig) {
	//pcap_close(descr);
	printf("\nCaptured packets / flagged packets : %d/%d.\n",packet_counter, flagged_packets);
	exit(0);
}

/*******************************************
 * The main function - this is the entry 
 * point for the program.
 ******************************************/

int main(int argc,char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;        
    bpf_u_int32 pMask;           
    bpf_u_int32 pNet;             
	char *network;
	char *netmask;
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};

	/**************************************************************************
	 * Register ctrl+c signal handler (SIGINT), so that on pressing control+c
	 * we display total packets captured and total packets flagged.
	 *************************************************************************/
	signal(SIGINT, ctrlc_handler);
   
	handle_command_line_options(argc, argv);

	
	/****************************************************************
 	 * In case the user has not provided the interface name on the
 	 * CLI, then collect all available network interfaces on the
 	 * system and list them for the user to choose from.
 	 ***************************************************************/
 
	if (dev == NULL) {
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
	        printf("\n ---You opted for device [%s] to capture [%d] packets with transport protocol [%s]---\n\n Starting capture..."
						,dev, packets_to_capture, transport_protocol);
	    }
    	if(dev == NULL)
    	{
        	printf("\n[%s]\n", errbuf);
        	return -1;
    	}
	} else {
	    printf("\n ---You opted for device [%s] to capture [%d] packets with transport protocol [%s]---\n\n Starting capture..."
					,dev, packets_to_capture, transport_protocol);
	}

    int ret = pcap_lookupnet(dev, &pNet, &pMask, errbuf);
	struct in_addr ip_addr;
    
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

    if(pcap_compile(descr, &fp, transport_protocol, 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    pcap_loop(descr,packets_to_capture, callback, NULL);

    printf("\nDone with packet sniffing!\n");
    return 0;
}
