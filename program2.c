//============================================
//Program 2:
//
// Creation of an IP packet that encapsulates
// an ICMP packet (PING), which is fragmented
// into two (2) small fragments
//============================================
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
#include <unistd.h>


// This is a function that returns the checksum
// of the data passed as arguments (data address, data size)
unsigned short in_chksum(unsigned short *, int);


int main (int argc, char * argv[])
{
	//Declarations
	int sock;
	int rc;
	int num;
	struct sockaddr_in addrsock_source;
	struct sockaddr_in addrsock_dest;
	struct iphdr *ip;
	struct icmphdr *icmp;
	char *packet;
	int psize;

	//Syntax verification (number of arguments needed)
	if (argc != 4)
	{
		perror("Syntax Error: The correct syntax is: execFile IPsource IPdestination size");
		exit(1);
	}

	//Size extraction
	psize= atoi(argv[3]);           // Packet size

	if (psize > 2952 || psize < 1476)
	{
		printf("Incorrect size. Authorized size is between 1476 and 2952)\n");
		exit(-1);
	}

	//Creation of the socket data structure
	addrsock_source.sin_addr.s_addr = inet_addr(argv[1]);  // address source
	addrsock_dest.sin_addr.s_addr = inet_addr(argv[2]);    // address destination
	addrsock_source.sin_family = AF_INET;                  // connection of type AF_INET
	addrsock_dest.sin_family = AF_INET;                    // connection of type AF_INET
	addrsock_source.sin_port = htons(0);                   // port source = 0
	addrsock_dest.sin_port = htons(0);                     // port destination = 0

	//Creation of the socket
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);         // protocol = RAW IP
	if (sock < 0)
	{
		perror("Socket creation Error");
		exit(-1);
	}

	//Allocating a memory space for the packet(IP header + ICMP header + data)
	packet = malloc(sizeof(struct iphdr) + sizeof (struct icmphdr) + psize);
	ip = (struct iphdr *) packet;
	icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

	//Initialization of all blocks to 0
	memset(packet, 0, sizeof(struct iphdr) + sizeof(struct icmphdr) + psize);

	//Construction of the IP & ICMP headers (first fragment)
	ip->tot_len = htons(1500);
	ip->ihl = 5;
	ip->version = 4;
	ip->ttl = 255;
	ip->tos = 0;
	ip->id= htons(62500);                                  // "id" slected randomly
	ip->frag_off = htons(0x2000);                          // bit "More Fragment"
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = addrsock_source.sin_addr.s_addr;
	ip->daddr = addrsock_dest.sin_addr.s_addr;
	ip->check = in_chksum((unsigned short *)ip, sizeof(struct iphdr));
	icmp->type = 8;
	icmp->code = 0;
	icmp->un.echo.id = htons(0x0000);
	icmp->checksum = in_chksum((unsigned short *)icmp, sizeof(struct icmphdr) + psize);

	//Sending the packet (fir fragment)
	rc=sendto(sock, packet, 1500, 0, (struct sockaddr *)&addrsock_dest, sizeof(struct sockaddr));
	printf("Number of bits transmitted: %d\n",rc);

	//Construction of the IP & ICMP headers (second fragment)
	ip->tot_len = htons(sizeof(struct iphdr) + psize - 1472);
	ip->id= htons(62500);                                  // "id" should be the same
	ip->frag_off = htons(0x00B9);      // Offset=((1500(MTU)-20(IP header)) >> 3) & no more fragment
	ip->check = in_chksum((unsigned short *)ip, sizeof(struct iphdr));

	//Sending the packet (second fragment)
	rc=sendto(sock, packet, sizeof(struct iphdr) + psize - 1472, 0, (struct sockaddr *)&addrsock_dest, sizeof(struct sockaddr));
	printf("Number of bits transmitted: %d\n",rc);

	//Freeing memory
	free(packet);
}


// Checksum function
unsigned short in_chksum (unsigned short *addr, int len)
{
	register int nleft = len;
	register int sum = 0;
	u_short answer = 0;

	while (nleft > 1)
	{
		sum += *addr++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(u_char *)(&answer) = *(u_char *)addr;
		sum += answer;
	}

	sum = (sum >> 16) + (sum + 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return(answer);
}



