//============================================
//Program 4:
//
// Creation of a TCP tram, with a SYN flag
// used to request a connection.
//============================================

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>


// creation of data structure of the "pseudohdr"
// used to compute the TCP checksum
struct pseudohdr
{
	struct in_addr saddr;
	struct in_addr daddr;
	u_char zero;
	u_char protocol;
	u_short length;
	struct tcphdr tcpheader;
};


// Checksum function of IP
u_short checksum_ip(u_short * data,u_short length)
{
	register long value;
	u_short i;
	for(i=0;i<(length>>1);i++)
			value+=data[i];
	if((length&1)==1)
			value+=(data[i]<<8);
	value=(value&65535)+(value>>16);
	return(~value);
}

// Checksum function of TCP
unsigned short checksum_tcp (unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
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

	sum = (sum + 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return(answer);
}


int main(int argc,char * * argv)
{
	//Declarations
	struct sockaddr_in dest;
	struct sockaddr_in source;
	int sock;
	char buffer[40];              //IP header + TCP header = 40
	struct ip * ipheader=(struct ip *) buffer;
	struct tcphdr * tcpheader=(struct tcphdr *) (buffer+sizeof(struct ip));
	struct pseudohdr pseudoheader;
	int rc;

	//Syntax verification (number of arguments needed)
	if (argc < 4)
	{
		perror("Syntax Error: The correct syntax is: execFile IPsource IPdestination");
		exit(-1);
	}

	//Data extraction
	source.sin_addr.s_addr = inet_addr(argv[1]);
	dest.sin_addr.s_addr = inet_addr(argv[2]);
	if ((dest.sin_port = htons(atoi(argv[3]))) == 0)
	{
		perror("Invalid destination port");
		exit(-1);
	}

	source.sin_family=AF_INET;
	dest.sin_family=AF_INET;

	//Creation of the socket
	if (( sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		perror("Socket creation Error");
	}

	//Buffer construction and initialization
	bzero(buffer, sizeof(struct ip) + sizeof(struct tcphdr));

	//IP header
	ipheader->ip_v=4;                                       // IP version
	ipheader->ip_hl=5;                                      // IP header size
	ipheader->ip_len=htons(20+20);                          // total size
	ipheader->ip_id=htons(0xF1C);                           // id (random)
	ipheader->ip_ttl=255;                                   // time to live
	ipheader->ip_src=source.sin_addr;                       // address source
	ipheader->ip_dst=dest.sin_addr;                         // address destination
	ipheader->ip_p=IPPROTO_TCP;                             // protocol
	ipheader->ip_sum=checksum_ip((u_short *)ipheader,20);   // checksum IP

	//TCP header
	tcpheader -> dest=dest.sin_port;                        // destination port
	tcpheader -> seq=htonl(0xF1C);                          // Sequence number
	tcpheader -> syn=1;                                     // Flags SYN … 1
	tcpheader -> doff=0x5;                                  // Offset Data
	tcpheader -> window=htons(2048);                        // Window size
	tcpheader -> source=htons(5025);                        // Source port (random)
	tcpheader -> check= 0;

	//Construction of pseudo header
	bzero(&pseudoheader,12+20);                             // size of pseudo header
	pseudoheader.saddr.s_addr=source.sin_addr.s_addr;
	pseudoheader.daddr.s_addr=dest.sin_addr.s_addr;
	pseudoheader.protocol=IPPROTO_TCP;
	pseudoheader.length=htons(20);
	pseudoheader.zero=0;

	//Copy of TCP header to the pseudo header
	bcopy((char *) tcpheader,(char *) &pseudoheader + 12,20);


	//TCP checksum computation
	tcpheader -> check=checksum_tcp((u_short *) &pseudoheader,12+20);// Checksum TCP

	//Sending TCP tram
	rc = sendto(sock, buffer, 20 + 20, 0, (struct sockaddr *) &dest, sizeof (struct sockaddr_in)) ;

	if (rc == -1)
	{
		perror("Error in sending the message");
		return (-1);
	}
	printf("Number of bits transmitted: %d\n",rc);
}



