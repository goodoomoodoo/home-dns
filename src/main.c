#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "dns.h"

#define PORT 53 /* Port number for DNS */
#define BUF_SIZE 1024

int main(int argc, char const *argv[])
{
	int server_fd;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char req_buf[BUF_SIZE];
	dns_res_t * res_buf = (dns_res_t *)malloc(sizeof(dns_res_t));
	int flag;
	
	/* Create socket file descriptor using IPv4 and UDP */
	if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	
	/* Set socket to reuse address and port */
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
												&opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	/* Define socket address */
	address.sin_family = AF_INET; /* IPv4 */
	address.sin_addr.s_addr = INADDR_ANY; /* Local host IP */
	address.sin_port = htons(PORT);
	
	/* Bind socket to the address */
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	printf("Domain Name Server started.\n");

	while (1) { 
		if (recvfrom(server_fd, req_buf, BUF_SIZE, 0, 
			(struct sockaddr *)&address, (socklen_t *)&addrlen) > 0)
		{
			char * ipString = inet_ntoa(address.sin_addr);

			fprintf(stdout, "Received query from %s\n", ipString);

			flag = handle_packet(req_buf, res_buf);
		}

		if (flag == 0) {
			/* Send response message */
		}
	}

	return 0;
}