#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#define PORT 53 /* Port number for DNS */
#define BUF_SIZE 1024

int main(int argc, char const *argv[])
{
	int server_fd;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	char buffer[BUF_SIZE] = {0};
	
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
	
	// if (listen(server_fd, 3) < 0)
	// {
	// 	perror("listen");
	// 	exit(EXIT_FAILURE);
	// }
	// if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
	// 				(socklen_t*)&addrlen))<0)
	// {
	// 	perror("accept");
	// 	exit(EXIT_FAILURE);
	// }

	printf("Domain Name Server started.\n");

	while (1) { 
		if (recvfrom(server_fd, buffer, BUF_SIZE, 0, 
			(struct sockaddr *)&address, (socklen_t *)&addrlen) > 0)
		{
			printf("%s\n", buffer);
		}
	}

	return 0;
}
