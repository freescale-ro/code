#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>

#define SERVERIP 192.168.100.100

int main()
{
	struct hostent *host;
	char * serverip = "192.168.8.8";
	int sock;
	struct sockaddr_in server_addr;
	
	host=gethostbyname(serverip);
	/*Create Socket*/
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        	perror("Socket");
		return 0;
	}	    
	printf("Prepare to start the socket: %s \n", serverip);	
	server_addr.sin_family = AF_INET;     
        server_addr.sin_port = htons(40101);   
        server_addr.sin_addr = *((struct in_addr *)host->h_addr);
        bzero(&(server_addr.sin_zero),8); 

	printf("Starting socket to server \n");
        if (connect(sock, (struct sockaddr *)&server_addr,
                    sizeof(struct sockaddr)) == -1){
		perror("Connect");
		return 0;
	}
	fflush(stdout);
	 
 	return 0;
}
