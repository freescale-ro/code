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
	unsigned char send[20];
	int length=5;
	int i, j;

	memset (&send[0],0x00, 20);
        send[length]='a';
        send[length+1]='b';

	printf("\n Data prior \n");
	for(j = 0; j < 20 ; j ++){
		printf("%02x ", send[j]);
	}	
	memset (&send[length],0x00, (20-length));	
	printf("\n Data After \n");
        for(i = 0; i < 20 ; i ++){
                printf("%02x ", send[i]);
        }
	printf("\n");
	
	return 0;
}
