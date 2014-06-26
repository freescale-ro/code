#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
/*OpenSSL Includes*/
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>


#define SERVERIP 192.168.100.100

void printhex(unsigned char * dataPrint, int size){
	int i = 0;
	for (i = 0; i < size; i ++){
		printf("%02x", *(dataPrint+i));
	}
	printf("\n");
}
int main(){

	/*Local Variables*/
	const unsigned char *data;	
	unsigned char  hash[SHA_DIGEST_LENGTH];
	unsigned char vector[]={1,2,3,4,5,6,7,8,9};
	unsigned long length = sizeof(vector);
	
	data=&vector[0];

	printf("\nData to be hashed \n");
	printhex((unsigned char *)data, length);
	/*Execute sha1*/
	SHA1(data, length, hash);
	memset(vector, 0x00, length);
	printf("\nHash to data \n");	
	
	printhex(hash, SHA_DIGEST_LENGTH);
	printhex(vector, length);
	return 0;
}
