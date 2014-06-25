/*
 *  Project: 	Diploma Project ETTI@2014
 *  Name:	Access system on P1025TWR Board implemented using Certificates
 *  Students: 	Liana Hebe, Iulia Creata
 *  Freescale:	Mircea Pop
 *
 *  Source: 	Client application that will run on P1025TWR.
 *  Description:The client implement socket to server(Tx and Rx)
 *  		RSA encrypt with Server Public Key
 *  		User Name and Password are taken using a Keyboard connected to
 *  		USB port of P1025TWR. User will be followed by password, the 
 *  		sequence will finish with enter
 */

/*Headers to be included*/
#include <time.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/pem.h>	
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>

/*Global variables*/
int padding = RSA_PKCS1_PADDING;
	
/*Private functions*/
RSA *createRSA(unsigned char *key, int public){
	RSA *rsa= NULL;
	BIO *keybio ;
	keybio = BIO_new_mem_buf(key, -1);
    	
	if (keybio==NULL){
		printf("Failed to create key BIO");
       		return 0;
    	}
    	if(public){
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
	}	
    	else{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    	}
    	if(rsa == NULL){
		printf( "Failed to create RSA");
	}
	
	return rsa;
}
/*Function that implement RSA encrypt using public key*/
int public_encrypt(unsigned char *data,int data_len, unsigned char *key, unsigned char *encrypted){
	int result = 0;
	/*Get Public Key*/
	RSA *rsa = createRSA(key,1);
	/*Execute RSA encrypt with public key*/
	result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);

	return result;
}
/*Function that implement RSA private dencrypt using private key*/
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, 	unsigned char *decrypted){
	int result = 0;
	/*Get private key*/
	RSA *rsa = createRSA(key,0);
   	/*Descrypt using the private key*/
	result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
	/*Return Result(length of decrypted data, 0 if decrypt fail)*/
	return result;
}

/*Debugging functions*/
void printLastError(char *msg){
	char *err = malloc(130);;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n",msg, err);

	free(err);
}

/*Main Function that will be executed*/
int main(){
 
	/*Local variables*/
	int t=0, STOP=0,res=0,sock,bytes_recieved;
    	char buf[255],b[10]="#",src[1024];
    	char s1[1024]="";
    	char s2[1024]="";
    	unsigned char send1[1024],send_data[1024],recv_data[1024];
    	struct hostent *host;
    	struct sockaddr_in server_addr;
	
	/* Get Server Public Key From local file */
	FILE *f=fopen("serverkey.pem","rb");
	fseek(f,0,SEEK_END);
	long fsize=ftell(f);
	fseek(f,0,SEEK_SET);

	char *publicKey=malloc(fsize+1);
	fread(publicKey,fsize,1,f);
	fclose(f);
	publicKey[fsize]=0;
	printf(publicKey);

	/*Get Private key of client from local file*/
       	FILE *f1=fopen("client1_priv.pem","rb");
       	fseek(f1,0,SEEK_END);
       	long fsize1=ftell(f1);
       	fseek(f1,0,SEEK_SET);
 
       	char *privateKey=malloc(fsize1+1);
       	fread(privateKey,fsize1,1,f1);
        	fclose(f1);
       	privateKey[fsize1]=0;
       	printf(privateKey);
	
	/*Open Socket to server*/
	host=gethostbyname("192.168.1.3");
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		/*If socket creation fail - report error*/	
		perror("Socket");
            	exit(1);
        }
	/*Prepare socket structure prior to open the connection*/
	server_addr.sin_family = AF_INET;     
	server_addr.sin_port = htons(50765);   
	server_addr.sin_addr = *((struct in_addr *)host->h_addr);
	bzero(&(server_addr.sin_zero),8); 
	/*Connect client to server*/
       	if (connect(sock, (struct sockaddr *)&server_addr,sizeof(struct sockaddr)) == -1){
		perror("Connect Fail");
		exit(1);
	}
	
	fflush(stdout);
	/*Main function that poll the KeyBoard that take the user and password*/
	while (STOP==0){
		while(1){
			/**/ 
			printf("\nEnter your userID ,followed by SPACE key, and your password or press 'q' to QUIT : \n");
			int fd = open("/dev/tty0", O_RDONLY);
			if(fd == -1){
				/*Check if the keyboard  could be open*/
				printf("Unable to open /dev/tty0");
			} 
			/*Read until Escape is made [ENTER]*/
			while ((res=read(fd,send1,255)) == 0){
			 /*Print content - buffer and size of the buffer*/
				if(res > 0){
					send1[res]=0;
					printf("%s:%d",send1,res);
					if(send1[sizeof(send1)]=='\n') break;
				}                                              
			}
			char *tmp=strchr(send1,' ');

			/*Split user and password*/
			if (tmp !=NULL){
				*tmp='\0';
				strcpy(s1,send1);
				strcpy(s2,tmp+1);
			}
			/*Copy user into SRC variable*/

			strcpy(src,s1);
			/*Get size of string*/
			size_t length = sizeof(s2);
			int d=sizeof(s2);
			printf("\nlength:%d",d);

			char hash[SHA_DIGEST_LENGTH];
			int n;
			/*Print PASSWORD*/
			/*print_data();*/
			for(n=0;n<10;n++)
				printf("%02x ",s2[n]);
			/*Compute HASH*/				
			SHA1(s2,length,hash);
			printf("\ns2 : %s",s2);
			//concatenare user + hash
			strcat(src,hash);	
			/*To move local variables at function begining*/	
			char result[10];
			char decryptiontmp[1024]="";
			int k;
			printf("\n");
			/*Prepare Print function print_data()*/
			for( k=0 ; k<20 ; k++ ){
				sprintf(result,"%x",src[k]);
				strcat(decryptiontmp,result);	
			}
			
			unsigned char *decryptionhex=(unsigned char*)decryptiontmp;
			printf("UserID+Password : %s",decryptionhex);
			
			/*Get Local Time*/
			time_t rawtime;
			struct tm *timeinfo;
			char buffer[128];
			time(&rawtime);
			
			timeinfo=localtime(&rawtime);
			strftime(buffer,128,"%T",timeinfo);
			printf("\n\nTime: %s",buffer);

			/*Concatenate User / HASH(Password) / Time */		
			strcat(src,b);
			strcat(src,buffer);
			printf("\n\nUser+Hash+Time: ");
			strcpy(send_data,src);

			int i;
			printf("\n");
			/*Use print function*/	
			for(i=0;i<32;i++)
				printf("%02x ",send_data[i]);
			
			/*Move the variables as variables of the function*/				
			unsigned char encrypted[1024]={};
			unsigned char decrypted[1024]={};

			int encrypted_length= public_encrypt(send_data,strlen(send_data),publicKey,encrypted);
			if(encrypted_length == -1){
				printLastError("Public Encrypt failed ");
				exit(0);
			}
			/*Move variables at function start*/
			int j;
			printf("\n\nEncrypted message sent to server : \n");
			/*Use print function */
			for(j=0;j<32;j++)
				printf("%02x ",encrypted[j]);
			/*Send data to server*/	
			send(sock,encrypted,encrypted_length, 0); 	
			/*Get response from server*/
			bytes_recieved = recv(sock,recv_data,256,0);
			/*Insert end caracter - this may not be required*/
			recv_data[bytes_recieved] = '\0';
			/*If server respond with null data than socket will be closed*/
			if (recv_data==0){
				close(sock);
				break;
			}
			else{
				int k = 0;
				int decrypted_length = 0;
				printf("\n\nConfirmed message from server : \n");
				/*Use Print function*/		
				for(k=0;k<32;k++)
					printf("%02x ",recv_data[k]);
				/*Decrpt received data with private key*/
				decrypted_length=private_decrypt(recv_data,256,privateKey,decrypted);
				printf("\n\nDecrypted confirmed message : %s\n",decrypted);
				/*Validate / Invalidate*/
				if(strcmp(decrypted,"User Not Granted")==0){
					t=t+1;
					int ok=0;
					do{
					/*If the */
						if (t==3){
							printf("\nYou entered the wrong password three times so WAIT 30 s\n");
							sleep(10); 
						  	t=0;
						}	
					}/*end of do */
					/*Need to check if this is mandatory*/
					while(ok=0);
						printf("\nWrong passwords: %d",t);	
				}  
			}  
		}
	close(sock);
	return 0;
	}/*End of socket while*/
}
