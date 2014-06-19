 	/*SERVER*/

	#include <stdio.h>
	#include <errno.h>
	#include <string.h>
	#include <stdlib.h>
	#include <unistd.h>
	#include <arpa/inet.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <sys/socket.h>
	#include <openssl/pem.h>
	#include <openssl/ssl.h>
	#include <openssl/rsa.h>
	#include <openssl/evp.h>
	#include <openssl/bio.h>
	#include <openssl/err.h>
	#include <openssl/sha.h>

	int padding = RSA_PKCS1_PADDING;
	
	RSA * createRSA(unsigned char * key,int public)
	{
    	 RSA *rsa= NULL;
    	 BIO *keybio ;
    	 keybio = BIO_new_mem_buf(key, -1);
    	
		if (keybio==NULL)
    		{
        	 printf( "Failed to create key BIO");
        	 return 0;
    		}
   
		if(public)
			{
        	 rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL); 
    		}
    		else
    		{
        	 rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    		}
    
		if(rsa == NULL)
		{
        	 printf( "Failed to create RSA");
    		}
 
	return rsa;
	}

	int public_encrypt(unsigned char *data, int data_len, unsigned char *key,unsigned char *encrypted)
	{
    	 RSA *rsa = createRSA(key,1);
    	 int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    	 return result;
	}

	int private_decrypt(unsigned char *enc_data,int data_len,unsigned char *key, unsigned char *decrypted)
	{
    	 RSA * rsa = createRSA(key,0);
    	 int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    	 return result;
	}
 
	void printLastError(char *msg)
	{
	 char *err = malloc(130);
    	 ERR_load_crypto_strings();
    	 ERR_error_string(ERR_get_error(), err);
    	 printf("%s ERROR: %s\n",msg, err);
    	 free(err);
	}
	
	struct utilizator
	 {	
	   char *user;
	   char *ip; 
	   char *publicKey;
	   char *privateKey;
	 };	 
	
	
	time_t to_seconds(const char *date)
	 {
 	    struct tm storage={0,0,0,0,0,0,0,0,0}; 
	    char *p=NULL;
	    time_t retval =0;
	    p=(char *)strptime(date,"%T", &storage );
         	if(p==NULL)
			{
			retval=0;
			}
		else
			{
			retval=mktime(&storage);
			}	
	    return retval;
	}
	
	int main(int argc, char* argv [])
	 {	
		fd_set fds, readfds;
		struct utilizator us[3];
		int i, clientaddrlen,rval;
		int clientsock[2], rc, numsocks = 0, maxsocks = 2;
		
		us[0].user="616e61489caabbb3050262e35cb47e1fdbde7a9"; //ana
		us[0].ip="192.168.1.1";
		//us[1].ip="127.0.0.1"; 
		us[1].user="6d6172696192c97e95bb2933f55c6d5e3ee796"; //maria
		//us[1].ip="127.0.0.1"; 
		us[1].ip="192.168.1.2";

       	        int sock, connected, bytes_recieved , true = 1;  
		unsigned char recv_data[1024];      
      		struct sockaddr_in server_addr,client_addr;    
       	 	int sin_size; 

		char plainText[128]="User Granted";
		char msg[128]="User Not Granted";
		unsigned char s1[1024]="";
		unsigned char s2[1024]="";
		
		//cheia publica din fisier a clientului 1 ana
		printf("\nPublic Key of Client1:\n");
		FILE *f=fopen("pubkey1.pem","rb");
		fseek(f,0,SEEK_END);
		long fsize=ftell(f);
		fseek(f,0,SEEK_SET);

		char *publicKey=malloc(fsize+1);
		fread(publicKey,fsize,1,f);
		fclose(f);
		publicKey[fsize]=0;
		printf(publicKey);
		us[0].publicKey=publicKey;
		
		//cheia publica din fisier a clientului 2 maria
		printf("\nPublic Key of Client2:\n");
      		FILE *f1=fopen("pubkey2.pem","rb");
        	fseek(f1,0,SEEK_END);
      		long fsize1=ftell(f1);
      		fseek(f1,0,SEEK_SET);

     		char *publicKey2=malloc(fsize1+1);
      		fread(publicKey2,fsize1,1,f1);
       		fclose(f1);
       		publicKey2[fsize1]=0;
       		printf(publicKey2);
		us[1].publicKey=publicKey2;
		
		//cheia privata din fisier a serverului
		printf("\nPrivate Key of Server:\n");
     		FILE *f2=fopen("newkey.pem","rb");
     		fseek(f2,0,SEEK_END);
     		long fsize2=ftell(f2);
    	        fseek(f2,0,SEEK_SET);

                char *privateKey=malloc(fsize2+1);
  	        fread(privateKey,fsize2,1,f2);
   	        fclose(f2);
   	        privateKey[fsize2]=0;
   	        printf(privateKey);	

		if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
		  {
         		perror("Socket");
         		exit(1);
        	   }

                 if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) 
	           {
         		perror("Setsockopt");
         		exit(1);
        	   }

       		 server_addr.sin_family = AF_INET;         
       		 server_addr.sin_port = htons(50765);  
       		 server_addr.sin_addr.s_addr = INADDR_ANY; 
       		 bzero(&(server_addr.sin_zero),8); 
	
       		 if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))== -1) 
	           {
         	       perror("Unable to bind");
       		       exit(1);
                   }

     		 if (listen(sock, 5) == -1) 
		   {
         	       perror("Listen");
                       exit(1);
        	   }

		FD_ZERO(&fds);
  		FD_SET(sock, &fds);
		
  		printf("\nServer is Waiting for Clients: \n");
          	fflush(stdout);

        	while(1)
        	  {    

		    readfds = fds;
    		    rc = select(FD_SETSIZE, &readfds, NULL, NULL, NULL);

    	            if (rc == -1) 
			{
                    	    perror("Select");
                            break;
    			}     

		for (i = 0; i < FD_SETSIZE; i++) {
     		 if (FD_ISSET(i, &readfds)) {
      		  if (i == sock) {
      		    if (numsocks < maxsocks) {
	
	    		sin_size = sizeof(struct sockaddr_in);
           		int connected;
	        	connected=accept(sock,(struct sockaddr *) &client_addr,&sin_size);
        		//printf("\nI got a connection from Client with IP(%s , %d)\n",
                	//inet_ntoa(client_addr.sin_addr),ntohs(client_addr.sin_port));
			printf("\nI got a connection from Client with IP(%s)\n",
               		inet_ntoa(client_addr.sin_addr));
	     		char *adresa=inet_ntoa(client_addr.sin_addr);
		
	  		if (connected == -1) perror("Accept");
              		FD_SET(connected, &fds);
            		numsocks++;	
		
					     }
				  }
   
 		else 
		  {
		        bzero(recv_data,sizeof(recv_data));
        	        if((rval=recv(i,recv_data,1024,0))<0)
                        perror("reading stream message");
           
		        char *adresa=inet_ntoa(client_addr.sin_addr);
	                int index_user =-1;
	                int i=0;
		        for (i=0;i<3;i++)
                          if (strcmp(us[i].ip,adresa)==0)
                            index_user=i;
	
		while (1)
		    {
		        bytes_recieved = recv(connected,recv_data,256,0);
		        recv_data[bytes_recieved] = '\0';	
		        int l;
			
		        if(strcmp(recv_data,"q")==0)
			   {
				printf("\nThe connection is closed\n");
				
				return 0;	
			    }
	
			printf("\nMessage encrypted from client: \n");
		
			for(l=0;l<32;l++)
				printf("%02x ",recv_data[l]);
					
			unsigned char decrypted[1024]={};
			unsigned char encrypted[1024]={};

			int decrypted_length = private_decrypt(recv_data,256,privateKey, decrypted);
			if(decrypted_length == -1)
				{
				   printLastError("Private Decrypt failed ");
				   exit(0);
				}
			printf("\n\nDecrypted message: \n");

			int t;
				for(t=0;t<32;t++)
				printf("%02x ",decrypted[t]);
						
			char *tmp=strchr(decrypted,'#');
			if (tmp !=NULL)
				{
					*tmp='\0';
					strcpy(s1,decrypted);
		
					char result[10];
					char decryptiontmp[1024]="";
					int k;
					printf("\n");
					for(k=0;k<20;k++)
					{	
						sprintf(result,"%x",s1[k]);
						strcat(decryptiontmp,result);	
					}
					unsigned char *decryptionhex=(unsigned char*)decryptiontmp;
					printf("\nHexa : %s",decryptionhex);

					strcpy(s2,tmp+1);
					printf("\n\nTime of Client: %s ",s2);
			
					time_t rawtime;
					struct tm *timeinfo;
					char buffer[128];
					buffer[128]=0;
					time(&rawtime);
					timeinfo=localtime(&rawtime);
	
					strftime(buffer,128,"%T",timeinfo);
					printf("\nTime of Server: %s",buffer);

					char *date1=buffer; //server
					char *date2=s2; 	//cl
					time_t d1=to_seconds(date2)+5;
					time_t d11=to_seconds(date2)-5;
					time_t d2=to_seconds(date1);  //server

			for (i = 0; i < FD_SETSIZE; i++) {
     			  if (FD_ISSET(i, &readfds)) {
                           if((((strcmp(decryptionhex,us[index_user].user)==0)&&(strcmp(adresa, us[index_user].ip)==0)))&&((d2<d1)&&(d11<d2)))
				{
		
					//char publicKey [2048]=publicKey[i];
					printf("\n\nAccept Access!");
					int encrypted_length = public_encrypt(plainText,strlen(plainText),us[index_user].publicKey,encrypted);
					printf("\n\nConfirmed message sent to Client: ");
					int t;
					printf("\n");
					for(t=0;t<32;t++)	
					printf("%02x ",encrypted[t]);	
					printf("\n");
					send(i,encrypted,encrypted_length,0);
					break;					
					printf("\n");
					break;
						
				} 
					
			   else 
			        {
					printf("\nDeny Access!");
					int encrypted_length=public_encrypt(msg,strlen(msg),us[index_user].publicKey,encrypted);
					printf("\n\nConfirmed message sent to Client: \n");
					int p;
					for(p=0;p<32;p++)	
					printf("%02x ",encrypted[p]);		
					printf("\n");
					send(i,encrypted,encrypted_length,0);
					break;
					printf("\n");
					break;	
				}

  			}     
	       }
      }	
break;
} 
break;
}
}
}
}

    return 0;
 
}
