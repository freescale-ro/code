/*
 * ETTI - SEC LAB applications
 * This application will init and enable the SRTP protocol
 */

#include <stdio.h>
#define MAX_ARRAY_SIZE 20

int data[MAX_ARRAY_SIZE];
int i;
int main(void){
    printf("test\n");
	printf("data is incomplete \n");
	data[1] = 10;
	data[2] = 20;
	for(i =0 ; i <= 2; i++){
		printf("number %d \n", data[i]);
	}
}
