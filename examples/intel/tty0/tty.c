/* 
 * Sample program that use the /dev/tty0 port.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>

int main () {

    int STOP = 0;
    char buf[255];
    int res; /* Variable that report the number of charahters read*/
    int fd = open("/dev/tty0", O_RDONLY);/*file descriptor*/
    if(fd == -1){
        /*Check if the keyboard  could be open*/
            printf("Unable to open /dev/tty0");
        }
        while(STOP == 0){
        /*Read until Escape is made [ENTER]*/
        while((res = read(fd,buf,255)) == 0);
        {
                /*Print content - buffer and zise of the buffer*/
                if(res > 0){
                        buf[res]=0;
                        printf("%s:%d\n", buf, res);
                    if(buf[sizeof(buf)]=='\n') break;
                }
            }
        }
     return 0;
}

