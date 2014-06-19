CC=${CROSS_COMPILE}gcc
CFLAGS=-I/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/ppce500v2-fsl_networking-linux-gnuspe/usr/local/ssl/include/ -c -Wall
LDFLAGS=-L/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/ppce500v2-fsl_networking-linux-gnuspe/usr/local/ssl/lib/ -lcrypto
SOURCES=test.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=test

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm *.o
