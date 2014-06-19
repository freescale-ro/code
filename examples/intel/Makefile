CC=gcc
CFLAGS= -I /usr/local/ssl/include  -c -Wall
LDFLAGS= -L /usr/local/ssl/lib -lcrypto
SOURCES=rsa.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=rsa

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm *.o
