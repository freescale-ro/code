CC=gcc
CFLAGS= -I /usr/local/ssl/include  -c -Wall
LDFLAGS= -L /usr/local/ssl/lib -lcrypto
SOURCES=tty.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=tty

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm *.o
