SNIFFER = sniffer

#SRC = sniffer.c datagram.c ethernetframe.c macaddress.c utils.c ippacket.c ipaddress.c arppacket.c simple-set.c icmppacket.c
SRC = $(wildcard ./*.c)

OBJ = $(SRC:.c=.o)

CC = cc
RM = rm

CFLAGS = -g
LIBS = -lpcap
LDFLAGS =


.PHONY: clean

all: $(SNIFFER)

debug: CFLAGS += -ggdb -O0
debug: $(SNIFFER)

$(SNIFFER): $(OBJ)
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LIBS)

.c.o: 
	$(CC) -c $< $(CFLAGS)

clean:
	$(RM) ./$(OBJ) ./$(SNIFFER)
