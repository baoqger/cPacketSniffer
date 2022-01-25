SNIFFER = sniffer

SRC = sniffer.c 
OBJ = $(SRC:.c=.o)

CC = cc
RM = rm

CFLAG = -g
LIBS = -lpcap
LDFLAGS =


.PHONY: clean

all: $(SNIFFER)

$(SNIFFER): $(OBJ)
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LIBS)

.c.o: 
	$(CC) -c $< $(CFLAGS)

clean:
	$(RM) ./$(OBJ) ./$(SNIFFER)