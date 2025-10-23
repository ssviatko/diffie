INCL = -I.
CFLAGS = -Wall -O3 $(INCL)
UNAME = $(shell uname)
CC = gcc
CPP = g++
LD = g++
LDFLAGS = -lgmp
TARGET = dhtest
OBJS = main.o dh.o aes.o

all: $(TARGET)

$(TARGET): $(OBJS)

	$(LD) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

%.o: %.cc
	$(CPP) $(CFLAGS) -c $<

clean:
	rm -f *.o
	rm -f *~
	rm -f $(TARGET)
	
