INCL = -I.
CFLAGS = -Wall -Wno-format-overflow -g -O3 $(INCL)
UNAME = $(shell uname)
CC = gcc
CPP = g++
LD = g++
LDFLAGS = -lgmp
TARGET = dhmtest
OBJS = main.o dhm.o aes.o sha2.o

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
	
