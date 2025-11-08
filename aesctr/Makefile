all:
	gcc -c main.c -o main.o
	gcc -c aes.c -o aes.o
	gcc main.o aes.o -o aesctr

clean:
	rm -f aesctr
	rm -f *.o

