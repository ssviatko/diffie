all:
	gcc -c main.c -o main.o
	gcc -c sha2.c -o sha2.o
	gcc -c aes.c -o aes.o
	gcc main.o sha2.o aes.o -o aesctr

clean:
	rm -f aesctr
	rm -f *.o

