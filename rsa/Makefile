all:
	gcc rsa-keygen.c -o rsa-keygen -lgmp -lpthread
	gcc -c rsa-util.c -o rsa-util.o
	gcc -c sha2.c -o sha2.o
	gcc rsa-util.o sha2.o -o rsa-util -lgmp

clean:
	rm -f rsa-keygen
	rm -f rsa-util
	rm -f *.o

