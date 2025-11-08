all:
	gcc rsa-keygen.c -o rsa-keygen -lgmp -lpthread
	gcc -c rsa.c -o rsa.o
	gcc -c sha2.c -o sha2.o
	gcc rsa.o sha2.o -o rsa -lgmp

clean:
	rm -f rsa-keygen
	rm -f rsa
	rm -f *.o

