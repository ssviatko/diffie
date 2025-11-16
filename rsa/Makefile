all:
	# common files
	gcc -c sha2.c -o sha2.o
	gcc -c ccct.c -o ccct.o
	# rsa-keygen
	gcc -c rsa-keygen.c -o rsa-keygen.o
	gcc rsa-keygen.o ccct.o -o rsa-keygen -lgmp -lpthread
	# rsa-util
	gcc -c rsa-util.c -o rsa-util.o
	gcc rsa-util.o ccct.o sha2.o -o rsa-util -lgmp -lpthread

clean:
	rm -f rsa-keygen
	rm -f rsa-util
	rm -f *.o

