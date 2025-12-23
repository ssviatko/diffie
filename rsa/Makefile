BUILD_NUMBER_FILE = build.no
RELEASE_NUMBER_FILE = release.no
BUILD_DATE=$$(date +'%Y-%m-%d %H:%M %z %Z')
BUILD_NUMBER=$$(cat $(BUILD_NUMBER_FILE))
RELEASE_NUMBER=$$(cat $(RELEASE_NUMBER_FILE))
CFLAGS = -DBUILD_NUMBER="\"$(BUILD_NUMBER)\"" -DBUILD_DATE="\"$(BUILD_DATE)\"" -DRELEASE_NUMBER="\"$(RELEASE_NUMBER)\"" -O3 -Wall -I.

all:
	# common files
	gcc $(CFLAGS) -c sha2.c -o sha2.o
	gcc $(CFLAGS) -c ccct.c -o ccct.o
	gcc $(CFLAGS) -c color_print.c -o color_print.o
	# rsa-keygen
	gcc $(CFLAGS) -c rsa-keygen.c -o rsa-keygen.o
	gcc rsa-keygen.o ccct.o color_print.o -o rsa-keygen -lgmp -lpthread
	# rsa-util
	gcc $(CFLAGS) -c rsa-util.c -o rsa-util.o
	gcc rsa-util.o ccct.o color_print.o sha2.o -o rsa-util -lgmp -lpthread
	# b64t
	gcc $(CFLAGS) -c b64t.c -o b64t.o
	gcc b64t.o ccct.o -o b64t
	# increment build number
	@echo $$(($$(cat $(BUILD_NUMBER_FILE)) + 1)) > $(BUILD_NUMBER_FILE)

clean:
	rm -f rsa-keygen
	rm -f rsa-util
	rm -f b64t
	rm -f *.o

