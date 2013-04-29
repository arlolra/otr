CC=gcc

all: libotr build

libotr:
	if [ ! -f libotr-3.2.0.tar.gz ]; \
	  then wget http://www.cypherpunks.ca/otr/libotr-3.2.0.tar.gz; \
	fi;
	rm -rf libotr-3.2.0;
	tar -xzvf libotr-3.2.0.tar.gz;
	cd libotr-3.2.0; ./configure --prefix=/tmp/libotr; make install;

build:
	$(CC) libotr_test_helper.c \
		-L/tmp/libotr/lib \
		-I/tmp/libotr/include/libotr \
		-lotr \
		-o /tmp/a.out

clean:
	rm -rf libotr-3.2.0* /tmp/libotr /tmp/a.out
