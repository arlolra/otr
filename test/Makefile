CC=gcc
PWD=$(shell pwd)
LIBOTR_DIR=$(PWD)/libotr

all: libotr build

libotr:
	if [ ! -f libotr-3.2.0.tar.gz ]; \
	  then wget http://www.cypherpunks.ca/otr/libotr-3.2.0.tar.gz; \
	fi;
	rm -rf libotr-3.2.0;
	tar -xzvf libotr-3.2.0.tar.gz;
	cd libotr-3.2.0; ./configure --prefix=$(LIBOTR_DIR); make install;

build:
	$(CC) libotr_test_helper.c \
		-L$(LIBOTR_DIR)/lib \
		-I$(LIBOTR_DIR)/include/libotr \
		-lotr \
		-o libotr_test_helper.out

clean:
	rm -rf libotr-3.2.0* libotr libotr_test_helper.out

.PHONY: clean build libotr
