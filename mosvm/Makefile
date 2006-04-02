ROOT=..
include $(ROOT)/Makefile.cf

OBJECTS=memory.o error.o exec.o main.o show.o thaw.o parse.o tree.o list.o string.o vector.o os.o buffer.o program.o regex.o prims/core.o prims/vm.o prims/os.o prims/progn.o prims/net.o prims/crypto.o prims/regex.o

build: $(MOSVM_STUB) $(GLUE)

ifeq ($(OS),Darwin)
# Mac OS X Tiger's linker is partially broken; we have to do something nasty..
$(MOSVM_STUB): $(OBJECTS)
	rm -rf cryptlib
	mkdir cryptlib
	cd cryptlib && ar x ../../crypt/libtomcrypt.a
	$(DO_CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) $(LIBGC) cryptlib/*.o $(LIBS) -o $(MOSVM_STUB)


else
$(MOSVM_STUB): $(OBJECTS)
	$(DO_CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) $(LIBGC) $(LIBTC) $(LIBS) -o $(MOSVM_STUB)

endif
$(GLUE): glue.o
	$(DO_CC) $(CFLAGS) $(LDFLAGS) glue.o $(LIBGC) $(LIBS) -o $(GLUE)

clean:
	rm -f *.o */*.o $(MOSVM) $(GLUE) *.core

