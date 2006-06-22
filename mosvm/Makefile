ROOT=..
include $(ROOT)/Makefile.cf

OBJECTS=memory.o number.o boolean.o list.o string.o tree.o vector.o regex.o package.o primitive.o procedure.o parse.o format.o print.o closure.o vm.o file.o error.o process.o crypto.o channel.o stream.o core.o tag.o multimethod.o time.o crc32.o shell.o init.o

TOOLS=$(MOSVM_STUB) $(MOSASM) $(MOSLD)

all: $(TOOLS)

REQS=$(OBJECTS)

LIBS=$(LIBRX)

ifeq ($(OS),Darwin)

# Mac OS X Tiger's linker is partially broken; we have to do something nasty..
cryptlib: $(LIBTC)
	rm -rf cryptlib
	mkdir cryptlib
	cd cryptlib && ar x ../../crypt/libtomcrypt.a

REQS+=cryptlib
LIBS+=cryptlib/*.o

else

LIBS+=$(LIBTC)

endif

$(MOSVM_STUB): $(REQS) mosvm.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) mosvm.o $(LIBS) -o $(MOSVM_STUB)

$(MOSASM): $(REQS) mosasm.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) mosasm.o $(LIBS) -o $(MOSASM)
	
$(MOSLD): $(REQS) mosld.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) mosld.o $(LIBS) -o $(MOSLD)

clean:
	rm -f $(TOOLS) *.o *.core
