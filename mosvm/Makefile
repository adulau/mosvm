ROOT=..
include $(ROOT)/Makefile.cf

OBJECTS=memory.o number.o boolean.o list.o string.o tree.o vector.o regex.o package.o primitive.o procedure.o parse.o format.o print.o closure.o vm.o file.o error.o process.o crypto.o channel.o stream.o core.o tag.o multimethod.o time.o init.o

TOOLS=$(MOSASM) $(MOSVM_STUB) $(MOSLD)

LIBS=$(LIBTC)

all: $(TOOLS)

$(MOSASM): mosvm/*.h mosvm.h $(OBJECTS) mosasm.o
	gcc $(CFLAGS) $(LDFLAGS) $(OBJECTS) mosasm.o $(LIBS) -o $(MOSASM)
	
$(MOSVM_STUB): mosvm/*.h mosvm.h $(OBJECTS) mosvm.o
	gcc $(CFLAGS) $(LDFLAGS) $(OBJECTS) mosvm.o $(LIBS) -o $(MOSVM_STUB)
	
$(MOSLD): mosvm/*.h mosvm.h $(OBJECTS) mosld.o
	gcc $(CFLAGS) $(LDFLAGS) $(OBJECTS) mosld.o $(LIBS) -o $(MOSLD)
	
clean:
	rm -f $(TOOLS) *.o *.core
