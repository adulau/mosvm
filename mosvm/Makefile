ROOT=..
include $(ROOT)/Makefile.cf

OBJECTS=memory.o error.o exec.o main.o show.o thaw.o parse.o tavl.o list.o string.o vector.o os.o program.o prims/core.o prims/vm.o prims/os.o prims/progn.o prims/net.o

build: $(MOSVM_STUB) $(GLUE)

$(MOSVM_STUB): $(OBJECTS)
	$(DO_CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) $(LIBGC) $(LIBS) -o $(MOSVM_STUB)

$(GLUE): glue.o
	$(DO_CC) $(CFLAGS) $(LDFLAGS) glue.o $(LIBGC) $(LIBS) -o $(GLUE)

clean:
	rm -f *.o */*.o $(MOSVM) $(GLUE) *.core

