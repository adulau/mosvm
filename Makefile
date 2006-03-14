ROOT=.
include $(ROOT)/Makefile.cf

# A list of unit test targets. All unit tests are to be compiled by MOSVM.
TESTS=test-core test-quasi test-parse test-assemble test-compile test-freeze test-process test-buffer

all: $(MOSC) $(MOSVM) libs mosrefs
test: $(TESTS)
test-%: test/%.mo $(MOSVM) libs mosrefs
	$(MOSVM) $<

mosrefs: $(MOSVM) libs
	sh bin/build-dir.sh mosref

libs: $(MOSVM)
	sh bin/build-dir.sh lib

clean:
	cd $(ROOT)/mosvm && $(MAKE) clean
	rm -f *.core tags build/bin/* examples/*mo test/*mo 

clean-seed:
	rm -f lib/*mo bin/*mo

$(LIBTC): crypt/src/* crypt/src/*/* crypt/src/*/*/*
	cd $(ROOT)/crypt && $(MAKE)

$(MOSVM_STUB): $(LIBTC) mosvm/*.[ch] mosvm/mosvm/*.[ch] mosvm/prims/*.[ch]
	cd $(ROOT)/mosvm && $(MAKE)

kabuki-filter:
	sh bin/build-app.sh $(MOSVM_STUB) examples/kabuki-filter build/bin/kabuki-filter$(EXE)

$(GLUE): mosvm/glue.c mosvm/mosvm/*.[ch]
	cd $(ROOT)/mosvm && $(MAKE)

$(MOSC): $(MOSVM_STUB) $(GLUE) 
	sh bin/build-app.sh $(MOSVM_STUB) bin/mosc $(MOSC)

$(MOSVM): $(MOSC) $(GLUE) lib/*.ms
	sh bin/build-app.sh $(MOSVM_STUB) bin/mosvm $(MOSVM)

%.mo: %.ms $(MOSC) 
	$(MOSC) $<

# We don't clean lib/*.mo, since we distribute a stock set of compiled
# objects for systems without guile.
really-clean: clean clean-seed

# Constructs a CTAGS file.
tags: mosvm/*.[ch] mosvm/*/*.[ch] lib/*.ms bin/*.ms 
	ectags --recurse=yes --langmap=scheme:+.ms mosvm lib bin

