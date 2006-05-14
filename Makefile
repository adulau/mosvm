ROOT=.
include $(ROOT)/Makefile.cf

# A list of unit test targets. All unit tests are to be compiled by MOSVM.
TESTS=test-core test-quasi test-parse test-assemble test-freeze test-process test-buffer test-regex test-url test-http
# test-compile is bugged atm..

all: $(MOSC) $(MOSVM) libs mosrefs $(MOSREF) share/symbols
test: $(TESTS)
test-%: test/%.mo $(MOSVM) libs mosrefs
	$(MOSVM) $<

import-all-lib.ms: $(MOSVM) lib/*.ms
	echo '(import "lib/module")' >import-all-lib.ms
	for x in `ls lib/*.ms | cut -d. -f 1`; do echo "(import \"$$x\")" >>import-all-lib.ms; done
	echo '(define (main) (halt))' >>import-all-lib.ms

share/symbols: $(MOSVM) import-all-lib.ms
	$(MOSVM) -g import-all-lib.ms >share/symbols
	
$(MOSREF): $(MOSC) $(MOSVM) libs mosrefs
	sh bin/build-app.sh $(MOSVM_STUB) bin/mosref $(MOSREF)

repl:
	rlwrap -b"()" -f share/symbols $(MOSVM)

package: $(PACKAGE)

$(PACKAGE): $(MOSC) $(MOSVM) $(MOSREF) libs mosrefs
	rm -rf $(PACKAGEDIR) $(PACKAGE)
	mkdir $(PACKAGEDIR)
	cp -rf bin lib mosref stubs core site test examples $(PACKAGEDIR)
	$(PACKAGECMD)

mosrefs: $(MOSVM) libs
	sh bin/build-dir.sh mosref

site/config.ms: bin/situation.sh
	sh bin/situation.sh

libs: lib/*ms core/*ms site/*ms site/config.ms
	sh bin/build-dir.sh core
	sh bin/build-dir.sh lib
	sh bin/build-dir.sh site

clean:
	cd $(ROOT)/mosvm && $(MAKE) clean
	rm -f *.tar.gz *.zip *.core tags build/bin/* examples/*mo test/*mo 
	rm -f $(MOSVM) $(MOSREF) $(MOSC)

clean-seed:
	rm -f lib/*mo bin/*mo core/*mo site/*mo

clean-stubs:
	rm -f stubs/*

$(LIBTC): crypt/src/* crypt/src/*/* crypt/src/*/*/*
	cd $(ROOT)/crypt && $(MAKE)

$(MOSVM_STUB): $(LIBTC) mosvm/*.[ch] mosvm/mosvm/*.[ch] mosvm/prims/*.[ch]
	cd $(ROOT)/mosvm && $(MAKE)

$(GLUE): mosvm/glue.c mosvm/mosvm/*.[ch]
	cd $(ROOT)/mosvm && $(MAKE)

$(MOSC): $(MOSVM_STUB) $(GLUE) libs
	sh bin/build-app.sh $(MOSVM_STUB) bin/mosc $(MOSC)

$(MOSVM): $(MOSC) $(GLUE) site/config.ms libs
	sh bin/build-app.sh $(MOSVM_STUB) bin/mosvm $(MOSVM)

%.mo: %.ms $(MOSC) 
	$(MOSC) $<

# We don't clean lib/*.mo, since we distribute a stock set of compiled
# objects for systems without guile.
really-clean: clean clean-seed

# Constructs a CTAGS file.
tags: mosvm/*.[ch] mosvm/*/*.[ch] lib/*.ms bin/*.ms 
	ectags --recurse=yes --langmap=scheme:+.ms mosvm lib bin

