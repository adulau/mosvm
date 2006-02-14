ROOT=.
include $(ROOT)/Makefile.cf

# SEED files are MOSVM modules that must be compiled using Scheme, and will
# be integrated with the VM to create a command providing a REPL and the 
# ability to execute MOSVM programs.
#
# These files use the traditional .scm file suffix since they are meant to 
# either be compiled using the Scheme implementation of MOSC, or are 
# written in a language that is a union between MOSVM and R5RS.

SEED=lib/core.mo lib/lib.mo lib/compile.mo lib/assemble.mo lib/optimize.mo lib/freeze.mo lib/trace.mo lib/repl.mo lib/run.mo

# The MODS are a superset of the SEED that are used by test cases and MOSVM
# applications. Any file in MODS that is not in SEED are compiled once the 
# final MOSVM executable has been created.
MODS=$(SEED) lib/test.mo lib/conn.mo lib/format.mo

# A list of unit test targets. All unit tests are to be compiled by MOSVM.
TESTS=test-core test-quasi test-parse test-assemble test-compile test-freeze test-process test-buffer

all: $(MOSVM) $(MODS) bin/mosc.mo

test: $(TESTS)

test-%: test/%.mo $(MOSVM) $(MODS)
	$(MOSVM) $<

# There are two .MO production rules, one for producing MO from SCM.
# SCM files are MOSVM source files that are also valid in Scheme.
%.mo: %.scm bin/*.scm lib/*.scm
	$(DO_SCHEME) bin/mosc.scm $< $@

# And the other for producing MO from MS.
# MS files are MOSVM source files that are only valid in MOSVM.
%.mo: %.ms $(MOSVM) $(SEED) bin/mosc.mo
	$(MOSVM) bin/mosc.mo $< $@

$(MOSVM_STUB): mosvm/*.[ch] mosvm/mosvm/*.[ch] mosvm/prims/*.[ch]
	cd $(ROOT)/mosvm && $(MAKE)

$(GLUE): mosvm/glue.c mosvm/mosvm/*.[ch]
	cd $(ROOT)/mosvm && $(MAKE)

$(MOSVM): $(MOSVM_STUB) $(SEED) $(GLUE)
	$(GLUE) $< $(SEED) $@ && chmod 0755 $@

clean:
	cd $(ROOT)/mosvm && $(MAKE) clean
	rm -f *.core tags build/bin/* examples/*mo test/*mo 

# We don't clean lib/*.mo, since we distribute a stock set of compiled
# objects for systems without guile.
really-clean: clean
	rm -f lib/*mo bin/*.mo

# Constructs a CTAGS file.
tags: mosvm/*.[ch] mosvm/mosvm/*.[ch] lib/* bin/*
	ectags --recurse=yes --langmap=scheme:+.ms mosvm lib bin

# Useful targets for the bin/mosvm shell script.
run: $(MOSVM) $(MODS) $(p).mo
	rm -f mosvm.core
	$(MOSVM) $(f) $(p).mo $(a)

debug: $(MOSVM) $(MODS) $(p).mo
	rm -f mosvm.core
	$(MOSVM) -d $(f) $(p).mo $(a) ||( [ -r mosvm.core ] && gdb $(MOSVM) mosvm.core ) 

# A useful target for building a "glued" binary.
glue: $(p).mo $(MOSVM)
	$(DO_GLUE) $(MOSVM) $(p).mo $(p) && chmod a+rx $(p)

