PREFIX ?= /usr/local

INCLUDEDIR = $(DESTDIR)$(PREFIX)/include
LIBDIR = $(DESTDIR)$(PREFIX)/lib

.PHONY: install uninstall

install:
	mkdir -p $(INCLUDEDIR)
	mkdir -p $(LIBDIR)

	cp ../../../src/ml_kem.h $(INCLUDEDIR)/
	cp ../ml_kem_userspace_port.h $(INCLUDEDIR)/

	sed '/^#if defined(USERSPACE)/,/^#endif \/\/ HEADERS/c\
#include <ml_kem_userspace_port.h>' \
	../../../src/ml_kem_core_header.h \
	> $(INCLUDEDIR)/ml_kem_core_header.h

	cp ../libmlkem.a $(LIBDIR)/

uninstall:
	rm -f \
		$(INCLUDEDIR)/ml_kem.h \
		$(INCLUDEDIR)/ml_kem_core_header.h \
		$(INCLUDEDIR)/ml_kem_userspace_port.h \
		$(LIBDIR)/libmlkem.a
