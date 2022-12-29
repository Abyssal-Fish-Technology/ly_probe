# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the nprobe
# (this file is processed with 'automake' to produce Makefile.in)
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
#       Copyright (C) 2002-2010 Luca Deri <deri@ntop.org> 
#
#                     http://www.ntop.org/ 
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


AUTOMAKE_OPTIONS = 1.6   # Require Automake 1.6 or better.

#
## The name of the game with its own major, minor and release version.
VERSION  = @PACKAGE_VERSION@
PROGRAM  = @PACKAGE_NAME@

APPL= lyprobe
APPL_DEMO= lyprobe_demo

PACKAGE=$(APPL)-@PACKAGE_VERSION@-0.i386.rpm
PKGNAME  = @PACKAGE_NAME@
PACKAGEDEMO=$(APPL)-demo-@PACKAGE_VERSION@-0.i386.rpm

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS)
LIBS      = @LIBS@ @CORELIBS@ @MORELIBS@
CC        = @CC@
CCLD      = @CCLD@
AM_CFLAGS = @CFLAGS@
AM_LDFLAGS= @LDFLAGS@

DISTCLEANFILES =  *~ *.log *.lo *.so *.o $(APPL) @PLUGINS@/*.o @PLUGINS@/*.lo  @PLUGINS@/*~ @PLUGINS@/*.so @PLUGINS@/*.la ./private/dmidecode-2.9/*.[oa~] .libs @PLUGINS@/.libs
CLEANFILES     = $(DISTCLEANFILES)

SUBDIRS = . @PLUGINS@

bin_PROGRAMS  		 = lyprobe
EXTRA_PROGRAMS		 = lyprobe_demo

# nprobe
lyprobe_SOURCES = nprobe.c
lyprobe_DEPENDENCIES = liblyprobe.la
lyprobe_LDADD = liblyprobe.la
lyprobe_LDFLAGS = $(AM_LDFLAGS) -pthread -lm
lyprobe_CFLAGS =

lib_LTLIBRARIES = liblyprobe.la

# nprobe core library

#
# On old systems getopt might be undefined
#
GETOPT_FILES=#getopt1.c getopt.c
liblyprobe_la_SOURCES = collect.c engine.c export.c database.c fb.c \
		       $(GETOPT_FILES) globals.c plugin.c \
		       sflow_collect.c util.c version.c base64.c $(PF_RING)
liblyprobe_la_LDFLAGS = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@

# demo nprobe
lyprobe_demo_SOURCES = nprobe.c
lyprobe_demo_DEPENDENCIES = liblyprobe.la
lyprobe_demo_LDADD = liblyprobe.la
lyprobe_demo_LDFLAGS = $(AM_LDFLAGS)
lyprobe_demo_CFLAGS = $(AM_LDFLAGS) -DDEMO_MODE

build-suse: $(APPL)
	@rm -f /usr/src/redhat/RPMS/i386/$(PACKAGE)
	@cp $(APPL)  /usr/src/packages/BUILD
	@rpm -bb $(APPL).spec
	@mv /usr/src/packages/RPMS/i386/$(PACKAGE) .

build-rh: $(APPL)
	@rm -f /usr/src/redhat/RPMS/i386/$(PACKAGE)
	@cp $(APPL) /usr/src/redhat/BUILD
	@rpmbuild -bb $(APPL).spec
	@mv /usr/src/redhat/RPMS/i386/$(PACKAGE) .

build-rh-demo: $(APPL_DEMO)
	@rm -f /usr/src/redhat/RPMS/i386/$(PACKAGE)
	@cp $(APPL_DEMO)  /usr/src/redhat/BUILD
	@mv /usr/src/redhat/BUILD/$(APPL_DEMO) /usr/src/redhat/BUILD/$(APPL)
	@rpmbuild -bb $(APPL).spec
	@mv /usr/src/redhat/RPMS/i386/$(PACKAGE) $(PACKAGEDEMO)

CLEANLIST = `ls -l $(DESTDIR)$(libdir)/*lyprobe*.so $(DESTDIR)$(libdir)/*Plugin*.so | \
          grep -v $(VERSION) | \
          grep -v '\->' | \
          $(AWK) '{ print $$NF }'`

listlibclean:
	@echo ""
	@echo "This is a list of old shared library files that will be deleted"
	@echo "if you run 'make libclean'"
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""

libclean:
	@echo ""
	@echo "Cleanup of old shared library files..."
	@echo ""
	@echo "  This is a list of files that will be deleted..."
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""
	@echo ""
	@echo "Press cntl-c to stop or enter to continue and delete these files..."
	@read select
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   ...Deleting $$file"; \
             rm -f $$file; \
          fi; \
        done


clean:
	/bin/rm -rf $(CLEANFILES)

lyprobes: $(lyprobe_OBJECTS) $(lyprobe_DEPENDENCIES)
	cd plugins; make
	$(CC) -static *.o plugins/*.o -o lyprobes -lz -lpcap -lpthread -ldl $(LIBS)

#nprobes: $(nprobe_OBJECTS) nprobe
#	$(CC) -static *.o -o nprobes $(LIBS)

############

TODAY=`date +"%D" | sed -e 's/\///g'`

maketar:
	\rm -rf nprobe_@PACKAGE_VERSION@_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)/plugins
	cp -r *.c *.h l7-patterns third_party nprobe_@PACKAGE_VERSION@_$(TODAY)
	cp plugins/*.c plugins/Makefile.am nprobe_@PACKAGE_VERSION@_$(TODAY)/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)
# Remove private + fastbit makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)/plugins/ntop*
	@REV@ nprobe_@PACKAGE_VERSION@_$(TODAY)/plugins/Makefile.am | sed '1,16d' | @REV@ | grep -v ntop > /tmp/a; mv /tmp/a nprobe_@PACKAGE_VERSION@_$(TODAY)/plugins/Makefile.am
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' > nprobe_@PACKAGE_VERSION@_$(TODAY)/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "svn-commit*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY).tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)

maketarntop:
	\rm -rf nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)/plugins
	mkdir nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)/private
	cp private/mongoose.[ch] nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)/private
	cp -r *.c *.h l7-patterns third_party nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)
	cp plugins/*.c plugins/ntop*.[ch] plugins/Makefile.am nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)
	cp -r html python nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)
# Remove private + fastbit makefile
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' > nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)/libtool
	\find nprobe_@PACKAGE_VERSION@_ntop_$(TODAY) -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "svn-commit*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_ntop_$(TODAY) -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_ntop_$(TODAY).tgz ./nprobe_@PACKAGE_VERSION@_ntop_$(TODAY)

maketarfastbit:
	\rm -rf nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/plugins
	mkdir nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/fastbit
	cp -r *.c *.h l7-patterns third_party nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)
	cp plugins/*.c plugins/Makefile.am nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/plugins
	cp -r fastbit/Makefile.in fastbit/*.cpp fastbit/*.[ch] fastbit/README* nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/fastbit
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)
# Remove private makefile
	\rm -f nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/plugins/ntop*
	@REV@ nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/plugins/Makefile.am | sed '1,16d' | @REV@ | grep -v ntop > /tmp/a; mv /tmp/a nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/plugins/Makefile.am
	grep -v 'private/Makefile' configure.in > nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/libtool
	\rm -rf nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)/fastbit/python/web/
	\find nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY) -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY) -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY) -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY) -name "svn-commit*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY) -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY).tgz ./nprobe_@PACKAGE_VERSION@_fastbit_$(TODAY)

maketarfull:
	\rm -rf nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp -r pro/ *.c *.h l7-patterns third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp plugins/*.c plugins/Makefile.am nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
# Remove private + fastbit makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins/ntop*
	@REV@ nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins/Makefile.am | sed '1,16d' | @REV@ | grep -v ntop > /tmp/a; mv /tmp/a nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins/Makefile.am
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' > nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_pro.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_pro

install: install-recursive
