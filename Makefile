# Path to parent kernel include files directory
#KERNEL_INCLUDE=/usr/src/linux/include
LIBC_INCLUDE=/usr/include

DEFINES= 

#options if you have a bind>=4.9.4 libresolv (or, maybe, glibc)
LDLIBS=-lresolv
ADDLIB=

#ifeq ($(LIBC_INCLUDE)/socketbits.h,$(wildcard $(LIBC_INCLUDE)/socketbits.h))
#  ifeq ($(LIBC_INCLUDE)/net/if_packet.h,$(wildcard $(LIBC_INCLUDE)/net/if_packet.h))
#    GLIBCFIX=-Iinclude-glibc -include include-glibc/glibc-bugs.h
#  endif
#endif
#ifeq ($(LIBC_INCLUDE)/bits/socket.h,$(wildcard $(LIBC_INCLUDE)/bits/socket.h))
#  GLIBCFIX=-Iinclude-glibc -include include-glibc/glibc-bugs.h
#endif


#options if you compile with libc5, and without a bind>=4.9.4 libresolv
# NOT AVAILABLE. Please, use libresolv.

CC=gcc
# What a pity, all new gccs are buggy and -Werror does not work. Sigh.
#CCOPT=-D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall -g -Werror
CCOPT=-D_GNU_SOURCE -O2 -Wstrict-prototypes -Wall -g
CFLAGS=$(CCOPT) $(GLIBCFIX) $(DEFINES) 

IPV4_TARGETS=tracepath ping arping
IPV6_TARGETS=tracepath6 traceroute6 ping6
TARGETS=$(IPV4_TARGETS) $(IPV6_TARGETS)

all: symlink $(TARGETS)


tftpd: tftpd.o tftpsubs.o
ping: ping.o ping_common.o
ping6: ping6.o ping_common.o
ping.o ping6.o ping_common.o: ping_common.h
tftpd.o tftpsubs.o: tftp.h


symlink:
	ln -sf ../socketbits.h include-glibc/bits/socket.h

check-kernel:
ifeq ($(KERNEL_INCLUDE),)
	@echo "Please, set correct KERNEL_INCLUDE"; false
else
	@set -e; \
	if [ ! -r $(KERNEL_INCLUDE)/linux/autoconf.h ]; then \
		echo "Please, set correct KERNEL_INCLUDE"; false; fi
endif

modules: check-kernel
	$(MAKE) KERNEL_INCLUDE=$(KERNEL_INCLUDE) -C Modules

man:
	$(MAKE) -C doc man

html:
	$(MAKE) -C doc html

clean:
	rm -f *.o $(TARGETS)
	rm -f include-glibc/bits/socket.h
	$(MAKE) -C Modules clean
	$(MAKE) -C doc clean

install: html
	$(MAKE) -C doc install

snapshot: clean
	@if [ ! -r RELNOTES.xxyyzz ]; then echo "Where are RELNOTES?"; exit 1; fi
	@cp RELNOTES RELNOTES.bak
	@date "+[%y%m%d]" > RELNOTES
	@cat RELNOTES.xxyyzz >> RELNOTES
	@cat RELNOTES.bak >> RELNOTES
	@date "+static char SNAPSHOT[] = \"%y%m%d\";" > SNAPSHOT.h
	@$(MAKE) -C doc snapshot
	@rm -f RELNOTES.xxyyzz RELNOTES.bak

