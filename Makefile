# Path to parent kernel include files directory (default /usr/include)
#KERNEL_INCLUDE=/usr/src/linux/include
#KERNEL_INCLUDE=/net/bh/var/src/vger/dist/linux/include
#KERNEL_INCLUDE=/net/bh/home/root/vger-mirror/linux/include
#KERNEL_INCLUDE=/home1/root/vger-129/vger-mirror/linux/include
#KERNEL_INCLUDE=/u2/lsrc/vger4/linux/include

DEFINES= 

#options if you have a bind>=4.9.4 libresolv (or, maybe, glibc)
LDLIBS=-lresolv
ADDLIB=

ifeq (/usr/include/socketbits.h,$(wildcard /usr/include/socketbits.h))
  ifeq (/usr/include/net/if_packet.h,$(wildcard /usr/include/net/if_packet.h))
    GLIBCFIX=-Iinclude-glibc -include include-glibc/glibc-bugs.h
  endif
endif
ifeq (/usr/include/bits/socket.h, $(wildcard /usr/include/bits/socket.h))
  GLIBCFIX=-Iinclude-glibc -include include-glibc/glibc-bugs.h
endif


#options if you compile with libc5, and without a bind>=4.9.4 libresolv
# NOT AVAILABLE. Please, use libresolv.

CC=gcc
CFLAGS=-O2 -Wall -g $(GLIBCFIX) -I../include $(DEFINES) # -I$(KERNEL_INCLUDE)

IPV4_TARGETS=tracepath ping clockdiff rdisc arping tftpd
IPV6_TARGETS=tracepath6 traceroute6 ping6
TARGETS=$(IPV4_TARGETS) $(IPV6_TARGETS)

all: check-kernel $(TARGETS)

tftpd: tftpd.o tftpsubs.o

check-kernel:
#ifeq ($(KERNEL_INCLUDE),)
#	@echo "Please, set correct KERNEL_INCLUDE"; false
#else
#	@set -e; \
#	if [ ! -r $(KERNEL_INCLUDE)/linux/autoconf.h ]; then \
#		echo "Please, set correct KERNEL_INCLUDE"; false; fi
#endif

clean:
	rm -f *.o $(TARGETS)

install: all
	install -m 4755 -o root -g root ping $(BASEDIR)/bin/
	install -m 4755 -o root -g root ping6 $(BASEDIR)/bin/
	install -m 4755 -o root -g root traceroute6 $(BASEDIR)/usr/sbin/
	install -m 0755 -o root -g root tracepath $(BASEDIR)/usr/sbin/
	install -m 0755 -o root -g root tracepath6 $(BASEDIR)/usr/sbin/
	install -m 0755 -o root -g root arping $(BASEDIR)/usr/sbin/
#	install -m 0755 -o root -g root rdisc $(BASEDIR)/usr/sbin/

