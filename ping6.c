/*
 *
 *	Modified for AF_INET6 by Pedro Roque
 *
 *	<roque@di.fc.ul.pt>
 *
 *	Original copyright notice included bellow
 */

/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1989 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	This program has to run SUID to ROOT to access the ICMP socket.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/bitops.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#define ICMPV6_FILTER_WILLPASS(type, filterp) \
	(test_bit(type, filterp) == 0)

#define ICMPV6_FILTER_WILLBLOCK(type, filterp) \
	test_bit(type, filterp)

#define ICMPV6_FILTER_SETPASS(type, filterp) \
	clear_bit(type & 0x1f, &((filterp)->data[type >> 5]))

#define ICMPV6_FILTER_SETBLOCK(type, filterp) \
	set_bit(type & 0x1f, &((filterp)->data[type >> 5]))

#define ICMPV6_FILTER_SETPASSALL(filterp) \
	memset(filterp, 0, sizeof(struct icmp6_filter));

#define ICMPV6_FILTER_SETBLOCKALL(filterp) \
	memset(filterp, 0xFF, sizeof(struct icmp6_filter));


#define MAX_IPOPTLEN	4096
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "SNAPSHOT.h"

#define ICMP_MINLEN	28

#define	DEFDATALEN	(64 - 8)	/* default data length */
#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	MAXPACKET	128000		/* max packet size */
#define	MAXWAIT		10		/* max seconds to wait for response */
#define	NROUTES		9		/* number of record route slots */

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(bit)	(A(bit) |= B(bit))
#define	CLR(bit)	(A(bit) &= (~B(bit)))
#define	TST(bit)	(A(bit) & B(bit))

/* various options */
int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100
#define	F_FLOWINFO	0x200
#define	F_TCLASS	0x400
#define	F_FLOOD_POLL	0x800
#define	F_LATENCY	0x1000

/* multicast options */
int moptions;
#define MULTICAST_NOLOOP	0x001
#define MULTICAST_TTL		0x002
#define MULTICAST_IF		0x004

#ifdef SO_TIMESTAMP
#define HAVE_SIN6_SCOPEID 1
#endif


__u32 flowlabel;
__u32 tclass;
struct cmsghdr *srcrt;

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define	MAX_DUP_CHK	(8 * 128)
int mx_dup_ck = MAX_DUP_CHK;
char rcvd_tbl[MAX_DUP_CHK / 8];

struct sockaddr_in6 whereto;	/* who to ping */
int datalen = DEFDATALEN;
u_char outpack[MAXPACKET];
char BSPACE = '\b';		/* characters written for flood */
char DOT = '.';
int uid;
char *hostname;
int ident;			/* process id to identify our packets */

/* counters */
long npackets;			/* max packets to transmit */
long nreceived;			/* # of packets we got back */
long nchecksum;			/* replies with bad checksum */
long nerrors;			/* icmp errors */
long nrepeats;			/* number of duplicates */
long ntransmitted;		/* sequence # for outbound packets = #sent */
int interval = 1000;		/* interval between packets (msec) */
int deadline;
time_t starttime;
int confirm = 0;

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

int confirm_flag = MSG_CONFIRM;

/* timing */
int timing;			/* flag to do timing */
long tmin = LONG_MAX;		/* minimum round trip time */
long tmax;			/* maximum round trip time */
unsigned long tsum;			/* sum of all times, for doing average */
long long tsum2;

static unsigned char cmsgbuf[4096];
static int cmsglen = 0;

static char * pr_addr(struct in6_addr *addr);
static char * pr_addr_n(struct in6_addr *addr);
static int pr_icmph(struct icmp6hdr *icmph);
static void catcher(int);
static void finish(int) __attribute__((noreturn));
static void usage(void) __attribute((noreturn));
static void pinger(void);
static int pr_pack(char *buf, int cc, struct sockaddr_in6 *from, int hops, struct timeval *tv);
static void fill(char *patp);

struct sockaddr_in6 source;
char *device;
int pmtudisc=-1;

static int icmp_sock;


/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static __inline__ void tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void set_signal(int signo, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
#ifdef SA_INTERRUPT
	sa.sa_flags = SA_INTERRUPT;
#endif
	sigaction(signo, &sa, NULL);
}


static struct in6_addr in6_anyaddr;
static __inline__ int ipv6_addr_any(struct in6_addr *addr)
{
	return (memcmp(addr, &in6_anyaddr, 16) == 0);
}

size_t inet6_srcrt_space(int type, int segments)
{
	if (type != 0 || segments > 24)
		return 0;

	return (sizeof(struct cmsghdr) + sizeof(struct rt0_hdr) +
		segments * sizeof(struct in6_addr));
}

extern struct cmsghdr *	inet6_srcrt_init(void *bp, int type)
{
	struct cmsghdr *cmsg;

	if (type)
	{
		return NULL;
	}

	memset(bp, 0, sizeof(struct cmsghdr) + sizeof(struct rt0_hdr));
	cmsg = (struct cmsghdr *) bp;

	cmsg->cmsg_len = sizeof(struct cmsghdr) + sizeof(struct rt0_hdr);
	cmsg->cmsg_level = SOL_IPV6;
	cmsg->cmsg_type = IPV6_RTHDR;

	return cmsg;
}

int inet6_srcrt_add(struct cmsghdr *cmsg, const struct in6_addr *addr)
{
	struct rt0_hdr *hdr;
	
	hdr = (struct rt0_hdr *) CMSG_DATA(cmsg);

	cmsg->cmsg_len += sizeof(struct in6_addr);
	hdr->rt_hdr.hdrlen += sizeof(struct in6_addr) / 8;

	memcpy(&hdr->addr[hdr->rt_hdr.segments_left++], addr,
	       sizeof(struct in6_addr));
		
	return 0;
}

int main(int argc, char *argv[])
{
	extern int errno, optind;
	extern char *optarg;
	int i;
	int ch, hold, packlen, preload;
	u_char *packet;
	char *target;
	struct sockaddr_in6 firsthop;
	int ttl, loop;
	int socket_errno;
	struct icmp6_filter filter;
	int err, csum_offset, sz_opt;
	struct iovec iov;

	icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	socket_errno = errno;

	uid = getuid();
	setuid(uid);

	source.sin6_family = AF_INET6;
	memset(&firsthop, 0, sizeof(firsthop));
	firsthop.sin6_family = AF_INET6;

	preload = 0;
	while ((ch = getopt(argc, argv, "I:LRc:dfh:i:l:np:qrs:t:vF:P:w:UVM:")) != EOF) {
		switch(ch) {
		case 'c':
			npackets = atoi(optarg);
			if (npackets <= 0) {
				fprintf(stderr, "ping: bad number of packets to transmit.\n");
				exit(2);
			}
			break;
		case 'd':
			options |= F_SO_DEBUG;
			break;
		case 'f':
			if (uid) {
				fprintf(stderr, "ping: %s\n", strerror(EPERM));
				exit(2);
			}
			options |= F_FLOOD;
			setbuf(stdout, (char *)NULL);
			break;
		case 'F':
			sscanf(optarg, "%x", &flowlabel);
			options |= F_FLOWINFO;
			break;
		case 'P':
			sscanf(optarg, "%x", &tclass);
			options |= F_TCLASS;
			break;
		case 'i':		/* wait between sending packets */
		{
			if (strchr(optarg, '.')) {
				float t;
				if (sscanf(optarg, "%f", &t) != 1) {
					fprintf(stderr, "ping: bad timing interval.\n");
					exit(2);
				}
				interval = (int)(t*1000);
			} else if (sscanf(optarg, "%d", &interval) == 1) {
				interval *= 1000;
			} else {
				fprintf(stderr, "ping: bad timing interval.\n");
				exit(2);
			}

			if (interval <= 0) {
				fprintf(stderr, "ping: bad timing interval.\n");
				exit(2);
			}
			if (interval <= 20 && uid) {
				fprintf(stderr, "ping: %s\n", strerror(EPERM));
				exit(2);
			}
			options |= F_INTERVAL;
			break;
		}
		case 'w':
			deadline = atoi(optarg);
			if (deadline < 0) {
				fprintf(stderr, "ping: bad wait time.\n");
				exit(2);
			}
			break;
		case 'l':
			preload = atoi(optarg);
			if (preload < 0) {
				fprintf(stderr, "ping6: bad preload value.\n");
				exit(2);
			}
			if (uid) {
				fprintf(stderr, "ping6: %s\n", strerror(EPERM));
				exit(2);
			}
			break;
		case 'n':
			options |= F_NUMERIC;
			break;
		case 'p':		/* fill buffer with user pattern */
			options |= F_PINGFILLED;
			fill(optarg);
			break;
		case 'q':
			options |= F_QUIET;
			break;
		case 'R':
			options |= F_RROUTE;
			break;
		case 'r':
			options |= F_SO_DONTROUTE;
			break;
		case 's':		/* size of packet to send */
			datalen = atoi(optarg);
			if (datalen > MAXPACKET-8) {
				fprintf(stderr, "ping: packet size too large.\n");
				if (uid)
					exit(2);
			}
			if (datalen < 0) {
				fprintf(stderr, "ping: illegal packet size.\n");
				exit(2);
			}
			break;
		case 'v':
			options |= F_VERBOSE;
			break;
		case 'L':
			moptions |= MULTICAST_NOLOOP;
			loop = 0;
			break;
		case 't':
			moptions |= MULTICAST_TTL;
			i = atoi(optarg);
			if (i < 0 || i > 255) {
				printf("ping: ttl %u out of range\n", i);
				exit(2);
			}
			ttl = i;
			break;
		case 'I':
			moptions |= MULTICAST_IF;
			if (strchr(optarg, ':')) {
				if (inet_pton(AF_INET6, optarg, (char*)&source.sin6_addr) <= 0) {
					fprintf(stderr, "ping: invalid source address %s\n", optarg);
					exit(2);
				}
			} else {
				device = optarg;
			}
			break;
		case 'U':
			options |= F_LATENCY;
			break;
		case 'M':
			if (strcmp(optarg, "do") == 0)
				pmtudisc = IPV6_PMTUDISC_DO;
			else if (strcmp(optarg, "dont") == 0)
				pmtudisc = IPV6_PMTUDISC_DONT;
			else if (strcmp(optarg, "want") == 0)
				pmtudisc = IPV6_PMTUDISC_WANT;
			else {
				fprintf(stderr, "ping: wrong value for -M: do, dont, want are valid ones.\n");
				exit(2);
			}
			break;
		case 'V':
			printf("ping6 utility, iputils-ss%s\n", SNAPSHOT);
			exit(0);
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	while (argc > 1)
	{
		struct in6_addr addr;

		if (srcrt == NULL)
		{
			int space;
			
			space = inet6_srcrt_space(IPV6_SRCRT_TYPE_0, argc - 1);

			if (space == 0)
			{
				fprintf(stderr, "srcrt_space failed\n");
			}
			if (space + cmsglen > sizeof(cmsgbuf))
			{
				fprintf(stderr, "no room for options\n");
				exit(2);
			}

			srcrt = (struct cmsghdr*)(cmsgbuf+cmsglen);
			cmsglen += CMSG_ALIGN(space);
			inet6_srcrt_init(srcrt, IPV6_SRCRT_TYPE_0);
		}

		target = *argv;

		if (inet_pton(AF_INET6, target, &addr) <= 0)
		{
			struct hostent *hp;

			hp = gethostbyname2(target, AF_INET6);

			if (hp == NULL)
			{
				fprintf(stderr, "unknown host %s\n", target);
				exit(2);
			}

			memcpy(&addr, hp->h_addr_list[0], 16);
		}

		inet6_srcrt_add(srcrt, &addr);
		if (ipv6_addr_any(&firsthop.sin6_addr))
			memcpy(&firsthop.sin6_addr, &addr, 16);

		argv++;
		argc--;
	}

	if (argc != 1)
		usage();
	target = *argv;

	memset(&whereto, 0, sizeof(struct sockaddr_in6));
	whereto.sin6_family = AF_INET6;
	whereto.sin6_port = htons(IPPROTO_ICMPV6);

	if (inet_pton(AF_INET6, target, &whereto.sin6_addr) <= 0)
	{
		struct hostent *hp;

		hp = gethostbyname2(target, AF_INET6);

		if (hp == NULL)
		{
			fprintf(stderr, "unknown host\n");
			exit(2);
		}
		
		memcpy(&whereto.sin6_addr, hp->h_addr_list[0], 16);
	} else {
		options |= F_NUMERIC;
	}
	if (ipv6_addr_any(&firsthop.sin6_addr))
		memcpy(&firsthop.sin6_addr, &whereto.sin6_addr, 16);

	hostname = target;

	if (options&F_FLOOD && options&F_INTERVAL) {
		fprintf(stderr, "ping: -f and -i incompatible options.\n");
		exit(2);
	}

	if (ipv6_addr_any(&source.sin6_addr)) {
		int alen;
		int probe_fd = socket(AF_INET6, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			perror("socket");
			exit(2);
		}
		if (device) {
			struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1) {
#ifdef HAVE_SIN6_SCOPEID
				if ((firsthop.sin6_addr.s6_addr16[0]&htons(0xffc0)) == htons (0xfe80) ||
				    (firsthop.sin6_addr.s6_addr16[0]&htons(0xffff)) == htons (0xff02)) {
					if (ioctl(probe_fd, SIOCGIFINDEX, &ifr) < 0) {
						fprintf(stderr, "ping6: unknown iface %s\n", device);
						exit(2);
					}
					firsthop.sin6_scope_id = ifr.ifr_ifindex;
				} else
#endif
				{
					perror("WARNING: interface is ignored");
				}
			}
		}
		firsthop.sin6_port = htons(1025);
		if (connect(probe_fd, (struct sockaddr*)&firsthop, sizeof(firsthop)) == -1) {
			perror("connect");
			exit(2);
		}
		alen = sizeof(source);
		if (getsockname(probe_fd, (struct sockaddr*)&source, &alen) == -1) {
			perror("getsockname");
			exit(2);
		}
		source.sin6_port = 0;
		close(probe_fd);
	}

	if (icmp_sock < 0) {
		errno = socket_errno;
		perror("ping: icmp open socket");
		exit(2);
	}

	if (device) {
		struct ifreq ifr;
		struct cmsghdr *cmsg;
		struct in6_pktinfo *ipi;
				
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
		if (ioctl(icmp_sock, SIOCGIFINDEX, &ifr) < 0) {
			fprintf(stderr, "ping: unknown iface %s\n", device);
			exit(2);
		}
		cmsg = (struct cmsghdr*)cmsgbuf;
		cmsglen += CMSG_SPACE(sizeof(*ipi));
		cmsg->cmsg_len = CMSG_LEN(sizeof(*ipi));
		cmsg->cmsg_level = SOL_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
				
		ipi = (struct in6_pktinfo*)CMSG_DATA(cmsg);
		memset(ipi, 0, sizeof(*ipi));
		ipi->ipi6_ifindex = ifr.ifr_ifindex;
	}

	if ((whereto.sin6_addr.s6_addr16[0]&htons(0xff00)) == htons (0xff00)) {
		if (uid) {
			if (interval < 1000) {
				fprintf(stderr, "ping6: multicast ping with too short interval.\n");
				exit(2);
			}
			if (pmtudisc >= 0 && pmtudisc != IPV6_PMTUDISC_DO) {
				fprintf(stderr, "ping6: multicast ping does not fragment.\n");
				exit(2);
			}
		}
		if (pmtudisc < 0)
			pmtudisc = IPV6_PMTUDISC_DO;
	}

	if (pmtudisc >= 0) {
		if (setsockopt(icmp_sock, SOL_IPV6, IPV6_MTU_DISCOVER, &pmtudisc, sizeof(pmtudisc)) == -1) {
			perror("ping6: IPV6_MTU_DISCOVER");
			exit(2);
		}
	}

	if (bind(icmp_sock, (struct sockaddr*)&source, sizeof(source)) == -1) {
		perror("ping: bind icmp socket");
		exit(2);
	}

	if (datalen >= sizeof(struct timeval))	/* can we time transfer */
		timing = 1;
	packlen = datalen + MAXIPLEN + MAXICMPLEN;
	if (!(packet = (u_char *)malloc((u_int)packlen))) {
		fprintf(stderr, "ping: out of memory.\n");
		exit(2);
	}

	if (!(options & F_PINGFILLED)) {
		char *datap = outpack+8;

		for (i = 0; i < datalen; ++i)
			*datap++ = i;
	}

	ident = getpid() & 0xFFFF;

	hold = 1;
	if (options & F_SO_DEBUG)
		setsockopt(icmp_sock, SOL_SOCKET, SO_DEBUG, (char *)&hold, sizeof(hold));
	if (options & F_SO_DONTROUTE)
		setsockopt(icmp_sock, SOL_SOCKET, SO_DONTROUTE, (char *)&hold, sizeof(hold));

	hold = datalen+8;
	hold += ((hold+511)/512)*(40+128);
	setsockopt(icmp_sock, SOL_SOCKET, SO_SNDBUF, (char *)&hold, sizeof(hold));

	hold = 65535;
	setsockopt(icmp_sock, SOL_SOCKET, SO_RCVBUF, (char *)&hold, sizeof(hold));

	csum_offset = 2;
	sz_opt = sizeof(int);

	err = setsockopt(icmp_sock, SOL_RAW, IPV6_CHECKSUM, &csum_offset, sz_opt);
	if (err < 0)
	{
		perror("setsockopt(RAW_CHECKSUM)");
		exit(2);
	}

	/*
	 *	select icmp echo reply as icmp type to receive
	 */

	ICMPV6_FILTER_SETBLOCKALL(&filter);

	ICMPV6_FILTER_SETPASS(ICMPV6_DEST_UNREACH, &filter);
	ICMPV6_FILTER_SETPASS(ICMPV6_PKT_TOOBIG, &filter);
	ICMPV6_FILTER_SETPASS(ICMPV6_TIME_EXCEED, &filter);
	ICMPV6_FILTER_SETPASS(ICMPV6_PARAMPROB, &filter);

	ICMPV6_FILTER_SETPASS(ICMPV6_ECHO_REPLY, &filter);

	err = setsockopt(icmp_sock, SOL_ICMPV6, ICMPV6_FILTER, &filter,
			 sizeof(struct icmp6_filter));

	if (err < 0) {
		perror("setsockopt(ICMPV6_FILTER)");
		exit(2);
	}

	if (moptions & MULTICAST_NOLOOP) {
		if (setsockopt(icmp_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
							&loop, sizeof(loop)) == -1) {
			perror ("can't disable multicast loopback");
			exit(2);
		}
	}
	if (moptions & MULTICAST_TTL) {
		if (setsockopt(icmp_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			       &ttl, sizeof(ttl)) == -1) {
			perror ("can't set multicast hop limit");
			exit(2);
		}
		if (setsockopt(icmp_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			       &ttl, sizeof(ttl)) == -1) {
			perror ("can't set unicast hop limit");
			exit(2);
		}
	}

	if (1) {
		int on = 1;
		if (setsockopt(icmp_sock, IPPROTO_IPV6, IPV6_HOPLIMIT,
			       &on, sizeof(on)) == -1) {
			perror ("can't receive hop limit");
			exit(2);
		}
	}

	if (options&F_FLOWINFO) {
#ifdef IPV6_FLOWLABEL_MGR
		char freq_buf[CMSG_ALIGN(sizeof(struct in6_flowlabel_req)) + cmsglen];
		struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)freq_buf;
		int freq_len = sizeof(*freq);
		if (srcrt)
			freq_len = CMSG_ALIGN(sizeof(*freq)) + srcrt->cmsg_len;
		memset(freq, 0, sizeof(*freq));
		freq->flr_label = htonl(flowlabel&0xFFFFF);
		freq->flr_action = IPV6_FL_A_GET;
		freq->flr_flags = IPV6_FL_F_CREATE;
		freq->flr_share = IPV6_FL_S_EXCL;
		memcpy(&freq->flr_dst, &whereto.sin6_addr, 16);
		if (srcrt)
			memcpy(freq_buf + CMSG_ALIGN(sizeof(*freq)), srcrt, srcrt->cmsg_len);
		if (setsockopt(icmp_sock, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR,
			       freq, freq_len) == -1) {
			perror ("can't set flowlabel");
			exit(2);
		}
		flowlabel = freq->flr_label;
		if (srcrt) {
			cmsglen = (char*)srcrt - (char*)cmsgbuf;
			srcrt = NULL;
		}
#else
		fprintf(stderr, "Flow labels are not supported.\n");
		exit(2);
#endif
	}
	if (options&(F_FLOWINFO|F_TCLASS)) {
#ifdef IPV6_FLOWINFO_SEND
		int on = 1;
		whereto.sin6_flowinfo = flowlabel | htonl((tclass&0xFF)<<20);
		if (setsockopt(icmp_sock, IPPROTO_IPV6, IPV6_FLOWINFO_SEND,
			       &on, sizeof(on)) == -1) {
			perror ("can't send flowinfo");
			exit(2);
		}
#else
		fprintf(stderr, "Flowinfo is not supported.\n");
		exit(2);
#endif
	}
#ifdef SO_TIMESTAMP
	if (!(options&F_LATENCY)) {
		int on = 1;
		if (setsockopt(icmp_sock, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)))
			fprintf(stderr, "Warning: no SO_TIMESTAMP support, falling back to SIOCGSTAMP\n");
	}
#endif
	if (1) {
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if (interval < 1000) {
			tv.tv_sec = 0;
			tv.tv_usec = interval%1000;
		}
		setsockopt(icmp_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
	}

	printf("PING %s(%s) ", hostname, pr_addr(&whereto.sin6_addr));
	if (flowlabel)
		printf(", flow 0x%05x, ", (unsigned)ntohl(flowlabel));
	if (device || (options&F_NUMERIC)) {
		printf("from %s %s: ",
		       pr_addr_n(&source.sin6_addr), device ? : "");
	}
	printf("%d data bytes\n", datalen);

	set_signal(SIGINT, finish);
	set_signal(SIGALRM, catcher);

	while (preload--)		/* fire off them quickies */
		pinger();

	if ((options & F_FLOOD) == 0) {
		catcher(0);		/* start things going */
	} else {
		struct timeval tv;
		tv.tv_usec = 20000;
		tv.tv_sec = 0;
		if (setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv))) {
			fprintf(stderr, "Warning: no SO_RCVTIMEO support, falling back to poll\n");
			options |= F_FLOOD_POLL;
		}
	}

	starttime = time(NULL);
	iov.iov_base = (char *)packet;

	for (;;) {
		char ans_data[128];
		struct sockaddr_in6 from;
		struct msghdr msg = {
			(void*)&from, sizeof(from),
			&iov, 1,
			ans_data, sizeof(ans_data),
		};
		struct cmsghdr *c;
		int cc;
		int hops = -1;

		if (npackets && nreceived >= npackets)
			break;
		if (deadline && (nerrors ||
				 (int)(time(NULL) - starttime) > deadline))
			break;

		if (options & F_FLOOD)
			pinger();

reselect:

		if (options & F_FLOOD_POLL) {
			struct pollfd pset;

			pset.fd = icmp_sock;
			pset.events = POLLIN|POLLERR;
			pset.revents = 0;
			if (poll(&pset, 1, 20) < 1 || !(pset.revents&(POLLIN|POLLERR)))
				continue;
		}

		iov.iov_len = packlen;

		if ((cc = recvmsg(icmp_sock, &msg, 0)) < 0) {
			if (errno != EINTR && errno != EWOULDBLOCK)
				perror("ping6: recvmsg");
		} else {
			struct timeval *recv_timep = NULL;
			struct timeval recv_time;

			for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
#ifdef SO_TIMESTAMP
				if (c->cmsg_level == SOL_SOCKET &&
				    c->cmsg_type == SO_TIMESTAMP &&
	 			    c->cmsg_len >= CMSG_LEN(sizeof(struct timeval))) {
					    recv_timep = (struct timeval*)CMSG_DATA(c);
					continue;
				}
#endif
				hops = *(int*)CMSG_DATA(c);
				if (c->cmsg_level != SOL_IPV6 ||
				    c->cmsg_type != IPV6_HOPLIMIT)
					continue;
				if (c->cmsg_len < CMSG_LEN(sizeof(int)))
					continue;
				hops = *(int*)CMSG_DATA(c);
			}

			if ((options&F_LATENCY) || recv_timep==NULL) {
				if ((options&F_LATENCY) ||
				    ioctl(icmp_sock, SIOCGSTAMP, &recv_time))
					gettimeofday(&recv_time, NULL);
				recv_timep = &recv_time;
			}
			if (pr_pack((char *)packet, cc, &from, hops, recv_timep)) {
				if (options & F_FLOOD)
					goto reselect;
			}
		}
	}
	finish(0);
	/* NOTREACHED */
}

/*
 * catcher --
 *	This routine causes another PING to be transmitted, and then
 * schedules another SIGALRM for 'interval' millisecond from now.
 * 
 * bug --
 *	Our sense of time will slowly skew (i.e., packets will not be
 * launched exactly at given intervals).  This does not affect the
 * quality of the delay and loss statistics.
 */
void catcher(int sig)
{
	static int slop = 10;
	static struct timeval prev;
	struct timeval now;
	long delta = 0;
	int waittime;
	int saved_errno = errno;

	gettimeofday(&now, NULL);

	if (sig) {
		delta = now.tv_sec - prev.tv_sec;
		delta = delta*1000 + (now.tv_usec - prev.tv_usec)/1000;
		if (delta >= (interval-slop))
			sig = 0;
	}

	if (sig == 0) {
		pinger();
		prev = now;
	}

	if (!npackets || ntransmitted < npackets || deadline) {
		waittime = interval*1000;
	} else {
		if (nreceived) {
			waittime = 2 * tmax;
			if (waittime<1000000)
				waittime = 1000000;
		} else
			waittime = MAXWAIT*1000000;
		set_signal(SIGALRM, finish);
	}

	do {
		struct itimerval it;

		it.it_interval.tv_sec = 0;
		it.it_interval.tv_usec = 0;
		it.it_value.tv_sec = waittime/1000000;
		it.it_value.tv_usec = waittime%1000000;
		setitimer(ITIMER_REAL, &it, NULL);
	} while (0);

	errno = saved_errno;
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
void pinger(void)
{
	struct icmp6hdr *icmph;
	register int cc;
	int i;

	icmph = (struct icmp6hdr *)outpack;
	icmph->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmph->icmp6_code = 0;
	icmph->icmp6_cksum = 0;
	icmph->icmp6_sequence = ntransmitted++;
	icmph->icmp6_identifier = ident;

	CLR(icmph->icmp6_sequence % mx_dup_ck);

	if (timing)
		gettimeofday((struct timeval *)&outpack[8],
		    (struct timezone *)NULL);

	cc = datalen + 8;			/* skips ICMP portion */

resend:
	if (cmsglen == 0)
	{
		i = sendto(icmp_sock, (char *)outpack, cc, confirm,
			   (struct sockaddr *) &whereto,
			   sizeof(struct sockaddr_in6));
	}
	else
	{
		struct msghdr mhdr;
		struct iovec iov;

		iov.iov_len  = cc;
		iov.iov_base = outpack;

		mhdr.msg_name = &whereto;
		mhdr.msg_namelen = sizeof(struct sockaddr_in6);
		mhdr.msg_iov = &iov;
		mhdr.msg_iovlen = 1;
		mhdr.msg_control = cmsgbuf;
		mhdr.msg_controllen = cmsglen;

		i = sendmsg(icmp_sock, &mhdr, confirm);
	}
	confirm = 0;

	if (i < 0 && confirm_flag) {
		confirm_flag = 0;
		goto resend;
	}

	if (i < 0 || i != cc)  {
		if (i < 0) {
			if (errno == EAGAIN) {
				ntransmitted--;
			} else {
				perror("ping: sendto");
			}
		} else {
			printf("ping: wrote %s %d chars, ret=%d\n",
			       hostname, cc, i);
		}
	} else if (!(options & F_QUIET) && options & F_FLOOD)
		write(STDOUT_FILENO, &DOT, 1);
}

/*
 * pr_pack --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
int pr_pack(char *buf, int cc, struct sockaddr_in6 *from, int hops, struct timeval *tv)
{
	struct icmp6hdr *icmph;
	u_char *cp,*dp;
	struct timeval *tp;
	long triptime = 0;
	int dupflag = 0;

	/* Now the ICMP part */

	icmph = (struct icmp6hdr *) buf;
	if (cc < 8) {
		if (options & F_VERBOSE)
			fprintf(stderr, "ping: packet too short (%d bytes)\n", cc);
		return 1;
	}

	if (icmph->icmp6_type == ICMPV6_ECHO_REPLY) {
		if (icmph->icmp6_identifier != ident)
			return 1;			/* 'Twas not our ECHO */
		++nreceived;
		if (timing && cc >= 8+sizeof(struct timeval)) {
			tp = (struct timeval *)(icmph + 1);

restamp:
			tvsub(tv, tp);
			triptime = tv->tv_sec * 1000000 + tv->tv_usec;
			if (triptime < 0) {
				fprintf(stderr, "Warning: time of day goes back, taking countermeasures.\n");
				triptime = 0;
				if (!(options & F_LATENCY)) {
					gettimeofday(tv, NULL);
					options |= F_LATENCY;
					goto restamp;
				}
			}
			tsum += triptime;
			tsum2 += (long long)triptime * (long long)triptime;
			if (triptime < tmin)
				tmin = triptime;
			if (triptime > tmax)
				tmax = triptime;
		}

		if (TST(icmph->icmp6_sequence % mx_dup_ck)) {
			++nrepeats;
			--nreceived;
			dupflag = 1;
		} else {
			SET(icmph->icmp6_sequence % mx_dup_ck);
			dupflag = 0;
		}
		confirm = confirm_flag;

		if (options & F_QUIET)
			return 0;

		if (options & F_FLOOD)
			write(STDOUT_FILENO, &BSPACE, 1);
		else {
			int i;
			printf("%d bytes from %s: icmp_seq=%u", cc,
				     pr_addr(&from->sin6_addr),
				     icmph->icmp6_sequence);

			if (hops >= 0)
				printf(" hops=%d", hops);

			if (cc < datalen+8) {
				printf(" (truncated)");
				return 1;
			}
			if (timing) {
				if (triptime >= 1000000) {
					printf(" time=%ld.%03ld sec", triptime/1000000,
					       (triptime%1000000)/1000);
				} else if (triptime >= 1000) {
					printf(" time=%ld.%03ld msec", triptime/1000,
					       triptime%1000);
				} else {
					printf(" time=%ld usec", triptime);
				}
			}
			if (dupflag)
				printf(" (DUP!)");

			/* check the data */
			cp = ((u_char*)(icmph + 1)) + sizeof(struct timeval);
			dp = &outpack[8 + sizeof(struct timeval)];
			for (i = sizeof(struct timeval); i < datalen; ++i, ++cp, ++dp) {
				if (*cp != *dp) {
					printf("\nwrong data byte #%d should be 0x%x but was 0x%x",
					       i, *dp, *cp);
					cp = (u_char*)(icmph + 1) + sizeof(struct timeval);
					for (i = sizeof(struct timeval); i < datalen; ++i, ++cp) {
						if ((i % 32) == sizeof(struct timeval))
							printf("\n#%d\t", i);
						printf("%x ", *cp);
					}
					break;
				}
			}
		}
	} else {
		struct ipv6hdr *iph1 = (struct ipv6hdr*)(icmph+1);

		if (cc < 8+sizeof(struct ipv6hdr)+8)
			return 1;

		if (memcmp(&iph1->daddr, &whereto.sin6_addr, 16))
			return 1;

		if (iph1->nexthdr == IPPROTO_ICMPV6) {
			struct icmp6hdr *icmph1 = (struct icmp6hdr *)(iph1+1);
			if (icmph1->icmp6_type != ICMPV6_ECHO_REQUEST ||
			    icmph1->icmp6_identifier != ident)
				return 1;
			nerrors++;
			if (options & F_FLOOD) {
				write(STDOUT_FILENO, "E", 1);
				return 0;
			}
			printf("From %s: ", pr_addr(&from->sin6_addr));
		} else {
			/* We've got something other than an ECHOREPLY */
			if (!(options & F_VERBOSE) || uid)
				return 1;
			printf("From %s: ", pr_addr(&from->sin6_addr));
		}
		pr_icmph(icmph);
	}

	if (!(options & F_FLOOD)) {
		putchar('\n');
		fflush(stdout);
	}
	return 0;
}


int pr_icmph(struct icmp6hdr *icmph)
{
	switch(icmph->icmp6_type) {
	case ICMPV6_DEST_UNREACH:
		printf("Destination unreachable: ");
		switch (icmph->icmp6_code) {
		case ICMPV6_NOROUTE:
			printf("No route");
			break;
		case ICMPV6_ADM_PROHIBITED:
			printf("Administratively prohibited");
			break;
		case ICMPV6_NOT_NEIGHBOUR:
			printf("Not neighbour");
			break;
		case ICMPV6_ADDR_UNREACH:
			printf("Address unreachable");
			break;
		case ICMPV6_PORT_UNREACH:
			printf("Port unreachable");
			break;
		default:	
			printf("Unknown code %d", icmph->icmp6_code);
			break;
		}
		break;
	case ICMPV6_PKT_TOOBIG:
		printf("Packet too big: mtu=%u",
		       (unsigned int)ntohl(icmph->icmp6_hop_limit));
		if (icmph->icmp6_code)
			printf(", code=%d", icmph->icmp6_code);
		break;
	case ICMPV6_TIME_EXCEED:
		printf("Time exceeded: ");
		if (icmph->icmp6_code == ICMPV6_EXC_HOPLIMIT)
			printf("Hop limit");
		else if (icmph->icmp6_code == ICMPV6_EXC_FRAGTIME)
			printf("Defragmentation failure");
		else
			printf("code %d", icmph->icmp6_code);
		break;
	case ICMPV6_PARAMPROB:
		printf("Parameter problem: ");
		if (icmph->icmp6_code == ICMPV6_HDR_FIELD)
			printf("Wrong header field ");
		else if (icmph->icmp6_code == ICMPV6_UNK_NEXTHDR)
			printf("Unknown header ");
		else if (icmph->icmp6_code == ICMPV6_UNK_OPTION)
			printf("Unknown option ");
		else
			printf("code %d ", icmph->icmp6_code);
		printf ("at %u", (unsigned int)ntohl(icmph->icmp6_pointer));
		break;
	case ICMPV6_ECHO_REQUEST:
		printf("Echo request");
		break;
	case ICMPV6_ECHO_REPLY:
		printf("Echo reply");
		break;
	case ICMPV6_MGM_QUERY:
		printf("MLD Query");
		break;
	case ICMPV6_MGM_REPORT:
		printf("MLD Report");
		break;
	case ICMPV6_MGM_REDUCTION:
		printf("MLD Reduction");
		break;
	default:
		printf("unknown icmp type");
		
	}
	return 0;
}

static long llsqrt(long long a)
{
	long long prev = ~((long long)1 << 63);
	long long x = a;

	if (x > 0) {
		while (x < prev) {
			prev = x;
			x = (x+(a/x))/2;
		}
	}

	return (long)x;
}

/*
 * finish --
 *	Print out statistics, and give up.
 */
void finish(int sig)
{
	set_signal(SIGALRM, SIG_IGN);

	putchar('\n');
	fflush(stdout);
	printf("--- %s ping statistics ---\n", hostname);
	printf("%ld packets transmitted, ", ntransmitted);
	printf("%ld packets received, ", nreceived);
	if (nrepeats)
		printf("+%ld duplicates, ", nrepeats);
	if (nchecksum)
		printf("+%ld corrupted, ", nchecksum);
	if (nerrors)
		printf("+%ld errors, ", nerrors);
	if (ntransmitted) {
		if (nreceived > ntransmitted)
			printf("-- somebody's printing up packets!");
		else
			printf("%d%% packet loss",
			    (int) (((ntransmitted - nreceived) * 100) /
			    ntransmitted));
	}
	putchar('\n');
	if (nreceived && timing) {
		long tmdev;

		tsum /= nreceived + nrepeats + nchecksum;
		tsum2 /= nreceived + nrepeats + nchecksum;
		tmdev = llsqrt(tsum2 - (long long)tsum * (long long)tsum);

		printf("round-trip min/avg/max/mdev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld ms\n",
		       tmin/1000, tmin%1000,
		       tsum/1000, tsum%1000,
		       tmax/1000, tmax%1000,
		       tmdev/1000, tmdev%1000
		       );
	}
	exit(deadline ? nreceived < npackets : nreceived==0);
}

#ifdef notdef
static char *ttab[] = {
	"Echo Reply",		/* ip + seq + udata */
	"Dest Unreachable",	/* net, host, proto, port, frag, sr + IP */
	"Source Quench",	/* IP */
	"Redirect",		/* redirect type, gateway, + IP  */
	"Echo",
	"Time Exceeded",	/* transit, frag reassem + IP */
	"Parameter Problem",	/* pointer + IP */
	"Timestamp",		/* id + seq + three timestamps */
	"Timestamp Reply",	/* " */
	"Info Request",		/* id + sq */
	"Info Reply"		/* " */
};
#endif


/*
 * pr_addr --
 *	Return an ascii host address as a dotted quad and optionally with
 * a hostname.
 */
char * pr_addr(struct in6_addr *addr)
{
	static char str[80];
	struct hostent *hp = NULL;

	if (!(options&F_NUMERIC))
		hp = gethostbyaddr((__u8*)addr, sizeof(struct in6_addr), AF_INET6);

	if (hp == NULL)	{
		inet_ntop(AF_INET6, addr, str, 80);
		return str;
	}

	return hp->h_name;
}

char * pr_addr_n(struct in6_addr *addr)
{
	static char str[80];
	inet_ntop(AF_INET6, addr, str, 80);
	return str;
}

void fill(char *patp)
{
	int ii, jj, kk;
	int pat[16];
	char *cp;
	char *bp = outpack+8;

	for (cp = patp; *cp; cp++) {
		if (!isxdigit(*cp)) {
			fprintf(stderr, "ping: patterns must be specified as hex digits.\n");
			exit(2);
		}
	}

	ii = sscanf(patp,
		    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		    &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
		    &pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
		    &pat[13], &pat[14], &pat[15]);

	if (ii > 0) {
		for (kk = 0; kk <= MAXPACKET - (8 + ii); kk += ii)
			for (jj = 0; jj < ii; ++jj)
				bp[jj + kk] = pat[jj];
	}
	if (!(options & F_QUIET)) {
		printf("PATTERN: 0x");
		for (jj = 0; jj < ii; ++jj)
			printf("%02x", bp[jj] & 0xFF);
		printf("\n");
	}
}

void usage(void)
{
	fprintf(stderr,
		"Usage: ping6 [-LRUdfnqrvV] [-c count] [-i interval] [-w wait]\n\t[-p pattern] [-s packetsize] [-t ttl] [-I interface address]\n\t[-T timestamp option] [-F flow label] [-P traffic class] host\n");
	exit(2);
}
