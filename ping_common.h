#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
/*#include <linux/sockios.h>*/
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>
/*#include <linux/errqueue.h>*/

#include "SNAPSHOT.h"

#define	DEFDATALEN	(64 - 8)	/* default data length */

#define	MAXWAIT		10		/* max seconds to wait for response */
#define MININTERVAL	10		/* Minimal interpacket gap */
#define MINUSERINTERVAL	200		/* Minimal allowed interval for non-root */

#define SCHINT(a)	(((a) <= MININTERVAL) ? MININTERVAL : (a))

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(bit)	(A(bit) |= B(bit))
#define	CLR(bit)	(A(bit) &= (~B(bit)))
#define	TST(bit)	(A(bit) & B(bit))

/* various options */
extern int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100
#define	F_TIMESTAMP	0x200
#define	F_FLOWINFO	0x200
#define	F_SOURCEROUTE	0x400
#define	F_TCLASS	0x400
#define	F_FLOOD_POLL	0x800
#define	F_LATENCY	0x1000
#define	F_AUDIBLE	0x2000
#define	F_ADAPTIVE	0x4000

/* multicast options */
extern int moptions;
#define MULTICAST_NOLOOP	0x001
#define MULTICAST_TTL		0x002
#define MULTICAST_IF		0x004

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define	MAX_DUP_CHK	0x10000
extern int mx_dup_ck;
extern char rcvd_tbl[MAX_DUP_CHK / 8];


extern u_char outpack[];
extern int maxpacket;

extern int datalen;
extern char *hostname;
extern int uid;
extern int ident;			/* process id to identify our packets */

extern int sndbuf;
extern int ttl, loop;

extern long npackets;			/* max packets to transmit */
extern long nreceived;			/* # of packets we got back */
extern long nrepeats;			/* number of duplicates */
extern long ntransmitted;		/* sequence # for outbound packets = #sent */
extern long nchecksum;			/* replies with bad checksum */
extern long nerrors;			/* icmp errors */
extern int interval;			/* interval between packets (msec) */
extern int preload;
extern int deadline;			/* time to die */
extern struct timeval start_time, cur_time;
extern volatile int exiting;
extern volatile int status_snapshot;
extern int confirm;
extern int confirm_flag;
extern int working_recverr;

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif


/* timing */
extern int timing;			/* flag to do timing */
extern long tmin;			/* minimum round trip time */
extern long tmax;			/* maximum round trip time */
extern long long tsum;			/* sum of all times, for doing average */
extern long long tsum2;
extern int rtt;
extern u_int16_t acked;
extern int pipesize;

#define COMMON_OPTIONS \
case 'a': case 'U': case 'c': case 'd': \
case 'f': case 'i': case 'w': case 'l': \
case 'S': case 'n': case 'p': case 'q': \
case 'r': case 's': case 'v': case 'L': \
case 't': case 'A':

#define COMMON_OPTSTR "h?VQ:I:M:aUc:dfi:w:l:S:np:qrs:vLt:A"


/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static inline void tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static inline void set_signal(int signo, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
#ifdef SA_INTERRUPT
	sa.sa_flags = SA_INTERRUPT;
#endif
	sigaction(signo, &sa, NULL);
}

extern int __schedule_exit(int next);

static inline int schedule_exit(int next)
{
	if (npackets && ntransmitted >= npackets && !deadline)
		next = __schedule_exit(next);
	return next;
}

static inline int in_flight(void)
{
	u_int16_t diff = (u_int16_t)ntransmitted - acked;
	return (diff<=0x7FFF) ? diff : ntransmitted-nreceived-nerrors;
}

static inline void acknowledge(u_int16_t seq)
{ 
	u_int16_t diff = (u_int16_t)ntransmitted - seq;
	if (diff <= 0x7FFF) {
		if ((int)diff+1 > pipesize)
			pipesize = (int)diff+1;
		if ((int16_t)(seq - acked) > 0 ||
		    (u_int16_t)ntransmitted - acked > 0x7FFF)
			acked = seq;
	}
}

static inline void advance_ntransmitted(void)
{
	ntransmitted++;
	/* Invalidate acked, if 16 bit seq overflows. */
	if ((u_int16_t)ntransmitted - acked > 0x7FFF)
		acked = (u_int16_t)ntransmitted + 1;
}


extern int send_probe(void);
extern int receive_error_msg(void);
extern int parse_reply(struct msghdr *msg, int len, void *addr, struct timeval *);
extern void install_filter(void);

extern int pinger(void);
extern void sock_setbufs(int icmp_sock, int alloc);
extern void setup(int icmp_sock);
extern void main_loop(int icmp_sock, uint8_t *buf, int buflen) __attribute__((noreturn));
extern void finish(void) __attribute__((noreturn));
extern void status(void);
extern void common_options(int ch);
extern int gather_statistics(uint8_t *ptr, int cc, u_int16_t seq, int hops,
			     int csfailed, struct timeval *tv, char *from);

#define SO_EE_ORIGIN_NONE       0
#define SO_EE_ORIGIN_LOCAL      1
#define SO_EE_ORIGIN_ICMP       2
#define SO_EE_ORIGIN_ICMP6      3

struct sock_extended_err
{
    u_int32_t       ee_errno;   /* error number */
    u_int8_t        ee_origin;  /* where the error originated */
    u_int8_t        ee_type;    /* type */
    u_int8_t        ee_code;    /* code */
    u_int8_t        ee_pad;
    u_int32_t       ee_info;    /* additional information */
    u_int32_t       ee_data;    /* other data */
    /* More data may follow */
};

/*
 *      constants for (set|get)sockopt
 *      XXX These were pulled from the kernel icmp.h.  They should be
 *	in glibc.
 */

#define ICMP_FILTER                     1

struct icmp_filter {
        u_int32_t           data;
};

/*
 *      Try and keep these values and structures similar to BSD, especially
 *      the BPF code definitions which need to match so you can share filters
 *	XXX These were pulled from linux/filter.h.  They should probably
 *	be in glibc.
 */
 
struct sock_filter      /* Filter block */
{
        u_int16_t   code;   /* Actual filter code */
        u_int8_t    jt;     /* Jump true */
        u_int8_t    jf;     /* Jump false */
        u_int32_t   k;      /* Generic multiuse field */
};

struct sock_fprog       /* Required for SO_ATTACH_FILTER. */
{
        unsigned short          len;    /* Number of filter blocks */
        struct sock_filter      *filter;
};
