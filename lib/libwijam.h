#ifndef LIB_WIJAM_H
#define LIB_WIJAM_H

#include <iwlib.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/* functions prototypes */

int validate_interface(int skfd,  char *ifname,  char *args[], int count);
int enum_interface(int skfd, char *ifname, char *args[], int count);
int select_interface(int skfd, char *ifname, char *args[], int count);
int prompt_choose(int limit);
struct sockaddr get_mac(int iw_sock, char *interface);
int get_ifindex(int iw_sock, char *interface);
void _die();

/* Data types */

struct rts_frame
{
    uint16_t control;
    uint16_t duration;
    uint8_t ra[ETH_ALEN];
    uint8_t ta[ETH_ALEN];
    uint32_t fcs;
} rts_frame;

struct cts_frame
{
    uint16_t control;
    uint16_t duration;
    uint8_t ra[ETH_ALEN];
    uint32_t fcs;
} cts_frame;

#define ack_frame   cts_frame

/* macros and inline functions */

#define die(s, ...) _die(fprintf(stderr,"[!] ") && fprintf(stderr, s, ##__VA_ARGS__) && fprintf(stderr,"\n"))
#define info(s, ...) do {printf("[i] "); printf(s, ##__VA_ARGS__); putchar('\n'); } while(0)

static inline void help(void)
{
    die(    "Usage: wijam [OPTION]...\n\
    Send Jamming signal to specified network.\n\n\
    --i, --interface INTERFACE \tuse specifed interface\n\
    --e, --essid ESSID\tNetwork ESSID\n\n\
With no OPTION, or when INTERFACE is invalid, begin dynamic mode.");
}

#endif
