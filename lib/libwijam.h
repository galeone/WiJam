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

/* Data types and constants */

    /* frame types */

#define   _FRAME_TYPE_MANAGEMENT          0
#define   _FRAME_TYPE_CONTROL             1
#define   _FRAME_TYPE_DATA                2
#define   _FRAME_TYPE_RESERVED            3
#define   _FRAME_TYPE_ERROR               10

    /* frame subtypes */

#define   _FRAME_SUBTYPE_ASS_REQ          0
#define   _FRAME_SUBTYPE_ASS_REP          1
#define   _FRAME_SUBTYPE_RES_REQ          2
#define   _FRAME_SUBTYPE_RES_REP          3
#define   _FRAME_SUBTYPE_PRB_REQ          4
#define   _FRAME_SUBTYPE_PRB_RES          5
#define   _FRAME_SUBTYPE_BEACON           8
#define   _FRAME_SUBTYPE_ATIM             9

#define   _FRAME_SUBTYPE_DISASS           10
#define   _FRAME_SUBTYPE_AUTH             11
#define   _FRAME_SUBTYPE_DEAUTH           12
#define   _FRAME_SUBTYPE_PS_POLL          10
#define   _FRAME_SUBTYPE_RTS              11
#define   _FRAME_SUBTYPE_CTS              12
#define   _FRAME_SUBTYPE_ACK              13
#define   _FRAME_SUBTYPE_CFE              14
#define   _FRAME_SUBTYPE_CFE_CFA          15
#define   _FRAME_SUBTYPE_DATA             0
#define   _FRAME_SUBTYPE_DATA_CFA         1
#define   _FRAME_SUBTYPE_DATA_CFP         2
#define   _FRAME_SUBTYPE_DATA_CFA_CFP     3
#define   _FRAME_SUBTYPE_NULL_NO_DATA     4
#define   _FRAME_SUBTYPE_CFA_NO_DATA      5
#define   _FRAME_SUBTYPE_CFP_NO_DATA      6
#define   _FRAME_SUBTYPE_CFA_CFP_NO_DATA  7

#define   _FRAME_SUBTYPE_RESERVED00       10
#define   _FRAME_SUBTYPE_RESERVED01       9
#define   _FRAME_SUBTYPE_RESERVED10       8
#define   _FRAME_SUBTYPE_RESERVED11       15

#define   _FRAME_SUBTYPE_ERROR            -1

union frame_control
{
    struct
    {
        unsigned int proto_version  : 2;
        unsigned int type           : 2;
        unsigned int subtype        : 4;
        unsigned int to_ds          : 1;
        unsigned int from_ds        : 1;
        unsigned int more_frag      : 1;
        unsigned int retry          : 1;
        unsigned int power_mgmt     : 1;
        unsigned int more_data      : 1;
        unsigned int protected_frame: 1;
        unsigned int order          : 1;
    } bits;
    uint16_t buffer;
};

struct rts_frame
{
    union frame_control control;
    uint16_t duration;
    uint8_t ra[ETH_ALEN];
    uint8_t ta[ETH_ALEN];
    uint32_t fcs;
};

struct cts_frame
{
    union frame_control control;
    uint16_t duration;
    uint8_t ra[ETH_ALEN];
    uint32_t fcs;
};

#define ack_frame   cts_frame

struct ps_poll_frame
{
    union frame_control control;
    uint16_t aid;
    uint8_t ra[ETH_ALEN];
    uint8_t ta[ETH_ALEN];
    uint32_t fcs;
};

#define cfe_frame       rts_frame
#define cfe_cfa_frame   rts_frame

#define _PAYLOAD_SIZE 2312
struct generic_frame
{
    union frame_control frame_control;
    uint16_t duration;
    uint8_t mac1[ETH_ALEN];
    uint8_t mac2[ETH_ALEN];
    uint8_t mac3[ETH_ALEN];
    uint16_t sequence_control;
    uint8_t mac4[ETH_ALEN];
    uint8_t payload[_PAYLOAD_SIZE];
    uint32_t fcs;
};

/* macros and inline functions */

#define die(s, ...) _die(fprintf(stderr,"[!] ") && fprintf(stderr, s, ##__VA_ARGS__) && fprintf(stderr,"\n"))
#define info(s, ...) do {printf("[i] "); printf(s, ##__VA_ARGS__); putchar('\n'); } while(0)

static inline void help(void)
{
    die(
"Usage: wijam [OPTION]...\n\
    Send Jamming signal to specified network.\n\n\
    --i, --interface INTERFACE \tuse specifed interface\n\
    --e, --essid ESSID\tNetwork ESSID\n\n\
With no OPTION, or when INTERFACE is invalid, begin dynamic mode."
       );
}

static inline unsigned char get_frame_subtype(union frame_control control)
{    
    switch(control.bits.type)
    {
        case _FRAME_TYPE_MANAGEMENT:
            switch(control.bits.subtype)
            {
                case _FRAME_SUBTYPE_ASS_REQ:
                case _FRAME_SUBTYPE_ASS_REP:
                case _FRAME_SUBTYPE_RES_REQ:
                case _FRAME_SUBTYPE_RES_REP:
                case _FRAME_SUBTYPE_PRB_REQ:
                case _FRAME_SUBTYPE_PRB_RES:
                case _FRAME_SUBTYPE_BEACON:
                case _FRAME_SUBTYPE_ATIM:
                case _FRAME_SUBTYPE_DISASS:
                case _FRAME_SUBTYPE_AUTH:
                case _FRAME_SUBTYPE_DEAUTH:
                    return control.bits.subtype;
                default:
                    return _FRAME_SUBTYPE_RESERVED00;
            }
        break;
        case _FRAME_TYPE_CONTROL:
            switch(control.bits.subtype)
            {
                case _FRAME_SUBTYPE_PS_POLL:
                case _FRAME_SUBTYPE_RTS:
                case _FRAME_SUBTYPE_CTS:
                case _FRAME_SUBTYPE_ACK:
                case _FRAME_SUBTYPE_CFE:
                case _FRAME_SUBTYPE_CFE_CFA:
                    return control.bits.subtype;
                default:
                    return _FRAME_SUBTYPE_RESERVED01;
            }
        break;
        case _FRAME_TYPE_DATA:
            switch(control.bits.subtype)
            {
                case _FRAME_SUBTYPE_DATA:
                case _FRAME_SUBTYPE_DATA_CFA:
                case _FRAME_SUBTYPE_DATA_CFP:
                case _FRAME_SUBTYPE_DATA_CFA_CFP:
                case _FRAME_SUBTYPE_NULL_NO_DATA:
                case _FRAME_SUBTYPE_CFA_NO_DATA:
                case _FRAME_SUBTYPE_CFP_NO_DATA:
                case _FRAME_SUBTYPE_CFA_CFP_NO_DATA:
                    return control.bits.subtype;
                default:
                    return _FRAME_SUBTYPE_RESERVED10;
            }
        break;

        case _FRAME_TYPE_RESERVED:
            return _FRAME_SUBTYPE_RESERVED11;
    }

    return _FRAME_SUBTYPE_ERROR;
}

static inline char * get_frame_subtype_string(union frame_control control)
{
    switch(control.bits.type)
    {
        case _FRAME_TYPE_MANAGEMENT:
            switch(control.bits.subtype)
            {
                case _FRAME_SUBTYPE_ASS_REQ:
                    return "_FRAME_SUBTYPE_ASS_REQ";
                case _FRAME_SUBTYPE_ASS_REP:
                    return " _FRAME_SUBTYPE_ASS_REP";
                case _FRAME_SUBTYPE_RES_REQ:
                    return "_FRAME_SUBTYPE_RES_REQ";
                case _FRAME_SUBTYPE_RES_REP:
                    return " _FRAME_SUBTYPE_RES_REP";
                case _FRAME_SUBTYPE_PRB_REQ:
                    return "_FRAME_SUBTYPE_PRB_REQ";
                case _FRAME_SUBTYPE_PRB_RES:
                    return "_FRAME_SUBTYPE_PRB_RES";
                case _FRAME_SUBTYPE_BEACON:
                    return " _FRAME_SUBTYPE_BEACON";
                case _FRAME_SUBTYPE_ATIM:
                    return "_FRAME_SUBTYPE_ATIM";
                case _FRAME_SUBTYPE_DISASS:
                    return "_FRAME_SUBTYPE_DISASS";
                case _FRAME_SUBTYPE_AUTH:
                    return " _FRAME_SUBTYPE_AUTH";
                case _FRAME_SUBTYPE_DEAUTH:
                    return " _FRAME_SUBTYPE_DEAUTH";
                default:
                    return "_FRAME_SUBTYPE_RESERVED00";
            }
        break;
        case _FRAME_TYPE_CONTROL:
            switch(control.bits.subtype)
            {
                case _FRAME_SUBTYPE_PS_POLL:
                    return "_FRAME_SUBTYPE_PS_POLL";
                case _FRAME_SUBTYPE_RTS:
                    return "_FRAME_SUBTYPE_RTS";
                case _FRAME_SUBTYPE_CTS:
                    return "_FRAME_SUBTYPE_CTS";
                case _FRAME_SUBTYPE_ACK:
                    return " _FRAME_SUBTYPE_ACK";
                case _FRAME_SUBTYPE_CFE:
                    return "_FRAME_SUBTYPE_CFE";
                case _FRAME_SUBTYPE_CFE_CFA:
                    return "_FRAME_SUBTYPE_CFE_CFA";
                default:
                    return "_FRAME_SUBTYPE_RESERVED01";
            }
        break;
        case _FRAME_TYPE_DATA:
            switch(control.bits.subtype)
            {
                case _FRAME_SUBTYPE_DATA:
                    return "_FRAME_SUBTYPE_DATA";
                case _FRAME_SUBTYPE_DATA_CFA:
                    return "_FRAME_SUBTYPE_DATA_CFA";
                case _FRAME_SUBTYPE_DATA_CFP:
                    return "_FRAME_SUBTYPE_DATA_CFP";
                case _FRAME_SUBTYPE_DATA_CFA_CFP:
                    return "_FRAME_SUBTYPE_DATA_CFA_CFP";
                case _FRAME_SUBTYPE_NULL_NO_DATA:
                    return "_FRAME_SUBTYPE_NULL_NO_DATA";
                case _FRAME_SUBTYPE_CFA_NO_DATA:
                    return "_FRAME_SUBTYPE_CFA_NO_DATA";
                case _FRAME_SUBTYPE_CFP_NO_DATA:
                    return "_FRAME_SUBTYPE_CFP_NO_DATA";
                case _FRAME_SUBTYPE_CFA_CFP_NO_DATA:
                    return "_FRAME_SUBTYPE_CFA_CFP_NO_DATA";
                default:
                    return "_FRAME_SUBTYPE_RESERVED10";
            }
        break;

        case _FRAME_TYPE_RESERVED:
            return "_FRAME_SUBTYPE_RESERVED11";
    }

    return "_FRAME_SUBTYPE_ERROR";
}

static inline unsigned char get_frame_type(union frame_control control)
{
    switch(control.bits.type)
    {
        case _FRAME_TYPE_MANAGEMENT:
        case _FRAME_TYPE_CONTROL:
        case _FRAME_TYPE_DATA:
        case  _FRAME_TYPE_RESERVED:
            return control.bits.type;
    }

    return  _FRAME_TYPE_ERROR;
}

static inline const char *get_frame_type_string(union frame_control control)
{
    switch(control.bits.type)
    {
        case _FRAME_TYPE_MANAGEMENT:
            return "_FRAME_TYPE_MANAGEMENT";
        case _FRAME_TYPE_CONTROL:
            return "_FRAME_TYPE_CONTROL";
        case _FRAME_TYPE_DATA:
            return "_FRAME_TYPE_DATA";
        case  _FRAME_TYPE_RESERVED:
            return  "_FRAME_TYPE_RESERVED";
    }

    return  "_FRAME_TYPE_ERROR";
}

/* In wt > 29 inline function iw_saether_ntop will be removed, so redeclaring here */
#if WT_VERSION > 29
    /*------------------------------------------------------------------
     *  * Display an Ethernet Socket Address in readable format.
     */
    static inline char *
    iw_saether_ntop(const struct sockaddr *sap, char* bufp)
    {
        iw_ether_ntop((const struct ether_addr *) sap->sa_data, bufp);
        return bufp;
    }
#endif

#endif
