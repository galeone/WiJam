#include "libwijam.h"

/* global variable */

unsigned short int _interface_counter = 0;


/* internal function */ 
void _die()
{
    exit(EXIT_FAILURE);
}

/* someone, someday will have to explain to me why the return type of iw_enum_handler is int and not void
callback function */

int validate_interface(int skfd,  char *ifname,  char *args[], int count)
{
    /* Avoid "unuserd parameter": warning */
    count = count, skfd = skfd;

    if(!strcmp(ifname,args[0])) //valid interface
        args[0][strlen(args[0])] = '!'; //flag

    return EXIT_SUCCESS;
}

/* callback function */

int enum_interface(int skfd, char *ifname, char *args[], int count)
{
    /* Avoid "unuserd parameter": warning */
    count = count, skfd = skfd, args = args;

    printf("    [%d]: %s\n",_interface_counter++, ifname);
    return EXIT_SUCCESS;
}

/* callback function */

int select_interface(int skfd, char *ifname, char *args[], int count)
{
    /* Avoid "unuserd parameter": warning */
    skfd = skfd;
    if(count == _interface_counter) {
        args[0] = strdup(ifname);
    }
    ++_interface_counter;
    return EXIT_SUCCESS;
}

int prompt_choose(int limit)
{
    int choice;

    scanf("%d",&choice);
    while(getchar() != '\n')
       ;
    while(choice < 0 || choice >= limit) {
        info("invalid choice. Insert a valid one:");
        scanf("%d",&choice);
        while(getchar() != '\n')
            ;
    }

    return choice;
}

struct sockaddr get_mac(int iw_sock, char *interface)
{
    struct ifreq hw;
    memset(&hw, 0, sizeof (struct ifreq));
    strncpy(hw.ifr_name, interface, strlen(interface));

    if(ioctl(iw_sock, SIOCGIFHWADDR, &hw) < 0)
        die("ioctl: %s",strerror(errno));

    return hw.ifr_hwaddr;
}

int get_ifindex(int iw_sock, char *interface)
{
    struct ifreq hw;
    memset(&hw, 0, sizeof (struct ifreq));
    strncpy(hw.ifr_name, interface, strlen(interface));
    if(ioctl(iw_sock, SIOCGIFINDEX, &hw) < 0)
        die("ioctl: %s",strerror(errno));

    return hw.ifr_ifindex;
}
