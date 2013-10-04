#include <iwlib.h>
#include <stdlib.h>
#include <stdio.h>


int my_enum_handler(int skfd,  char *ifname,  char *args[], int count)
{
    static int counter = 0;
    int i;
    printf("[%d]: %s\n",counter++, ifname);
}

int main(int argc, char **argv)
{
    int iw_sock;
    iw_enum_handler fn = my_enum_handler;

    iw_sock = iw_sockets_open();

    iw_enum_devices(iw_sock, fn, NULL, 0);

    return EXIT_SUCCESS;
}
