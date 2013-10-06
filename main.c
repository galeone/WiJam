#include <iwlib.h>
#include <getopt.h>

void _die() {
    exit(EXIT_FAILURE);
}

#define die(s, ...) _die(fprintf(stderr,"[!] ") && fprintf(stderr, s, ##__VA_ARGS__) && fprintf(stderr,"\n"))

#define info(s, ...) do {printf("[i] "); printf(s, ##__VA_ARGS__); putchar('\n'); } while(0)

static short int _interface_counter = 0;

//someone, someday will have to explain to me why the return type of iw_enum_handler is int and not void
int
validate_interface(int skfd,  char *ifname,  char *args[], int count) {

    /* Avoid "unuserd parameter": warning */
    count = count, skfd = skfd;

    if(!strcmp(ifname,args[0])) //valid interface
        args[0][strlen(args[0])] = '!'; //flag

    return EXIT_SUCCESS;
}

int
enum_interface(int skfd, char *ifname, char *args[], int count) {

    /* Avoid "unuserd parameter": warning */
    count = count, skfd = skfd, args = args;

    printf("    [%d]: %s\n",_interface_counter++, ifname);
    return EXIT_SUCCESS;
}

int
select_interface(int skfd, char *ifname, char *args[], int count) {

    /* Avoid "unuserd parameter": warning */
    skfd = skfd;
    if(count == _interface_counter) {
        args[0] = strdup(ifname);
    }
    ++_interface_counter;
    return EXIT_SUCCESS;
}

static inline void
help(void) {
    die(    "Usage: wijam [OPTION]...\n\
    Send Jamming signal to specified network.\n\n\
    --i, --interface INTERFACE \tuse specifed interface\n\
    --e, --essid ESSID\tNetwork ESSID\n\n\
With no OPTION, or when INTERFACE is invalid, begin dynamic mode.");
}

int prompt_choose(int limit)
{
    int choice;

    scanf("%d",&choice);
    while(getchar() != '\n')
       ;
    while(choice < 0 || choice >= limit) {
        info("invalid choice number.\nInsert a valid one:");
        scanf("%d",&choice);
        while(getchar() != '\n')
            ;
    }

    return choice;
}


int
main(int argc, char **argv) {

    int iw_sock, optIndex = -1;
    iw_enum_handler fn;
    char *essid = NULL, *interface = NULL,  valid;
    extern int opterr;
    wireless_scan_head context;
    wireless_scan *scanResult;

    static struct option long_options[] =
    {
        {"interface",required_argument, NULL, 'i'}, // optIndex 0
        {"essid", required_argument, NULL, 'e'}, //optIndex 1
        {NULL, 0, NULL, 0}
    };

    //disable default error message
    opterr  = 0;

    while( getopt_long(argc, argv, "e:i:", long_options, &optIndex) != -1 )
    {
        switch(optIndex)
        {
            case 1: //essid
                essid = strdup(optarg);
                break;

            case 0: //interface
                interface = strdup(optarg);
                break;

            default:
                help();
        }
    }

    if( ( iw_sock = iw_sockets_open() ) < 0 )
        die("%s",strerror(errno));

    //interface selection and validation
    valid = 0;
    do
    {
        if( ! interface ) { //start dynamic mode
            info("Select your wireless interface:");
            fn = enum_interface;
            iw_enum_devices(iw_sock, fn, NULL, 0);

            optIndex = prompt_choose(_interface_counter);

            fn = select_interface;
            _interface_counter = 0;
            iw_enum_devices(iw_sock, fn, &interface, optIndex);
            valid = 1;
        }
        else { //validity control of interface
            fn = validate_interface;
            iw_enum_devices(iw_sock, fn, &interface, 0);

            optIndex = strlen(interface) - 1;

            if(interface[optIndex] != '!') { //invalid -> goto dynamic mode
                interface[optIndex] = '\0';
                info("%s invalid interface... swtching to dynamic mode\n", interface);
                free(interface);
                interface= NULL;
            }
            else {
                valid = 1;
                interface[optIndex] = '\0';
            }
        }
    }
    while(!valid);

    //essid selection and validation
    valid = 0;
    do
    {
        info("performing net scan....");
        if( ! essid) { //start AP scan
            if( ! iw_scan(iw_sock, interface, WE_VERSION, &context) ) { //success

                valid = 'n';
                while(valid != 'y') {

                    for(scanResult = context.result, optIndex = 0; scanResult != NULL; scanResult = scanResult->next, ++optIndex) { //linked list
                        info("%d: %s",optIndex, (scanResult->b).essid);
                    }

                    if(optIndex < 1) {
                        info("no network found.. retry? [y/n]");
                        valid = prompt_choose('n');
                        if(optIndex != 'y') {
                            return EXIT_SUCCESS;
                        }
                    }
                    else {
                        valid = 'y';
                    }
                }

                info("select target essid: ");
                optIndex = prompt_choose(optIndex);

                for(scanResult = context.result, valid = 0; valid < optIndex; ++valid, scanResult = scanResult->next) 
                    ; //set scanResult to selected network

                valid = 1;
            }
            else
                die("Failed to scan.\nIs %s a valid wireless interface?",interface);
        }
        else { //scan AP AND control if essid is a valid essid
            if( ! iw_scan(iw_sock, interface, WE_VERSION, &context) ) { //success

                for(scanResult = context.result, optIndex = strlen(essid); scanResult != NULL; scanResult = scanResult->next) { //linked list
                    if( ! strncmp(essid,(scanResult->b).essid,optIndex) ) { //found
                        valid = 1;
                        break;
                    }
                }
                if(!valid) { //not found, switch to dynamic mode
                    info("%s: network not found... switching to dynamic mode",essid);
                    free(essid);
                    essid = NULL;
                }
                
            }
            else
                die("Failed to scan.\nIs %s a valid wireless interface?",interface);
        }
    }
    while(!valid);

    //valid essid is into: essid, and scanResult is filled with network information
    //valid interface is into: interface

    //now i've got a valid interface and a valid network, let's enter in layer 2 of iso/osi model and make some magic

    //clean up
    iw_sockets_close(iw_sock);
    free(interface);
    free(essid);

    return EXIT_SUCCESS;
}
