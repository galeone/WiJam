#include "lib/libwijam.h"

int
main(int argc, char **argv) {

    int iw_sock, optIndex = -1, eth_sock;
    iw_enum_handler fn;
    char *essid = NULL, *interface = NULL,  valid, eth_addr[17];
    extern int opterr;
    extern unsigned short int _interface_counter;
    wireless_scan_head context;
    wireless_scan *scanResult;

    struct sockaddr me;
    struct sockaddr_ll packet_sockaddr; //packet version of sockaddr 
    struct rts_frame rts;
    struct cts_frame cts;
    uint16_t proto_port = htons(ETH_P_ALL);

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

    //getting my MAC interface address

    me = get_mac(iw_sock, interface);

    printf("%s MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
            interface,
            (unsigned char) me.sa_data[0],
            (unsigned char) me.sa_data[1],
            (unsigned char) me.sa_data[2],
            (unsigned char) me.sa_data[3],
            (unsigned char) me.sa_data[4],
            (unsigned char) me.sa_data[5]
          );

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
                        printf("%d: %s - %s\n",optIndex, (scanResult->b).has_essid && (scanResult->b).essid_on ? (scanResult->b).essid : "Hidden network", iw_saether_ntop(&(scanResult->ap_addr),eth_addr));
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

    proto_port = htons(ETH_P_ALL);

    if( (eth_sock = socket(AF_PACKET, SOCK_RAW, proto_port)) < 0) //protocol defined in linux/if_ether.h
        die("%s",strerror(errno));

    //fill ethernet frame header
    memset(&rts, 0, sizeof (struct rts_frame));
    rts.control = 0x4b00;
    rts.duration = 3800;
    memcpy(rts.ra, scanResult->ap_addr.sa_data, ETH_ALEN);
    memcpy(rts.ta, me.sa_data, ETH_ALEN);

    //fille sockaddr_ll (packet_sockaddr)
    memset(&packet_sockaddr, 0, sizeof (struct sockaddr_ll));
    packet_sockaddr.sll_family = AF_PACKET; //always
    packet_sockaddr.sll_halen = ETH_ALEN; //address length
    packet_sockaddr.sll_ifindex = get_ifindex(iw_sock, interface);
    memcpy(&(packet_sockaddr.sll_addr),&(scanResult->ap_addr), ETH_ALEN);

    //BEGIN TEST source code

    for(;;)
    {
        if(sendto(eth_sock, &rts, sizeof (struct rts_frame) , 0,(struct sockaddr *) &packet_sockaddr, sizeof(struct sockaddr_ll)) < 0)
            die("sendto: %s",strerror(errno));

        if(recvfrom(eth_sock, &cts, sizeof (struct cts_frame), 0, NULL, 0) < 0)
            die("recvfrom: %s", strerror(errno));

        //Frame type must be identified by checking value of type and subtype bits in control (bitmask)
        info("Frame received!\nControl: %u\nDuration: %u\nra: %02X:%02X:%02X:%02X:%02X:%02X\n fcs: %d",
                cts.control,
                cts.duration,
                (unsigned char)cts.ra[0],
                (unsigned char)cts.ra[1],
                (unsigned char)cts.ra[2],
                (unsigned char)cts.ra[3],
                (unsigned char)cts.ra[4],
                (unsigned char)cts.ra[5],
                cts.fcs
            );
    }
    //END TESTING

    //clean up
    iw_sockets_close(iw_sock);
    close(eth_sock);
    free(interface);
    free(essid);

    return EXIT_SUCCESS;
}
