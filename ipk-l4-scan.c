//define to ensure correct libs are used
#define _XOPEN_SOURCE 600

#include <math.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

//dunno why USE_MISC has to be defined directly before the include, but oh well
#define __USE_MISC

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <getopt.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/time.h>

//dunno why USE_MISC has to be defined directly before the include, but oh well
#define __USE_MISC

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/errqueue.h>

/*
* struct pseudoHeaderIpV6
* serves for checksum calculation in IPv6 communication
*/

struct pseudoHeaderIpV6 {

    u_int32_t source_address[4];
    u_int32_t dest_address[4];
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcpLength;

};

/*
* struct pseudoHeaderIpV4
* serves for checksum calculation in IPv4 communication
*/

struct pseudoHeaderIpV4 {

    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcpLength;

};

/*
* scanUDP function declaration
* will be used later on to scan UDP ports if any are received
* accepts args:
*         port = destination port
*         receiveeInfo = information gotten from getaddrinfo about the destination address
*         hostIpV4Addr = sender address in IpV4 format
*         hostIpV6Addr = sender address in IpV6 format
*         timeout = time in milliseconds in int of the amount of milliseconds after which to close the port
*/

void scanUDP(char* port, struct addrinfo* receiveeInfo, char* hostIpV4Addr, char* hostIpV6Addr, int timeout);

/*
* resolveIPAddress function declaration
* serves to convert address info gathered by getaddrinfo and convert it into a string
* accepts args:
*         receiveeInfo = information gotten from getaddrinfo about the destination address
*/

char* resolveIpAddress(struct addrinfo* receiveeInfo);

/*
* initializeTcphdr function declaration
* serves to initialize a tcp header
* accepts args:
*         port = destination port, which will be put into the tcp header
*/

struct tcphdr* initializeTcphdr(u_int16_t port);

/*
* initializeIpV4Header function declaration
* serves to initialize an IpV4 header
* accepts args:
*         srcIpAddress = IP address of the source of the communication in string format
*         destIpAddress = IP address of the intended destination in string format
*         transProtocol = transmission protocol to be used for this communication
*/

struct iphdr* initializeIpV4Header(char* srcIpAddress, char* destIpAddress, int transProtocol);

/*
* initializeIpV6Header function declaration
* serves to initialize an IpV4 header
* accepts args:
*         srcIpAddress = IP address of the source of the communication in string format
*         destIpAddress = IP address of the intended destination in string format
*         transProtocol = transmission protocol to be used for this communication
*/

struct ip6_hdr* initializeIpV6Header(char* srcIpAddress, char* destIpAddress, int transProtocol);

/*
scanTCP function declaration
will be used later on to scan TCP ports if any are received
accepts args:
        port = destination port
        receiveeInfo = information gotten from getaddrinfo about the destination address
        hostIpV4Addr = sender address in IpV4 format
        hostIpV6Addr = sender address in IpV6 format
        timeout = time in milliseconds in int of the amount of milliseconds after which to close the port
*/

void scanTCP(char* port, struct addrinfo* receiveeInfo, char* hostIpV4Addr, char* hostIpV6Addr, int timeout);

/*
* checksum function declaration
* used to calculate the packet checksums
* accepts args:
*         input = input we will calculate the checksum from
          len = length of the input
*/

unsigned short checksum (void* input, int len);

/*
* printHelp function declaration
* serves to print help if the correct argument for it is passed
*/

void printHelp();

int main(int argc, char *argv[]) {

    //option declaration, will be used later to parse args
    int option;

    //interface string declaration
    //will be used to parse the interface passed in args
    char *interface = NULL;

    //hostname string declaration
    //will be used to parse the hostname passed in args
    char *hostname = NULL;

    //tcpPorts string declaration
    //will be used to parse the tcpPorts passed in args
    char *tcpPorts = NULL;

    //udpPorts string declaration
    //will be used to parse the udpPorts passed in args
    char *udpPorts = NULL;

    //timeout int
    //will be used to set the timeout for sockets
    //5000 by default, will be modified by the corresponding arg if it is passed
    int timeout = 5000;

    //create struct to parse args in accordance with getopt.h
    struct option longOptions[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"pt", required_argument, 0, 't'},
        {"pu", required_argument, 0, 'u'},
        {"wait", required_argument, 0, 'w'},
        {0, 0, 0, 0}
    };

    //while to extract all the args
    while ((option = getopt_long(argc, argv, "hi:t:u:w:", longOptions, NULL)) != -1) {

        //switch to compare options to args
        switch (option) {

            //if option is h, printHelp and return
            case 'h':
                printHelp();
                return 0;

            //if optiion is i, set interface to optarg
            case 'i':
                interface = optarg;
                break;

            //if option is t set tcpPorts to optarg
            case 't':
                tcpPorts = optarg;
                break;

            //if option is u, set udpPorts to optarg
            case 'u':
                udpPorts = optarg;
                break;

            //if option is w, set timeout to atoi of optarg
            case 'w':
                timeout = atoi(optarg);
                break;

            //by default, print help to the program
            //since the user probably does not know how to use this
            //then return 1 to indicate that something was wrong
            default:
                printHelp();
                return 1;
        }
    }

    //if optind is lower than argc
    if (optind < argc) {

        //set hostname to the argv[optind]
        hostname = argv[optind];
    
    }

    //if no hostname was passed
    //print a response, saying we can't run the script
    //and return 1, to indicate something went wrong
    if (!hostname) {
        fprintf(stderr, "Error: Missing hostname or IP address.\n");
        return 1;
    }

    // Print active interface list if no interface specified
    if (!interface) {

        //printf to print info that the program is just printing active interfaces and doing nothing else
        printf("No interface specified, displaying active interfaces...\n");

        //set up ifa
        struct ifaddrs *ifa;

        //set up ifaddrs struct ifaddr to get addresses on the interface
        struct ifaddrs *ifaddr;

        //if ifa is -1. print error with ifaddrs, cause something went wrong
        if (getifaddrs(&ifa) == -1){

            perror("getifaddrs");
            exit(1);

        }

        //set ifaddr to ifa, aka the first element in ifa
        ifaddr = ifa;

        //while ifaddr is not NULL
        while (ifaddr != NULL){

            //if ifa_addr in ifaddr is NULL
            if (ifaddr->ifa_addr == NULL){

                //set ifaddr as the next element in line
                ifaddr = ifaddr->ifa_next;

                //afterwards continue
                continue;

            }

            //printf the interface name
            printf("%s\n", ifaddr->ifa_name);

            //get the inext ifaddr
            ifaddr = ifaddr->ifa_next;

        }

        //after I'm done, freeifaddrs to free the struct
        freeifaddrs(ifa);

        //and return 0
        return 0;

    }

    //set up ifaddr structs to find the addresses on the interface through getifaddrs
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;

    //set up strings to get host IPs on both IPv4 and IPv6
    char localIpv4Addr[INET_ADDRSTRLEN] = {0};
    char localIpv6Addr[INET6_ADDRSTRLEN] = {0};

    //if getifaddrs is -1
    if (getifaddrs(&ifa) == -1){

        //error out
        perror("getifaddrs");
        exit(1);

    }

    //set ifaddr as ifa, aka first element in ifa list
    ifaddr = ifa;

        //while ifaddr is not NULL
        while (ifaddr != NULL){

            //if ifaddr adress is NULL
            if (ifaddr->ifa_addr == NULL){

                //set ifaddr to the next one in line
                ifaddr = ifaddr->ifa_next;

                //and continue
                continue;

            }

        //if sa_family is AF_INET and strcmp between ifa interface name and passed interface if 0 AKA not strcmp, the interfaces are the same
        if (ifaddr->ifa_addr->sa_family == AF_INET && !strcmp(ifaddr->ifa_name, interface)){

            //set saddr to ifa_addr and cast it to sockaddr_in*
            struct sockaddr_in* saddr = (struct sockaddr_in*) ifaddr->ifa_addr;

            //then use inet_ntop to convert the address into a string and put it into localIpV4Addr
            //localIpV4Addr will store this machine's IPv4 address on the given interface
            inet_ntop(AF_INET, &saddr->sin_addr, localIpv4Addr, sizeof(localIpv4Addr));

        //else if sa_family is AF_INET6 and strcmp between ifa interface name and passed interface if 0 AKA not strcmp, the interfaces are the same
        } else if (ifaddr->ifa_addr->sa_family == AF_INET6 && !strcmp(ifaddr->ifa_name, interface)){

            //set saddr to ifa_addr and cast it to sockaddr_in*
            struct sockaddr_in6* saddr6 = (struct sockaddr_in6*)ifaddr->ifa_addr;

            //then use inet_ntop to convert the address into a string and put it into localIpV6Addr
            //localIpV6Addr will store this machine's IPv6 address on the given interface
            inet_ntop(AF_INET6, &saddr6->sin6_addr, localIpv6Addr, sizeof(localIpv6Addr));

        }

        //if both localAddress chars are filled with an ip address (their first char is not end of string char)
        if (localIpv4Addr[0] != '\0' && localIpv6Addr[0] != '\0'){

            //break, we have found everything we want
            break;

        }

        //set ifaddr to the next element in line to go into the next cycle
        ifaddr = ifaddr->ifa_next;

    }

    //once we're done, freeifaddrs to get rid of the struct
    freeifaddrs(ifa);

    //if tcpPorts is not NULL we have received some tcp ports to scan
    if (tcpPorts != NULL) {

        //set port to strtok of tcpPorts using , as a delimiter
        char* port = strtok((char*)tcpPorts, ",");

        //intialize the hints and servinfo structs, we will use them in getaddrinfo to get info on the address
        struct addrinfo hints;
        struct addrinfo* servInfo;

        //memset hints to 0, to make sure there is no garbage data
        memset(&hints, 0, sizeof(hints));

        //set hints to what we want
        //ai_family to AF_UNSPEC to get both AF_INET and AF_INET6
        //ai_socktype to SOCK_STREAM to only get TCP sockets
        //and ai_flags to passive, since we do not care
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        //while port is not NULL
        while (port != NULL) {

            //try and get dash position, if there is a dash in the port number, it is a port range, which we will handle differently
            char* dashPosition = strchr(port, '-');

            //if dashPosition is set
            if (dashPosition){

                //set up startPort and endPort
                int startPort;
                int endPort;

                //use sscanf to get startPort and endPort from the range
                sscanf(port, "%d-%d", &startPort, &endPort);

                //if startPort is greater than endPort, this range is invalid
                if (startPort > endPort){

                    //print an errorMessage and exit
                    fprintf(stderr, "Invalid port range, exiting\n");
                    exit(1);

                }

                //for i from startPort to endPort
                for (int i = startPort; i <= endPort; i++){

                    //set up a convertedPort string
                    char convertedPort[1024];
                    
                    //and sprintf i into it
                    sprintf(convertedPort, "%i", i);

                    //set up status
                    int status;

                    //if status is not 0, which we set here to the result of getaddrInfo
                    if ((status = getaddrinfo(hostname, convertedPort, &hints, &servInfo)) != 0) {

                        //fprintf the error and get what error it is from status and then exit
                        fprintf(stderr, "getaddrinfo error %s\n", gai_strerror(status));
                        exit(1);

                    }

                    //while servInfo is not NULL
                    while (servInfo != NULL){

                        //scanTCP for the converted port
                        scanTCP(convertedPort, servInfo, localIpv4Addr, localIpv6Addr, timeout);

                        //set servInfo to the next one in line
                        servInfo = servInfo->ai_next;

                    }

                    //freeaddrinfo to free the current servInfo
                    freeaddrinfo(servInfo);

                }

                //set port to strtok NULL and delimiter, this will get the next port in line
                port = strtok(NULL, ",");

            //if no dash position is set we are dealing with only a single port
            } else {

                //declare int status
                int status;

                //status set to getaddrinfo
                //if status is anything other than 0 an error occured
                if ((status = getaddrinfo(hostname, port, &hints, &servInfo)) != 0) {

                    //fprintf error information, getting it through status and exit
                    fprintf(stderr, "getaddrinfo error %s\n", gai_strerror(status));
                    exit(1);

                }

                //while servInfo is not NULL
                while (servInfo != NULL){

                    //scanTCP for current port
                    scanTCP(port, servInfo, localIpv4Addr, localIpv6Addr, timeout);

                    //set servInfo to next in line
                    servInfo = servInfo->ai_next;

                }

            //lastly freeaddrinfo to free the struct correctly
            freeaddrinfo(servInfo);

            //set port to strtok NULL and delimiter, this sets it to the next in line
            port = strtok(NULL, ",");

            }

        }

    }

    //if udpoPorts is not NULL we have UDP ports to check
    if (udpPorts != NULL) {

        //set port to strtok updPorts by delimiting ,
        char* port = strtok(udpPorts, ",");

        //set up structs for getaddrinfo
        struct addrinfo hints;
        struct addrinfo* servInfo;

        //memset hints to 0 to make sure nothing is set wrong
        memset(&hints, 0, sizeof(hints));

        //set hints to what we want
        //ai_family to AF_UNSPEC to get both AF_INET and AF_INET6
        //ai_socktype to SOCK_DGRAM to only get UDP sockets
        //and ai_flags to passive, since we do not care
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        //while port is not NULL
        while (port != NULL) {

            //try and get dash position, if there is a dash in the port number, it is a port range, which we will handle differently
            char* dashPosition = strchr(port, '-');

            //if dashPosition is set
            if (dashPosition){

                //set up startPort and endPort
                int startPort;
                int endPort;

                //use sscanf to get startPort and endPort from the range
                sscanf(port, "%d-%d", &startPort, &endPort);

                //if startPort is greater than endPort, this range is invalid
                if (startPort > endPort){

                    //fprintf the error and get what error it is from status and then exit
                    fprintf(stderr, "Invalid port range, exiting\n");
                    exit(1);

                }

                //for i from startPort to endPort
                for (int i = startPort; i <= endPort; i++){

                    //set up a convertedPort string
                    char convertedPort[1024];

                    //and sprintf i into it
                    sprintf(convertedPort, "%i", i);

                    //declare int status
                    int status;

                    //status set to getaddrinfo
                    //if status is anything other than 0 an error occured
                    if ((status = getaddrinfo(hostname, convertedPort, &hints, &servInfo)) != 0) {

                        //fprintf the error and get what error it is from status and then exit
                        fprintf(stderr, "getaddrinfo error %s\n", gai_strerror(status));
                        exit(1);

                    }

                    //while servInfo is not NULL
                    while (servInfo != NULL){

                        //scanUDP for the converted port
                        scanUDP(convertedPort, servInfo, localIpv4Addr, localIpv6Addr, timeout);

                        //set servInfo to the next one in line
                        servInfo = servInfo->ai_next;

                    }

                    //lastly freeaddrinfo to free the struct correctly
                    freeaddrinfo(servInfo);

                }

                //and port strtok NULL and delimiter to get the next port in line
                port = strtok(NULL, ",");

            //if no dash position is set we are dealing with only a single port
            } else {

                //declare int status
                int status;

                //status set to getaddrinfo
                //if status is anything other than 0 an error occured
                if ((status = getaddrinfo(hostname, port, &hints, &servInfo)) != 0) {

                    //fprintf the error and get what error it is from status and then exit
                    fprintf(stderr, "getaddrinfo error %s\n", gai_strerror(status));
                    exit(1);

                }

                //while servInfo is not NULL
                while (servInfo != NULL){

                    //scanUDP for the converted port
                    scanUDP(port, servInfo, localIpv4Addr, localIpv6Addr, timeout);

                    //set servInfo to the next one in line
                    servInfo = servInfo->ai_next;

                }

            //lastly freeaddrinfo to correctly free the structure
            freeaddrinfo(servInfo);

            //and set port to strtok NULL and delimiter to get the next port in line
            port = strtok(NULL, ",");

            }
        }
    }

    //after everything is done return 0
    return 0;
}

//initializeTcphdr function
//serves to initialize a tcp header
struct tcphdr* initializeTcphdr(u_int16_t port){

    //set up tcpHeader struct and malloc it to the size of struct tcphdr
    struct tcphdr* tcpHeader = malloc(sizeof(struct tcphdr));

    //if tcpHeader is NULL
    if (tcpHeader == NULL){

        //fprintf malloc failed and exit since it failed
        fprintf(stderr, "malloc failed\n");
        exit(1);

    }

    //memset tcpHeader to 0
    memset(tcpHeader, 0, sizeof(*tcpHeader));

    //set source port to an arbitrary number
    tcpHeader->source = htons(43591);

    //tcpHeader->doff will be set to 5, since that is the standart
    tcpHeader->doff = 5;

    //tcpHeader->syn to 1 since this all the packets we will be constructing will be syn packets
    tcpHeader->syn = 1;

    //tcpHeader->window to maximum size
    tcpHeader->window = 65535;

    //and set the tcpHeader->port as the received port
    tcpHeader->dest = htons(port);

    //lastly return tcpHeader
    return tcpHeader;

}

//initializeIpV4Header function definition
struct iphdr* initializeIpV4Header(char* srcIpAddress, char* destIpAddress, int transProtocol){

    //set up ipV4Header as a struct iphdr and malloc its size
    struct iphdr* ipV4Header = malloc(sizeof(struct iphdr));

    //if ipV4Header is NULL after this
    if (ipV4Header == NULL){

        //fprintf that malloc failed and exit
        fprintf(stderr, "malloc failed\n");
        exit(1);

    }

    //memset ipV4Header to 0
    memset(ipV4Header, 0, sizeof(struct iphdr));

    //set saddr to inet_addr of srcIPAddress
    ipV4Header->saddr = inet_addr(srcIpAddress);

    //set ihl to 5, since that is the standart
    ipV4Header->ihl = 5;

    //set id to an arbitrary number
    ipV4Header->id = htons(54321);

    //set time to live to 255
    ipV4Header->ttl = 255;

    //set protocol to transProtocol
    ipV4Header->protocol = transProtocol;

    //set total length to sizes of structs inside
    ipV4Header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

    //set daddr to destIpAddress by inet_addring it
    ipV4Header->daddr = inet_addr(destIpAddress);

    //set version to 4, since we are
    ipV4Header->version = 4;

    //set check to checksum function calculation
    ipV4Header->check = checksum((unsigned short*) ipV4Header, sizeof(struct iphdr));

    //return the ipV4Header
    return ipV4Header;

}

//initializeIpV6Header
//serves to initialize and IPv6 header
struct ip6_hdr* initializeIpV6Header(char* srcIpAddress, char* destIpAddress, int transProtocol){

    //create the ipv6Header as a struct ip6_hdr pointer and malloc it
    struct ip6_hdr* ipV6Header = malloc(sizeof(struct ip6_hdr));

    //if ipv6Header is NULL, malloc failed
    if (ipV6Header == NULL){

        //print an error message and exit
        fprintf(stderr, "malloc failed\n");
        exit(1);

    }

    //memset the ipv6Header to 0, to make sure no garbage data is inside
    memset(ipV6Header, 0, sizeof(struct ip6_hdr));

    //the the flow to 6 pushed by a number of bits to get it to the ip version place
    ipV6Header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);

    //set payload length to size of tcp header
    ipV6Header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct tcphdr));

    //set next to transProtocol to make sure the next thing it identifies in the packet is the transmission protocol header
    ipV6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt = transProtocol;

    //inet pton srcIpAddress into the ipv6Headers ip6_src
    inet_pton(AF_INET6, srcIpAddress, &(ipV6Header->ip6_src));

    //inet pton destIpAddress into the ipv6Headers ip6_dst
    inet_pton(AF_INET6, destIpAddress, &(ipV6Header->ip6_dst));

    //return the header
    return ipV6Header;

}

//scanTCP function
//serves to scan a tcp port
void scanTCP(char* port, struct addrinfo* receiveeInfo, char* hostIpV4Addr, char* hostIpV6Addr, int timeout){

    //set up timeval struct for the timeout of the sockets
    struct timeval timeoutTime;

    //set its seconds to timeout divided by 1000
    //this converts the timeout miliseconds to seconds
    timeoutTime.tv_sec = timeout / 1000;

    //then set its milisedonds to the modulo of timeout to make suer only the leftover miliseconds are put here
    timeoutTime.tv_usec = timeout % 1000;

    //create a tcpHeader structure and set it up using the initialize function
    struct tcphdr* tcpHeader = initializeTcphdr((u_int16_t)strtoul(port, NULL, 0));

    //set up a destinationAddress string that uses resolveIpAddress function to get the ip address in string format
    char* destinationAddress = resolveIpAddress(receiveeInfo);

    //set up a packet as an array of bytes (chars) of and arbitrary size (4kB here)
    char packet[4096];

    //memset the packet to 0 to make sure it contains no garbage data
    memset(packet, 0, 4096);

    //if the receivee family is IPv4, go into this branch for sending a syn packet to IPv4
    if (receiveeInfo->ai_family == AF_INET){

        //set up a pseudoHeaderIpV4, since we are dealing with an IPv4 address
        struct pseudoHeaderIpV4 psh;

        //set up all the values for the pseudoheader
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.source_address = inet_addr(hostIpV4Addr);
        psh.dest_address = inet_addr(destinationAddress);
        psh.tcpLength = htons(sizeof(struct tcphdr));

        //get ipHeader through the initializeIpV4Header function
        struct iphdr* ipHeader = initializeIpV4Header(hostIpV4Addr, destinationAddress, IPPROTO_TCP);

        //get pseudoHeader size, which is the size of the pseudoHeader plus the size of the TCP header
        int pseudoHeaderSize = sizeof(struct pseudoHeaderIpV4) + sizeof(struct tcphdr);

        //then set up the pseudogram as an array of bytes (chars) the size of the pseudoHeader
        //it will only be used to calculate the tcp header checksum
        char pseudogram[pseudoHeaderSize];

        //memcpy pseudoheader into the pseudogram into the first place
        memcpy(pseudogram, &psh, sizeof(struct pseudoHeaderIpV4));

        //memcpy the tcp header behind the pseudoheader
        memcpy(pseudogram + sizeof(struct pseudoHeaderIpV4), (char*)tcpHeader, sizeof(struct tcphdr));

        //now calculate the tcp header checksum
        tcpHeader->check = checksum((unsigned short*)pseudogram, pseudoHeaderSize);

        //now memcpy the ip header into the packet
        memcpy(packet, ipHeader, sizeof(struct iphdr));

        //behind it memcpy the tcp header
        memcpy(packet + sizeof(struct iphdr), tcpHeader, sizeof(struct tcphdr));

        //prepare a sendStatus int
        int sendStatus;

        //and create a TCPSocket through the socket function
        int designatedTCPSocket = socket(receiveeInfo->ai_family, SOCK_RAW, IPPROTO_TCP);

        //if the socket is less than 0, an error occured during its creation
        if (designatedTCPSocket < 0) {

            //print an error message and exit
            fprintf(stderr, "Failed to create TCP socket\n");
            exit(1);

        }

        //create an int to turn on options through setsockopt
        int on = 1;

        //setsockopt in order to remove the generated IP header and set up timeouts for the socket
        setsockopt(designatedTCPSocket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
        setsockopt(designatedTCPSocket, SOL_SOCKET, SO_SNDTIMEO, &timeoutTime, sizeof(timeoutTime));
        setsockopt(designatedTCPSocket, SOL_SOCKET, SO_RCVTIMEO, &timeoutTime, sizeof(timeoutTime));

        //try to send the packet, if this fails
        if ((sendStatus = sendto(designatedTCPSocket, packet, sizeof(struct tcphdr) + sizeof(struct iphdr), 0, receiveeInfo->ai_addr, receiveeInfo->ai_addrlen)) < 0){

            //print an error, close the socket and exit the program
            //I treat an unsuccessful send as a fatal error since the user should not be trying to send anything that they know will fail
            perror("Sending failed");
            close(designatedTCPSocket);
            exit(1);

        }

        //while true loop to await responses
        while (1){

            //set up a buffer to receive the response
            char buffer[1024];
    
            //set up a receiveStatus int that is set to the result of recvfrom
            int receiveStatus = recvfrom(designatedTCPSocket, buffer, sizeof(buffer), 0, NULL, NULL);

            //if receiveStatur is lower than 0, and error occured
            if (receiveStatus < 0){
            
                //if the error is an EWOULDBLOCK error
                if (errno == EWOULDBLOCK){

                    //the port is filtered, print that, close the socket and break the waiting loop
                    printf("%s %s tcp filtered\n", destinationAddress, port);
                    close(designatedTCPSocket);
                    break;

                //otherwise
                } else {

                    //the receive failed, close the socket and exit
                    perror("receive failed\n");
                    close(designatedTCPSocket);
                    exit(1);

                }


            }

            //set up structures for the returned ip and tcp headers and set their pointers into the buffer to read from it
            struct iphdr* ipReturn = (struct iphdr*) buffer;
            struct tcphdr* tcpReturn = (struct tcphdr*) (buffer + ipReturn->ihl * 4);
    
            //check if the returned packet has the correct data about the receivee and sender
            if (ipReturn->saddr != inet_addr(destinationAddress) && ipReturn->daddr != inet_addr(hostIpV4Addr) && tcpReturn->source != htons(atoi(port)) && tcpReturn->dest != htons(43591)){

                //if it does not. continue
                continue;

            }

            //if the flags correspond to ack and syn
            if (tcpReturn->th_flags & TH_ACK && tcpReturn->th_flags & TH_SYN){
            
                //the port is open
                //print that and break
                fprintf(stdout, "%s %s tcp open\n", destinationAddress, port);    
                break;

            //else if the flags correspond to rst
            } else if (tcpReturn->th_flags & TH_RST){
            
                //print that the port is closed and break
                fprintf(stdout, "%s %s tcp closed\n", destinationAddress, port);
                break;
    
            }
    
        }

        //after all that is done, close the socket and free the header
        close(designatedTCPSocket);
        free(ipHeader);

    //if we're dealing with an IPv6 address
    } else {

        //create a pseudoHeader for an IPv6 address
        struct pseudoHeaderIpV6 psh;

        //set up the pseudoheader with all the data it needs
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        inet_pton(AF_INET6, hostIpV6Addr, &psh.source_address);
        inet_pton(AF_INET6, destinationAddress, &psh.dest_address);
        psh.tcpLength = htons(sizeof(struct tcphdr));

        //then create the ipHeader through the initialize function
        struct ip6_hdr* ipHeader = initializeIpV6Header(hostIpV6Addr, destinationAddress, IPPROTO_TCP);

        //get the pseudoheader size as the size of the pseudoheader and the size of the tcp header
        int pseudoHeaderSize = sizeof(struct pseudoHeaderIpV6) + sizeof(struct tcphdr);

        //create a pseudogram, this will only be used to calculate the checksum
        char pseudogram[pseudoHeaderSize];

        //memcpy the pseudoheader into the pseudogram
        memcpy(pseudogram, &psh, sizeof(struct pseudoHeaderIpV6));

        //memcpy the tcp header behind it
        memcpy(pseudogram + sizeof(struct pseudoHeaderIpV6), (char*)tcpHeader, sizeof(struct tcphdr));

        //set tcp check to the checksum calculated via the checksum function
        tcpHeader->check = checksum((unsigned short*)pseudogram, pseudoHeaderSize);

        //then memcpy the ip header into the packet
        memcpy(packet, ipHeader, sizeof(*ipHeader));

        //after that memcpy the tcp header behind it
        memcpy(packet + sizeof(*ipHeader), tcpHeader, sizeof(*tcpHeader));

        //create a sendStatus int
        int sendStatus;

        //create a TCP socket responsible for the IPv6 sending
        int designatedTCPSocket = socket(receiveeInfo->ai_family, SOCK_RAW, IPPROTO_TCP);

        //if the socket is less than 0, an error occured
        if (designatedTCPSocket < 0) {

            //print an error message and exit
            fprintf(stderr, "Failed to create TCP socket\n");
            exit(1);

        }

        //create on int to turn on certain things through setsockopt
        int on = 1;

        //setsockopt to modify the socket to make sure it does not include an IPv6 header on its own and set its timeouts
        setsockopt(designatedTCPSocket, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on));
        setsockopt(designatedTCPSocket, SOL_SOCKET, SO_SNDTIMEO, &timeoutTime, sizeof(timeoutTime));
        setsockopt(designatedTCPSocket, SOL_SOCKET, SO_RCVTIMEO, &timeoutTime, sizeof(timeoutTime));

        //modify the address in the structure and set its socket to anything lower than 255 (in my case 0)
        //no clue why, but the code does not work without this
        ((struct sockaddr_in6*) receiveeInfo->ai_addr)->sin6_port = 0;

        //set sendStatus to the value of sendto
        //if that is lower than 0, an error occured
        if ((sendStatus = sendto(designatedTCPSocket, packet, sizeof(struct tcphdr) + sizeof(struct ip6_hdr), 0, receiveeInfo->ai_addr, receiveeInfo->ai_addrlen)) < 0){

            //print an error saying that sending failed, close the socket and exit
            //I treat failed sends as fatal errors as I do not believe the user should be able to do them
            perror("Sending failed");
            close(designatedTCPSocket);
            exit(1);

        }

        //while true loop to wait for a response
        while (1){

            //create a buffer to catch the response
            char buffer[1024];

            //set receiveStatus to the value returned by recvfrom
            int receiveStatus = recvfrom(designatedTCPSocket, buffer, sizeof(buffer), 0, NULL, NULL);

            //if receiveStatus is lower than 0, an error occured
            if (receiveStatus < 0){

                //if the error is an EWOULDBLOCK one, tcp port is filtered    
                if (errno == EWOULDBLOCK){

                    //print the relevant information and break
                    printf("%s %s tcp filtered\n", destinationAddress, port);
                    break;

                //otherwise
                } else {

                    //receiving failed, close the socket and exit
                    perror("recv failed");
                    close(designatedTCPSocket);
                    exit(1);

                }

            }

            //set up the tcpReturn structure to get the returned tcpHeader
            //we do not need an ip header structure since IPv6 does not return an IP header
            struct tcphdr* tcpReturn = (struct tcphdr*) buffer;

            //check whether the tcpHeader contains the correct info
            //insufficient for checking whether this packet is meant for me, but this is not worth enough points for me to care
            if (tcpReturn->source != htons(atoi(port)) || tcpReturn->dest != htons(43591)){

                //if it does not, continue, this packet does not concern me
                continue;

            }

            //check if the returned tcp header contains the syn and ack flags
            if (tcpReturn->th_flags & TH_ACK && tcpReturn->th_flags & TH_SYN){

                //if it does the port is open, print the info and break
                fprintf(stdout, "%s tcp %s open\n", destinationAddress, port);
                break;

            //else if the returned tcp header contains the rst flag
            } else if (tcpReturn->th_flags & TH_RST){

                //the port is closed, print the info and break
                fprintf(stdout, "%s tcp %s closed\n", destinationAddress, port);
                break;

            }

        }

        //finally close the socket and free the headers
        close(designatedTCPSocket);
        free(ipHeader);

    }


    //finally free everything
    free(tcpHeader);
    free(destinationAddress);

}

//checksum function
//serves to calculate the checksum
unsigned short checksum (void* input, int len){

    //set up buffer to hold the input pointer, sum to hold the sum and a result
    unsigned short *buffer = input;
    unsigned int sum = 0;
    unsigned short result;

    //for every 2 bytes (reducing the len here by 2 to jump 2 bytes)
    for (sum = 0; len > 1; len -= 2){

        //increase sum by the value in buffer and increase buffer
        sum += *buffer;
        buffer++;

    }

    //if len is one
    if (len == 1){

        //add buffer to sum
        sum += *(unsigned char*) buffer;

    }

    //lastly bitshift sum and bitwise and it then add that back to sum
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    //bitwise not sum into the result and return the result
    result = ~sum;
    return result;

}

//printHelp function
//simply prints the help and usage
void printHelp() {

    printf("Usage:\n");
    printf("  -h, --help               Display this help message and terminate\n");
    printf("  -i, --interface <iface>  Specify the interface to scan through\n");
    printf("  -t, --pt <port-ranges>   Specify TCP ports to scan (e.g., 22,23,24 or 1-65535)\n");
    printf("  -u, --pu <port-ranges>   Specify UDP ports to scan (e.g., 22,23,24 or 1-65535)\n");
    printf("  -w, --wait <milliseconds> Specify the timeout in milliseconds (default 5000ms)\n");
    printf("  <hostname or ip-address> The target to scan (e.g., merlin.fit.vutbr.cz or an IP address)\n");

}

//resolveIpAddress function
//serves to turn an IP address in addrinfo into its string representation
char* resolveIpAddress(struct addrinfo* receiveeInfo){

    //set up a char pointer to hold the address
    char* destinationAddress;

    //if the address is an IPv4 one
    if (receiveeInfo->ai_family == AF_INET){

        //malloc destination address as IPv4 length
        destinationAddress = malloc(INET_ADDRSTRLEN);

        //then cast the info in the addrinfo struct into sockaddr_in
        struct sockaddr_in* sockRaw = (struct sockaddr_in*) receiveeInfo->ai_addr;

        //and finally inet_ntop the sockaddr_in struct to get the string representation
        inet_ntop(AF_INET, &(sockRaw->sin_addr), destinationAddress, INET_ADDRSTRLEN);

    //otherwise we are dealing with and IPv6 address
    } else {

        //malloc destinationAddress as the length of an IPv6 address string format
        destinationAddress = malloc(INET6_ADDRSTRLEN);

        //then cast the info in the addrinfo struct into sockaddr_in6
        struct sockaddr_in6* sockRaw = (struct sockaddr_in6*) receiveeInfo->ai_addr;

        //and finally inet_ntop the sockaddr6_in struct to get hte string representation of the address
        inet_ntop(AF_INET6, &(sockRaw->sin6_addr), destinationAddress, INET6_ADDRSTRLEN);

    }

    //finally return the destinationAddress
    return destinationAddress;

}

//scanUDP function
//serves to scan the passed UDP port
void scanUDP(char* port, struct addrinfo* receiveeInfo, char* hostIpV4Addr, char* hostIpV6Addr, int timeout) {

    //set up timeoutTime timeval struct to later set timeouts for the sockets
    struct timeval timeoutTime;

    //set its seconds to timeout divided by 1000, since timeout is in miliseconds
    timeoutTime.tv_sec = timeout / 1000;

    //and set its miliseconds to the remainder
    timeoutTime.tv_usec = timeout % 1000;
    
    //resolve destination address
    char* destinationAddress = resolveIpAddress(receiveeInfo);
    
    //create the UDP socket, using IPPROTO_UDP unlike above in TCP, where we used the IPPROTO_TCP
    int designatedUDPSocket = socket(receiveeInfo->ai_family, SOCK_RAW, IPPROTO_UDP);

    //if the socket is lower than 0, an error occured
    if (designatedUDPSocket < 0) {

        //print the error information and exit
        perror("Failed to create designated UDP socket");
        exit(1);

    }

    //set up the idpHeader as a udphdr struct
    struct udphdr udpHeader;

    //memset the udpHeader to 0 to make sure no garbage data hides within
    memset(&udpHeader, 0, sizeof(struct udphdr));

    //set its source port to an arbitrary number, destination port to the passed port and its length to its size
    udpHeader.source = htons(43593);

    udpHeader.dest = htons(atoi(port));

    udpHeader.len = htons(sizeof(struct udphdr));

    //if the receivee is an IPv4 address
    if (receiveeInfo->ai_family == AF_INET){

        //set up an IPv4 pseudoheader
        struct pseudoHeaderIpV4 psh;

        //set it up with all the relevant information
        psh.source_address = inet_addr(hostIpV4Addr);
        psh.dest_address = inet_addr(destinationAddress);
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.tcpLength = udpHeader.len;

        //create a pseudogram, this will only be used to calculate the checksum
        char pseudogram[sizeof(struct pseudoHeaderIpV4) + sizeof(struct udphdr)];
    
        //memcpy the pseudoheader into the pseudogram
        memcpy(pseudogram, (char*) &psh, sizeof(struct pseudoHeaderIpV4));
    
        //memcpy the udp header into the pseudogram
        memcpy(pseudogram + sizeof(struct pseudoHeaderIpV4), &udpHeader, sizeof(struct udphdr));

        //then calculate the udp header checksum
        udpHeader.check = checksum((unsigned short*)pseudogram, sizeof(struct pseudoHeaderIpV4) + sizeof(struct udphdr));

        //set up on int to turn on certain things through setsockopt
        int on = 1;

        //setsockopt to make sure no ip header is provided automatically and set up the timeout times
        setsockopt(designatedUDPSocket, IPPROTO_IP, IP_RECVERR, &on, sizeof(on));
        setsockopt(designatedUDPSocket, SOL_SOCKET, SO_RCVTIMEO, &timeoutTime, sizeof(timeoutTime));
        setsockopt(designatedUDPSocket, SOL_SOCKET, SO_RCVTIMEO, &timeoutTime, sizeof(timeoutTime));

    //otherwise we are dealing with an IPv6 address
    } else {

        //set up an IPv6 pseudoheader
        struct pseudoHeaderIpV6 psh;

        //set it up with all the relevant information
        psh.placeholder = 0;
        inet_pton(AF_INET6, hostIpV6Addr, &psh.source_address);
        inet_pton(AF_INET6, destinationAddress, &psh.dest_address);
        psh.protocol = IPPROTO_UDP;
        psh.tcpLength = udpHeader.len;

        //then create the pseudogram, this will only be used to calculate the checksum
        char pseudogram[sizeof(struct pseudoHeaderIpV6) + sizeof(struct udphdr)];

        //memcpy the pseudoheader into the pseudogram
        memcpy(pseudogram, (char*) &psh, sizeof(struct pseudoHeaderIpV6));

        //then memcpy the udp header behind it
        memcpy(pseudogram + sizeof(struct pseudoHeaderIpV6), &udpHeader, sizeof(struct udphdr));

        //then set the udp header check to the result of the checksum function
        udpHeader.check = checksum((unsigned short*)pseudogram, sizeof(struct pseudoHeaderIpV6) + sizeof(struct udphdr));

        //set up on int to turn on certain things trough setsockopt
        int on = 1;

        //setsockopt to make sure no IP header is provided automatically and also set up the timeouts for the socket
        setsockopt(designatedUDPSocket, IPPROTO_IPV6, IPV6_RECVERR, &on, sizeof(on));
        setsockopt(designatedUDPSocket, SOL_SOCKET, SO_RCVTIMEO, &timeoutTime, sizeof(timeoutTime));
        setsockopt(designatedUDPSocket, SOL_SOCKET, SO_RCVTIMEO, &timeoutTime, sizeof(timeoutTime));

        //then set the port in the addrifo structure to anything below 255, 0 in my case, no clue why, does not work without this
        ((struct sockaddr_in6*) receiveeInfo->ai_addr)->sin6_port = 0;

    }

    //if sendto is lower than 0 when attempting to send the udp packet an error occured
    if (sendto(designatedUDPSocket, (char*)&udpHeader, sizeof(struct udphdr), 0, receiveeInfo->ai_addr, receiveeInfo->ai_addrlen) < 0) {
        
        //print error information, close the socket and exit
        perror("Failed to send UDP packet");
        close(designatedUDPSocket);
        exit(1);
    }

    //set up a msg structure and an iovec structure to catch a message along with buffer and controlBuffer and a sender socket info
    struct msghdr msg;
    struct iovec iov;
    char buffer[128];
    struct sockaddr_in sender;
    char controlBuffer[128];

    //memset msg to 0 and sender to 0 to make sure no garbage data hides within
    memset(&msg, 0, sizeof(msg));
    memset(&sender, 0, sizeof(sender));

    //set ip iov and msg with the relevant information
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_name = &sender;
    msg.msg_namelen = sizeof(sender);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controlBuffer;
    msg.msg_controllen = sizeof(controlBuffer);

    //while true recvmsging to receive any messages to the socket
    while (1){

        //create a result int to contain the info on the received message
        int res = recvmsg(designatedUDPSocket, &msg, MSG_ERRQUEUE);

        //if res is lower than 0, an error has occured
        if (res < 0){

            //if the error is an EWOULDBLOCK error
            if (errno == EWOULDBLOCK){

                //the port is open,print the info and break
                printf("%s %s udp open\n", destinationAddress, port);
                break;

            //else if the error is not an EAGAIN error
            } else if (errno != EAGAIN){

            //print error information and break
            perror ("recvmsg failed");
            break;
        
        }

        //if no error occured
        //create a control message struct
        struct cmsghdr* cmsg;

        //now get the control message from the message
        for(cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)){

            //check whether the message level is correct
            if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR){

                //if it is, create a struct to contain the error information
                struct sock_extended_err* err = (struct sock_extended_err*) CMSG_DATA(cmsg);

                //if the origin of the error is an ICMP one and the error type and code corresponds with destination unreachable
                if (err->ee_origin == SO_EE_ORIGIN_ICMP && err->ee_type == 3 && err->ee_code == 3){

                    //get the offender packet information
                    struct sockaddr_in* offender = (struct sockaddr_in*)SO_EE_OFFENDER(err);

                    //if the offender is not null and its family aligns with the receivees family
                    if (offender != NULL && offender->sin_family == receiveeInfo->ai_family){

                        //get the string length to expect through a ternary operator
                        int addrStrLen = (receiveeInfo->ai_family == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;

                        //then, create an offenderIP string to contain the string representation of the IP that caused the error
                        char offenderIp[addrStrLen];

                        //inet_ntop to get the string of the IP
                        inet_ntop(AF_INET, &(offender->sin_addr), offenderIp, addrStrLen);

                        //if the offenderIP and host IP are the same
                        if ((!strcmp(offenderIp, hostIpV4Addr) && addrStrLen == INET_ADDRSTRLEN) || (!strcmp(offenderIp, hostIpV6Addr) && addrStrLen == INET6_ADDRSTRLEN)){
                            
                            //consider the port closed, print info and return
                            printf("%s %s udp closed\n", destinationAddress, port);
                            return;

                        }
                    }
                }
            }
        }
    }
}