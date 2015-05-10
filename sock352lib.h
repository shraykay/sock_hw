
#ifndef SOCK352LIB_H_
#define SOCK352LIB_H_

#include <sys/types.h>
#include <pthread.h>
#include <endian.h>
#include "sock352.h"
#include "uthash.h"
#define MAX_BUFFER 60000

typedef struct link {
        struct sockaddr_in myAddress;
        struct sockaddr_in yourAddress;
        socklen_t socklength;
        socklen_t socklength_cli;
        int myPort;
        int yourPort;
		int myFD;
        int myFDbind;
        int myFDconnect;
        int sequence;
        uint64_t ackSent;
        uint64_t ackReceived;
} link;

typedef struct pkt {
        sock352_pkt_hdr_t Msg;
        char info[MAX_BUFFER];
        int size;
} pkt;

typedef enum ack {
    ackReceived,
    ackSent
} ack;

#endif /* SOCK352LIB_H_ */

/*
 * Client Order is:
 * init -> socket -> connect -> write -> close
 * Server Order is:
 * init -> socket -> bind -> listen -> accept -> read -> close
 */

