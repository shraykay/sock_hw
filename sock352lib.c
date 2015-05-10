#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <inttypes.h>
#include <stdbool.h>
#include "uthash.h"
#include "utlist.h"
#include "sock352.h"
#include "sock352lib.h"

link * myConnection = NULL;
void init();
void printPacketInfo(sock352_pkt_hdr_t);
void setAck(ack, uint64_t);
sock352_pkt_hdr_t switchAckSeq(sock352_pkt_hdr_t);
sock352_pkt_hdr_t createPacket(int, uint64_t, uint8_t);
int getSeq();

/* global initialization function */
void init() {
	myConnection = (link *) malloc (sizeof(link));
	memset(myConnection, 0, sizeof(link));
	myConnection->sequence = 0;
	myConnection->ackReceived = 0;
	myConnection->ackSent = 0;
	return;
}

/* this function allows me to set the ack packets globally */
void setAck(ack type, uint64_t position) {
	if (type == ackReceived) {
		if (position > myConnection->ackReceived) myConnection->ackReceived = position;
	}
	else if (type == ackSent) {
		if (position > myConnection->ackSent) myConnection->ackSent = position;
	}
	return;
}

/* this function prints out the packets info as a debug tool for myself */
void printPacketInfo(sock352_pkt_hdr_t packet) {
	printf("Packet Sequence Number: %" PRIu64 "\n", packet.sequence_no);
	printf("Packet Ack Number: %" PRIu64 "\n", packet.ack_no);
	
	/* print the packet's flags in this switch case */
	switch(packet.flags) {
		case (SOCK352_SYN | SOCK352_ACK):
		printf("Packet Flags: SYN/ACK\n");
		break;
		case SOCK352_SYN:
		printf("Packet Flags: SYN\n");
		break;
		case SOCK352_ACK:
		printf("Packet Flags: ACK\n");
		break;
		case SOCK352_FIN:
		printf("Packet Flags: FIN\n");
		break;
		default:
		printf("Packet Flags: None\n");
		break;
	}	
	return;
}

sock352_pkt_hdr_t switchAckSeq(sock352_pkt_hdr_t packet) {
	/* when a packet has been acknowledged and the next one must go out,
	   increment the ack_no by assigning the sequence_no to it, and
	   increment the sequence_no
	*/
	packet.ack_no = packet.sequence_no;
	packet.sequence_no = getSeq();
	return packet;
}

sock352_pkt_hdr_t createPacket(int sequence_no, uint64_t ack_no, uint8_t flag) {
	/* create a packet and plugin the sequence_no and the flag */
	sock352_pkt_hdr_t newPacket;
	newPacket.source_port = 0;
    newPacket.dest_port = 0;
    newPacket.sequence_no = sequence_no;
	newPacket.ack_no = ack_no;
    newPacket.flags = flag;
    newPacket.version = SOCK352_VER_1;
    newPacket.header_len = sizeof(sock352_pkt_hdr_t);
    newPacket.opt_ptr = 0;
    newPacket.protocol = 0;
	newPacket.window = MAX_BUFFER;
	return newPacket;	
}

/* This is a sequence number incrementor */
int getSeq() {
    return myConnection->sequence++;
}

/* this is the initial init function if there is only a single port listed */
int sock352_init(int port) {
	init();
	
	/* here, I attempt to sanitize the input and decide where to plugin the ports */
	if (port < 0) return SOCK352_FAILURE;
	
	if (port == 0) {
		myConnection->myPort = SOCK352_DEFAULT_UDP_PORT;
		myConnection->yourPort = SOCK352_DEFAULT_UDP_PORT;
	}
	else if (port > 0) {
		myConnection->myPort = port;
		myConnection->yourPort = port;
	}
	
	printf("My Port: %d\n", myConnection->myPort);
    printf("Server Port: %d\n", myConnection->yourPort);
	printf("sock352_init: success\n");

	return SOCK352_SUCCESS;
}

/* if there is more than one port, and it is not the crypto version, use this */
int sock352_init2(int remote_port, int local_port) {
	init();
	
	/* here, I attempt to sanitize the input and decide where to plugin the ports */
	if (remote_port < 0 || local_port < 0) {
		return SOCK352_FAILURE;
	}
	
	if (remote_port == 0) {
		myConnection->yourPort = SOCK352_DEFAULT_UDP_PORT;
	}
	else {
		myConnection->yourPort = remote_port;
	}
	
	if (local_port == 0) {
		myConnection->myPort = SOCK352_DEFAULT_UDP_PORT;
	}
	else {
		myConnection->myPort = local_port;
	}
	
	printf("My Port: %d\n", myConnection->myPort);
    printf("Server Port: %d\n", myConnection->yourPort);
	printf("sock352_init2: success\n");
	
	return SOCK352_SUCCESS;
}

int sock352_init3(int remote_port, int local_port, char *envp[] ) {
	/* I have no idea how the 3rd argument in this function works */
	
	/* call global initializing function */
	init(); 
	
	/* here, I attempt to sanitize the input and decide where to plugin the ports */
	if (remote_port < 0 || local_port < 0) {
		return SOCK352_FAILURE;
	}
	
	if (remote_port == 0) {
		myConnection->yourPort = SOCK352_DEFAULT_UDP_PORT;
	}
	else {
		myConnection->yourPort = remote_port;
	}
	
	if (local_port == 0) {
		myConnection->myPort = SOCK352_DEFAULT_UDP_PORT;
	}
	else {
		myConnection->myPort = local_port;
	}
	
	printf("My Port: %d\n", myConnection->myPort);
    printf("Server Port: %d\n", myConnection->yourPort);
	printf("sock352_init3: success\n");
	
	return SOCK352_SUCCESS;
}

int sock352_socket(int domain, int type, int protocol) {
	/* check if the information is correct */
	if(domain != AF_CS352 && type != SOCK_STREAM) {
		printf("sock352_socket: failure\n");
		return SOCK352_FAILURE;
	}
	
	/* create a socket and store its value */
	int reply = socket(AF_INET, SOCK_DGRAM, 0);
	myConnection->myFD = reply;
	
	printf("sock352_socket: fd=%d\n",myConnection->myFD);
	printf("sock352_socket: success\n");
	
	return reply;
}

int sock352_bind (int fd, struct sockaddr_sock352 *addr, socklen_t len){
	/* store the socklength and fd to a global variable */
	myConnection->socklength = len;
	myConnection->myFDbind = fd;
	
	/* create a sockaddr_in of my address */
	struct sockaddr_in myAddr;
	memset((char *) &myAddr, 0, sizeof(myAddr));
	myAddr.sin_family = AF_INET;
	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myAddr.sin_port = htons(myConnection->myPort);
	
	printf("sock352_bind: success, bind port is %d\n",ntohs(myAddr.sin_port));
	
	if(bind(fd, (struct sockaddr *) &myAddr, len) < 0) {
		printf("sock352_bind: failure to bind\n");
		return SOCK352_FAILURE;
	}

	return SOCK352_SUCCESS;
}

int sock352_listen (int fd, int n){
	/* just do this in accept, because it's easier */
	return SOCK352_SUCCESS;
}

int sock352_accept (int fd, sockaddr_sock352_t *addr, int *len) {	
	/* create two packets for receiving and sending */
	sock352_pkt_hdr_t recvMsg, sentMsg;
	
	/* create the struct to receive the outside client's address */
	struct sockaddr_in yourAddr;
	yourAddr.sin_family = AF_INET;
	yourAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	yourAddr.sin_port = htons(myConnection->myPort);
	
	/* receive a SYN packet */
	if(recvfrom(fd, &recvMsg, sizeof(recvMsg), 0, (struct sockaddr *) &yourAddr, &myConnection->socklength) < 0){
		printf("sock352_accept: failed to get SYN\n");
		return SOCK352_FAILURE;
	}
	/* check its flag */	
	if(recvMsg.flags != SOCK352_SYN) {
		printf("socket352_accept: packet is not a SYN\n");
		return SOCK352_FAILURE;
	}
	
	setAck(ackReceived, recvMsg.ack_no);
	printf("sock352_accept: received initial SYN\n");
	printPacketInfo(recvMsg);
	
	/* store the address for later use by the server in read/write */
	myConnection->yourAddress = yourAddr;
	
	/* createPacket(int sequence_no, int ack_no, uint8_t flag) */
	sentMsg = createPacket(getSeq(), (recvMsg.sequence_no + 1), (SOCK352_SYN | SOCK352_ACK)); 
	
	/* send the SYN/ACK */
	if(sendto(fd, &sentMsg, sizeof(sentMsg), 0, (struct sockaddr *) &yourAddr, sizeof(yourAddr)) < 0) {
		printf("sock352_accept: sendto of SYN/ACK failed\n");
		return SOCK352_FAILURE;
	}
	
	setAck(ackSent, recvMsg.sequence_no + 1);
	printf("sock352_accept: sent SYN/ACK\n");
	printPacketInfo(sentMsg);
	
	/* receive the ACK */
	if(recvfrom(fd, &sentMsg, sizeof(sentMsg), 0, (struct sockaddr *) &yourAddr, &myConnection->socklength) < 0) {
		printf("sock352_accept: failed to get final ACK\n");
		return SOCK352_FAILURE;
	}
	
	/* check its flag for ACK */
	if(sentMsg.flags == SOCK352_ACK) {
		printf("sock352_accept: received final ACK\n");
	}
	
	/* print the packet's info */
	printPacketInfo(sentMsg);
	setAck(ackReceived, sentMsg.ack_no);
	
	return fd;
}

int sock352_connect(int fd, sockaddr_sock352_t *addr, socklen_t len) {
	/* create struct for storing the server (not client's) address. */
	struct sockaddr_in yourAddy;
	yourAddy.sin_family = AF_INET;
	yourAddy.sin_addr.s_addr = addr->sin_addr.s_addr;
	yourAddy.sin_port = htons(myConnection->yourPort);
	
	/* store server address for use later in read/write */
	myConnection->yourAddress = yourAddy;
	myConnection->socklength = len;
	
    /* create the packets we plan to use for the SYN/ACK */
    sock352_pkt_hdr_t sentMsg, receivedMsg;

    /* filling this packet out as per project specifications */
	sentMsg = createPacket(getSeq(), myConnection->ackSent, SOCK352_SYN); 

	/* Send the SYN */
	if(sendto(fd, &sentMsg, sizeof(sentMsg), 0, (struct sockaddr *) &yourAddy, len) < 0) {
		printf("sock352_connect: failed to send initial SYN\n");
		return SOCK352_FAILURE;
	}
	
	printf("sock352_connect: sent the initial SYN\n");
	printPacketInfo(sentMsg);
		
	/* receive the SYN/ACK */
	if(recvfrom(fd, &receivedMsg, sizeof(receivedMsg), 0, (struct sockaddr *) &yourAddy, &myConnection->socklength) < 0) {
		printf("sock352_connect: failed to receive SYN/ACK\n");
		return SOCK352_FAILURE;
	}
	
	/* check the flags */
	if(receivedMsg.flags == (SOCK352_SYN | SOCK352_ACK) && (receivedMsg.ack_no == sentMsg.sequence_no + 1)) {
		printf("sock352_connect: received SYN/ACK\n");
	}
	else {
		printf("sock352_connect: failed to receive SYN/ACK\n");
		return SOCK352_FAILURE;
	}
	
	setAck(ackReceived, receivedMsg.ack_no);
	printPacketInfo(receivedMsg);
	
	/* The final message sends an ACK back to server */
	sentMsg.flags = SOCK352_ACK;
	sentMsg.sequence_no = getSeq();
	sentMsg.ack_no = receivedMsg.sequence_no + 1;
	
	if(sendto(fd, &sentMsg, sizeof(sentMsg), 0, (struct sockaddr *) &yourAddy, len) < 0) {
		printf("sock352_connect: failed to send final ACK\n");
		return SOCK352_FAILURE;
	}
	
	setAck(ackSent, receivedMsg.sequence_no + 1);
	printf("sock352_connect: sent final ACK\n");
	printPacketInfo(sentMsg);
	
	return SOCK352_SUCCESS;
}

extern int sock352_close(int fd) {
	/* this was my attempt to close by sending the FIN/ACK/ACK bit I was not sure if it worked */

	/*
	pkt closePacket, receiveClosePacket;
	closePacket.Msg = createPacket(getSeq(), (myConnection->ackSent), SOCK352_FIN);

	if(sendto(fd, &closePacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, myConnection->socklength) < 0) {
		printf("sock352_close: failed to send packet 1\n");
		return SOCK352_FAILURE;
	}
	printPacketInfo(closePacket.Msg);
	
	if(recvfrom(fd, &receiveClosePacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, &myConnection->socklength) < 0) {
		printf("sock352_close: failed to get final ACK\n");
		return SOCK352_FAILURE;
	}
	
	closePacket.Msg = createPacket(getSeq(), (myConnection->ackSent), SOCK352_ACK);
	
	if(sendto(fd, &closePacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, myConnection->socklength) < 0) {
		printf("sock352_close: failed to send packet 2\n");
		return SOCK352_FAILURE;
	}
	printPacketInfo(closePacket.Msg);
	
	if(recvfrom(fd, &receiveClosePacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, &myConnection->socklength) < 0) {
		printf("sock352_close: failed to get final ACK\n");
		return SOCK352_FAILURE;
	}
	free(myConnection);
	
	*/

	close(fd);
	return SOCK352_SUCCESS;
}

int sock352_read(int fd, void *buf, int count) {
	/* setup packet to read what is received, and to send an ACK */
	pkt receivePacket, sendPacket;

	/* receive the packet and store to receivePacket */	
	if(recvfrom(fd, &receivePacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, &myConnection->socklength) < 0) {
		printf("sock352_read: failed to receive packet\n");
		return SOCK352_FAILURE;
	}

	printPacketInfo(receivePacket.Msg);
	
	/* copy the packet's information over to buffer */
	memcpy(buf, receivePacket.info, receivePacket.Msg.payload_len);
	sendPacket.Msg = createPacket(getSeq(), (receivePacket.Msg.sequence_no + 1), SOCK352_ACK);
	
	/* send an ACK packet after you increment the appropriate information */
	if(sendto(fd, &sendPacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, myConnection->socklength) < 0) {
		printf("sock352_read: failed to send packet\n");
		return SOCK352_FAILURE;
	}
	
	setAck(ackSent, sendPacket.Msg.sequence_no + 1);
	setAck(ackReceived, receivePacket.Msg.sequence_no);
	
	/* return the bytes received in the payload */
	int bytes = receivePacket.Msg.payload_len; 
	return bytes;
}

int sock352_write(int fd, void *buf, int count){
	/* initialize two packets for sending and receiving */
	pkt receivePacket, sendPacket;
	
	/* setup packet with payload and without a flag */
	sendPacket.Msg = createPacket(getSeq(), (myConnection->ackSent), 0);
	sendPacket.Msg.payload_len = count;
	
	/* copy the information from buf over to the pkt */
	memcpy(sendPacket.info, buf, count);
	bool sent = false;
	
	/* loop through and attempt to send the packet and get an ack in return */
	while(sent == false) {
		if(sendto(fd, &sendPacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, myConnection->socklength) < 0) {
			printf("sock352_write: failed to send packet\n");
			return SOCK352_FAILURE;	
		}
		printPacketInfo(sendPacket.Msg);
		
		if(recvfrom(fd, &receivePacket, sizeof(pkt), 0, (struct sockaddr *) &myConnection->yourAddress, &myConnection->socklength) < 0) {
			printf("sock352_write: failed to receive ACK\n");
			return SOCK352_FAILURE;
		}
		
		if((receivePacket.Msg.ack_no != sendPacket.Msg.sequence_no + 1) || (receivePacket.Msg.flags != SOCK352_ACK)) {
			printf("sock352_write: failed to receive proper packet\n");
			return SOCK352_FAILURE;
		}
		else {
			sent = true;
			printPacketInfo(receivePacket.Msg);
			setAck(ackSent, sendPacket.Msg.sequence_no + 1);
			setAck(ackReceived, receivePacket.Msg.sequence_no);
		}
	}
	printf("sock352_write: success\n");
	return count;
}

