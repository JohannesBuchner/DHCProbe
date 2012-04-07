//
// $Id: dhcping.c,v 1.3 2002/01/27 01:57:15 mavetju Exp $
//

/*
 * Copyright 2000, 2001, 2002 by Edwin Groothuis, edwin@mavetju.org
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "dhcp_options.h"

#define BUF_SIZ 256*256

int offset=0;
void addpacket(char *pktbuf,char *msgbuf,int size) {
    memcpy(pktbuf+offset,msgbuf,size);
    offset+=size;
}

void dhcp_setup(char *);
int  dhcp_read(void);
void dhcp_close(void);
void dhcp_dump(unsigned char *buffer,int size);
void dhcp_inform(char *ipaddr,char *gwaddr,char *hardware);
void dhcp_request(char *ipaddr,char *gwaddr,char *hardware);
void dhcp_release(char *ipaddr,char *gwaddr,char *hardware);
void dhcp_packet(int type,char *ciaddr,char *opt50,char *gwaddr,char *hardware);

int dhcp_socket;
struct sockaddr_in dhcp_to;

int _serveripaddress;

int inform,request,verbose,quiet;
char *ci,*gi,*server,*hw;
unsigned char serveridentifier[4];
int maxwait=3;

void doargs(int argc,char **argv) {
    char ch;

    inform=request=verbose=quiet=0;
    ci=gi=server="0.0.0.0";
    hw="00:00:00:00:00:00";

    if (argc==1) {
	printf("dhcping -c ciaddr -g giaddr -h chaddr -r -s server -t maxwait -i -v -q\n");
	exit(1);
    }

    while ((ch = getopt(argc,argv,"c:g:h:iqrs:t:vV"))>0) {
	switch (ch) {
	case 'c': ci=optarg;break;
	case 'g': gi=optarg;break;
	case 'h': hw=optarg;break;
	case 'i': inform=1;break;
	case 'q': quiet=1;break;
	case 'r': request=1;break;
	case 's': server=optarg;break;
	case 't': maxwait=atoi(optarg);break;
	case 'v': verbose++;break;
	}
    }

    if (request && inform) {
	fprintf(stderr,"Error: -r and -i are mutally exclusive.\n");
	exit(1);
    }

    // DHCPREQUEST is by default.
    if (!inform) request=1;
}

int main(int argc,char **argv) {
    fd_set read;
    struct timeval timeout;
    int foundpacket=0;
    int returnvalue=0;

    if (geteuid()!=0) {
	printf("This program should only be ran by root or be installed as setuid root.\n");
	// exit(1);
    }

    doargs(argc,argv);

    if (verbose) puts("setup");
    dhcp_setup(server);

    if (setuid(getuid())!=0) {
	perror("setuid");
	printf("Can't drop privileges back to normal user, program aborted.\n");
	exit(1);
    }

    if (inform) {
	if (verbose) puts("inform");
	dhcp_inform(ci,gi,hw);
    }
    if (request) {
	if (verbose) puts("request");
	dhcp_request(ci,gi,hw);
    }

    while (!foundpacket) {
	FD_ZERO(&read);
	FD_SET(dhcp_socket,&read);
	timeout.tv_sec=maxwait;
	timeout.tv_usec=0;
	if(select(dhcp_socket+1,&read,NULL,NULL,&timeout)<0) {
	    perror("select");
	    exit(0);
	}
	if (FD_ISSET(dhcp_socket,&read)) {
	    if (verbose) puts("read");
	    /* If a expected packet was found, then also release it. */
	    if ((foundpacket=dhcp_read())!=0) {
		if (request) {
		    if (verbose) puts("release");
		    dhcp_release(ci,gi,hw);
		}
	    }
	} else {
	    if (!quiet)
		fprintf(stderr,"no answer\n");
	    returnvalue=1;
	    foundpacket=1;
	}
    }
    if (verbose) puts("close");
    dhcp_close();
    return returnvalue;
}


void dhcp_setup(char *serveripaddress) {
    struct servent *servent,*clientent;
    struct hostent *hostent;
    int flag;
    struct sockaddr_in name;

    /*
    // setup sending socket
    */
    if ((servent=getservbyname("bootps",0))==NULL) {
	perror("getservbyname: bootps");
	exit(1);
    }
    if ((hostent=gethostbyname(serveripaddress))==NULL) {
	perror("gethostbyname");
	exit(1);
    }

    dhcp_to.sin_family=AF_INET;
    bcopy(hostent->h_addr,&dhcp_to.sin_addr.s_addr,hostent->h_length);
    _serveripaddress=ntohl(dhcp_to.sin_addr.s_addr);
/*  dhcp_to.sin_addr.s_addr=INADDR_BROADCAST; */
    dhcp_to.sin_port=servent->s_port;

    if ((dhcp_socket=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))==-1) {
	perror("dhcp_socket/socket");
	exit(1);
    }

    flag=1;
    if (setsockopt (dhcp_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof flag) < 0) {
	perror("dhcp_socket/setsockopt: SO_REUSEADDR");
	exit(1);
    }

    if (setsockopt(dhcp_socket,SOL_SOCKET,SO_BROADCAST,(char *)&flag, sizeof flag) < 0) {
	perror ("dhcp_socket/setsockopt: SO_BROADCAST");
	exit(1);
    }

    if ((clientent=getservbyname("bootpc",0))==NULL) {
	perror("getservbyname: bootpc");
	exit(1);
    }
    name.sin_family = AF_INET;
    name.sin_port = clientent->s_port;
    name.sin_addr.s_addr = INADDR_ANY;
/*  name.sin_addr.s_addr = INADDR_NONE; */
    memset (name.sin_zero, 0, sizeof (name.sin_zero));

    if (bind (dhcp_socket, (struct sockaddr *)&name, sizeof name) < 0) {
	perror("bind");
	exit(1);
    }
}

void dhcp_request(char *ipaddr,char *gwaddr,char *hardware) {
    dhcp_packet(3,ipaddr,ipaddr,gwaddr,hardware);
}
void dhcp_release(char *ipaddr,char *gwaddr,char *hardware) {
    dhcp_packet(7,ipaddr,NULL,gwaddr,hardware);
}
void dhcp_inform(char *ipaddr,char *gwaddr,char *hardware) {
    dhcp_packet(8,ipaddr,NULL,gwaddr,hardware);
}


void dhcp_packet(int type,char *ipaddr,char *opt50,char *gwaddr,char *hardware) {
    static time_t l=0;
    unsigned char msgbuf[BUF_SIZ];
    unsigned char pktbuf[BUF_SIZ];
    int ip[4],gw[4],hw[16],ip50[4];
    int hwcount;

    sscanf(ipaddr,"%d.%d.%d.%d",&ip[0],&ip[1],&ip[2],&ip[3]);
    sscanf(gwaddr,"%d.%d.%d.%d",&gw[0],&gw[1],&gw[2],&gw[3]);
    if (opt50)
	sscanf(opt50,"%d.%d.%d.%d",&ip50[0],&ip50[1],&ip50[2],&ip50[3]);
    memset(&hw,0,sizeof(hw));
    hwcount=sscanf(hardware,"%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
	&hw[0],&hw[1],&hw[2],&hw[3],
	&hw[4],&hw[5],&hw[6],&hw[7],
	&hw[8],&hw[9],&hw[10],&hw[11],
	&hw[12],&hw[13],&hw[14],&hw[15]);

    memset(msgbuf,0,sizeof(msgbuf));
    sprintf(msgbuf,"\1\1%c%c",hwcount,0);
    addpacket(pktbuf,msgbuf,4);

    /* xid */
    if (l>time(NULL))
	l++;
    else
	l=time(NULL);
    memcpy(msgbuf,&l,4);
    addpacket(pktbuf,msgbuf,4);

    /* secs and flags */
    memset(msgbuf,0,4);
    addpacket(pktbuf,msgbuf,4);
/*  sprintf(msgbuf,"%c%c",0x80,0x00); */
/*  sprintf(msgbuf,"%c%c",0x00,0x00); */
/*  addpacket(pktbuf,msgbuf,2); */

    /* ciaddr */
    memset(msgbuf,0,4);
    sprintf(msgbuf,"%c%c%c%c",ip[0],ip[1],ip[2],ip[3]);
    addpacket(pktbuf,msgbuf,4);

    /* yiaddr */
    memset(msgbuf,0,4);
    addpacket(pktbuf,msgbuf,4);

    /* siaddr */
    memset(msgbuf,0,4);
    addpacket(pktbuf,msgbuf,4);

    /* giaddr */
    sprintf(msgbuf,"%c%c%c%c",gw[0],gw[1],gw[2],gw[3]);
    addpacket(pktbuf,msgbuf,4);

    /* chaddr */
    sprintf(msgbuf,"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
	hw[0],hw[1],hw[2],hw[3],hw[4],hw[5],hw[6],hw[7],
	hw[8],hw[9],hw[10],hw[11],hw[12],hw[13],hw[14],hw[15]);
    addpacket(pktbuf,msgbuf,16);

    /* sname */
    memset(msgbuf,0,64);
    addpacket(pktbuf,msgbuf,64);

    /* file */
    memset(msgbuf,0,128);
    addpacket(pktbuf,msgbuf,128);

    /* options */
    {
	/* cookie */
	sprintf(msgbuf,"%c%c%c%c",99,130,83,99);
	addpacket(pktbuf,msgbuf,4);

	/* dhcp-type */
	sprintf(msgbuf,"%c%c%c",53,1,type);
	addpacket(pktbuf,msgbuf,3);

	/* Not for inform */
	if (type!=8) {
	    /* requested IP address */
	    if (opt50) {
		sprintf(msgbuf,"%c%c%c%c%c%c",50,4,ip50[0],ip50[1],ip50[2],ip50[3]);
		addpacket(pktbuf,msgbuf,6);
	    }

	    /* server-identifier */
	    if (serveridentifier[0]) {
		sprintf(msgbuf,"%c%c%c%c%c%c",54,4,
		    serveridentifier[0],serveridentifier[1],
		    serveridentifier[2],serveridentifier[3]);
		addpacket(pktbuf,msgbuf,6);
	    }
	}

	/* client-identifier */
//	sprintf(msgbuf,"%c%c%c%c%c%c%c%c",61,6,
//		hw[0],hw[1],hw[2],hw[3],hw[4],hw[5]);
//	addpacket(pktbuf,msgbuf,8);

	/* parameter request list */
	if (type==8) {
	    sprintf(msgbuf,"%c%c%c",55,1,1);
	    addpacket(pktbuf,msgbuf,3);
	}

	/* end of options */
	sprintf(msgbuf,"%c",255);
	addpacket(pktbuf,msgbuf,1);
    }

    // dhcp_dump(pktbuf,offset);

    sendto(dhcp_socket,pktbuf,offset,0,(struct sockaddr *)&dhcp_to,sizeof(dhcp_to));

    offset=0;
}


int dhcp_read(void) {
    unsigned char msgbuf[BUF_SIZ];
    struct sockaddr_in fromsock;
    socklen_t fromlen=sizeof(fromsock);
    int addr;
    int i;

    i=recvfrom(dhcp_socket,msgbuf,BUF_SIZ,0,(struct sockaddr *)&fromsock,&fromlen);
    addr=ntohl(fromsock.sin_addr.s_addr);

    if (!quiet) {
	printf( "Got answer from: %d.%d.%d.%d\n",
	    ( addr >> 24 ) & 0xFF, ( addr >> 16 ) & 0xFF,
	    ( addr >>  8 ) & 0xFF, ( addr       ) & 0xFF
	    );
    }

    if (_serveripaddress!=addr) {
	if (!quiet)
	    fprintf(stderr,"received from %d.%d.%d.%d, expected from %d.%d.%d.%d\n",
		( addr >> 24 ) & 0xFF, ( addr >> 16 ) & 0xFF,
		( addr >>  8 ) & 0xFF, ( addr       ) & 0xFF,
		( _serveripaddress >> 24 )&0xFF,(_serveripaddress >> 16 )&0xFF,
		( _serveripaddress >>  8 )&0xFF,(_serveripaddress       )&0xFF
	    );
	return 0;

    }


    dhcp_dump(msgbuf,i);
    return 1;
}

void printip(unsigned char * buffer) {
	printf("%d.%d.%d.%d", buffer[0],buffer[1],buffer[2],buffer[3]);
}

void dhcp_dump(unsigned char *buffer,int size) {
    int j;

    if (verbose == 0)
    return;

    //
    // Are you sure you want to see this? Try dhcpdump, which is better
    // suited for this kind of work... See http://www.mavetju.org
    //
    if (verbose > 1) {
	printf("packet %d bytes\n",size);
	    for (j = 0; j < size; j++) {
		printf("%02x ",buffer[j]);
		if (j%16==15) printf(" (%2d)\n", j / 16);
	    }
	    printf("\n");
	    for (j = 0; j < size; j++) {
		if (isprint(buffer[j]))
			printf("%c ",buffer[j]);
		else 
			printf("  ",buffer[j]);
		if (j%16==15) printf(" (%2d)\n", j / 16);
	    }
	    printf("\n");

	    printf("op: %d\n",buffer[0]);
	    printf("htype: %d\n",buffer[1]);
	    printf("hlen: %d\n",buffer[2]);
		printf("hops: %d\n",buffer[3]);

	    printf("xid: %02x%02x%02x%02x\n",
		    buffer[4],buffer[5],buffer[6],buffer[7]);
	    printf("secs: %d\n",255*buffer[8]+buffer[9]);
	    printf("flags: %x\n",255*buffer[10]+buffer[11]);

	    printf("ciaddr: %d.%d.%d.%d\n",
		    buffer[12],buffer[13],buffer[14],buffer[15]);
	    printf("yiaddr: %d.%d.%d.%d\n",
		    buffer[16],buffer[17],buffer[18],buffer[19]);
	    printf("siaddr: %d.%d.%d.%d\n",
		    buffer[20],buffer[21],buffer[22],buffer[23]);
	    printf("giaddr: %d.%d.%d.%d\n",
		    buffer[24],buffer[25],buffer[26],buffer[27]);
	    printf("chaddr: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		    buffer[28],buffer[29],buffer[30],buffer[31],
		    buffer[32],buffer[33],buffer[34],buffer[35],
		    buffer[36],buffer[37],buffer[38],buffer[39],
		    buffer[40],buffer[41],buffer[42],buffer[43]);
	    printf("sname : %s.\n",buffer+44);
	    printf("fname : %s.\n",buffer+108);
    }

    j=236;
    j+=4;	/* cookie */
    while (j<size && buffer[j]!=255) {
	printf("option %d %s ",buffer[j],dhcp_options[buffer[j]]);

	switch (buffer[j]) {
	case 54:
	    memcpy(serveridentifier,buffer+j+2,4);
	case 1:
	case 3:
	case 6:
	case 50:
	case 42:
	case 28:
	case 44:
	case 4:
	    printip(&buffer[j+2]);
	    break;

	case 53:
	    printf("%d (%s)",
		buffer[j+2],dhcp_message_types[buffer[j+2]]);
	    break;
	case 61:
	    printf("%02x%02x%02x%02x%02x%02x",
		buffer[j+2],buffer[j+3],buffer[j+4],
		buffer[j+5],buffer[j+6],buffer[j+7]);
	    break;
	case 15:
	    printf("%s", &buffer[j+2]);
	    break;
	}
	printf("\n");

	/*
	// This might go wrong if a mallformed packet is received.
	// Maybe from a bogus server which is instructed to reply
	// with invalid data and thus causing an exploit.
	// My head hurts... but I think it's solved by the checking
	// for j<size at the begin of the while-loop.
	*/
	j+=buffer[j+1]+2;
    }
}


void dhcp_close(void) {
    close(dhcp_socket);
}

