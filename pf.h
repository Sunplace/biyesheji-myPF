/*
 * to do
 */

#ifndef _PF_H_
#define _PF_H_

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<asm/byteorder.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
//#include<sys/prtcl.h>
#include<sys/socket.h>
#include<linux/netfilter.h>
#include<libnetfilter_queue/libnetfilter_queue.h>
#include<signal.h>


#include"parse.h"
#include"myerr.h"
#include"syscall_wrappers.h"

#define MAX_LINE_LEN 256
#define PROG_VERSION "pf 0.0.1"

enum TARGET {
    DROP,
    ACCEPT
};

enum Proto {
    TCP,
    UDP
};


typedef struct out_rule_node{
    u_int16_t lport;        //local port
    u_int32_t raddr;    //remote address
    u_int16_t rport;        //remote port
    int proto;              //protocol
    enum TARGET target;          //packet target
    struct out_rule_node * next;    //next rule node
}out_nd, * out_rules_link;



void rules_file_load(void);

void print_help_info(struct parameter_tags param []);

bool isrunning(void);

void init_iptables(void);

void init_nfqueue(void);

static int cb (struct nfq_q_handle * qh, struct nfgenmsg * nfmsg , struct nfq_data * nfa, void * data);

void set_rpc_server(void);

void out_rule_insert(u_int16_t lport, u_int32_t raddr, u_int16_t rport, int proto, enum TARGET targ);

void parse_rules(char line[], u_int16_t * lport_n_p, u_int32_t * raddr_p, u_int16_t * rport_n_p, int * proto_p, enum TARGET * targ_p);

enum TARGET execute_verdict(u_int16_t lport, u_int32_t raddr, u_int16_t rport, int proto);

static void sig_init_exit(int signo);

static void clean_rules_link(void);

void out_rules_list(int fd);

void do_it (int connfd);

void send_cmd_to_serv(char *);

int rule_del(int );

#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]
#endif



#endif
