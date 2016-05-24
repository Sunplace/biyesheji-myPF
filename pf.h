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
#include<linux/ip.h>
#include<linux/netfilter.h>
#include<libnetfilter_queue/libnetfilter_queue.h>


#include"parse.h"
#include"myerr.h"
#include"syscall_wrappers.h"

#define MAX_LINE 80
#define PROG_VERSION "pf 0.0.1"

void rules_file_load(void);

void print_help_info(struct parameter_tags param []);

bool isrunning(void);

void init_iptables(void);

void init_nfqueue(void);

static int cb (struct nfq_q_handle * qh, struct nfgenmsg * nfmsg , struct nfq_data * nfa, void * data);

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
