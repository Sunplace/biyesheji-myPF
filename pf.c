/*
 * to do
 */

#include"pf.h"

out_rules_link head = NULL;         //out rule link head
struct nfq_handle * h;
pthread_mutex_t out_rules_lock = PTHREAD_MUTEX_INITIALIZER;


int main(int argc,  char *argv[]){

    bool isshowversion = false;
    bool isshowhelp = false;
    bool isdaemon = false;
    bool islist = false;

    char sec_parse[MAX_LINE_LEN] = {0};       //require the second parse
    
    struct parameter_tags param [] = {
        { "--version",  (char *)&isshowversion,  "--verion\t\tshow the verion of pf",   9,    sizeof(isshowversion),  _NULL_},
        { "--help",     (char *)&isshowhelp,    "--help\t\t\tshow the help document",     6,     sizeof(isshowhelp),      _NULL_},
        { "-a",         (char *)sec_parse,      "-a\t\t\tadd rule to the pf",             2,     sizeof(sec_parse),      STRING},
        { "-d",         (char *)sec_parse,      "-d\t\t\tdelet rule from the pf",         2,     sizeof(sec_parse),      STRING},
        { "-D",         (char *)&isdaemon,      "-D\t\t\trun the pf",                     2,      sizeof(isdaemon),       _NULL_},
        { "--list",     (char *)&islist,        "--list\t\t\tlist the exsit rules",         6,  sizeof(islist),         _NULL_},
        {0}
    };

    if(! parse_command_line(argc,   argv,   param)){                     //error input
        fprintf(stderr, "error Parameters!\n"
                "try \'pf --help\' for more information.\n");
        exit(1);
    }

    if(isshowversion)          //show version
        err_quit("%s",  PROG_VERSION);

    if(isshowhelp){             //show help info
        print_help_info(param);
        exit(1);
    }


    if(isdaemon){                       //demamd pf run
        /* to do
        if(isrunning()){             //if the pf running
            fprintf(stderr, "error message: pf is running.\n");
            err_quit("pf is running.\n");
        }
        else{   */
            rules_file_load();   //load the rules file
            err_msg("\n");
            init_iptables();      //initiate iptables
            signal(SIGINT, sig_init_exit);          //init exit clean
            out_rules_list(STDOUT_FILENO);
            err_msg("\n");
            init_nfqueue();        //initiate nfqueue
            //set_rpc_server();       //open a tcp server ,receive the rpc command

            //to do
            //running daemon
            //
        /*}*/
        return 1;
    }
    else{
        /*
         * to do
         */
        if(islist)
            strncpy(sec_parse, "--list", 7);
        err_msg("%s", sec_parse);
        send_cmd_to_serv(sec_parse);
        err_msg("send end");
    }

    //to do
    //handle rule
    return 1;
}

void send_cmd_to_serv(char * cmd){
    int sockfd;
    struct sockaddr_in servaddr;
    char buff[MAX_LINE_LEN];
    int n;

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        err_sys("socket error");

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);

    if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        err_sys("connect error");
    if(send(sockfd, cmd, strlen(cmd), 0) < 0)
        err_sys("send error");
    while((n = recv(sockfd, buff, MAX_LINE_LEN, 0)) > 0){
        buff[n] = '\0';
        fputs(buff, stdout);
    }
    if(n == -1)
        err_sys("recv error");
}



    
/*
 * print the program help document
 */
void print_help_info(struct parameter_tags p[]){
    struct parameter_tags * q = p;
    fputs("usage: pf []\n",stdout);
    fputs("\n",stdout);
    while(q->describe){
        fprintf(stdout,"\t\t%s\n",q->describe);     
        q++;
    }
}
        

bool isrunning(void){
    char pidtmp[10];
    int pf_fd = open("/tmp/pf.pid",O_RDWR,NULL);                //if there a pf.pid file exsit
    if(pf_fd == -1){                                            //not exsit
        int new_pf_fd = open("/tmp/pf.pid",O_WRONLY | O_CREAT); //create it
        if(new_pf_fd == -1)
            err_sys("open");
        pid_t pf_pid = getpid();                                //get the current pid
        sprintf(pidtmp,"%d",pf_pid);
        if(-1 == write(new_pf_fd,pidtmp,strlen(pidtmp)))        //write it to the pf.pid file
            err_sys("write");
        close(new_pf_fd);
        return false;
    }
    else{                                                       //pf.pid exsit
        if(-1 == read(pf_fd,pidtmp,10))                           //read it's pid
            err_sys("read");
        char path [20] = "/proc/";
        strncat(path,pidtmp,10);
        strncat(path,"/status",8);
        int proc_fd = open(path,O_RDONLY);                      //if opened,then there is a running daemon
        if(-1 == proc_fd){
            if(-1 == lseek(pf_fd,0,SEEK_SET))
                err_sys("lseek");
            if(-1 == write(pf_fd,pidtmp,strlen(pidtmp)))          //
                err_sys("write");
            close(pf_fd);
            close(proc_fd);
            return false;
        }
        else{                                                   //then return true
            close(pf_fd);
            close(proc_fd);
            return true;
        }
    }
}


void init_iptables(void){
    /*
     * to do
     */
    //do nothing
    return;
    int ret_out = system("iptables -I OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11220");
    int ret_in = system("iptables -I INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11221");
    if(ret_out == -1 || ret_in == -1)
        err_sys("init_iptables");
    return;
}


void rules_file_load(void){
    /*
     * to do
     */
    //load the out rule file
    FILE * fp;
    if((fp = fopen("./out_rules_file","r")) == NULL)
        err_sys("fopen error");
    char line[MAX_LINE_LEN];
    u_int32_t raddr;
    u_int16_t lport_n;
    u_int16_t rport_n;
    int protocol;
    enum TARGET targ;
    
    while((fgets(line, MAX_LINE_LEN, fp)) != NULL){
        if(line[0] == '#')      //skip comment
            continue;
        err_msg("%s",line);
        parse_rules(line, &lport_n, &raddr, &rport_n, &protocol, &targ);
        out_rule_insert(lport_n, raddr, rport_n, protocol, targ);
    }
    fclose(fp);
    return;
}


void out_rule_insert(u_int16_t lport, u_int32_t raddr, u_int16_t rport, int proto, enum TARGET targ){
    out_rules_link p;
    if((p = malloc(sizeof(out_nd))) == NULL)
        err_sys("malloc error");
    p->lport = lport;
    p->raddr = raddr;
    p->rport = rport;
    p->proto = proto;
    p->target = targ;
    pthread_mutex_lock(&out_rules_lock);
    if(!head){
        head = p;
        p->next = NULL;
    }
    else{
        out_rules_link q = head;
        head = p;
        head->next = q;
    }
    pthread_mutex_unlock(&out_rules_lock);
    return;
}




void parse_rules(char line[], u_int16_t * lport_n_p, u_int32_t * raddr_p, u_int16_t * rport_n_p, int * proto_p, enum TARGET * targ_p){
        char lport[10];         //local port
        char raddr[20];         //remote address
        char rport[10];         //remote port
        char proto[5];          //protocol
        char target[10];        //target
        if((sscanf(line, "%s%s%s%s%s", lport, raddr, rport, proto, target)) != 5)
            err_quit("out rules file have wrong rule:%s", line);
        if(strncmp(raddr, "-", 1) == 0)
            *raddr_p = 0;              //all port
        else
            if(inet_pton(AF_INET, raddr, raddr_p) <= 0)
                err_quit("inet_pton error for %s",raddr);
        err_msg("remote addrr:%s:%x",raddr,*raddr_p);
        if(strncmp(lport, "-", 1) == 0)
            *lport_n_p = 0;
        else
            *lport_n_p = htons(atoi(lport));
        if(strncmp(rport, "-", 1) == 0)
            *rport_n_p = 0;
        else
            *rport_n_p = htons(atoi(rport));
        err_msg("local port:%s:%x",lport,*lport_n_p);
        err_msg("remote port:%s:%x",rport,*rport_n_p);

        if(strncmp(proto, "TCP", 3) == 0)
            *proto_p = IPPROTO_TCP;
        else if((strncmp(proto, "UDP", 3) == 0))
            *proto_p = IPPROTO_UDP;
        else
            err_quit("unknow for %s", proto);
        err_msg("portocol:%s",proto);

        if(strncmp(target, "DROP", 4) == 0)
            *targ_p = DROP;
        else if(strncmp(target, "ACCEPT", 6) == 0)
            *targ_p = ACCEPT;
        else
            err_quit("unknow for %s", target);
        err_msg("target:%s",target);

    return;
}


void init_nfqueue(void){
    /*
     * to do
     */
    struct nfq_handle * h;
    h = nfq_open();
    if(! h){
        err_sys("nfq_open()");
    }
    if(nfq_unbind_pf(h, AF_INET) < 0){
        err_sys("nfq_unbind()");
    }
    if(nfq_bind_pf(h, AF_INET) < 0)
        err_sys("nfq_bind()");
    struct nfq_q_handle * qh;
    qh = nfq_create_queue(h, 11220, &cb, NULL);
    if(! qh)
        err_sys("nfq_create_queue()");
    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 40) < 0)
        err_sys("nfq_set_mode()");
    int fd = nfq_fd(h);
    int err;
    pthread_t out_tid;
    err = pthread_create(&out_tid, NULL, thread_nfq_out, (void *)&fd);
    if(err != 0)
        err_exit(err, "can't create thread");
}

void * thread_nfq_out(void * arg){

    char buf[1024];
    int rv;
    int fd = *((int *)arg);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0){
        printf("packet received.\n");
        nfq_handle_packet(h, buf, rv);
    }
}

static int cb (struct nfq_q_handle * qh, struct nfgenmsg * nfmsg , struct nfq_data * nfa, void * data){
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr * ph;
    struct iphdr * ip ;
    int ipdata_len;
    u_int32_t id = 0;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(ph){
        id = ntohl(ph->packet_id);
    }
    ipdata_len = nfq_get_payload(nfa, (unsigned char **)&ip);
    if(ipdata_len == -1){
        ipdata_len = 0;
    }
    //char raddr[INET_ADDRSTRLEN];
    //inet_ntop(AF_INET, &(ip->daddr), raddr, INET_ADDRSTRLEN);
    u_int32_t raddr = ip->daddr;
    u_int16_t lport,rport;
    int proto = ip->protocol;
    if(proto == IPPROTO_TCP){
        struct tcphdr * tcp = ( struct tcphdr * )((char *)ip + (4 * ip->ihl));
        lport = tcp->source;
        rport = tcp->dest;
    }
    else if(proto == IPPROTO_UDP){
        struct udphdr * udp = (struct udphdr * )((char *)ip + (4 * ip->ihl));
        lport = udp->source;
        rport = udp->dest;
    }
    else{
        return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)ipdata_len, (unsigned char *)ip);
    }
    if(execute_verdict(lport, raddr, rport, proto) == ACCEPT){
        err_msg("packet accepted!");
        printf("len %d iphdr %d %u.%u.%u.%u:%u -> ",ipdata_len,(ip->ihl)<<2,IPQUAD(ip->saddr),ntohs(lport));
        printf("%u.%u.%u.%u:%u  proto:%s",IPQUAD(raddr),ntohs(rport),getprotobynumber(ip->protocol)->p_name);
        err_msg("\n");

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    else{
        err_msg("packet droped!");
        printf("len %d iphdr %d %u.%u.%u.%u:%u -> ",ipdata_len,(ip->ihl)<<2,IPQUAD(ip->saddr),ntohs(lport));
        printf("%u.%u.%u.%u:%u  proto:%s",IPQUAD(raddr),ntohs(rport),getprotobynumber(ip->protocol)->p_name);
        err_msg("\n");

        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }





    //printf("len %d iphdr %d %u.%u.%u.%u -> ",pdata_len,(iphdrp->ihl)<<2,IPQUAD(iphdrp->saddr));
    //printf("%u.%u.%u.%u %s",IPQUAD(iphdrp->daddr),getprotobynumber(iphdrp->protocol)->p_name);
    //return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
}

enum TARGET execute_verdict(u_int16_t lport, u_int32_t raddr, u_int16_t rport, int proto){
    /*
     * to do
     */
    pthread_mutex_lock(&out_rules_lock);
    out_rules_link p = head;
    while(p){
        if(    ( !(p->lport) || (lport == p->lport) )     &&    ( !(p->raddr) || (raddr == p->raddr)  )   && \
                    ( !(p->rport) || (rport == p->rport) )    &&   ( proto == p->proto)    ){
            //find a rule;
            pthread_mutex_unlock(&out_rules_lock);
            return p->target;
        }
        //if(p->lport == lport && p->raddr == raddr && p->rport == rport && p->proto == proto){
        p = p->next;
    }


    pthread_mutex_unlock(&out_rules_lock);
    return ACCEPT;          //default target;

}

void set_rpc_server(void){
    /*
     * to do
     */
    int listenfd, connfd;
    socklen_t len;
    struct sockaddr_in servaddr, cliaddr;
    char buff[MAX_LINE_LEN];

    if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        err_sys("socket error");
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);

    if(bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        err_sys("bind error");

    if(listen(listenfd, 5) < 0)
        err_sys("listen error");

    for( ; ; ){
        len = sizeof(cliaddr);
        if((connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &len)) < 0){
            if(errno == EINTR)
                continue;           //re accept
            else
                err_sys("accept error");
        }
        do_it(connfd);              //parse command, return result;
        close(connfd);
    }
    
    return;
}

void do_it (int connfd){
    /*
     * fix me
     */
    int n;
    char buff[MAX_LINE_LEN];
    u_int32_t raddr;
    u_int16_t rport;
    u_int16_t lport;
    enum TARGET targ;
    int proto;
    if((n = recv(connfd, buff, MAX_LINE_LEN, 0)) < 0)           //receive command
        err_sys("recv error");
    buff[n] = '\0';
    err_msg("%s",buff);
    if(strncmp(buff, "-a", 2) == 0){                    //add rule
        parse_rules(buff+2, &lport, &raddr, &rport, &proto, &targ);
        out_rule_insert(lport, raddr, rport, proto, targ);
        err_msg("rule add:%s", buff+2);
        if(send(connfd, "rule added", 10, 0) < 0)
            err_sys("send error");
    }
    else if(strncmp(buff, "-d", 2) == 0){               //delete rule
        int num;
        if(sscanf(buff+2, "%d", &num) != 1)
            err_quit("rule delete,unknow:%s", buff+2);
        err_msg("rule del:%d", num);
        if(rule_del(num) < 0){
            if(send(connfd, "rule delete failed", 18, 0) < 0)
                err_sys("send error");
        }
        else
            if(send(connfd, "rule deleted", 12, 0) < 0)
                err_sys("send error");

    }
    else if(strncmp(buff, "--list", 6) == 0){               //rule list
        err_msg("rules list");
        out_rules_list(connfd);
        err_msg("rules list");
    }
    else
        if(send(connfd, "unknow command", 14, 0) < 0)       //unknow
            err_sys("send error");

    err_msg("\n");
    


}

int rule_del(int num){
    /*
     * to do
     */
    //
    if(num <= 0)
        return -1;
    out_rules_link p, pre = NULL;
    pthread_mutex_lock(&out_rules_lock);
    p = head;
    int i = num;
    while(--i){
        if(p){
            pre = p;
            p = p->next;
        }
        else
            break;
    }
    if(!p){
        pthread_mutex_unlock(&out_rules_lock);
        return -1;
    }
    else{
        if(!pre)
            head = p->next;
        else
            pre->next = p->next;
        free(p);
        pthread_mutex_unlock(&out_rules_lock);
        return num;
    }
}




static void sig_init_exit(int signo){
    out_rules_list(STDOUT_FILENO);
    clean_rules_link();
    err_msg("head is %s null", head ? "not" : " ");
    out_rules_list(STDOUT_FILENO);
    /*
     * do something else
     */

    exit(0);
}

static void clean_rules_link(void){
    out_rules_link p;
    while(head){
        p = head;
        head = head->next;
        free(p);
    }
    err_msg("\n");
    err_msg("out rules clean");
}

void out_rules_list(int  fd){
    pthread_mutex_lock(&out_rules_lock);
    out_rules_link p = head;
    char buff[20];
    char tmp[MAX_LINE_LEN];
    while(p){
        //fputf("\n", out);
        //fprintf(out, "local port:%d",ntohs(p->lport));
        //fprintf(out, "remote address:%s",inet_ntop(AF_INET, &(p->raddr), buff, 20));
        //fprintf(out, "remote port:%d",ntohs(p->rport));
        //fprintf(out, "protocol:%s", getprotobynumber(p->proto)->p_name);
        //fprintf(out, "target:%s", p->target == ACCEPT ? "ACCEPT" : "DROP");
        sprintf(tmp, "localport:%d\tremote address:%s\tremote port:%d\tprotocol:%s\ttarget:%s\n",
                ntohs(p->lport), inet_ntop(AF_INET, &(p->raddr), buff, 20),
                ntohs(p->rport), getprotobynumber(p->proto)->p_name,
                p->target == ACCEPT ? "ACCEPT" : "DROP" );


        if(write(fd, tmp, strlen(tmp)) < 0)
            err_sys("write error");

        p = p->next;
    }
    pthread_mutex_unlock(&out_rules_lock);
}
