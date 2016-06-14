/*
 * to do
 */

#include"pf.h"

rules_link out_head = NULL;         //out rule link head
rules_link in_head = NULL;         //in rule link head
struct nfq_handle * h_out;
struct nfq_handle * h_in;
pthread_mutex_t out_rules_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t in_rules_lock = PTHREAD_MUTEX_INITIALIZER;
enum DIRECTION out = OUT;
enum DIRECTION in = IN;
static bool Internet = true;


int main(int argc,  char *argv[]){

    bool isshowversion = false;
    bool isshowhelp = false;
    bool isdaemon = false;
    bool islist = false;
    bool isdisconnect = false;
    bool isreconnect = false;

    char sec_parse[MAX_LINE_LEN] = {0};       //require the second parse
    
    struct parameter_tags param [] = {
        { "--version",  (char *)&isshowversion,  "--verion\t\tshow the verion of pf",   9,    sizeof(isshowversion),  _NULL_},
        { "--help",     (char *)&isshowhelp,    "--help\t\t\tshow the help document",     6,     sizeof(isshowhelp),      _NULL_},
        { "-a",         (char *)sec_parse,      "-a\t\t\tadd rule to the pf",             2,     sizeof(sec_parse),      STRING},
        { "-d",         (char *)sec_parse,      "-d\t\t\tdelet rule from the pf",         2,     sizeof(sec_parse),      STRING},
        { "-D",         (char *)&isdaemon,      "-D\t\t\trun the pf",                     2,      sizeof(isdaemon),       _NULL_},
        { "--list",     (char *)&islist,        "--list\t\t\tlist the exsit rules",         6,  sizeof(islist),         _NULL_},
        { "--disconnect", (char *)&isdisconnect,  "--disconnet\t\tdisconnect the Internet", 12,   sizeof(isdisconnect),   _NULL_},
        { "--reconnect", (char *)&isreconnect,  "--reconnet\t\treconnect the Internet", 11,   sizeof(isreconnect),   _NULL_},
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
            iptables_local(true);           //true : enable the local connection
            openlog("pf log", LOG_CONS | LOG_PID, 0);           //init log service
            rules_file_load();   //load the rules file
            err_msg("\n");
            init_iptables();      //initiate iptables
            signal(SIGINT, sig_init_exit);          //init exit clean
            rules_list(STDOUT_FILENO);
            err_msg("\n");
            init_nfqueue();        //initiate nfqueue
            set_rpc_server();       //open a tcp server ,receive the rpc command

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
        if(isdisconnect)
            strncpy(sec_parse, "--disconnect", 13);
        if(isreconnect)
            strncpy(sec_parse, "--reconnect", 12);
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
    //return;
    int ret_out = system("iptables -A OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11220");
    int ret_in = system("iptables -A INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11221");
    if(ret_out == -1 || ret_in == -1)
        err_sys("init_iptables");
    err_msg("init_iptables");
    return;
}

void end_iptables(void){
    /*
     * to do
     */
    //do nothing
    //return;
    int ret_out = system("iptables -D OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11220");
    int ret_in = system("iptables -D INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11221");
    if(ret_out == -1 || ret_in == -1)
        err_sys("end_iptables error");
    err_msg("end_iptables");
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
    u_int32_t raddr_n;
    u_int32_t mask_n;
    u_int16_t lport_n;
    u_int16_t rport_n;
    int protocol;
    enum TARGET targ;
    enum DIRECTION direc;
    
    while((fgets(line, MAX_LINE_LEN, fp)) != NULL){
        if(line[0] == '#')      //skip comment
            continue;
        err_msg("%s",line);
        if(parse_rules(line, &lport_n, &raddr_n, &mask_n, &rport_n, &protocol, &targ, &direc))          //parse rule successfully
            rule_insert(lport_n, raddr_n, mask_n, rport_n, protocol, targ, direc);
        else{
            err_msg("%s", "failed to insert rule");
            continue;
        }
    }
    fclose(fp);

    //load the in rule file
    FILE * fp1;
    if((fp1 = fopen("./in_rules_file", "r")) == NULL)
        err_sys("fopen error");
    while((fgets(line, MAX_LINE_LEN, fp)) != NULL){
        if(line[0] == '#')      //skip comment
            continue;
        err_msg("%s",line);
        if(parse_rules(line, &lport_n, &raddr_n, &mask_n, &rport_n, &protocol, &targ, &direc))          //parse rule successfully
            rule_insert(lport_n, raddr_n, mask_n, rport_n, protocol, targ, direc);
        else{
            err_msg("%s", "failed to insert rule");
            continue;
        }
    }
    fclose(fp1);
    
    
    return;
}


void rule_insert(u_int16_t lport, u_int32_t raddr, u_int32_t mask, u_int16_t rport, int proto, enum TARGET targ, enum DIRECTION direc){
    rules_link p, * head_p;
    if((p = malloc(sizeof(rule_nd))) == NULL)
        err_sys("malloc error");
    p->lport = lport;
    p->raddr = raddr;
    p->mask = mask;
    p->rport = rport;
    p->proto = proto;
    p->target = targ;
    if(direc == OUT){                   //direc is out
        head_p = &out_head;
        pthread_mutex_lock(&out_rules_lock);
    }
    else{                               //direc is in
        head_p = &in_head;
        pthread_mutex_lock(&in_rules_lock);
    }

    //critical zone
    if(!(*head_p)){
        *head_p = p;
        p->next = NULL;
    }
    else{
        rules_link q = *head_p;
        *head_p = p;
        (*head_p)->next = q;
    }
    //critical zone
    
    if(direc == OUT){                   //direc is out
        pthread_mutex_unlock(&out_rules_lock);
    }
    else{                               //direc is in
        pthread_mutex_unlock(&in_rules_lock);
    }


    //add rule insert log
    syslog(LOG_USER | LOG_DEBUG, "rule add,direction:%s,local port:%u,remote address:%u.%u.%u.%u,mask:%u.%u.%u.%u,remote port:%u,protocol:%s,target:%s.",
            ((direc == OUT) ? "OUT" : "IN"), ntohs(lport),
            IPQUAD(raddr), IPQUAD(mask), ntohs(rport), getprotobynumber(proto)->p_name,
            ((targ == DROP) ? "DROP" : "ACCEPT"));

    return;
}




bool parse_rules(char line[], u_int16_t * lport_n_p, u_int32_t * raddr_p, u_int32_t * mask_p, u_int16_t * rport_n_p, int * proto_p, enum TARGET * targ_p, enum DIRECTION * direc_p){
        char lport[10];         //local port
        char raddr[20];         //remote address
        char rport[10];         //remote port
        char proto[5];          //protocol
        char target[10];        //target
        char direc[5];          //connection direction
        if((sscanf(line, "%s%s%s%s%s%s", direc, lport, raddr, rport, proto, target)) != 6){
            //parameter error , too less parameters
            err_msg("wrong rule:%s", line);
            return false;
        }
        if((strncmp(direc, "OUT", 3)) == 0)
            *direc_p = OUT;
        else if((strncmp(direc, "IN", 2)) == 0)
            *direc_p = IN;
        else{               //unknow direction of rule
            err_msg("wrong rule,unknow direction:%s", direc);
            return false;
        }
        if(strncmp(raddr, "-", 1) == 0){
            *raddr_p = 0;              //all address
            *mask_p = 0;
        }
        else
            if(!parse_subnet(raddr, raddr_p, mask_p))           //perhaps the remote address is a subnet
                return false;
        /*
            if(inet_pton(AF_INET, raddr, raddr_p) <= 0)
                err_quit("inet_pton error for %s",raddr);
                */
        err_msg("remote addr:%s:%x",raddr, *raddr_p);
        err_msg("remote addr:%u.%u.%u.%u", IPQUAD(*raddr_p));
        err_msg("mask:%u.%u.%u.%u", IPQUAD(*mask_p));
        if(strncmp(lport, "-", 1) == 0)
            *lport_n_p = 0;
        else{                                                   //check the port between 0 - 65535
            int port = atoi(lport);
            if(port < 1 || port > 65535){                       //wrong port
                err_msg("wrong port :%d", port);
                return false;
            }
            *lport_n_p = htons(port);
        }
        if(strncmp(rport, "-", 1) == 0)
            *rport_n_p = 0;
        else{
            int port = atoi(rport);
            if(port < 1 || port > 65535){                       //wrong port
                err_msg("wrong port :%d", port);
                return false;
            }
            *rport_n_p = htons(port);
        }
        err_msg("local port:%s:%x",lport,*lport_n_p);
        err_msg("remote port:%s:%x",rport,*rport_n_p);

        if(strncmp(proto, "TCP", 3) == 0)
            *proto_p = IPPROTO_TCP;
        else if((strncmp(proto, "UDP", 3) == 0))
            *proto_p = IPPROTO_UDP;
        else{                                                   //wrong protocol
            err_msg("unknow for %s", proto);
            return false;
        }
        err_msg("portocol:%s",proto);

        if(strncmp(target, "DROP", 4) == 0)
            *targ_p = DROP;
        else if(strncmp(target, "ACCEPT", 6) == 0)
            *targ_p = ACCEPT;
        else{                                                   //wrong target
            err_msg("unknow for %s", target);
            return false;
        }
        err_msg("target:%s",target);

    return true;
}


void init_nfqueue(void){
    /*
     * to do
     */
    int err;
    //struct nfq_handle * h;
    //out queue handler
    //out = OUT;
    h_out = nfq_open();
    if(! h_out)
        err_sys("nfq_open()");
    if(nfq_unbind_pf(h_out, AF_INET) < 0)
        err_sys("nfq_unbind()");
    if(nfq_bind_pf(h_out, AF_INET) < 0)
        err_sys("nfq_bind()");
    struct nfq_q_handle * qh_out;
    qh_out = nfq_create_queue(h_out, 11220, &cb, (void *)&out);
    if(! qh_out)
        err_sys("nfq_create_queue()");
    if(nfq_set_mode(qh_out, NFQNL_COPY_PACKET, 40) < 0)
        err_sys("nfq_set_mode()");
    int fd_out = nfq_fd(h_out);
    pthread_t out_tid;
    err = pthread_create(&out_tid, NULL, thread_nfq_out, (void *)&fd_out);
    err_msg("created out queue handle pthread");
    if(err != 0)
        err_exit(err, "can't create thread");


    //int queue handler
    enum DIRECTION in = IN;
    h_in= nfq_open();
    if(! h_in){
        err_sys("nfq_open()");
    }
    if(nfq_unbind_pf(h_in, AF_INET) < 0){
        err_sys("nfq_unbind()");
    }
    if(nfq_bind_pf(h_in, AF_INET) < 0)
        err_sys("nfq_bind()");
    struct nfq_q_handle * qh_in;
    qh_in = nfq_create_queue(h_in, 11221, &cb, (void *)&in);
    if(! qh_in)
        err_sys("nfq_create_queue()");
    if(nfq_set_mode(qh_in, NFQNL_COPY_PACKET, 40) < 0)
        err_sys("nfq_set_mode()");
    int fd_in = nfq_fd(h_in);
    pthread_t in_tid;
    err = pthread_create(&in_tid, NULL, thread_nfq_in, (void *)&fd_in);
    err_msg("created in queue handle pthread");
    if(err != 0)
        err_exit(err, "can't create thread");
}

void * thread_nfq_out(void * arg){

    char buf[1024];
    int rv;
    int fd = *((int *)arg);
    err_msg("pthread out queue handle running...");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0){
        printf("packet received.\n");
        nfq_handle_packet(h_out, buf, rv);
    }
}


void * thread_nfq_in(void * arg){

    char buf[1024];
    int rv;
    int fd = *((int *)arg);
    err_msg("pthread in queue handle running...");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0){
        printf("packet received.\n");
        nfq_handle_packet(h_in, buf, rv);
    }
}

static int cb (struct nfq_q_handle * qh, struct nfgenmsg * nfmsg , struct nfq_data * nfa, void * threaddata){
    (void)nfmsg;


    char buff[MAX_LINE_LEN];
    struct nfqnl_msg_packet_hdr * ph;
    struct iphdr * ip ;
    int ipdata_len;
    u_int32_t id = 0;
    enum DIRECTION direc;
    //if(*((enum DIRECION *)threaddata) == 
    direc = *((enum DIRECTION *)threaddata);
    err_msg("call back is running,direction:%s", ((direc == OUT) ? "OUT" : "IN"));

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
    u_int32_t raddr = (direc == OUT) ? ip->daddr : ip->saddr;
    u_int32_t laddr = (direc == OUT) ? ip->saddr : ip->daddr;
    u_int16_t lport,rport;
    int proto = ip->protocol;
    if(proto == IPPROTO_TCP){
        struct tcphdr * tcp = ( struct tcphdr * )((char *)ip + (4 * ip->ihl));
        lport = (direc == OUT) ? tcp->source : tcp->dest;
        rport = (direc == OUT) ? tcp->dest : tcp->source;
    }
    else if(proto == IPPROTO_UDP){
        struct udphdr * udp = (struct udphdr * )((char *)ip + (4 * ip->ihl));
        lport = (direc == OUT) ? udp->source : udp->dest;
        rport = (direc == OUT) ? udp->dest : udp->source;
    }
    else{
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    if(execute_verdict(lport, raddr, rport, proto, direc) == ACCEPT){
        err_msg("packet accepted!");
        printf("len %d iphdr %d %u.%u.%u.%u:%u %s ",ipdata_len,(ip->ihl)<<2,IPQUAD(laddr),ntohs(lport), ((direc == OUT) ? "->" : "<-"));
        printf("%u.%u.%u.%u:%u  proto:%s",IPQUAD(raddr),ntohs(rport),getprotobynumber(proto)->p_name);
        err_msg("\n");
        sprintf(buff, "%u.%u.%u.%u:%u %s %u.%u.%u.%u:%u  protocol:%s  target:%s",
                IPQUAD(laddr), ntohs(lport), ((direc == OUT) ? "->" : "<-"),
                IPQUAD(raddr), ntohs(rport), getprotobynumber(proto)->p_name, "ACCEPT");
        send_to_front(buff);


        //connection accept
        syslog(LOG_USER | LOG_DEBUG, "connection accepted,direction:%s,local port:%u,remote address:%u.%u.%u.%u,remote port:%u,protocol:%s,target:%s.",
                ((direc == OUT) ? "OUT" : "IN"), ntohs(lport),
                IPQUAD(raddr), ntohs(rport), getprotobynumber(proto)->p_name,
                "ACCEPT");

        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    else{
        err_msg("packet droped!");
        printf("len %d iphdr %d %u.%u.%u.%u:%u %s ",ipdata_len,(ip->ihl)<<2,IPQUAD(laddr),ntohs(lport), ((direc == OUT) ? "->" : "<-"));
        printf("%u.%u.%u.%u:%u  proto:%s",IPQUAD(raddr),ntohs(rport),getprotobynumber(proto)->p_name);
        err_msg("\n");
        sprintf(buff, "%u.%u.%u.%u:%u %s %u.%u.%u.%u:%u  protocol:%s  target:%s",
                IPQUAD(laddr), ntohs(lport), ((direc == OUT) ? "->" : "<-"),
                IPQUAD(raddr), ntohs(rport), getprotobynumber(proto)->p_name, "DROP");
        send_to_front(buff);


        //connection droped. 
        syslog(LOG_USER | LOG_DEBUG, "connection droped,direction:%s,local port:%u,remote address:%u.%u.%u.%u,remote port:%u,protocol:%s,target:%s.",
                ((direc == OUT) ? "OUT" : "IN"), ntohs(lport),
                IPQUAD(raddr), ntohs(rport), getprotobynumber(proto)->p_name,
                "DROP");

        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }





    //printf("len %d iphdr %d %u.%u.%u.%u -> ",pdata_len,(iphdrp->ihl)<<2,IPQUAD(iphdrp->saddr));
    //printf("%u.%u.%u.%u %s",IPQUAD(iphdrp->daddr),getprotobynumber(iphdrp->protocol)->p_name);
    //return nfq_set_verdict(qh, id, NF_ACCEPT, (u_int32_t)pdata_len, pdata);
}

enum TARGET execute_verdict(u_int16_t lport, u_int32_t raddr, u_int16_t rport, int proto, enum DIRECTION direc){
    /*
     * to do
     */
    rules_link p;
    if(direc == OUT){
        pthread_mutex_lock(&out_rules_lock);
        p = out_head;
    }
    else{
        pthread_mutex_lock(&in_rules_lock);
        p = in_head;
    }

    //critical zone
    err_msg("%s", (direc == OUT) ? "travel out rules link" : "travel in rules link");
    while(p){
        if(    ( !(p->lport) || (lport == p->lport) )     &&    ( (raddr & (p->mask)) == p->raddr)  && \
                    ( !(p->rport) || (rport == p->rport) )    &&   ( proto == p->proto)    ){
                //( !(p->raddr) || (raddr == p->raddr)  )   && out date
            //find a rule;
            //pthread_mutex_unlock(&out_rules_lock);
            //go to REDIREC_TARG;
            if(direc == OUT){
                pthread_mutex_unlock(&out_rules_lock);
            }
            else{
                pthread_mutex_unlock(&in_rules_lock);
            }
            return p->target;
        }
        //if(p->lport == lport && p->raddr == raddr && p->rport == rport && p->proto == proto){
        p = p->next;
    }
    //critical zone


//REDIREC_TARG:
    if(direc == OUT){
        pthread_mutex_unlock(&out_rules_lock);
    }
    else{
        pthread_mutex_unlock(&in_rules_lock);
    }
    //return p->target;
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
    u_int32_t mask;
    u_int16_t rport;
    u_int16_t lport;
    enum TARGET targ;
    enum DIRECTION direc;
    char direction[5];
    int proto;
    if((n = recv(connfd, buff, MAX_LINE_LEN, 0)) < 0)           //receive command
        err_sys("recv error");
    buff[n] = '\0';
    err_msg("%s",buff);
    if(strncmp(buff, "-a", 2) == 0){                    //add rule
        err_msg("rule add:%s", buff+2);
        if(parse_rules(buff+2, &lport, &raddr, &mask, &rport, &proto, &targ, &direc)){                   //parse rule successfully
            rule_insert(lport, raddr, mask, rport, proto, targ, direc);
            if(send(connfd, "rule added", 10, 0) < 0)
                err_sys("send error");
        }
        else{                                                                                       //parse rule failed
            if(send(connfd, "failed to add rule", 18, 0) < 0)
                err_sys("send error");
        }
    }
    else if(strncmp(buff, "-d", 2) == 0){               //delete rule
        int num;
        if(sscanf(buff+2, "%s%d", direction, &num) != 2){           //wrong parameters
            err_msg("rule delete failed,unknow:%s", buff+2);
            if(send(connfd, "rule delete failed", 18, 0) < 0)
                err_sys("send error");
        }
        if(strncmp(direction, "OUT", 3) == 0)
            direc = OUT;
        else if(strncmp(direction, "IN", 2) == 0)
            direc = IN;
        else{                                                       //wrong direction
            err_msg("rule delete failed,unknow:%s", direction);
            if(send(connfd, "rule delete failed", 18, 0) < 0)
                err_sys("send error");
        }
        err_msg("rule del,queue:%s,num:%d", direction, num);
        if(rule_del(num, direc) < 0){
            if(send(connfd, "rule delete failed", 18, 0) < 0)
                err_sys("send error");
        }
        else
            if(send(connfd, "rule deleted", 12, 0) < 0)
                err_sys("send error");

    }
    else if(strncmp(buff, "--list", 6) == 0){               //rule list
        err_msg("rules list");
        rules_list(connfd);
        err_msg("rules list");
    }
    else if(strncmp(buff, "--disconnect", 12) == 0){              //disconnect Internet
        err_msg("disconnection");
        change_connection_status(false);
        if(send(connfd, "disconnected", 11, 0) < 0)
            err_sys("send error");
    }
    else if(strncmp(buff, "--reconnect", 11) == 0){              //reconnect Internet
        err_msg("reconnection");
        change_connection_status(true);
        if(send(connfd, "reconnected", 11, 0) < 0)
            err_sys("send error");
    }
    else
        if(send(connfd, "unknow command", 14, 0) < 0)       //unknow
            err_sys("send error");

    err_msg("\n");
    


}


void change_connection_status(bool status){
    /*
     * to do
     */
    if(Internet){                           //already connected to internet
        fputs("connected the internet\n",stdout);
        if(status)
            fputs("do nothing\n", stdout);
        else{
            int ret1 = system("iptables -I INPUT 2 -m conntrack --ctstate NEW -j DROP");
            int ret2 = system("iptables -I OUTPUT 2 -m conntrack --ctstate NEW -j DROP");
            if(ret1 == -1 || ret2 == -1)
                err_sys("system error, disconnection failed");
            fputs("diconnected the internet\n", stdout);
            Internet = false;
        }
    }
    else{                                   //now not connected to internet
        fputs("not connected the internet\n", stdout);
        if(status){
            int ret1 = system("iptables -D INPUT -m conntrack --ctstate NEW -j DROP");
            int ret2 = system("iptables -D OUTPUT -m conntrack --ctstate NEW -j DROP");
            if(ret1 == -1 || ret2 == -1)
                err_sys("system error, disconnection failed");
            fputs("reconnected the internet\n", stdout);
            Internet = true;
        }
        else
            fputs("do nothing\n", stdout);
    }
    return;
}

int rule_del(int num, enum DIRECTION direc){
    /*
     * to do
     */
    //
    if(num <= 0)
        return -1;
    rules_link p, pre = NULL, * head_p;
    if(direc == OUT){
        pthread_mutex_lock(&out_rules_lock);
        head_p = &out_head;
    }
    else{
        pthread_mutex_lock(&in_rules_lock);
        head_p = &in_head;
    }

    //critical zone
    p = *head_p;
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
        if(direc == OUT)
            pthread_mutex_unlock(&out_rules_lock);
        else
            pthread_mutex_unlock(&in_rules_lock);
        return -1;
    }
    else{
        if(!pre)
            *head_p = p->next;
        else
            pre->next = p->next;
        if(direc == OUT)
            pthread_mutex_unlock(&out_rules_lock);
        else
            pthread_mutex_unlock(&in_rules_lock);


        //rule delete
        syslog(LOG_USER | LOG_DEBUG, "rule delete,direction:%s,local port:%u,remote address:%u.%u.%u.%u,remote port:%u,protocol:%s,target:%s.",
                ((direc == OUT) ? "OUT" : "IN"), ntohs(p->lport),
                IPQUAD(p->raddr), ntohs(p->rport), getprotobynumber(p->proto)->p_name,
                ((p->target == DROP) ? "DROP" : "ACCEPT"));

        free(p);
        return num;
    }
}




static void sig_init_exit(int signo){
    rules_list(STDOUT_FILENO);
    clean_rules_link();
    err_msg("out head is %s null", out_head ? "not" : " ");
    err_msg("in head is %s null", in_head ? "not" : " ");
    rules_list(STDOUT_FILENO);
    /*
     * do something else
     */
    //because there is hard to gain the qh_in's value and the qh_out's value
    //so do not to destory the queue
    //and so close the h_out and h_in is not neccsary
    //destory the nfqueue;
    //nfq_destroy_queue();
    //nfq_destroy_queue();
    //err_msg("nfq_destory_queue");
    //nfq_close(h_out);
    //nfq_close(h_in);
    //err_msg("nfq_close")

    closelog();             //close the log service
    err_msg("end log service");

    end_iptables();
    clean_connection();
    iptables_local(false);

    exit(0);
}

static void clean_rules_link(void){
    rules_link p;
    while(out_head){
        p = out_head;
        out_head = out_head->next;
        free(p);
    }
    err_msg("\n");
    err_msg("out rules clean");

    while(in_head){
        p = in_head;
        in_head = in_head->next;
        free(p);
    }
    err_msg("\n");
    err_msg("in rules clean");
}

void rules_list(int  fd){
    rules_link p;
    char buff_addr[20];
    char buff[20];
    char tmp[MAX_LINE_LEN];

    err_msg("\n");
    err_msg("out rules list");
    //out queue list
    pthread_mutex_lock(&out_rules_lock);
    p = out_head;
    while(p){
        //fputf("\n", out);
        //fprintf(out, "local port:%d",ntohs(p->lport));
        //fprintf(out, "remote address:%s",inet_ntop(AF_INET, &(p->raddr), buff, 20));
        //fprintf(out, "remote port:%d",ntohs(p->rport));
        //fprintf(out, "protocol:%s", getprotobynumber(p->proto)->p_name);
        //fprintf(out, "target:%s", p->target == ACCEPT ? "ACCEPT" : "DROP");
        sprintf(buff, "%s/%d", inet_ntop(AF_INET, &(p->raddr), buff_addr, 20), subnet(p->mask));
        sprintf(tmp, "direction:%s\tlocalport:%d\tremote address:%s\tremote port:%d\tprotocol:%s\ttarget:%s\n",
                "OUT",
                ntohs(p->lport), buff,//inet_ntop(AF_INET, &(p->raddr), buff_addr, 20), inet_ntop(AF_INET, &(p->mask), buff_mask, 20),
                ntohs(p->rport), getprotobynumber(p->proto)->p_name,
                p->target == ACCEPT ? "ACCEPT" : "DROP" );


        if(write(fd, tmp, strlen(tmp)) < 0)
            err_sys("write error");

        p = p->next;
    }
    pthread_mutex_unlock(&out_rules_lock);


    err_msg("\n");
    err_msg("in rules list");
    //in queue list
    pthread_mutex_lock(&in_rules_lock);
    p = in_head;
    while(p){
        //fputf("\n", out);
        //fprintf(out, "local port:%d",ntohs(p->lport));
        //fprintf(out, "remote address:%s",inet_ntop(AF_INET, &(p->raddr), buff, 20));
        //fprintf(out, "remote port:%d",ntohs(p->rport));
        //fprintf(out, "protocol:%s", getprotobynumber(p->proto)->p_name);
        //fprintf(out, "target:%s", p->target == ACCEPT ? "ACCEPT" : "DROP");
        sprintf(buff, "%s/%d", inet_ntop(AF_INET, &(p->raddr), buff_addr, 20), subnet(p->mask));
        sprintf(tmp, "direction:%s\tlocalport:%d\tremote address:%s\tremote port:%d\tprotocol:%s\ttarget:%s\n",
                "IN",
                ntohs(p->lport), buff, //inet_ntop(AF_INET, &(p->raddr), buff_addr, 20), inet_ntop(AF_INET, &(p->raddr), buff_mask, 20),
                ntohs(p->rport), getprotobynumber(p->proto)->p_name,
                p->target == ACCEPT ? "ACCEPT" : "DROP" );


        if(write(fd, tmp, strlen(tmp)) < 0)
            err_sys("write error");

        p = p->next;
    }
    pthread_mutex_unlock(&in_rules_lock);
}

static void clean_connection(void){
    if(!Internet){
        int ret1 = system("iptables -D INPUT -m conntrack --ctstate NEW -j DROP");
        int ret2 = system("iptables -D OUTPUT -m conntrack --ctstate NEW -j DROP");
        if(ret1 == -1 || ret2 == -1)
            err_sys("system error, clean connections failed");
    }
        fputs("clean the connections\n", stdout);
    return;
}

static void iptables_local(bool isenable){
    if(isenable){
        int ret1 = system("iptables -I OUTPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT");
        int ret2 = system("iptables -I INPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT");
        if( ret1 == -1 || ret2 == -1)
            err_sys("system error, iptable local");
        fputs("iptables local\n", stdout);
    }
    else{
        int ret1 = system("iptables -D OUTPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT");
        int ret2 = system("iptables -D INPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT");
        if( ret1 == -1 || ret2 == -1)
            err_sys("system error, iptable local");
        fputs("iptables local\n", stdout);
    }
    return;
}

void send_to_front(char * msg){
    struct sockaddr_in saddr;
    bzero(&saddr,sizeof(saddr));
    saddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr);
    saddr.sin_port = htons(9998);
    int fd;
    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        err_sys("socket error");
    if(sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0)
        err_sys("sendto error");
    close(fd);
    return;
}


bool parse_subnet(char * raddr, u_int32_t * raddr_p, u_int32_t * mask_p){
    if( 1 == inet_pton(AF_INET, raddr, raddr_p)){               //remote address isn't a subnet
        *mask_p = 0xffffffff;       //address mask 255.255.255.255
        return true;
    }
    else{
        char addr[20];
        int subnet;
        char * slash_p = strstr(raddr, "/");            //the tag of split the address and subnet num
        if(!slash_p){                                   //no slash
            err_msg("subnet address slash error:%s\n",raddr);
            return false;
        }
        slash_p[0] = ' ';           //divide two parameter
        if(2 != sscanf(raddr, "%s%d", addr, &subnet)){      //read the two parameter
            err_msg("subnet error:%s\n", raddr);
            return false;
        }
        if(0 == inet_pton(AF_INET, addr, raddr_p)){         //can't parse the address
            err_msg("subnet address error:%s\n", raddr);
            return false;
        }
        //printf("%u\n%d\n", ((unsigned char *)raddr_p)[3], subnet);
        //printf("%x\n", ~(0xffffffff << (32-subnet)) & ntohl(*raddr_p));
        if(subnet > 0 && subnet <= 32 && (!( ~(0xffffffff << (32-subnet)) & ntohl(*raddr_p) )) ){
            //subnet > 0 and subnet <= 24 ,and addr is valid
            *mask_p = htonl(0xffffffff << (32-subnet));
            //u_int32_t tmpaddr = ntohl(*raddr_p);
            //printf("%u.%u.%u.%u\n", IPQUAD(tmpaddr));
            //u_int32_t tmpmask = (0xffffffff << (32-subnet));
            //printf("%u.%u.%u.%u\n", IPQUAD(tmpmask));
            return true;

        }
        else{                                           //subnet num is incorrect
            err_msg("subnet mask error:%s\n", raddr);
            return false;
        }
    }
}

static int subnet(u_int32_t mask){
    int i = 0;
    u_int32_t mask_h = ntohl(mask);
    while(mask_h){
        mask_h = (mask_h << 1);
        i++;
    }
    return i;
}
