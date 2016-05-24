/*
 * to do
 */

#include"parse.h"

int parse_command_line(int argc,char * argv[],struct parameter_tags p[]){
    
    for(int i = 1;i < argc;i++){
        struct parameter_tags * q = p;
        while(q->describe){
            if(! strncmp(argv[i],q->prefix,q->prefix_len)){
                switch (q->type) {
                    case _NULL_ : 
                       *((bool *)(q->parameter)) =  true;
                        break;
                    case INTEGER :
                        break;
                    case STRING :
                        {
                            *((char *)(q->parameter)) = 0;
                            for(i++ ;i < argc;i++){
                               strncat((char *)(q->parameter),argv[i],20);
                               strncat((char *)(q->parameter)," ",2);
                            }
                            return 1;
                        }
                    default :
                        return 0;
                }
            }
            q++;
        }
    }
    return 1;
}

