/*
 * to do
 */

#include"mylog.h"


void debuglog(char * format, ...){
    /*
     * to do
     */
    syslog(LOG_USER | LOG_DEBUG, format, ...);
    return;
}

