/*
 * to do
 */

#ifndef _MYERR_H_
#define _MYERR_H_

#include<stdio.h>
#include<errno.h>
#include<stdlib.h>
#include<stdarg.h>
#include<string.h>


void err_sys(const char *, ...);

void err_quit(const char *, ...);

void err_ret(const char *, ...);

void err_msg(const char *, ...);

void err_exit(int error, const char *fmt, ...);



#endif
