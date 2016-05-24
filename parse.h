/*
 * to do
 */

#ifndef _PARSE_H_
#define _PARSE_H_

#include<string.h>
#include<stdbool.h>

enum parameter_type {

    INTEGER,        //parameter is a integer
    STRING,         //parameter is a string
    BOOL,           //parameter is a bool
    _NULL_          //parameter is null
};

struct parameter_tags {

    const char * const prefix;      //ie. -a,-d,--std
    const char * const parameter;   //ie. [string]
    const char * const describe;    //ie. show the version of pf
    const int prefix_len;           //prefix's length
    const int parameter_len;        //parameter's length
    const enum parameter_type type; //parameter's type ie.integer
};

int parse_command_line(int argc,char * argv[],struct parameter_tags param[]);

#endif
