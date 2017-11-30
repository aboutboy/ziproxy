/*
 * usettings_process.h
 *
 *  Created on: Jul 17, 2012
 *      Author: Eric Jiang (jxd431@gmail.com)
 */

#ifndef USETTINGS_PROCESS_H_
#define USETTINGS_PROCESS_H_

#ifdef USER_SETTINGS
#include "session.h"

extern unsigned char REQUEST_SIGNATURE[4];

/**
 * create user settings fetcher process
 */
extern int init_usprocess();

extern int get_hosts_fromjson(server_host_ip shp[],int imax,char * );

extern char* get_host_fromip(server_host_ip shp[],int imax,const char * ipbuf);

#endif
#endif /* USETTINGS_PROCESS_H_ */
