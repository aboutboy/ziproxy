/*
 * logstat.h
 *
 *  Created on: Jun 12, 2012
 *      Author: jiangxd
 */

#ifndef SRC_LOGREDUCE_H
#define SRC_LOGREDUCE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LOG_REDUCE

extern int accesslog2_active;
extern int summarylog_active;
extern FILE *accesslog2_file;
extern FILE *summarylog_file;

struct struct_summary_log_item;
struct struct_summary_log_item {
	int count;		/* num. of the log items with the same dport, dport and dip */
	int dport;		/* dport */
	char dip[64];		/* dip */
	char username[100];	/* username */
	char appAgent[256];	/* appAgent */
	char realAgent[64];/* realAgent */
	unsigned int orilength;		/* original length before being compressed */
	unsigned int ziplength;		/* length after being compressed */

	int accessTime;		/* sec part of the accessTime */
	int usec;		/* msec part of the accessTime */
	char ip[64];		/* ip address of the client */
	char url[512];    /* url is the last one url for client */

	struct struct_summary_log_item *next;	/* next item with the same hash value,
						   the memory is allocated/freed dynamically */
} summary_log_item;

struct struct_summary_log_hashtab {
	int magic;
	int count;		/* total num. of all log items exists in the hash table */
	int slots;		/* num. of the slots in this hash table */
	struct struct_summary_log_item *head;	/* the head pointer refers to the hash table of
						   summary_log_item */
} summary_log_hashtab[2];

extern int init_log_reduce();
extern void destroy_log_reduce();
#endif
#endif /* SRC_LOGREDUCE_H */
