/*
 * logstat.c
 *
 *  Created on: Jun 12, 2012
 *      Author: jiangxd
 */
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <limits.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logreduce.h"

#ifdef LOG_REDUCE

#include "cfgfile.h"
#include "log.h"
#include "mmap_api.h"

#define MAGIC_SUMMARY_LOG_HASHTAB_0 1234
#define MAGIC_SUMMARY_LOG_HASHTAB_1 1235

static pid_t logreduce_pid = 0;

extern int *MSG_QUEUE_ACTIVE;

/* body of log reduce process */

/* Fowler/Noll/Vo hash */
/*
 * 32 bit magic FNV-0 and FNV-1 prime
 */
#define FNV_32_PRIME ((unsigned int)0x01000193)

#define FNV0_32_INIT ((unsigned int)0)
#define FNV1_32_INIT ((unsigned int)0x811c9dc5)
#define FNV1_32A_INIT FNV1_32_INIT

/*
 * fnv_32_buf - perform a 32 bit Fowler/Noll/Vo hash on a buffer
 *
 * input:
 *	buf	- start of buffer to hash
 *	len	- length of buffer in octets
 *	hval	- previous hash value or 0 if first call
 *
 * returns:
 *	32 bit hash as a static hash type
 *
 * NOTE: To use the 32 bit FNV-0 historic hash, use FNV0_32_INIT as the hval
 *	 argument on the first call to either fnv_32_buf() or fnv_32_str().
 *
 * NOTE: To use the recommended 32 bit FNV-1 hash, use FNV1_32_INIT as the hval
 *	 argument on the first call to either fnv_32_buf() or fnv_32_str().
 */
unsigned int
fnv_32_buf(void *buf, size_t len, unsigned int hval)
{

    if (buf == NULL)
    {
	error_log_printf (LOGMT_ERROR, LOGSS_DAEMON,
		"fnv_32_buf: NULL buf found len %d hval %d\n",
		len, hval);
        return 0;
    }

    unsigned char *bp = (unsigned char *)buf;	/* start of buffer */
    unsigned char *be = bp + len;		/* beyond end of buffer */

    /*
     * FNV-1 hash each octet in the buffer
     */
    while (bp < be) {

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif

	/* xor the bottom with the current octet */
	hval ^= (unsigned int)*bp++;
    }

    /* return our new hash value */
    return hval;
}


/*
 * fnv_32_str - perform a 32 bit Fowler/Noll/Vo hash on a string
 *
 * input:
 *	str	- string to hash
 *	hval	- previous hash value or 0 if first call
 *
 * returns:
 *	32 bit hash as a static hash type
 *
 * NOTE: To use the 32 bit FNV-0 historic hash, use FNV0_32_INIT as the hval
 *	 argument on the first call to either fnv_32_buf() or fnv_32_str().
 *
 * NOTE: To use the recommended 32 bit FNV-1 hash, use FNV1_32_INIT as the hval
 *	 argument on the first call to either fnv_32_buf() or fnv_32_str().
 */
unsigned int
fnv_32_str(char *str, unsigned int hval)
{
    if (str == NULL)
    {
	error_log_printf (LOGMT_ERROR, LOGSS_DAEMON,
		"fnv_32_str: NULL str found hval %d\n",
		hval);
        return 0;
    }

    unsigned char *s = (unsigned char *)str;	/* unsigned string */

    /*
     * FNV-1 hash each octet in the buffer
     */
    while (*s) {

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif

	/* xor the bottom with the current octet */
	hval ^= (unsigned int)*s++;
    }

    /* return our new hash value */
    return hval;
}

#define hash_buf(s, len, hval) fnv_32_buf(s, len, hval)
#define hash_str(s, hval) fnv_32_str(s, hval)

int write_log_item_to_access_logfile(int msg_index, MSG_Item *msgP)
{

	if (accesslog2_active == 0)
		return 0;

	if (msgP == NULL)
		return -1;

	char str_time[33]={0};
	time_t t=msgP->accesslog.accessTime;
	struct tm *stm=localtime( &t );
	strftime(str_time, sizeof (str_time), "%Y-%m-%d %H:%M:%S",stm);
    fprintf(accesslog2_file,
            "DATA:%s,%d,%s,%s,%d,%s,%s,%d,%d,%s,%s,%s,%s\n",
            str_time,
            (int)(msgP->accesslog.usec),
            msgP->accesslog.username,
            msgP->accesslog.ip,
            (int)msgP->accesslog.dport,
            msgP->accesslog.dip,
            msgP->accesslog.proxytype,
            (int)msgP->accesslog.orilength,
            (int)msgP->accesslog.ziplength,
            msgP->accesslog.requestMethod,
            msgP->accesslog.url,
            msgP->accesslog.userAgent,
            msgP->accesslog.appAgent);

		/*
        fprintf(accesslog2_file,
                "insert into accessLog%d%02d%02d (accessTime,usec,username,ip,dport,dip,proxytype,"
                "orilength,ziplength,requestMethod,url,userAgent,appAgent) VALUES(FROM_UNIXTIME(%d), "
                "%d, '%s', '%s',%d, '%s', '%s', %d, %d, '%s', '%s', '%s', '%s' );\n",
                (int)(msgP->accesslog.year),(int)(msgP->accesslog.month),
		(int)(msgP->accesslog.day),
		(int)(msgP->accesslog.accessTime),
		(int)(msgP->accesslog.usec),
		msgP->accesslog.username,
		msgP->accesslog.ip,
		(int)msgP->accesslog.dport,
		msgP->accesslog.dip,
		msgP->accesslog.proxytype,
		(int)msgP->accesslog.orilength,
		(int)msgP->accesslog.ziplength,
		msgP->accesslog.requestMethod,
		msgP->accesslog.url,
		msgP->accesslog.userAgent,
		msgP->accesslog.appAgent); */
		//msgP->accesslog.realAgent);

	return 0;
}

int write_log_summary_to_summary_logfile(int msg_index, struct struct_summary_log_item *sliP)
{
	if (summarylog_active == 0)
		return 0;

	if (sliP == NULL)
		return -1;

	struct timeval currtime;
	struct tm *logtime;
	gettimeofday (&currtime, NULL);
	time_t t = currtime.tv_sec ;
	logtime = localtime( &t );


	char str_time[33]={0};
	t=sliP->accessTime;
	struct tm *stm=localtime( &t );
	strftime(str_time, sizeof (str_time), "%Y-%m-%d %H:%M:%S",stm);
	fprintf(summarylog_file,
			"DATA:%s,%d,%s,%d,%s,%d,%s,%d,%d,%s,%s\n",
			str_time,
			(int)sliP->usec,
			sliP->ip,
			sliP->count,
			sliP->dip,
			sliP->dport,
			sliP->appAgent,
			sliP->orilength,
			sliP->ziplength,
			sliP->url,
			sliP->username);


	/* cport is used to save the count */
	/*
	fprintf(summarylog_file,
		"insert into accessLog%d%02d%02d (accessTime,usec,ip,cport,dip,dport,appAgent,orilength,ziplength,url,username) VALUES("
		"FROM_UNIXTIME(%d), %d, '%s', %d, '%s', %d, '%s', %d, %d ,'%s' ,'%s');\n",
		(int)(1900+logtime->tm_year),(int)(1+logtime->tm_mon),(int)logtime->tm_mday,
		(int)sliP->accessTime,
		(int)sliP->usec,
		sliP->ip,
		sliP->count,
		sliP->dip,
		sliP->dport,
		sliP->appAgent,
		sliP->orilength,
		sliP->ziplength,
		sliP->url,
		sliP->username);
		*/
		//sliP->realAgent);

	return 0;
}

int is_slot_to_insert(struct struct_summary_log_item *sliP, MSG_Item *msgP)
{
	if (msgP == NULL || sliP == NULL)
		return -1;

#ifdef DEBUG_DETAILS
	debug_log_printf ("is_slot_to_insert: sliP %x msgP %x\n",
		sliP, msgP);
	debug_log_printf ("    sliP: dport %d dip %s appAgent %s\n",
		sliP->dport, sliP->dip, sliP->appAgent);
	debug_log_printf ("    msgP: dport %d dip %s appAgent %s\n",
		msgP->accesslog.dport, msgP->accesslog.dip, msgP->accesslog.appAgent);
#endif

	return (sliP->count == 0 || 		/* new item */
	    (msgP->accesslog.username && strlen(msgP->accesslog.username)>0 ?
	       (
	    	(sliP->username && msgP->accesslog.username &&strncmp(sliP->username, msgP->accesslog.username, 100) == 0) &&
	    	(sliP->appAgent && msgP->accesslog.appAgent &&strncmp(sliP->appAgent, msgP->accesslog.appAgent, 256) == 0)
	       ):
	      (
	       (sliP->dport == msgP->accesslog.dport) &&
	       (sliP->dip && msgP->accesslog.dip && strncmp(sliP->dip, msgP->accesslog.dip, 64) == 0) &&
	       (sliP->appAgent && msgP->accesslog.appAgent && strncmp(sliP->appAgent, msgP->accesslog.appAgent, 256) == 0)
	      )
	    )				/* the same item exists, reuse it */
	   );
}

int copy_domain_from_url(char *pdst,char*psrc)
{
	int res=0;
	int ilen=0;
	int iset=0;
	char *pt=NULL;

	res=ilen=strlen(psrc);
	if(ilen>1){
			iset=strcspn(psrc,"/");
			pt=psrc;
			if(iset>=0){
				if(ilen > iset +2)
					pt=psrc+iset+2;
			}
			iset=strcspn(pt,"/");
			if(iset>=0){
				res=iset;
			}
			memcpy(pdst,pt,res);
	}
	return res;
}


/* insert the log item into the summary hashtab */
int insert_log_item_to_summary_hashtab(int msg_index, MSG_Item *msgP)
{
	char buf[136];
	int hash_index = 0;
	unsigned int hash_value = 0;
	struct struct_summary_log_item *sliP = NULL, *tmp_sliP = NULL;
	int sli_found = 0;

	if (msgP == NULL)
		return -1;
	//deviceid
	if(strlen(msgP->accesslog.username)>0){
		snprintf(buf, 135, "%81s%64s", msgP->accesslog.username, msgP->accesslog.appAgent);
	}else{
		snprintf(buf, 135, "%7d%64s%64s", msgP->accesslog.dport, msgP->accesslog.dip, msgP->accesslog.appAgent);
	}
	buf[135] = '\0';

	/* caculate the hash value */
	hash_value = fnv_32_buf(buf, 134, FNV0_32_INIT);
	hash_index = (int)(hash_value % (unsigned int)summary_log_hashtab[msg_index].slots);

	sliP = summary_log_hashtab[msg_index].head + hash_index;

#ifdef DEBUG_DETAILS
	debug_log_printf ("insert_log_item_to_summary_hashtab: msg_index %d hash_value %x hash_index %d slots %d head %x sliP %x\n",
			msg_index, hash_value, hash_index, summary_log_hashtab[msg_index].slots,
			summary_log_hashtab[msg_index].head, sliP);
#endif

	if (sliP < summary_log_hashtab[msg_index].head ||
            sliP > summary_log_hashtab[msg_index].head + summary_log_hashtab[msg_index].slots)
	{
		/* sliP is not in the right range of the hash table */
		error_log_printf (LOGMT_ERROR, LOGSS_LOGREDUCE, "insert_log_item_to_summary_hashtab: sliP in wrong range msg_index %d head %x tail %x sliP %x\n",
			msg_index,
			summary_log_hashtab[msg_index].head,
			summary_log_hashtab[msg_index].head + summary_log_hashtab[msg_index].slots,
			sliP);
		return -1;
	}

	if (is_slot_to_insert(sliP, msgP))
	{
		/* insert the log item here */
		sli_found = 1;
	}
	else
	{
		/* different items with the same hash value */
		/* loop through the chain by next pointer to find the tail */
		while (sliP->next)
		{
			sliP = sliP->next;
			if (is_slot_to_insert(sliP, msgP))
			{
				sli_found = 1;
				break;
			}
		}
	}

	if (sli_found == 0)
	{
		/* not existing log item found, it should be a new item with
		   the same hash value, allocate a new one and attach it to
		   the tail of the chain */
		tmp_sliP = (struct struct_summary_log_item *)malloc(sizeof(struct struct_summary_log_item));
		if (tmp_sliP == NULL)
		{
			/* failed, no mem? */
			debug_log_printf ("insert_log_item_to_summary_hashtab: malloc failed %s\n",
				strerror(errno));
			return -1;
		}
		bzero(tmp_sliP, sizeof(struct struct_summary_log_item));
		sliP->next = tmp_sliP;
		sliP = sliP->next;
		sliP->next = NULL;
	}

	/* now we get the correct place to insert the log item in sliP */
	sliP->dport = msgP->accesslog.dport;
	sliP->count += 1;
	if(sliP->orilength < (UINT_MAX-msgP->accesslog.orilength))
	sliP->orilength += msgP->accesslog.orilength;
	if(sliP->ziplength < (UINT_MAX-msgP->accesslog.ziplength))
	sliP->ziplength += msgP->accesslog.ziplength;
	memcpy(sliP->dip, msgP->accesslog.dip, 64);
	memcpy(sliP->appAgent, msgP->accesslog.appAgent, 256);
	memcpy(sliP->realAgent, msgP->accesslog.realAgent, 64);
	//need domain not url
	memcpy(sliP->url, msgP->accesslog.url, 512);
	//memset(sliP->url,0,512);
	//copy_domain_from_url(sliP->url,msgP->accesslog.url);
	memcpy(sliP->username,msgP->accesslog.username,100);

	sliP->accessTime = (int)msgP->accesslog.accessTime;
	sliP->usec = (int)msgP->accesslog.usec;
	memcpy(sliP->ip, msgP->accesslog.ip, 64);

	/* update the summary_log_hashtab count */
	summary_log_hashtab[msg_index].count += 1;

#ifdef DEBUG_DETAILS
	debug_log_printf ("insert_log_item_to_summary_hashtab: msg_index %d allcount %d sliP %x count %d dport %d dip %s appAgent %s\n",
		msg_index, summary_log_hashtab[msg_index].count, sliP,
		sliP->count, sliP->dport, sliP->dip, sliP->appAgent);
#endif

	return 0;
}

/* summary the logitems fro mthe summary_log_hashtab, and write it to
 * the summary access log file */
int summary_logitems_in_hashtab(msg_index)
{
	int li_count = 0;
	int i = 0;
	int code = 0;
	struct struct_summary_log_item *sliP = NULL, *tmp_sliP = NULL, *save_sliP = NULL;

#ifdef DEBUG_DETAILS
	debug_log_printf ("summary_logitems_in_hashtab: enter msg_index %d slots %d \n",
		msg_index,summary_log_hashtab[msg_index].slots);
#endif
	if (! summary_log_hashtab[msg_index].head)
	{
		error_log_printf (LOGMT_ERROR, LOGSS_DAEMON,
			"summary_logitems_in_hashtab: NULL head found summary_log_hashtab[%d].head\n",
			msg_index);
	}

	for (i=0; i<summary_log_hashtab[msg_index].slots; i++)
	{
		/* move sliP to the next slot */
		sliP = summary_log_hashtab[msg_index].head + i;
		if (sliP->count > 0)
		{
			/* a valid log item found */
			li_count += sliP->count;
			code = 1;
#ifdef DEBUG_DETAILS
			debug_log_printf ("summary_logitems_in_hashtab: item found sliP %x count %d index %d code %d\n",
				sliP, sliP->count, i, code);
#endif
			/* FIXME: write it to the summary access log file */
			write_log_summary_to_summary_logfile(msg_index, sliP);

			save_sliP = sliP;
			tmp_sliP = sliP->next;
			while (tmp_sliP)
			{
				/* go through the chain with the same hash value */
				sliP = tmp_sliP;
				if (sliP->count > 0)
				{
					/* a valid log item found */
					li_count += sliP->count;
					code = 3;
#ifdef DEBUG_DETAILS
					debug_log_printf ("summary_logitems_in_hashtab: item found sliP %x count %d index %d code %d\n",
					sliP, sliP->count, i, code);
#endif
					/* FIXME: write it to the summary access log file */
					write_log_summary_to_summary_logfile(msg_index, sliP);
				}
				else if (sliP->next)
				{
					/* error happens, an invalid item has the next pointer
			   		   which should never happen */
					code = 4;
					debug_log_printf ("summary_logitems_in_hashtab: invalid item has the next pointer code %d\n",
					code);

					break;
				}

				/* save the next pointer to tmp_sliP */
				tmp_sliP = sliP->next;
				/* free sliP */
				if (sliP)
				{
					free(sliP);
					sliP = NULL;
				}
			}
			/* the current slot has been processed, so free it */
			save_sliP->next = NULL;
			save_sliP->count = 0;
		}
		else if (sliP->next)
		{
			/* error happens, an invalid item has the next pointer
			   which should never happen */
			code = 2;
			debug_log_printf ("summary_logitems_in_hashtab: invalid item has the next pointer code %d\n",
				code);
		}
	}

	if (li_count != summary_log_hashtab[msg_index].count)
	{
		/* the count in summary_log_hashtab/hashtab don't match */
		debug_log_printf ("summary_logitems_in_hashtab: summary_log_hashtab[%d].count %d li_count %d\n",
			msg_index, summary_log_hashtab[msg_index].count, li_count);
	}
	else
	{
		/* the count in summary_log_hashtab/hashtab do match */
		debug_log_printf ("summary_logitems_in_hashtab: summary_log_hashtab[%d].count %d li_count %d\n",
			msg_index, summary_log_hashtab[msg_index].count, li_count);
	}
	debug_log_printf ("summary_logitems_in_hashtab: exit msg_index %d head %x li_count %d count %d slots %d code %d\n",
		msg_index, summary_log_hashtab[msg_index].head, li_count, summary_log_hashtab[msg_index].count,
		summary_log_hashtab[msg_index].slots, code);
}

/* main body of the log reduce process */
int process_msgqueue(int msg_index, int needwait)
{
	int msg_count = 0;
	int msg_count_save = -1;
	struct timeval stime, ctime, ttime, etime;
	int sec_passed;
	MSG_Item msg;
	int rc = 0;

	if (! needwait)
		debug_log_printf ("process_msgqueue: enter msg_index %d\n",
			msg_index);

	msg_count = 0;
	gettimeofday(&stime, NULL);

retry_msg_receive:
	bzero(&ttime, sizeof(ttime));
	gettimeofday(&ttime, NULL);
	while ( (rc = MSG_Recv(msg_index, &msg, sizeof(MSG_Item))) > 0 )
	{
#ifdef DEBUG_DETAILS
		debug_log_printf ("log_reduce_body: after MSG_Recv msg_index %d MSG_QUEUE_ACTIVE %x(%d)\n",
			msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#endif

		/* receive a new message from the msgqueue */
		msg_count++;
		/* To do, real process on the msg received */
		/* insert the msg/log item to the summary hash table */
		insert_log_item_to_summary_hashtab(msg_index, &msg);
		/* write it to the access log file */
		write_log_item_to_access_logfile(msg_index, &msg);
	}
	if (rc < 0)
	{
		/* error happens */
		error_log_printf (LOGMT_ERROR, LOGSS_DAEMON,
			"log_reduce_body: MSG_Recv return rc %d\n",
			rc);
	}
	gettimeofday(&ctime, NULL);
	/* rc == 0; no more message avaiable in the msgqueue */
	if (rc == 0 && msg_count_save != msg_count)
	{
#ifdef DEBUG_DETAILS
		debug_log_printf ("log_reduce_body: details after receiving msgmsg_count %d "
			"msg_count_save %d from msgqueue %d time spent %f "
			"ctime sec %d usec %d ttime sec %d usec %d\n",
			msg_count, msg_count_save, msg_index,
			// (float)((float)(ZP_TIMEVAL_TYPE)timeval_subtract_us(&ctime, &ttime) / 1000000.0) );
			((float)((ctime.tv_sec - ttime.tv_sec)*1000000 + ctime.tv_usec - ttime.tv_usec)) / 1000000.0,
			ctime.tv_sec, ctime.tv_usec, ttime.tv_sec, ttime.tv_usec);
#endif
		msg_count_save = msg_count;
	}
	sec_passed = timeval_subtract_us(&ctime, &stime);
#ifdef DEBUG_DETAILS
	debug_log_printf ("log_reduce_body: sec_passed in msgqueue %d LogReduceInterval %d msg_index %d MSG_QUEUE_ACTIVE %x(%d)\n",
		sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#endif
	if (sec_passed > LogReduceInterval * 500000)
		error_log_printf (LOGMT_WARN, LOGSS_DAEMON,
			"log_reduce_body: sec_passed in msgqueue %d LogReduceInterval %d msg_index %d "
			"MSG_QUEUE_ACTIVE %x(%d)\n",
			sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#if 0
	if (sec_passed / 1000000 < LogReduceInterval)
	{
		if (needwait)
		{
			sleep(1);
			goto retry_msg_receive;
		}
	}
	else
	{
		debug_log_printf ("log_reduce_body: recycle after receiving msgmsg_count %d "
			"from msgqueue %d time spent %f\n",
			msg_count, msg_index, (float)((float)sec_passed / 1000000.0) );
	}
#endif
	sec_passed = (sec_passed + 500000) / 1000000;
	if (needwait)
		sleep(LogReduceInterval - sec_passed);
		gettimeofday(&ctime, NULL);
	summary_logitems_in_hashtab(msg_index);
	gettimeofday(&etime, NULL);
	sec_passed = timeval_subtract_us(&etime, &ctime);
#ifdef DEBUG_DETAILS
	debug_log_printf ("log_reduce_body: sec_passed in hashtab %d LogReduceInterval %d msg_index %d MSG_QUEUE_ACTIVE %x(%d)\n",
		sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#endif
	if (sec_passed > LogReduceInterval * 500000)
		debug_log_printf ("log_reduce_body: sec_passed in hashtab %d LogReduceInterval %d msg_index %d "
			"MSG_QUEUE_ACTIVE %x(%d)\n",
			sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
		/* cleanup the current summary_log_hashtab and the shared memory for summary_log_item */
	summary_log_hashtab[msg_index].count = 0;
	bzero(summary_log_hashtab[msg_index].head,
		sizeof(struct struct_summary_log_item) * summary_log_hashtab[msg_index].slots);

	if (! needwait)
		debug_log_printf ("process_msgqueue: exit msg_index %d\n",
			msg_index);

	return 0;
}

/* main body of the log reduce process */
void log_reduce_body()
{
	/* msg_index in log reduce process is different with the deamon */
	int msg_index = 1;
	int needwait = 1;

	while (1)
	{
		process_msgqueue(msg_index, needwait);
		/* switch to the other msg queue */
		*MSG_QUEUE_ACTIVE += 1;
		msg_index = ((*MSG_QUEUE_ACTIVE) + 1) % MSG_MAX_NUMS;
		debug_log_printf ("log_reduce_body: switch to the msg_index %d *MSG_QUEUE_ACTIVE %d\n",
			msg_index, *MSG_QUEUE_ACTIVE);
	}
}

/* main body of the log reduce process */
int log_reduce_body_orig()
{
	int msg_count = 0;
	int msg_count_save = -1;
	struct timeval stime, ctime, ttime, etime;
	int sec_passed;
	MSG_Item msg;
	int rc = 0;
	/* msg_index in log reduce process is different with the deamon */
	int msg_index = 1;

	while (1)
	{
		msg_count = 0;
		gettimeofday(&stime, NULL);

retry_msg_receive:
		bzero(&ttime, sizeof(ttime));
		gettimeofday(&ttime, NULL);
		while ( (rc = MSG_Recv(msg_index, &msg, sizeof(MSG_Item))) > 0 )
		{
#ifdef DEBUG_DETAILS
			debug_log_printf ("log_reduce_body: after MSG_Recv msg_index %d MSG_QUEUE_ACTIVE %x(%d)\n",
				msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#endif

			/* receive a new message from the msgqueue */
			msg_count++;
			/* To do, real process on the msg received */
			/* insert the msg/log item to the summary hash table */
			insert_log_item_to_summary_hashtab(msg_index, &msg);
			/* write it to the access log file */
			write_log_item_to_access_logfile(msg_index, &msg);
		}
		if (rc < 0)
		{
			/* error happens */
			error_log_printf (LOGMT_ERROR, LOGSS_DAEMON,
				"log_reduce_body: MSG_Recv return rc %d\n",
				rc);
		}

		gettimeofday(&ctime, NULL);
		/* rc == 0; no more message avaiable in the msgqueue */
		if (rc == 0 && msg_count_save != msg_count)
		{
#ifdef DEBUG_DETAILS
			debug_log_printf ("log_reduce_body: details after receiving msgmsg_count %d "
				"msg_count_save %d from msgqueue %d time spent %f "
				"ctime sec %d usec %d ttime sec %d usec %d\n",
				msg_count, msg_count_save, msg_index,
				// (float)((float)(ZP_TIMEVAL_TYPE)timeval_subtract_us(&ctime, &ttime) / 1000000.0) );
				((float)((ctime.tv_sec - ttime.tv_sec)*1000000 + ctime.tv_usec - ttime.tv_usec)) / 1000000.0,
				ctime.tv_sec, ctime.tv_usec, ttime.tv_sec, ttime.tv_usec);
#endif
			msg_count_save = msg_count;
		}
		sec_passed = timeval_subtract_us(&ctime, &stime);
#ifdef DEBUG_DETAILS
		debug_log_printf ("log_reduce_body: sec_passed in msgqueue %d LogReduceInterval %d msg_index %d MSG_QUEUE_ACTIVE %x(%d)\n",
			sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#endif
		if (sec_passed > LogReduceInterval * 500000)
			debug_log_printf ("log_reduce_body: sec_passed in msgqueue %d LogReduceInterval %d msg_index %d "
				"MSG_QUEUE_ACTIVE %x(%d)\n",
				sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#if 0
		if (sec_passed / 1000000 < LogReduceInterval)
		{
			sleep(1);
			goto retry_msg_receive;
		}
		else
		{
			debug_log_printf ("log_reduce_body: recycle after receiving msgmsg_count %d "
				"from msgqueue %d time spent %f\n",
				msg_count, msg_index, (float)((float)sec_passed / 1000000.0) );
		}
#endif
		sec_passed = (sec_passed + 500000) / 1000000;
		sleep(LogReduceInterval - sec_passed);

		gettimeofday(&ctime, NULL);
		summary_logitems_in_hashtab(msg_index);
		gettimeofday(&etime, NULL);
		sec_passed = timeval_subtract_us(&etime, &ctime);
#ifdef DEBUG_DETAILS
		debug_log_printf ("log_reduce_body: sec_passed in hashtab %d LogReduceInterval %d msg_index %d MSG_QUEUE_ACTIVE %x(%d)\n",
			sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#endif
		if (sec_passed > LogReduceInterval * 500000)
			debug_log_printf ("log_reduce_body: sec_passed in hashtab %d LogReduceInterval %d msg_index %d "
				"MSG_QUEUE_ACTIVE %x(%d)\n",
				sec_passed, LogReduceInterval, msg_index, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);

		/* cleanup the current summary_log_hashtab and the shared memory for summary_log_item */
		summary_log_hashtab[msg_index].count = 0;
		bzero(summary_log_hashtab[msg_index].head,
			sizeof(struct struct_summary_log_item) * summary_log_hashtab[msg_index].slots);

		/* switch to the other msg queue */
		*MSG_QUEUE_ACTIVE += 1;
		msg_index = ((*MSG_QUEUE_ACTIVE) + 1) % MSG_MAX_NUMS;
		debug_log_printf ("log_reduce_body: switch to the msg_index %d *MSG_QUEUE_ACTIVE %d\n",
			msg_index, *MSG_QUEUE_ACTIVE);
	}
}

void destroy_log_reduce() {
	if (logreduce_pid) {
		kill(logreduce_pid,SIGTERM);
		int status;
		waitpid(logreduce_pid,&status,0);
	}
}

/*
 * initialize for the log reduce, including:
 * create the shared/memory, message queue
 * fork the seperate process to summarize the access log
 *
 * return code:
 *   0 on success
 *   -1 on failure
 */
int init_log_reduce()
{
	int msgid[2];
	int i;
	pid_t pid;
/*
	int* _random_index = (int*)MMAP_Get_Address(INDEX_RANDOM);
	*_random_index = 0;

	sem_t* sem_mutex = (sem_t*)MMAP_Get_Address(MUTEX_IDNEX);

	int sem_ret = sem_init(sem_mutex, 1, 1);
	error_log_printf (LOGMT_INFO, LOGSS_DAEMON,
		"init_log_reduce: _random_index %x with key %x "
		"sem_mutex %xi with key %x\n",
		_random_index, INDEX_RANDOM, sem_mutex, MUTEX_IDNEX);
*/


fork_retry:
	switch(pid = fork())
	{
	case 0:
		/* CHILD */
		/* we don't want children using daemon's SIGTERM handler */
		// ������ɱ��
		prctl(PR_SET_NAME, "ziproxy_log", NULL, NULL, NULL);

		signal (SIGTERM, SIG_DFL);

		debug_log_puts("in child\n");
		if ( !(MSG_QUEUE_ACTIVE = (int *)MMAP_Get_Address(MSG_QUEUE))) {
			error_log_printf(LOGMT_INFO, LOGSS_DAEMON,"init_log_reduce: Cannot get mmap address\n");
			return -1;
		}
		*MSG_QUEUE_ACTIVE = 0;
		debug_log_printf ("init_log_reduce: MSG_QUEUE_ACTIVE %x (%d) with key %x\n",
			MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE, MSG_QUEUE);

		for (i=0; i<MSG_MAX_NUMS; i++)
		{
			msgid[i] = MSG_Init(i);
			if (msgid[i] < 0)
			{
				debug_log_printf ("init_log_reduce: failed: msgqueue %d with msgid %d error %s\n",
					i, msgid[i], strerror(errno));
				return -1;
			}
			else
			{
				debug_log_printf ("init_log_reduce: msgqueue %d with msgid %d\n",
					i, msgid[i]);
			}
		}

		/* prepare the hashtab used for summary logs */
		for (i=0; i<MSG_MAX_NUMS; i++)
		{
			struct struct_summary_log_item *sliP = NULL;
			if (! (summary_log_hashtab[i].head = malloc(sizeof(struct struct_summary_log_item) * MaxSummarySlots)) )
			{
				debug_log_printf ("init_log_reduce: failed to malloc for MaxSummarySlots %d of summary_log_item %d\n",
					MaxSummarySlots, sizeof(struct struct_summary_log_item));
				return -1;
			}

			summary_log_hashtab[i].magic = MAGIC_SUMMARY_LOG_HASHTAB_0 + i;
			summary_log_hashtab[i].count = 0;
			summary_log_hashtab[i].slots = MaxSummarySlots;
			bzero(summary_log_hashtab[i].head, sizeof(struct struct_summary_log_item) * MaxSummarySlots);

			int j = 0;
			for (j=0; j<MaxSummarySlots; j++)
			{
				sliP = summary_log_hashtab[i].head + j;
				sliP->count = 0;
				sliP->next = NULL;
			}

			debug_log_printf ("init_log_reduce: malloc head: %x for MaxSummarySlots %d of summary_log_item %d\n",
				summary_log_hashtab[i].head, MaxSummarySlots, sizeof(struct struct_summary_log_item));
		}

		log_reduce_body();
		for (i=0; i<MSG_MAX_NUMS; i++) {
			if (summary_log_hashtab[i].head) {
				free(summary_log_hashtab[i].head);
				summary_log_hashtab[i].head = NULL;
			}
		}
		break;
	case -1:
		/* ERROR */
		error_log_puts (LOGMT_ERROR, LOGSS_DAEMON, "Fork() failed, waiting then retrying...\n");

		/* collect terminated child procs */
		while (waitpid (-1, NULL, WNOHANG) > 0) {
			/* do nothing here */
		}

		/* sleep a bit, to avoid busy-looping the machine,
		   just in case this fork() failure is due
		   to something more serious */
		sleep (1);

		goto fork_retry;
		break;
	default:
		/* PARENT */
		debug_log_printf ("init_log_reduce: fork the reduce log process with pid %d\n",
			pid);
		logreduce_pid = pid;
		break;
	}

	return 0;
}
#endif
