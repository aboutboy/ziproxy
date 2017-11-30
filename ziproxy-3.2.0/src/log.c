/* log.c
 * Convenient logging functions.
 *
 * Ziproxy - the HTTP acceleration proxy
 * This code is under the following conditions:
 *
 * ---------------------------------------------------------------------
 * Copyright (c)2005-2010 Daniel Mealha Cabrita
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111 USA
 * ---------------------------------------------------------------------
 *
 * This code also contains portions under the following conditions:
 *
 * ---------------------------------------------------------------------
 * Copyright (c) Juraj Variny, 2004
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY JURAJ VARINY
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ---------------------------------------------------------------------
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include "log.h"
#include "globaldefs.h"
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "mmap_api.h"

static struct timeval debuglog_newtime, debuglog_oldtime;

static int debuglog_active = 0;
static FILE *debuglog_file = NULL;
static pid_t debuglog_pid;

static int accesslog_active = 0;
static FILE *accesslog_file = NULL;
#ifdef LOG_REDUCE
int accesslog2_active = 0;
int summarylog_active = 0;
FILE *accesslog2_file = NULL;
FILE *summarylog_file = NULL;
#endif
static struct timeval accesslog_giventime;

static char *accesslog_client_addr = NULL;
static char *accesslog_dip = NULL;
static unsigned short accesslog_port = 0;
static char *accesslog_username = NULL;
static char *accesslog_method = NULL;
static char *accesslog_user_agent = NULL;  //added by lidiansen
static char *accesslog_realuser_agent = NULL;
static char *accesslog_url = NULL;
static ZP_FLAGS accesslog_flags;
ZP_DATASIZE_TYPE accesslog_inlen;
ZP_DATASIZE_TYPE accesslog_outlen;

static int errorlog_active = 0;	/* !=0 if calls to error_log are to be honored */
static FILE *errorlog_file = NULL;
static int errorlog_file_is_stderr = 1;	/* !=0 if we're using stderr instead of a regular file */

static void access_log_redefine_str_var (const char *given_str, char **given_var);

// static ZP_TIMEVAL_TYPE timeval_subtract_us (struct timeval *x, struct timeval *y);
void debug_log_goodbye (void);

/*
 * MISCELLANEOUS ROUTINES ##############################
 */

/* subtracts time structures and return the result in micro-seconds
   x - the current, or most recent time
   y - the original, previous, time
   result = x - y */
//static ZP_TIMEVAL_TYPE timeval_subtract_us (struct timeval *x, struct timeval *y)
ZP_TIMEVAL_TYPE timeval_subtract_us (struct timeval *x, struct timeval *y)
{
	ZP_TIMEVAL_TYPE usec_part;
	ZP_TIMEVAL_TYPE sec_part;

	usec_part = x->tv_usec - y->tv_usec;
	sec_part = x->tv_sec - y->tv_sec;

	return ((1000000 * sec_part) + usec_part);
}

int replace_char(char *sSrc, char cMatchChar, char cReplaceChar)
{
	char *p = sSrc;
	while (p && *p)
	{
		if (*p == cMatchChar)
		{
			*(sSrc + (p - sSrc)) = cReplaceChar;
		}
		p++;
	}
	return 0;
}
/*
 * DEBUG LOG ##############################
 */

/*
 *  there's no "debug_log_close" function
 * when a process finishes, the file handler is automatically
 * closed by the OS
 */
/* returns: ==0,ok !=0,error */
int debug_log_init (const char *debuglog_filename)
{
	time_t tm;
	
	if (debuglog_filename != NULL) {
		if ((debuglog_file = fopen (debuglog_filename, "a")) != NULL) {
			debuglog_pid = getpid ();
			time(&tm);

			//set line buffered mode for debuglog_file
			setvbuf (debuglog_file, NULL, _IOLBF, BUFSIZ);
	
			fprintf (debuglog_file, "[%d] Starting - %s", (int) debuglog_pid, ctime (&tm));
			gettimeofday (&debuglog_oldtime,NULL);
			atexit (debug_log_goodbye);

			debuglog_active = 1;
			return (0);
		}
		return (1);
	}
	return (0);
}

void debug_log_set_pid_current (void) {
	if (! debuglog_active)
		return;
	debuglog_pid = getpid ();
}

int debug_log_printf (char *fmt, ...)
{
	va_list ap;
	int i;
	if (! debuglog_active) return 0;
	va_start(ap, fmt);
	fprintf (debuglog_file, "[%d] ", (int) debuglog_pid);
	i = vfprintf (debuglog_file, fmt, ap);
	va_end(ap);
	return i;
}

void debug_log_puts (char *str)
{
	if (! debuglog_active) return;
	time_t t_now = time(NULL);
	struct tm* t_info = localtime(&t_now);
	fprintf (debuglog_file, "[%04d-%02d-%02d %02d:%02d:%02d][%d] %s\n", t_info->tm_year+1900, t_info->tm_mon+1, t_info->tm_mday, t_info->tm_hour, t_info->tm_min, t_info->tm_sec, (int) debuglog_pid, str);
}

void debug_log_puts_hdr (char *str)
{
	if (! debuglog_active) return;
	time_t t_now = time(NULL);
	struct tm* t_info = localtime(&t_now);
	fprintf (debuglog_file, "[%04d-%02d-%02d %02d:%02d:%02d][%d]    %s\n", t_info->tm_year+1900, t_info->tm_mon+1, t_info->tm_mday, t_info->tm_hour, t_info->tm_min, t_info->tm_sec, (int) debuglog_pid, str);
}

void debug_log_reset_difftime (void)
{
	gettimeofday (&debuglog_oldtime, NULL);
}

void debug_log_difftime (char *activity)
{
	if (! debuglog_active) return;
	gettimeofday (&debuglog_newtime, NULL);
	fprintf (debuglog_file, "[%d] %s took %" ZP_TIMEVAL_STR  " us. \n", 
			(int) debuglog_pid, activity,
			timeval_subtract_us (&debuglog_newtime, &debuglog_oldtime));
	gettimeofday (&debuglog_oldtime, NULL);

}

void debug_log_goodbye (void)
{
	debug_log_puts ("Finished.");
}

/*
 * ACCESS LOG ##############################
 */

/* returns: ==0,ok !=0,error */
/* Note: for each HTTP request access_log_reset() must be invoked */
int access_log_init (const char *accesslog_filename)
{
	if (accesslog_filename != NULL) {
		if ((accesslog_file = fopen (accesslog_filename, "a")) != NULL) {
			// set line buffered mode for access accesslog_file
			setvbuf (accesslog_file, NULL, _IOLBF, BUFSIZ);
			accesslog_active = 1;
			return (0);
		}
		return (1);	
	}
	return (0);
}

#ifdef LOG_REDUCE
int access_log2_init (const char *accesslog2_filename)
{
	if (accesslog2_filename != NULL) {
		if ((accesslog2_file = fopen (accesslog2_filename, "a")) != NULL) {
			// set line buffered mode for access accesslog2_file
			setvbuf (accesslog2_file, NULL, _IOLBF, BUFSIZ);
			accesslog2_active = 1;
			return (0);
		}
		return (1);	
	}
	return (0);
}

int summary_log_init (const char *summarylog_filename)
{
	if (summarylog_filename != NULL) {
		if ((summarylog_file = fopen (summarylog_filename, "a")) != NULL) {
			// set line buffered mode for access summarylog_file
			setvbuf (summarylog_file, NULL, _IOLBF, BUFSIZ);
			summarylog_active = 1;
			return (0);
		}
		return (1);	
	}
	return (0);
}
#endif

/* Initialize the vars for the current HTTP request.
   This function must be invoked for each HTTP request. */
void access_log_reset (void)
{
	if (accesslog_active == 0)
		return;

	access_log_define_client_adrr (NULL);
	access_log_define_client_port (0);
	access_log_define_username (NULL);
	access_log_define_dip (NULL);
	access_log_define_method (NULL);
	access_log_define_url (NULL);
	access_log_define_UA (NULL); //added by lidiansen

	gettimeofday (&accesslog_giventime, NULL);

	accesslog_inlen = 0;
	accesslog_outlen = 0;
	accesslog_flags = LOG_AC_FLAG_NONE;
}

static void access_log_redefine_str_var (const char *given_str, char **given_var)
{
	/* free previous string (if previously allocated) */
	if (*given_var != NULL)
		free (*given_var);

	if (given_str != NULL)
		*given_var = strdup (given_str);
	else
		*given_var = NULL;
}

void access_log_define_client_adrr (const char *client_addr)
{
	if (accesslog_active == 0)
		return;

	access_log_redefine_str_var (client_addr, &accesslog_client_addr);
}

void access_log_define_dip (const char *dip)
{
	if (accesslog_active == 0)
		return;

	access_log_redefine_str_var (dip, &accesslog_dip);
}

void access_log_define_client_port (unsigned short client_port)
{
	if (accesslog_active == 0)
		return;

	accesslog_port = client_port;
}

void access_log_define_username (const char *username)
{
	if (accesslog_active == 0)
		return;

	access_log_redefine_str_var (username, &accesslog_username);
}

void access_log_define_UA ( const char *user_agent) //added by lidiansen
{
	if( accesslog_active == 0 )
		return;

	if( user_agent == NULL)
		return;

	//char * ua = strchr ( user_agent, '/');

	//if( ua != NULL )
	//accesslog_user_agent = strndup( user_agent, strlen(user_agent) -strlen(ua) );
	access_log_redefine_str_var (user_agent, &accesslog_user_agent);
}

void access_log_define_relUA(const char *realuser_agent)
{
	if( accesslog_active == 0 )
		return;

	if( realuser_agent == NULL)
		return;

	access_log_redefine_str_var (realuser_agent, &accesslog_realuser_agent);
}

void access_log_define_method (const char *method)
{
	if (accesslog_active == 0)
		return;

	access_log_redefine_str_var (method, &accesslog_method);
}

void access_log_define_url (const char *url)
{
	if (accesslog_active == 0)
		return;

	access_log_redefine_str_var (url, &accesslog_url);
}

/* al_flags will be OR'ed to the current accesslog_flags */
void access_log_set_flags (ZP_FLAGS given_flags)
{
	accesslog_flags |= given_flags;
}

/* al_flags will be zero'ed in the accesslog_flags */
void access_log_unset_flags (ZP_FLAGS given_flags)
{
	accesslog_flags |= given_flags;
	accesslog_flags ^= given_flags;
}

ZP_FLAGS access_log_get_flags (void)
{
	return (accesslog_flags);
}

void access_log_dump_entry (void)
{
	char flags_str [32];
	int has_client_addr = 0;
	int has_username = 0;
	int has_method = 0;
	int has_url = 0;
	struct timeval currtime;
	struct tm *logtime;
	ZP_TIMEVAL_TYPE time_spent_msec;
	char client_source [256];	/* string composed of: [username@]<IP|"?"> */
#ifdef LOG_REDUCE
	MSG_Item msg;
	int msgid;
#endif

	/* Access logs have at least 'T' or 'P' flag set to be considered valid.
	   This function may be called prematurely before proper flag initialization
	   (a crash - which forces accesslog dump - occuring during early stages). */
	if ( ((accesslog_active == 0) || (accesslog_flags == LOG_AC_FLAG_NONE))
#ifdef LOG_REDUCE
			&& (summarylog_active == 0)
#endif
	   )
		return;

	gettimeofday (&currtime, NULL);
	time_spent_msec = timeval_subtract_us (&currtime, &accesslog_giventime) / 1000;
	
	if (accesslog_client_addr != NULL)
		has_client_addr = 1;
	if (accesslog_username != NULL)
		has_username = 1;
	if (accesslog_method != NULL)
		has_method = 1;
	if (accesslog_url != NULL)
		has_url = 1;
	
	flags_str[0]='\0';

	if (accesslog_flags & LOG_AC_FLAG_TRANSP_PROXY) strcat (flags_str, "T");
	if (accesslog_flags & LOG_AC_FLAG_CONV_PROXY) strcat (flags_str, "P");
	if (accesslog_flags & LOG_AC_FLAG_TOS_CHANGED) strcat (flags_str, "Q");
	if (accesslog_flags & LOG_AC_FLAG_CONN_METHOD) strcat (flags_str, "S");
	if (accesslog_flags & LOG_AC_FLAG_BROKEN_PIPE) strcat (flags_str, "B");
	if (accesslog_flags & LOG_AC_FLAG_IMG_TOO_EXPANSIVE) strcat (flags_str, "K");
	if (accesslog_flags & LOG_AC_FLAG_LLCOMP_TOO_EXPANSIVE) strcat (flags_str, "G");
	if (accesslog_flags & LOG_AC_FLAG_XFER_TIMEOUT) strcat (flags_str, "Z");
	if (accesslog_flags & LOG_AC_FLAG_URL_NOTPROC) strcat (flags_str, "N");
	if (accesslog_flags & LOG_AC_FLAG_TOOBIG_NOMEM) strcat (flags_str, "W");
	if (accesslog_flags & LOG_AC_FLAG_REPLACED_DATA) strcat (flags_str, "R");
	if (accesslog_flags & LOG_AC_FLAG_SIGSEGV) strcat (flags_str, "1");
	if (accesslog_flags & LOG_AC_FLAG_SIGFPE) strcat (flags_str, "2");
	if (accesslog_flags & LOG_AC_FLAG_SIGILL) strcat (flags_str, "3");
	if (accesslog_flags & LOG_AC_FLAG_SIGBUS) strcat (flags_str, "4");
	if (accesslog_flags & LOG_AC_FLAG_SIGSYS) strcat (flags_str, "5");
	if (accesslog_flags & LOG_AC_FLAG_SIGTERM) strcat (flags_str, "X");
	if (accesslog_flags & LOG_AC_SOFTWARE_BUG) strcat (flags_str, "*");

/*
	client_source [255] = '\0';
	snprintf (client_source, 255, "%s %s", has_username?accesslog_username:"unknown", has_client_addr?accesslog_client_addr:"0.0.0.0");

	fprintf (accesslog_file,
		"%"ZP_TIMEVAL_STR".%03"ZP_TIMEVAL_STR" %6"ZP_TIMEVAL_STR" %15s %2s %6"ZP_DATASIZE_STR" %6"ZP_DATASIZE_STR" %s %s %s\n",
		(ZP_TIMEVAL_TYPE) currtime.tv_sec,
		(ZP_TIMEVAL_TYPE) currtime.tv_usec / 1000,
		(ZP_TIMEVAL_TYPE) time_spent_msec, client_source, flags_str, accesslog_inlen, accesslog_outlen,
		has_method?accesslog_method:"?",
		has_url?accesslog_url:"?",
		accesslog_user_agent);  //add by lidiansen
*/

	char accesslog_app_agent[1024];
	memset(accesslog_app_agent, 0, 1024);
	if(accesslog_user_agent!=NULL)
	{
		int index=0;
		/*
		while(accesslog_user_agent[index]!='\0')
		{
			if( accesslog_user_agent[index] == '/' )
			{
				accesslog_user_agent[index] = '\0';
				break;
			}
			index++;

		}
		if(index>=64) index=64;
		if( strstr(accesslog_user_agent,"_weibo_") != NULL ) //find sina weibo key word
			strcpy(accesslog_app_agent,"weibo");
		else
			strncpy(accesslog_app_agent, accesslog_user_agent, index);
			*/
		strcpy(accesslog_app_agent, accesslog_user_agent);
		
	}
	else
	{
		accesslog_app_agent[0] = '\0';
	}

	time_t t = currtime.tv_sec ;
	logtime = localtime( &t );

	replace_char(accesslog_url,'\'','"');
	replace_char(accesslog_user_agent,'\'','"');
	replace_char(accesslog_app_agent,'\'','"');


	replace_char(accesslog_url,',',' ');
	replace_char(accesslog_user_agent,',',' ');
	replace_char(accesslog_app_agent,',',' ');

	replace_char(accesslog_url,'{',' ');
	replace_char(accesslog_user_agent,'{',' ');
	replace_char(accesslog_app_agent,'{',' ');

	replace_char(accesslog_url,'}',' ');
	replace_char(accesslog_user_agent,'}',' ');
	replace_char(accesslog_app_agent,'}',' ');

	replace_char(accesslog_url,';',' ');
	replace_char(accesslog_user_agent,';',' ');
	replace_char(accesslog_app_agent,';',' ');

/*
typedef struct {
        int year;
        int month;
        int day;
        int accessTime;
        int usec;
        char username[100];
        char ip[64];
        char proxytype[20];
        int orilength;
        int ziplength;
        char requestMethod[10];
        char url[512];
#ifdef NEVER
        char refer[512];
#endif
        char userAgent[256];
        char appAgent[64]; 
        int cport;
        int dport;
        char dip[64];
} ACCESSLOG;

typedef struct {        
        long mtype;
        ACCESSLOG accesslog;
} MSG_Item;

*/
	if (accesslog_active != 0){
		char str_time[33]={0};
		strftime(str_time, sizeof (str_time), "%Y-%m-%d %H:%M:%S",logtime);
	    fprintf(accesslog_file,
	     "DATA:%s,%d,%s,%s,%d,%s,%s,%d,%d,%s,%s,%s,%s\n",
	     str_time, (int)time_spent_msec, has_username?accesslog_username:"",
		 has_client_addr?accesslog_client_addr:"0.0.0.0",accesslog_port,accesslog_dip,
		 flags_str, (int)accesslog_inlen, (int)accesslog_outlen, has_method?accesslog_method:"?",
		 has_url?accesslog_url:"?", accesslog_user_agent, accesslog_app_agent);
	}

	/*
	if (accesslog_active != 0)
	  fprintf(accesslog_file, 
		"insert into accessLog%d%02d%02d (accessTime,usec,username,ip,dport,dip,proxytype,"
		"orilength,ziplength,requestMethod,url,userAgent,appAgent) VALUES(FROM_UNIXTIME(%d), "
		"%d, '%s', '%s',%d, '%s', '%s', %d, %d, '%s', '%s', '%s', '%s','%s','%s');\n",
		(int)(1900+logtime->tm_year),(int)(1+logtime->tm_mon),(int)logtime->tm_mday, 
		(int)currtime.tv_sec, (int)time_spent_msec, has_username?accesslog_username:"",
		has_client_addr?accesslog_client_addr:"0.0.0.0",accesslog_port,accesslog_dip, 
		flags_str, (int)accesslog_inlen, (int)accesslog_outlen, has_method?accesslog_method:"?", 
		has_url?accesslog_url:"?", accesslog_user_agent, accesslog_app_agent); //add by linjinsen
		*/

#ifdef LOG_REDUCE
   if (summarylog_active != 0)
   {
	/* send the msg to the msgqueue */
	bzero(&msg, sizeof(MSG_Item));

	msg.accesslog.year = (int)(1900+logtime->tm_year);
	msg.accesslog.month = (int)(1+logtime->tm_mon);
	msg.accesslog.day = (int)logtime->tm_mday;
	msg.accesslog.accessTime = (int)currtime.tv_sec;
	msg.accesslog.usec = (int)time_spent_msec;
	strncpy(msg.accesslog.username, has_username?accesslog_username:"", 99);
	strncpy(msg.accesslog.ip, has_client_addr?accesslog_client_addr:"0.0.0.0", 63);
	strncpy(msg.accesslog.proxytype, flags_str, 19);
	msg.accesslog.orilength = (int)accesslog_inlen;
	msg.accesslog.ziplength = (int)accesslog_outlen;
	strncpy(msg.accesslog.requestMethod, has_method?accesslog_method:"?", 9);
	strncpy(msg.accesslog.url, has_url?accesslog_url:"?", 511);
	// strncpy(msg.accesslog.refer, has_url?accesslog_url:"?", 511);
	if (accesslog_user_agent)
		strncpy(msg.accesslog.userAgent, accesslog_user_agent, 255);
	else
		msg.accesslog.userAgent[0] = '\0';
	if(accesslog_app_agent)
		strncpy(msg.accesslog.appAgent, accesslog_app_agent, 255);
	else
		msg.accesslog.appAgent[0]= '\0';

	if(accesslog_realuser_agent)
		strncpy(msg.accesslog.realAgent, accesslog_realuser_agent, 63);
	else
		msg.accesslog.realAgent[0]= '\0';

	// msg.accesslog.cport = (int) 0;
	msg.accesslog.dport = (int) accesslog_port;
	if (accesslog_dip)
		strncpy(msg.accesslog.dip, accesslog_dip, 63);
	else
		msg.accesslog.dip[0] = '0';

	MSG_QUEUE_ACTIVE = (int *)MMAP_Get_Address(MSG_QUEUE);
	msgid = *MSG_QUEUE_ACTIVE % MSG_MAX_NUMS;
	MSG_Send(msgid, &msg, sizeof(MSG_Item));
#ifdef DEBUG_DETAILS
	debug_log_printf ("access_log_dump_entry: after MSG_Send msgid %d MSG_QUEUE_ACTIVE %x(%d)\n",
		msgid, MSG_QUEUE_ACTIVE, *MSG_QUEUE_ACTIVE);
#endif
	MMAP_detache(MSG_QUEUE_ACTIVE);
    }
#endif
}

/*
 *  there's no "access_log_close" function
 * when the daemon finishes, the file handler is automatically
 * closed by the OS
 */

/* 
 * ERROR LOG ##############################
 */

/* returns: ==0,ok !=0,error
   If fails, stderr will be used (as backup measure)
   but the program is supposed to abort soon after.
   If errfilename == NULL, always return 0. */
int error_log_init (const char *errfilename)
{
	/* error_log is necessarily active at least during the
	   program initialization. -- see also: error_log_no_stderr() */
	errorlog_active = 1;

	if (errfilename != NULL) {
		if ((errorlog_file = fopen (errfilename, "a")) != NULL) {
			// set line buffered mode for errorlog_file
			setvbuf (errorlog_file, NULL, _IOLBF, BUFSIZ);
			errorlog_file_is_stderr = 0;
			return (0);
		} else {
			/* just in case someone forgets to abort
			   ziproxy after this error, at least things
			   won't collapse */
			errorlog_file = stderr;
			setvbuf (errorlog_file, NULL, _IOLBF, BUFSIZ);
			return (1);
		}
	}

	/* no ErrorLog file defined, let's dump to stderr then */
	errorlog_file = stderr;
	setvbuf (errorlog_file, NULL, _IOLBF, BUFSIZ);
	return (0);
}

/* Similar to error_log_init(), but sets output to stderr.
   It's invoked before we have a chance to parse the configuration file
   (to know where is the definitive destination of error logs) so,
   at least, we can output errors before that point using stderr.
   error_log_init() may be invoked afterwards in order to initialize
   error log properly.
   Note: from the point of view of error_log system, invoking this function
         is NOT required before calling error_log_init(). */
void error_log_pre_init (void)
{
	error_log_init (NULL);	/* the NULL pointer forces error_log to stderr */
}

/* disable error_log if output is stderr */
void error_log_no_stderr (void)
{
	if (errorlog_file_is_stderr != 0)
		errorlog_active = 0;
}

/* FIXME: this code is not safe (may render garbage) after fork()'ing */
int error_log_vprintf (t_log_msg_type log_msg_type, t_log_subsystem log_subsystem, const char *fmt, va_list ap)
{
	int i;
	time_t cur_time;
	struct tm *tm_time;
	char str_time[32];

	if (errorlog_active == 0)
		return (-1);

	/* dumps date/time only if this goes to a file */
	if (errorlog_file_is_stderr == 0) {
		/* generates date/time string */
		time (&cur_time);
		if ((tm_time = localtime (&cur_time)) == NULL) {
			sprintf (str_time, "UNABLE_TO_GET_TIME");
		} else {
			strftime (str_time, sizeof (str_time), "%Y-%m-%d %H:%M:%S", tm_time);
		}

		/* and dump it to file */
		fprintf (errorlog_file, "%s - ", str_time);
	}

	switch (log_msg_type) {
	case LOGMT_ERROR:
		fprintf (errorlog_file, "ERROR");
		break;
	case LOGMT_FATALERROR:
		fprintf (errorlog_file, "FATAL ERROR");
		break;
	case LOGMT_WARN:
		fprintf (errorlog_file, "WARNING");
		break;
	case LOGMT_INFO:
		fprintf (errorlog_file, "INFORMATION");
		break;
	default:
		/* empty, just to avoid compiler warnings */
		break;
	}

	switch (log_subsystem) {
	case LOGSS_CONFIG:
		fprintf (errorlog_file, " (configuration): ");
		break;
	case LOGSS_PARAMETER:
		fprintf (errorlog_file, " (parameter): ");
		break;
	case LOGSS_DAEMON:
		fprintf (errorlog_file, " (daemon): ");
		break;
	case LOGSS_LOGREDUCE:
		fprintf (errorlog_file, " (log-reduce): ");
		break;
	case LOGSS_USSERVER:
		fprintf (errorlog_file, " (us-server): ");
		break;
	case LOGSS_UNSPECIFIED:
		fprintf (errorlog_file, ": ");
		break;
	default:
		/* empty, just to avoid compiler warnings */
		break;
	}

	/* dump provided strings */
	i = vfprintf (errorlog_file, fmt, ap);

	return (i);
}

int error_log_printf (t_log_msg_type log_msg_type, t_log_subsystem log_subsystem, const char *fmt, ...)
{
	int retcode;
	va_list ap;

	if (errorlog_active == 0)
		return (-1);

	va_start (ap, fmt);	
	retcode = error_log_vprintf (log_msg_type, log_subsystem, fmt, ap);
	va_end (ap);

	return (retcode);
}

void error_log_puts (t_log_msg_type log_msg_type, t_log_subsystem log_subsystem, const char *str)
{
	if (errorlog_active == 0)
		return;
	error_log_printf (log_msg_type, log_subsystem, "%s\n", str);
}

void error_log_putsn (t_log_msg_type log_msg_type, t_log_subsystem log_subsystem, const char *str, unsigned int size)
{
	if (errorlog_active == 0)
		return;
	char* output = (char*)malloc(size+1);
	memcpy(output,str,size);
	output[size] = 0;
	error_log_printf (log_msg_type, log_subsystem, "%s\n", output);
	free(output);
}

void error_log_dumpbuf(t_log_msg_type log_msg_type, t_log_subsystem log_subsystem, const char* buf, unsigned int size) {
	char* output = (char*)malloc(3*size+1);
	output[3*size] = 0;
	int i;
	unsigned char val;
	for (i = 0; i < size; i++) {
		val = ((unsigned char) buf[i] >> 4);
		output[3 * i] = (val < 10) ? (val + '0') : (val + 'a');
		val = ((unsigned char) buf[i] & 0xf);
		output[3 * i + 1] = (val < 10) ? (val + '0') : (val - 10 + 'a');
		output[3 * i + 2] = ' ';
	}
	error_log_printf(log_msg_type,log_subsystem,"%s\n",output);
	free(output);
}

void dump_file(const char* buf, unsigned int size, const char* filepath) {
	FILE* f = fopen(filepath,"w");
	if (f) {
		fwrite(buf,size,1,f);
		fclose(f);
	}
}

void urldecode(char *dst, const char *src, int size)
{
   char tmp[3];
   tmp[2] = '\0';
   while (*src && size > 1) {
       if (*src == '%' && src[1] != '\0' && src[2] != '\0') {
           ++src;
           tmp[0] = *src;
           ++src;
           tmp[1] = *src;
           ++src;
           *dst = strtol(tmp, NULL, 16);
           ++dst;
       } else {
           *dst = *src;
           ++dst;
           ++src;
       }

       --size;
   }
   *dst = '\0';
}

void translate_agent(char **srcagent,const char* host,char ** newagent)
{
	char *oldagent=NULL;
	char *pagent=NULL;
	char *spt=NULL;
	char *psrc=NULL;
	int agentlen=0;
	int ifcheck=0;
	int inalen=0;
	int iarr[10]={0};
	int irk=0;

	oldagent=*srcagent;
	if(oldagent!=NULL){

		if(strstr(oldagent,"_weibo_") != NULL ){
			strcpy(*srcagent,"weibo");
			(*srcagent)[5]='\0';
			*newagent=strdup("weibo");
			return;
		}

		agentlen=strlen(oldagent);
		pagent=malloc(agentlen+1);

		memset(pagent,0,agentlen+1);
		urldecode(pagent,oldagent, agentlen+1);

		debug_log_printf("urldecode agent %s \n",pagent);
		//check "."   versoin  demo  1.2.3
		ifcheck=strcspn(pagent,".");
		if(ifcheck>0){
			while(ifcheck>0 && (isdigit(pagent[ifcheck-1]))>0){
			//while(ifcheck>0&&((pagent[ifcheck-1])>='0')&&((pagent[ifcheck-1])<='9')){
				ifcheck--;
			}
		}

		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}

		// check "("
		ifcheck=strcspn(pagent,"(");
		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}

		// check "/"
		ifcheck=strcspn(pagent,"/");
		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}

		// check "/"
		ifcheck=strcspn(pagent,"[");
		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}


		if(irk>0){
			inalen=iarr[irk-1];
			for(;irk>0;irk--){
				if(inalen>iarr[irk-1])
					inalen=iarr[irk-1];
			}
			if(inalen>0){
				if(inalen>63)
					inalen=63;
				*newagent=strndup(pagent,inalen);
			}
		}else{
			inalen=agentlen;
			if(inalen>63)
				inalen=63;
			*newagent=strndup(oldagent,inalen);
		}

		if(inalen>0){
			replace_char(*newagent,'\'','"');
			replace_char(*newagent,',',' ');
			replace_char(*newagent,'{',' ');
			replace_char(*newagent,'}',' ');
			replace_char(*newagent,';',' ');
		}
		replace_char(*srcagent,'\'','"');
		replace_char(*srcagent,',',' ');
		replace_char(*srcagent,'{',' ');
		replace_char(*srcagent,'}',' ');
		replace_char(*srcagent,';',' ');

		//for old version
		strncpy(*srcagent,*newagent,inalen);
		(*srcagent)[inalen]='\0';
		/*    */
	}else{
		if(host!=NULL){
			*srcagent=strdup(host);
			*newagent=strdup(host);
			psrc=strdup(host);
			memset(*newagent,0,strlen(host));
			spt = strtok(psrc,".");
			while(spt != NULL) {
				if(spt!=NULL){
					if(strcasecmp(spt,"www")!=0 &&
					   strcasecmp(spt,"cn")!=0 &&
					   strcasecmp(spt,"com")!=0){
						strcat(*newagent,spt);
						strcat(*newagent,".");
					}
				}
			     spt = strtok(NULL, ".");
			}
			inalen=strlen(*newagent);
			if(inalen>1)
			(*newagent)[inalen-1]='\0';
		}
	}
	debug_log_printf("real agent len %d is %s \n",inalen,*newagent);
}
//
//#ifdef TEST
//int log_test() {
//	char buf[8] = "\x00\x0d";
//	error_log_dumpbuf(LOGMT_INFO,LOGSS_DAEMON,buf,2);
//	return 0;
//}
//#endif
