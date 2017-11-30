/*
 * app_specific_resp.c
 *
 *  Created on: Jun 14, 2012
 *      Author: jiangxd
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "cfgfile.h"
#include "session.h"
#include "http.h"
#include "log.h"
#include "googlemap.h"
#include "applemap.h"

#undef DUMP_MAP

static inline int is_googlemap_request(http_headers *client_hdr)
{
	return (strncasecmp(client_hdr->url, "http://www.google.com/glm/mmap",30) == 0
	   || strncasecmp(client_hdr->url, "http://www.google.cn/glm/mmap",29) == 0 );
}

//			strncasecmp(client_hdr->host,"r.mzstatic.com",14) == 0
//			|| strcasestr(client_hdr->host, ".mzstatic.com")
//		|| strncasecmp(client_hdr->host, "ax.init.itunes.apple.com",24) == 0
//		|| strncasecmp(client_hdr->host, "phobos.apple.com",16) == 0
//		|| strncasecmp(client_hdr->host,"safebrowsing-cache.google.com",29 == 0)
static inline int is_ios_appstore_request(http_headers *client_hdr) {
	if (
			! strncasecmp(client_hdr->host, "ax.search.itunes.apple.com", 26)
			|| ! strncasecmp(client_hdr->host, "itunes.apple.com", 16) ) {
		char *temp = strrchr(client_hdr->url, '.');
		if (temp && !strncasecmp(temp, ".js", 3))
			return 1;
		return 0;
	}
	return 0;
}


static inline int is_ios_ipa_request(http_headers *client_hdr)
{
	if ( strncasecmp( client_hdr->url, "http://a1.phobos.apple.com",26) == 0 )
	{
		char *temp = strrchr( client_hdr->url,'.');
		if( temp != NULL && strcasecmp(temp,".ipa") == 0  ) return 1;
	}
	return 0;
}

static inline int is_mole_of_taomi_request(http_headers* client_hdr) {
	return ( client_hdr->user_agent && strncasecmp("Mole's%20World",client_hdr->user_agent,14) == 0 );
////			&& strncasecmp( client_hdr->url, "http://data.flurry.com/aas.do",29) == 0
//			&& strncmp(client_hdr->method,"POST",4) );
}

static inline int is_apple_map_request(http_headers* client_hdr)
{
	if ( (strstr(client_hdr->url,"cn.apple.com/appmaptile") ||strstr(client_hdr->url,"-cn.ls.apple.com/") ) &&
			!strncmp(client_hdr->method,"POST",4) )
		return 1;
	return 0;
}

FILE* open_dump_file(const char* url, int is_input) {
	static unsigned int dump_no = 0;
	FILE* dumpf = NULL;
	char dump_file_name[0x100];
	char url_encoded[0x100];
	int i;
	int len = strnlen(url,0x100);
	for (i=0;i<len;i++) {
		if (url[i] == '/') url_encoded[i] = '|';
		else url_encoded[i] = url[i];
	}
	url_encoded[i] = '\0';
	if (is_input)
		snprintf(dump_file_name,0x100,"/tmp/%s-%d",url_encoded,getpid());
	else
		snprintf(dump_file_name,0x100,"/tmp/%s-%d.out",url_encoded,getpid());
	dumpf = fopen(dump_file_name,"a+");
	if (!dumpf)
		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"open file failed:%s with error:%s\n",dump_file_name,strerror(errno));
	else
		debug_log_printf("open file for dumping: %s\n", dump_file_name);
	return dumpf;
}

#ifdef DUMP_APP_SPECIFIC_BODY
#define STRM_BUFSIZE 16384
ZP_DATASIZE_TYPE forward_and_dump_content (const char* url, http_headers *hdr, FILE *from, FILE *to)
{
	unsigned char stream [STRM_BUFSIZE];
	int inlen = 0;
	int outlen = 0;
	int alarmcount = 0;
	ZP_DATASIZE_TYPE remainlen = hdr->content_length; // if == -1 then content-length is not provided by client: so we won't rely on size checking.
	int requestlen = STRM_BUFSIZE;
	FILE* dumpf = open_dump_file(url,1);

	while ((remainlen != 0) && (feof (from) == 0) && (ferror (from) == 0) && (ferror (to) == 0) && (feof (to) == 0)) {
		if (remainlen >= 0) {
			if (remainlen < STRM_BUFSIZE)
				requestlen = remainlen;
			remainlen -= requestlen;
		}

		inlen = fread (stream, 1, requestlen, from);
		tosmarking_add_check_bytecount (inlen);
		access_log_add_inlen(inlen);
		alarmcount += inlen;

		// If we are sending a big file down a slow line, we
		// need to reset the alarm once a while.
		if ((ConnTimeout) && (alarmcount > 10000)) {
			alarmcount = 0;
			alarm (ConnTimeout);
		}

		/*
		//added by lidiansen , to know what's pust to google.com/ map
		int d=0;
		for(d=0;d<inlen;++d)
			debug_log_printf("POST TO GOOOGLE map:stream[%d] = %d,char is %c\n",d,stream[d],stream[d]);
		*/

		if (inlen > 0) {
			outlen = fwrite (stream, 1, inlen, to);
			if (dumpf)
				fwrite(stream,1,inlen,dumpf);
			access_log_add_outlen(outlen);
		}


		// If we are sending a big file down a slow line, we
		// need to reset the alarm once a while.
		if ((ConnTimeout) && (alarmcount > 10000)) {
			alarmcount = 0;
			alarm (ConnTimeout);
		}
	}

	fflush (to);

	if (dumpf) fclose(dumpf);

	return (access_log_ret_outlen());
}
#endif

static inline void just_forward(const char* url, http_headers *serv_hdr, FILE* sockrfp)
{
#ifdef DUMP_APP_SPECIFIC_BODY
	ZP_DATASIZE_TYPE outlen = forward_and_dump_content(url, serv_hdr, sockrfp, sess_wclient);
#else
	ZP_DATASIZE_TYPE outlen = forward_content(serv_hdr, sockrfp, sess_wclient);
#endif

	access_log_def_inlen(outlen);
	access_log_def_outlen(outlen);
	access_log_dump_entry();
}

static send_response_headers(ZP_DATASIZE_TYPE outlen, http_headers *client_hdr, http_headers *serv_hdr, FILE* sockrfp, FILE* sockwfp) {

	debug_log_puts ("Forwarding header and modified content.");
	debug_log_puts ("Out Headers:");

	char line[0x40];
	snprintf (line, sizeof(line), "Content-Length: %"ZP_DATASIZE_STR, outlen);
	if (serv_hdr->where_content_length > 0) {
		serv_hdr->hdr[serv_hdr->where_content_length] = strndup(line,0x40);
	} else {
		add_header (serv_hdr, line);
	}
	add_header (serv_hdr, "Connection: close");

	if( client_hdr->need_close_proxy_connection)
		add_header (serv_hdr, "Proxy-Connection: close");

	send_headers_to (sess_wclient, serv_hdr);

}

void decide_by_app(http_headers *client_hdr, http_headers *serv_hdr) {
	if (is_ios_ipa_request(client_hdr)) {
		client_hdr->flags &= (~H_WILLGZIP);
		serv_hdr->flags &= (~DO_COMPRESS);
	}
	else if (is_mole_of_taomi_request(client_hdr)) {
		client_hdr->flags &= (~H_WILLGZIP);
		serv_hdr->flags &= (~DO_COMPRESS);
	}
	else if (is_ios_appstore_request(client_hdr)) {
		client_hdr->flags &= (~H_WILLGZIP);
//		serv_hdr->flags &= (~DO_COMPRESS);
		serv_hdr->flags = DO_NOTHING;
	}
}

/**
 * @return ==0, sent response body to client; ==1, haven't sent response body to client
 */
int do_app_specific_response(http_headers *client_hdr, http_headers *serv_hdr, FILE* sockrfp, FILE* sockwfp)
{
	if ( is_googlemap_request(client_hdr) || is_apple_map_request(client_hdr))
	{
#ifdef DUMP_APP_SPECIFIC_BODY
		just_forward(client_hdr->url,serv_hdr,sockrfp);
#else
		serv_hdr->flags &= ~DO_RECOMPRESS_PICTURE;
		ZP_DATASIZE_TYPE inlen = 0;
		int streamed_len = 0;
		char* inbuf = NULL;
		debug_log_puts ("Trying to load the whole data into memory");
		// this will read both streaming data and data with specified content-length
		if ( (streamed_len = read_content(serv_hdr,sockrfp, sess_wclient, &inbuf, &inlen)) ) {
			debug_log_puts ("Data is of streaming type and doesn't fit MaxSize - streamed original data");

			/* flag this as 'W' since we had to fall back to streaming instead */
			access_log_set_flags (LOG_AC_FLAG_TOOBIG_NOMEM);
			access_log_def_inlen(streamed_len);
			access_log_def_outlen(streamed_len);
			access_log_dump_entry ();
			return 1;
		}
		add_oldlen_forsquid(serv_hdr,inlen);
		access_log_def_inlen(inlen);
		if (!inlen) {
			if (serv_hdr->content_length > 0)
				error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"Content length is %d but inlen is 0\n",serv_hdr->content_length);
			access_log_def_outlen(inlen);
			access_log_dump_entry ();
			return 1;
		}
		debug_log_puts ("Ok, whole data loaded into memory specific");

		if (is_googlemap_request(client_hdr)) {
			gmap_imageset_header ihdr;
			if (gmap_compress_imageset(inbuf,inlen,&ihdr,serv_hdr,client_hdr))
			{
				// forward inbuf to client
				send_response_headers(inlen,client_hdr,serv_hdr,sockrfp,sockwfp);
				fwrite(inbuf,inlen,1,sess_wclient);
				access_log_def_outlen(inlen);
				access_log_dump_entry ();
				return 0;
			}
			send_response_headers(ihdr.outlen,client_hdr,serv_hdr,sockrfp,sockwfp);
			if (gmap_write_imageset(&ihdr,sess_wclient)) {
				error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"write imageset error");
			}
			access_log_def_outlen(ihdr.outlen);
			debug_log_puts ("Ok, do gmap_compress_imageset ");
//			gmap_free(&ihdr);
		}
		else {
			amap_imageset_header ihdr;
			if (amap_compress_imageset(inbuf,inlen,&ihdr,serv_hdr,client_hdr))
			{
				// forward inbuf to client
				send_response_headers(inlen,client_hdr,serv_hdr,sockrfp,sockwfp);
				fwrite(inbuf,inlen,1,sess_wclient);
				access_log_def_inlen(inlen);
				access_log_def_outlen(inlen);
				access_log_dump_entry ();
				return 0;
			}
			send_response_headers(ihdr.outlen,client_hdr,serv_hdr,sockrfp,sockwfp);
			if (amap_write_imageset(&ihdr,sess_wclient)) {
				error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"write imageset error");
			}
#ifdef DUMP_MAP
			FILE* df = open_dump_file(client_hdr->url,0);
			fwrite(ihdr.outbuf,ihdr.outlen,1,df);
			fclose(df);
#endif
			access_log_def_outlen(ihdr.outlen);
			debug_log_puts ("Ok, do amap_compress_imageset ");
//			amap_free(&ihdr);
		}
		access_log_dump_entry ();
//		if (inbuf) {
//			free(inbuf);
//			inbuf = NULL;
//		}

#endif

		return 0;
	}

	return 1;
}

