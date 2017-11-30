/*
 * http_resp.
 *
 *  Created on: Jun 14, 2012
 *      Author: jiangxd
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http.h"

#include "image.h"
#include "cfgfile.h"
#include "htmlopt.h"
#include "log.h"
#include "text.h"
#include "preemptdns.h"
#include "cdetect.h"
#include "urltables.h"
#include "auth.h"
#include "misc.h"
#include "tosmarking.h"
#include "globaldefs.h"
#include "session.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

//html 页面 优化中 去掉 js 的子项目
static inline int is_js_of_weixin_request(http_headers* client_hdr) {
	if(strncasecmp( client_hdr->url, "http://mp.weixin.qq.com/mp/appmsg",33) == 0){
		return 1;
	}else if(strncasecmp( client_hdr->url, "http://m.shijiebang.com",23) == 0){
		return 1;
	}
		return 0;
}

void do_generic_response(http_headers *client_hdr, http_headers *serv_hdr, FILE* sockrfp, FILE* sockwfp)
{
	long i;
	char *inbuf = NULL, *outbuf = NULL;
	ZP_DATASIZE_TYPE inlen=0, outlen=0;
	int status = 0;
	ZP_DATASIZE_TYPE original_size =0;
	ZP_DATASIZE_TYPE streamed_len;	// used when load into memory failed and data was streamed
	char *tempp;

	if(serv_hdr->content_length>0){
		inlen=outlen=original_size=serv_hdr->content_length;
	}

	decide_what_to_do(client_hdr, serv_hdr);

	//data form squid is not to compress
	decide_by_usesquid(client_hdr, serv_hdr);

	decide_by_app(client_hdr, serv_hdr);

	//for some pass domain 直接放过不处理
	decide_by_checkdomain(client_hdr, serv_hdr);

	//log so far
	debug_log_printf ("Image = %d, Chunked = %d\n",
		serv_hdr->type, (serv_hdr->where_chunked > 0));

	debug_log_printf ("WillGZip = %d, Compress = %d, DoPreDecompress = %d\n",
			(client_hdr->flags & H_WILLGZIP) != 0,
			(serv_hdr->flags & DO_COMPRESS) != 0,
			(serv_hdr->flags & DO_PRE_DECOMPRESS) != 0);

	//if no data requested only forward header and exit
	if (strcasecmp(client_hdr->method, "HEAD") == 0) {
		debug_log_puts ("Forwarding header only.");
		add_header(serv_hdr, "Connection: close");
		if( client_hdr->need_close_proxy_connection)
				add_header (serv_hdr, "Proxy-Connection: close");

		send_headers_to (sess_wclient, serv_hdr);
		fflush (sess_wclient);

		access_log_dump_entry ();
		goto free_resource;
	}

	// if HTTP/0.9 simple response is received, just forward that and exit
	if (serv_hdr->flags & H_SIMPLE_RESPONSE) {
		debug_log_puts ("Forwarding HTTP/0.9 Simple Response.");
		fputs (serv_hdr->hdr[0], sess_wclient); // first few bytes of a simple response
		outlen = forward_content (serv_hdr, sockrfp, sess_wclient);

		access_log_def_inlen(outlen);
		access_log_def_outlen(outlen);
		access_log_dump_entry ();
		goto free_resource;
	}

	// data is encoded (gzip/other) and cannot be decoded (either because is unsupported or user requested no decoding)
	// just stream that, unmodified
	if  ( ((serv_hdr->content_encoding_flags & ~PROP_ENCODED_GZIP) != PROP_ENCODED_NONE) ||
		( (serv_hdr->content_encoding_flags == PROP_ENCODED_GZIP) && (! (serv_hdr->flags & DO_PRE_DECOMPRESS)) ) ) {

		debug_log_puts ("Data is encoded and cannot be decoded");
		is_sending_data = 1;
		debug_log_puts ("Forwarding header and streaming data.");
		add_header (serv_hdr, "Connection: close");
		if( client_hdr->need_close_proxy_connection)
			add_header (serv_hdr, "Proxy-Connection: close");

		send_headers_to (sess_wclient, serv_hdr);
		outlen = forward_content (serv_hdr, sockrfp, sess_wclient);

		access_log_def_inlen(outlen);
		access_log_def_outlen(outlen);
		access_log_dump_entry ();
		goto free_resource;
	}

	// stream-to-stream compression, if we're not requesting pre-decompression AND (either one of the following):
	// - gzip is the only optimization requested
	// - file too big, but gzipping requested - we can do gzip, so stream it
	// 	(no other optimization/processing will be applied)
	// - streaming file (can't know its size unless we download it) and requests gzipping
	// 	(no other optimization/processing will be applied)
	if ( (! (serv_hdr->flags & DO_PRE_DECOMPRESS)) && \
			( \
			  ( (serv_hdr->flags & DO_COMPRESS) && (MaxSize && (serv_hdr->content_length > MaxSize)) ) \
			  || ((serv_hdr->flags & META_CONTENT_MUSTREAD) == DO_COMPRESS) \
			) \
		) {
		int ret;

		//没办法取得长度
		add_oldlen_forsquid(serv_hdr,inlen);//add for squid sum zip len
		ret = do_compress_stream_stream (serv_hdr, sockrfp, sess_wclient, &inlen, &outlen);
		if (ret != 0) {
			// TODO: add flags of 'error' to access log in this case
			debug_log_printf ("Error while gzip-streaming: %d\n", ret);
		}

		access_log_def_inlen(inlen);
		access_log_def_outlen(outlen);
		access_log_dump_entry ();
		goto free_resource;
	}

	// stream-to-stream decompression, if client does not support gzip AND (either one of the following):
	// - gunzip is the only operation requested
	// - file too big, but gunzipping requested and NO gzipping afterwards
	// 	we can do gunzip, so stream it (no other optimization/processing will be applied)
	// - streaming file (can't know its size unless we download it) and requests gunzipping and NO gzipping
	// 	(no other optimization/processing will be applied)
	if (((serv_hdr->flags & DO_PRE_DECOMPRESS) && (! (serv_hdr->flags & DO_COMPRESS))) && \
			( \
			  ( (serv_hdr->flags & DO_PRE_DECOMPRESS) && (MaxSize && (serv_hdr->content_length > MaxSize)) ) \
			  || ((serv_hdr->flags & META_CONTENT_MUSTREAD) == DO_PRE_DECOMPRESS) \
			) \
		) {
		int ret;

		int oldlen=0;//get before squid cached size
		add_oldlen_forsquid(serv_hdr,inlen);//add for squid sum zip len
		remove_oldlen_forsquid(serv_hdr,&oldlen);


		ret = do_decompress_stream_stream (serv_hdr, sockrfp, sess_wclient, &inlen, &outlen, MaxUncompressedGzipRatio, MinUncompressedGzipStreamEval);
		if (ret != 0) {
			// TODO: add flags of 'error' to access log in this case
			debug_log_printf ("Error while gunzip-streaming: %d\n", ret);
		}

		access_log_def_inlen(inlen);
		access_log_def_outlen(outlen);
		access_log_dump_entry ();
		goto free_resource;
	}

	// if either:
	// - the server advertises the data as > MaxSize,
	// - there's no process to be done to the data.
	// - there's nothing except DECOMPRESS->COMPRESS (gzip, again) -- semi-useless (we could gain a few bytes, but adds latency)
	// don't even try to load into memory, stream that directly and reduce latency.
	if ( \
			(MaxSize && (serv_hdr->content_length > MaxSize)) \
			|| ((serv_hdr->flags & META_CONTENT_MUSTREAD) == DO_NOTHING) \
			|| ( ! ((serv_hdr->flags & META_CONTENT_MUSTREAD) & ~(DO_COMPRESS | DO_PRE_DECOMPRESS)) ) \
			) {
		is_sending_data = 1;
		if ((serv_hdr->flags & META_CONTENT_MUSTREAD) == DO_NOTHING)
			debug_log_puts ("Nothing to do - streaming original data");
		else
			debug_log_puts ("MaxSize reached - streaming original data");
		add_header(serv_hdr, "Connection: close");
		if( client_hdr->need_close_proxy_connection)
			add_header (serv_hdr, "Proxy-Connection: close");

		int oldlen=0;//get before squid cached size
		remove_oldlen_forsquid(serv_hdr,&oldlen);

		send_headers_to (sess_wclient, serv_hdr);
		outlen = forward_content(serv_hdr, sockrfp, sess_wclient);

		access_log_def_inlen(outlen);
		//chang squid befor cached  size
		if(oldlen>0&&(domain_isin_squidcached==1)&&(SquidUsedIn==1)){
			access_log_def_inlen(oldlen);
			debug_log_printf(">>>>squid cached compress for oldlen:%d  newlen:%d  \n",oldlen,outlen);
		}

		access_log_def_outlen(outlen);
		access_log_dump_entry();
		goto free_resource;
	}

	debug_log_puts ("Trying to load the whole data into memory");
	// this will read both streaming data and data with specified content-length
	if ((streamed_len = read_content(serv_hdr,sockrfp, sess_wclient, &inbuf, &inlen)) != 0) {
		debug_log_puts ("Data is of streaming type and doesn't fit MaxSize - streamed original data");

		/* flag this as 'W' since we had to fall back to streaming instead */
		access_log_set_flags (LOG_AC_FLAG_TOOBIG_NOMEM);
		access_log_def_inlen(streamed_len);
		access_log_def_outlen(streamed_len);
		access_log_dump_entry ();
		goto free_resource;
	}
	debug_log_puts ("Ok, whole data loaded into memory");
	original_size = inlen;

	/* IF IT REACHES THIS POINT
	   it means that the data is wholly loaded into memory and it will be processed */

	// user requested data, but there's none.
	// only forward header and exit
	if (inlen == 0) {
		debug_log_puts ("Forwarding header only.");
		add_header(serv_hdr, "Connection: close");
		if( client_hdr->need_close_proxy_connection)
			add_header (serv_hdr, "Proxy-Connection: close");

		send_headers_to (sess_wclient, serv_hdr);
		fflush (sess_wclient);

		access_log_dump_entry ();
		goto free_resource;
	}

	//serv_hdr->chunklen isn't used anywhere else
	/* TODO: i'm not sure what this block of code does (legacy code).
	         verify this later */
	if(serv_hdr->chunklen > 0){
		if('1' == client_hdr->proto[7]){
			is_sending_data = 1;
			debug_log_puts ("MaxSize reached - streaming original chunked data");
			add_header(serv_hdr, "Transfer-Encoding: chunked");
			add_header(serv_hdr, "Connection: close");

			if( client_hdr->need_close_proxy_connection)
				add_header (serv_hdr, "Proxy-Connection: close");

			send_headers_to (sess_wclient, serv_hdr);
			if(inlen > 0){
				printf("%"ZP_DATASIZE_MSTR"X\r\n",inlen);//TODO verify format
				tosmarking_add_check_bytecount (inlen);	/* check if TOS needs to be changed */
				fwrite (inbuf, 1, inlen, sess_wclient);
				fputs ("\r\n", sess_wclient);
			}
			printf("%X\r\n",serv_hdr->chunklen);
			outlen = forward_content (serv_hdr, sockrfp, sess_wclient);
		}else{
			//It is not worth to code proper unchunking
			//for this exceptional situation.
			send_error(500,"Internal error",NULL,
					"Too big file. Try using HTTP/1.1 client.");
		}

		access_log_def_inlen(outlen);
		access_log_def_outlen(outlen);
		access_log_dump_entry ();
		goto free_resource;
	}

	if (inlen != serv_hdr->content_length) debug_log_printf ("In Content-Length: %"ZP_DATASIZE_STR"\n", inlen);

	/* unpacks data gzipped by remote server, in order to process it */
	if (serv_hdr->flags & DO_PRE_DECOMPRESS) {
		char **inbuf_addr;
		int new_inlen;

		debug_log_puts ("Decompressing Gzip data...");
		inbuf_addr = &inbuf;
		new_inlen = replace_gzipped_with_gunzipped(inbuf_addr, inlen, MaxUncompressedGzipRatio);
		if (new_inlen >= 0) {
			inlen = new_inlen;
			inbuf = *inbuf_addr;

			/* no longer gzipped, modify headers accordingly */
			serv_hdr->content_encoding_flags = PROP_ENCODED_NONE;
			serv_hdr->content_encoding = NULL;
			serv_hdr->where_content_encoding = -1;
			remove_header_str(serv_hdr, "Content-Encoding");

			/* data size is changed, modify headers accordingly */
			serv_hdr->content_length = inlen;
			serv_hdr->where_content_length = -1;
			remove_header_str(serv_hdr, "Content-Length");

			debug_log_printf ("Gzip body decompressed for further processing. Decompressed size: %"ZP_DATASIZE_STR"\n", inlen);
		} else {
			switch (new_inlen * -1) {
			case 100:
				send_error( 500, "Internal Error", NULL, "Uncompressed gzipped data exceedes safety threshold." );
				break;
			case 120:
				debug_log_puts ("Broken Gzip data. Forwarding unmodified data.");
				/* will not attempt to compress it again */
				/* since the data is a blackbox, neither we can apply Preemptive DNS */
				serv_hdr->flags &= ~META_CONTENT_MUSTREAD;
				break;
			}
		}
	} else if (serv_hdr->content_encoding_flags != PROP_ENCODED_NONE) {
		/* either:
		 * - data is gzipped but is not supposed to be uncompressed (!DO_PRE_DECOMPRESS)
		 * - data is encoded in an unknown way
		 * we cannot modify it, neither compress it */
		/* since the data is a blackbox, neither we can apply Preemptive DNS */
		serv_hdr->flags &= ~META_CONTENT_MUSTREAD;
		debug_log_puts ("Data is gzipped but is not supposed to be uncompressed OR\n	Data is encoded in an unknown way.");
	}

	//in case something fails later and forgets to do this:
	outbuf = inbuf;
	outlen = inlen;

	// (start) only if data is not encoded
	// data may (still) be encoded in case gzip decompressing failed
	if ((serv_hdr->content_encoding_flags == PROP_ENCODED_NONE) && (inlen > 0)) {

	/* text/html optimizer */
	/* FIXME: inbuf must be at least (inlen + 1) chars big in order to hold added '\0' from htmlopt */
	if (serv_hdr->flags & DO_OPTIMIZE_HTML) {
		HOPT_FLAGS hopt_flags = HOPT_NONE;
		if (ProcessHTML_CSS)
			hopt_flags |= HOPT_CSS;
		if (ProcessHTML_JS){
			 if(!is_js_of_weixin_request(client_hdr)){
				 hopt_flags |= HOPT_JAVASCRIPT;
			}
		}
		if (ProcessHTML_tags)
			hopt_flags |= HOPT_HTMLTAGS;
		if (ProcessHTML_text)
			hopt_flags |= HOPT_HTMLTEXT;
		if (ProcessHTML_PRE)
			hopt_flags |= HOPT_PRE;
		if (ProcessHTML_TEXTAREA)
			hopt_flags |= HOPT_TEXTAREA;
		if (ProcessHTML_NoComments)
			hopt_flags |= HOPT_NOCOMMENTS;

		/* we may find files claiming to be "text/html" while in fact they're not,
		 * (typically CSS or JS)
		 * we cannot optimize those as HTML otherwise we'll get garbage */
		switch (detect_content_type (inbuf)) {
		case CD_TEXT_HTML:
			debug_log_puts ("HTMLopt -> HTML");
			inlen = hopt_pack_html (inbuf, inlen, inbuf, hopt_flags);
			outlen = inlen;
			break;
		default:
			debug_log_puts ("HTMLopt WARNING: Data claimed to be HTML, but it's not.");
			break;
		}
	}

	/* text/css optimizer */
	/* FIXME: inbuf must be at least (inlen + 1) chars big in order to hold added '\0' from htmlopt */
	if (serv_hdr->flags & DO_OPTIMIZE_CSS) {
		debug_log_puts ("HTMLopt -> CSS");
		inlen = hopt_pack_css (inbuf, inlen, inbuf);
		outlen = inlen;
	}

	/* application/[x-]javascript optimizer */
	/* FIXME: inbuf must be at least (inlen + 1) chars big in order to hold added '\0' from htmlopt */
	if (serv_hdr->flags & DO_OPTIMIZE_JS) {
		debug_log_puts ("HTMLopt -> JS");
		inlen = hopt_pack_javascript (inbuf, inlen, inbuf);
		outlen = inlen;
	}

	/* preemptive name resolution */
	if (serv_hdr->flags & DO_PREEMPT_DNS)
		preempt_dns_from_html (inbuf, inlen);

	if (serv_hdr->flags & DO_RECOMPRESS_PICTURE) {
		status = compress_image(serv_hdr, client_hdr, inbuf, inlen, &outbuf, &outlen);
		if ((status & IMG_UNIQUE_RET_MASK) == IMG_RET_TOO_EXPANSIVE) {
			debug_log_puts ("WARNING: Image too expansive. Not recompressed.");
			access_log_set_flags (LOG_AC_FLAG_IMG_TOO_EXPANSIVE);
		}
		debug_log_difftime ("Image modification/compression");
		debug_log_printf ("  and returned %d.\n", status);
	}

	if(serv_hdr->flags & DO_COMPRESS
			&& serv_hdr->content_length > 256){	// TODO: move into decide_what_to_do

		add_oldlen_forsquid(serv_hdr,original_size);//add for squid sum zip len
		do_compress_memory_stream (serv_hdr, inbuf, sess_wclient, inlen, &outlen);

		access_log_def_inlen(original_size);
		access_log_def_outlen(outlen);
		access_log_dump_entry ();
		exit (0);
	}

	} /* (end) only if data is not encoded */

	is_sending_data = 1;

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

	add_oldlen_forsquid(serv_hdr,original_size);//add for squid sum zip len
	send_headers_to (sess_wclient, serv_hdr);

	//forward content
	tempp = outbuf;
	tosmarking_add_check_bytecount (outlen); /* update TOS if necessary */
	if (inlen != 0){
		int outcount = outlen;

		do{
			i = fwrite(tempp, 1, outcount, sess_wclient);
			outcount -= i;
			tempp += i;
		}while((i > 0) && outcount);

		fflush (sess_wclient);

		if(outcount == 0) {
			fsync(1);
			debug_log_difftime ("Forwarding");
		}
		else debug_log_printf ("Error - Last %d bytes of content could not be written\n",
			outcount);
	}


	access_log_def_inlen(original_size);
	access_log_def_outlen(outlen);
	access_log_dump_entry ();

free_resource:
//  freeing of outbuf is not correct, for outbuf maybe buffer of jpeg objects
//	if (outbuf != inbuf) {
//		free (outbuf);
//		outbuf = NULL;
//	}
//	if (inbuf) {
//		free (inbuf);
//		inbuf = NULL;
//	}
	return;
}
