/*
 * googlemap.c
 *
 *  Created on: Jun 15, 2012
 *      Author: jiangxd
 */

#ifndef APPLEMAP_C_
#define APPLEMAP_C_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <png.h>
#include "session.h"
#include "globaldefs.h"
#include "log.h"
#include "image.h"
#include "png_compressor.h"
#include "applemap.h"

#define MIN_INSIZE_PNG 100
#define MIN_COMPRESSING_SIZE 0x400

#define MIN_HEAD_SIZE 13
#define MAX_HEAD_SIZE 60

//#define free_and_return(retval) \
//	if (inbuf) free (inbuf); \
//	if (ihdr.outbuf) free (ihdr.outbuf); \
//	return retval;

amap_free(amap_imageset_header* hdr) {
	if (hdr->outbuf) {
		free(hdr->outbuf);
		hdr->outbuf = NULL;
	}
}

/**
 * return ==0: successfully; !=0: failed
 */
static int amap_read_imageset_header(amap_imageset_header* hdr, char* inbuf, ZP_DATASIZE_TYPE inlen)
{
	hdr->outbuf = (char*)malloc(inlen);
	hdr->outlen = 0;
	if (!hdr->outbuf)
	{
		error_log_printf(LOGMT_FATALERROR,LOGSS_DAEMON,"Malloc apple map image outbuf failed\n");
		return 1;
	}
	hdr->cursor = hdr->inbuf = inbuf; // ignore header
	hdr->remaining_size = hdr->inlen = inlen;
	return 0;
}

static inline int amap_is_imageset(const char* inbuf, ZP_DATASIZE_TYPE inlen)
{
	return ( inlen > 0x100 && inbuf[0] == 0x00);
}

static inline char* amap_get_image_head_outbuf(amap_imageset_header* hdr) {
	return (hdr->outbuf + hdr->outlen);
}

static inline char* amap_get_image_data_outbuf(amap_imageset_header* hdr) {
	return (hdr->outbuf + hdr->outlen + hdr->curr_img.headlen);
}

inline void amap_move_cursor(amap_imageset_header* hdr, unsigned int offset) {
	hdr->cursor += offset;
	hdr->remaining_size -= offset;
}

static inline int read_image_head(amap_imageset_header* hdr) {
	const unsigned char* p = (const unsigned char*)hdr->cursor;
	int offset;

	offset = MAX_HEAD_SIZE < hdr->remaining_size ? MAX_HEAD_SIZE : hdr->remaining_size;

	while ((--offset) >= 0) {
		if ( *p == 0x0 && *(p+1) == 0x0) break;
		p++;
	}
	if ( offset < 0 ) {
//		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"Could not find head end of apple image set\n");
//		error_log_dumpbuf(LOGMT_ERROR,LOGSS_DAEMON,hdr->inbuf,hdr->inlen < 100 ? hdr->inlen : 100);
//		dump_file(hdr->inbuf,hdr->inlen,"/tmp/applemap.a");
		return 1;
	}

	// check image head, 12 is the size of image head
	hdr->curr_img.data_length = ((*(p + 2)) << 8) + *(p + 3);
	hdr->curr_img.headlen = ((char*)p) + 4 - hdr->cursor;

	memcpy(amap_get_image_head_outbuf(hdr),hdr->cursor,hdr->curr_img.headlen);
	amap_move_cursor(hdr,hdr->curr_img.headlen);

	return 0;
}

static inline int is_image_end(amap_imageset_header* hdr) {
	return hdr->remaining_size < MIN_HEAD_SIZE;
}

static inline void write_image(amap_imageset_header* hdr, ZP_DATASIZE_TYPE datalen) {
	*(amap_get_image_head_outbuf(hdr) + hdr->curr_img.headlen - 2) = datalen / 0x100;
	*(amap_get_image_head_outbuf(hdr) + hdr->curr_img.headlen - 1) = datalen % 0x100;
	hdr->outlen += hdr->curr_img.headlen + datalen; // point to next image output buffer
}

inline int amap_write_imageset(amap_imageset_header* hdr, FILE* sockwfp) {
	if (fwrite(hdr->outbuf,hdr->outlen,1,sockwfp) != 1) return 1;
	return 0;
}

/**
 * @return ==0, sent response body to client; !=0, haven't sent response body to client
 */
int amap_compress_imageset( char* inbuf, ZP_DATASIZE_TYPE inlen, amap_imageset_header *ihdr, http_headers *serv_hdr, http_headers *client_hdr)
{
	int comp_ret;
	ZP_DATASIZE_TYPE outlen_of_compressed_image;

	if (inlen < MIN_COMPRESSING_SIZE || !amap_is_imageset(inbuf,inlen)) {
		error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"not apple map:%d\n",inlen);
		error_log_dumpbuf(LOGMT_INFO, LOGSS_DAEMON, inbuf,
				inlen < 100 ? inlen : 100);
		return COMP_NOCOMP;
	}

	if (amap_read_imageset_header(ihdr,inbuf,inlen)) return 1;

	int i = 0;
	while (!is_image_end(ihdr))
	{
		if (read_image_head(ihdr)) return COMP_NOCOMP;

		comp_ret = compress_png(ihdr->cursor,ihdr->curr_img.data_length,amap_get_image_data_outbuf(ihdr),&outlen_of_compressed_image, NULL, 0);
		if (comp_ret == COMP_OK) {
			write_image(ihdr,outlen_of_compressed_image);
			error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"outlen:%d\n",ihdr->outlen);
		}
		else if (comp_ret == COMP_NOCOMP) {
			memcpy(amap_get_image_data_outbuf(ihdr),ihdr->cursor,ihdr->curr_img.data_length);
			write_image(ihdr,ihdr->curr_img.data_length);
			error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"outlen:%d\n",ihdr->outlen);
		}
		else {
#ifdef TEST
			fprintf(stderr,"invalid return value:%d while compress %d png\n", comp_ret,i);
			exit(1);
#else
			// cannot compress or has error
			error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"retval:%d\n",comp_ret);
			memcpy(amap_get_image_data_outbuf(ihdr),ihdr->cursor,ihdr->curr_img.data_length);
			write_image(ihdr,ihdr->curr_img.data_length);
			error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"after retval:%d\n",comp_ret);
#endif
		}
		amap_move_cursor(ihdr,ihdr->curr_img.data_length);
		i++;

	}

	return 0;
}

#ifdef TEST
int apple_map_test() {
//	int compress_google_map_imageset(http_headers *serv_hdr, FILE* sockrfp, FILE* sess_wclient)
	ZP_DATASIZE_TYPE filesize = 0;
	char* inbuf = NULL;
	amap_imageset_header ihdr;
	FILE* in = fopen("test/applemap4.a","r");
	FILE* out = fopen("test/applemap4.out","w");
	if (!in || !out) return 1;
	fseek(in,0,SEEK_END);
	filesize = ftell(in);
	fseek(in,0,SEEK_SET);
	inbuf = (char*)malloc(filesize);
	fread(inbuf,1024,filesize/1024 + 1,in);
	if ( amap_compress_imageset(inbuf,filesize,&ihdr,NULL,NULL) == 1) {
		fwrite(inbuf,filesize,1,out);
		return 0;
	}

	if (ihdr.outbuf) {
		amap_write_imageset(&ihdr,out);
		free(ihdr.outbuf);
	}

	return 0;

}
#endif

#endif /* GOOGLEMAP_C_ */
