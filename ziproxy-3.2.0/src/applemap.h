/*
 * googlemap.h
 *
 *  Created on: Jun 15, 2012
 *      Author: jiangxd
 */

#ifndef APPLEMAP_H_
#define APPLEMAP_H_

#define PNG_TYPE 2

typedef struct {
	unsigned char headlen; // if there is LTIP head, length is 12 + 22, or length is 12
	ZP_DATASIZE_TYPE data_length; // real image data length
} amap_image_header;

typedef struct {
	char* inbuf;
	ZP_DATASIZE_TYPE inlen;
	char* cursor;
	int remaining_size; // remaining size of cursor
	char* outbuf;
	ZP_DATASIZE_TYPE outlen;
	amap_image_header curr_img; // current image struct
} amap_imageset_header;

extern amap_free(amap_imageset_header* hdr);
extern inline void amap_move_cursor(amap_imageset_header* hdr, unsigned int offset);
extern int amap_compress_imageset(char* inbuf, ZP_DATASIZE_TYPE inlen, amap_imageset_header *ihdr, http_headers *serv_hdr, http_headers *client_hdr);
extern int amap_write_imageset(amap_imageset_header* hdr, FILE* sockwfp);
#endif /* APPLEMAP_H_ */
