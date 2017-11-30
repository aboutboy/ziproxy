/*
 * googlemap.h
 *
 *  Created on: Jun 15, 2012
 *      Author: jiangxd
 */

#ifndef GOOGLEMAP_H_
#define GOOGLEMAP_H_

#define PNG_TYPE 2

typedef struct {
	unsigned char img_type; // 2 is png
//	char* headbuf; // image head buffer with size of 12 bytes
	unsigned char headlen; // if there is LTIP head, length is 12 + 22, or length is 12
	ZP_DATASIZE_TYPE data_length; // real image data length
} gmap_image_header;

typedef struct {
	unsigned char image_num;
	char* cursor;
	int remaining_size; // remaining size of cursor
	char* outbuf;
	ZP_DATASIZE_TYPE outlen;
	gmap_image_header curr_img; // current image struct
//	const char* headbuf;
} gmap_imageset_header;

extern gmap_free(gmap_imageset_header* hdr);
extern inline void gmap_move_cursor(gmap_imageset_header* hdr, unsigned int offset);
extern int gmap_compress_imageset(char* inbuf, ZP_DATASIZE_TYPE inlen, gmap_imageset_header *ihdr, http_headers *serv_hdr, http_headers *client_hdr);
extern int gmap_write_imageset(gmap_imageset_header* hdr, FILE* sockwfp);
#endif /* GOOGLEMAP_H_ */
