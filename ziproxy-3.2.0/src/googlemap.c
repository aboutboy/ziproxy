/*
 * googlemap.c
 *
 *  Created on: Jun 15, 2012
 *      Author: jiangxd
 */

#ifndef GOOGLEMAP_C_
#define GOOGLEMAP_C_

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
#include "googlemap.h"

#define MIN_INSIZE_PNG 100
#define MIN_COMPRESSING_SIZE 0x400
//
//#define IMMUTABLE_PALETTE_SIZE 16
//static png_color IMMUTABLE_PALETTE[] = {
//		{63,47,63},
//		{158,77,61},
//		{63,78,158},
//		{158,170,63},
//		{158,181,158},
//		{82,165,158},
//		{158,63,159},
//		{63,144,63},
//		{223,63,52},
//		{56,54,223},
//		{223,183,63},
//		{223,158,170},
//		{158,181,223},
//		{71,161,223},
//		{223,116,149},
//		{223,223,191}
//};

//#define free_and_return(retval) \
//	if (inbuf) free (inbuf); \
//	if (ihdr.outbuf) free (ihdr.outbuf); \
//	return retval;

gmap_free(gmap_imageset_header* hdr) {
	if (hdr->outbuf) {
		free(hdr->outbuf);
		hdr->outbuf = NULL;
	}
}
/**
 * return ==0: successfully; !=0: failed
 */
static int read_and_write_imageset_header(gmap_imageset_header* hdr, char* inbuf, ZP_DATASIZE_TYPE inlen)
{
	hdr->image_num = ( ((unsigned char)inbuf[11]) << 8 ) + (unsigned char)inbuf[12];
	hdr->outbuf = (char*)malloc(inlen);
	hdr->outlen = 0;
	if (!hdr->outbuf)
	{
		error_log_printf(LOGMT_FATALERROR,LOGSS_DAEMON,"Malloc google map image outbuf failed\n");
		return 1;
	}
	memcpy(hdr->outbuf,inbuf,13);
	hdr->cursor = inbuf; // ignore header
	hdr->remaining_size = inlen;
	gmap_move_cursor(hdr,13);
	hdr->outlen = 13;	// point to first image output buffer
	return 0;
}

static inline int is_imageset(const char* inbuf, ZP_DATASIZE_TYPE inlen)
{
	return ( inlen > 0x100 && inbuf[0] == 0x00 && inbuf[1] == 0x0e
			&& inbuf[2] == 0x3e && inbuf[13] == 0x02); /*inbuf[7] == 0x1a*/
}

static inline char* get_image_head_outbuf(gmap_imageset_header* hdr) {
	return (hdr->outbuf + hdr->outlen);
}

static inline char* get_image_data_outbuf(gmap_imageset_header* hdr) {
	return (hdr->outbuf + hdr->outlen + hdr->curr_img.headlen);
}

inline void gmap_move_cursor(gmap_imageset_header* hdr, unsigned int offset) {
	hdr->cursor += offset;
	hdr->remaining_size -= offset;
}

static inline int read_image_head(gmap_imageset_header* hdr) {
	if (hdr->remaining_size < 12) return 1;
	hdr->curr_img.img_type = *(hdr->cursor);
	// check image head, 12 is the size of image head
	hdr->curr_img.data_length = 256 * (unsigned char) hdr->cursor[10] + (unsigned char) hdr->cursor[11];
	hdr->curr_img.headlen = 12;
	// check LTIP head, 22 is the size of LTIP head
	if (hdr->remaining_size > (12 + 4) && !memcmp(hdr->cursor+12,"LTIP",4)) {
		const char* offset = hdr->cursor + 16;
		while ( ( (unsigned char)(*offset) != 0xf || (unsigned char)(*(offset-1)) != 0xdc) // dc 0f is end characters
				&& (offset - hdr->cursor) < hdr->remaining_size) {
			offset++;
		}
		if ((unsigned char)(*offset) != 0xf) return 2; // LTIP end char
		hdr->curr_img.headlen = (offset + 1 - hdr->cursor);
		hdr->curr_img.data_length -= (offset + 1 - hdr->cursor - 12); // the length in head include LTIP size
	}

	memcpy(get_image_head_outbuf(hdr),hdr->cursor,hdr->curr_img.headlen);
	gmap_move_cursor(hdr,hdr->curr_img.headlen);
	return !(hdr->curr_img.data_length);
}

static inline void write_image(gmap_imageset_header* hdr, ZP_DATASIZE_TYPE datalen) {
	ZP_DATASIZE_TYPE reallen = datalen + hdr->curr_img.headlen - 12;
	*(get_image_head_outbuf(hdr) + 10) = reallen / 0x100;
	*(get_image_head_outbuf(hdr) + 11) = reallen % 0x100;
	hdr->outlen += hdr->curr_img.headlen + datalen; // point to next image output buffer
}

inline int gmap_write_imageset(gmap_imageset_header* hdr, FILE* sockwfp) {
	if (fwrite(hdr->outbuf,hdr->outlen,1,sockwfp) != 1) return 1;
	return 0;
}

//static inline int write_image_head(imageset_header* hdr, ZP_DATASIZE_TYPE image_len) {
//	hdr->
//}

//static inline void read_png_head(imageset_header* hdr, ZP_DATASIZE_TYPE* len)
//{
//	hdr->cursor += 8; // ignore png signature: 137 80 78 71 13 10 26 10
//	*len = *((unsigned int*)hdr->cursor);
//}
//

//int compress_google_map_png (http_headers *serv_hdr, http_headers *client_hdr, char *inbuf, ZP_DATASIZE_TYPE insize, char *outb, ZP_DATASIZE_TYPE *outl);

/**
 * @return ==0, sent response body to client; !=0, haven't sent response body to client
 */
int gmap_compress_imageset( char* inbuf, ZP_DATASIZE_TYPE inlen, gmap_imageset_header *ihdr, http_headers *serv_hdr, http_headers *client_hdr)
{
	int comp_ret;

	if (inlen < MIN_COMPRESSING_SIZE || !is_imageset(inbuf,inlen)) {
//		error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"not google map\n");
//		error_log_dumpbuf(LOGMT_INFO, LOGSS_DAEMON, inbuf, inlen < 100 ? inlen : 100);
		return 1;
	}

	if (read_and_write_imageset_header(ihdr,inbuf,inlen)) return 1;

	// no picture,just forward
	if (!ihdr->image_num)
		return 1;

	int i = 0;
	while (i < ihdr->image_num)
	{
		if (read_image_head(ihdr)) break;

		ZP_DATASIZE_TYPE outlen_of_compressed_image;
		if (ihdr->curr_img.img_type == PNG_TYPE) {

//			comp_ret = compress_png(ihdr->cursor,ihdr->curr_img.data_length,get_image_data_outbuf(ihdr),&outlen_of_compressed_image, IMMUTABLE_PALETTE, IMMUTABLE_PALETTE_SIZE);
			comp_ret = compress_png(ihdr->cursor,ihdr->curr_img.data_length,get_image_data_outbuf(ihdr),&outlen_of_compressed_image, NULL, 0);
			if (comp_ret == COMP_OK ) {
				write_image(ihdr,outlen_of_compressed_image);
			}
			else if (comp_ret == COMP_NOCOMP) {
				memcpy(get_image_data_outbuf(ihdr),ihdr->cursor,ihdr->curr_img.data_length);
				write_image(ihdr,ihdr->curr_img.data_length);
			}
			else {
#ifdef TEST
				fprintf(stderr,"invalid return value:%d while compress %d png\n", comp_ret,i);
				exit(1);
#else
				// cannot compress or has error
				error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"retval:%d\n",comp_ret);
				memcpy(get_image_data_outbuf(ihdr),ihdr->cursor,ihdr->curr_img.data_length);
				write_image(ihdr,ihdr->curr_img.data_length);
				error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"after retval:%d\n",comp_ret);
#endif
			}
		}
		else {
			char* outb = NULL;
//			ZP_DATASIZE_TYPE* outl = NULL;
//			compress_image(serv_hdr,client_hdr,ihdr->cursor,ihdr->curr_img.data_length,&outb,&outl);
//			memcpy(get_image_data_outbuf(ihdr),outb,*outl);
			//			write_image(ihdr,*outl);
			memcpy(get_image_data_outbuf(ihdr),ihdr->cursor,ihdr->curr_img.data_length);
			write_image(ihdr,ihdr->curr_img.data_length);
		}
		gmap_move_cursor(ihdr,ihdr->curr_img.data_length);
		i++;

	}

	return 0;
}
//
//static int reduce_palatte_colors (raw_bitmap *bmp)
//{
//	int color_entry [256];
//	int color_remap [256]; /* data = old color number */
//	int color_remap2 [256]; /* data = new color number */
//	unsigned char new_palette [1024];
//	int rawsize = bmp->width * bmp->height;
//	int i, j;
//	int cur_id, cur_id2, used_colors = 0;
//	int useful_alpha = 0;
//	int total_alpha = 0;
//
//	/* is that really a image with palette? */
//	if ((bmp->pal_entries <= 0) || (bmp->raster == NULL))
//		return 1;
//
//	/* remove unnecessary palette entries */
//
//	/* determine used_colors */
//	for (i = 0; i < 256; i++)
//		color_entry [i] = 0;
//	for (i = 0; i < rawsize; i++)
//		color_entry [bmp->raster [i]] = 1;
//	for (i = 0; i < 256; i++)
//		used_colors += color_entry [i];
//
//	if (used_colors < bmp->pal_entries) {
//		debug_log_printf ("Image has unnecessary palette entries. Allocated: %d  Used: %d\n", bmp->pal_entries, used_colors);
//
//		/* generate remap tables */
//		cur_id = 0;
//		for (i = 0; i < 256; i++) {
//			if (color_entry [i] != 0) {
//				color_remap [cur_id] = i;
//				color_remap2 [i] = cur_id;
//				cur_id++;
//			}
//		}
//
//		/* regenerate palette */
//		for (i = 0; i < used_colors; i++) {
//			for (j = 0; j < bmp->pal_bpp; j++) {
//				new_palette [i * bmp->pal_bpp + j] = bmp->palette [color_remap [i] * bmp->pal_bpp + j];
//			}
//		}
//		memcpy (bmp->palette, new_palette, sizeof (unsigned char) * bmp->pal_bpp * used_colors);
//
//		/* regenerate bitmap */
//		for (i = 0; i < rawsize; i++) {
//			bmp->raster [i] = color_remap2 [bmp->raster [i]];
//		}
//
//		bmp->pal_entries = used_colors;
//	}
//
//	/* detect unecessary alpha in palette and remove it */
//
//	if (bmp->pal_bpp == 4) {
//		for (i = 0; i < bmp->pal_entries; i++) {
//			if (bmp->palette [i * 4 + 3] != (unsigned char) 0xff)
//				useful_alpha = 1;
//		}
//
//		if (useful_alpha == 0) {
//			debug_log_puts ("Image has unnecessary alpha in palette entries.");
//			for (i = 0; i < bmp->pal_entries; i++) {
//				bmp->palette [i * 3] = bmp->palette [i * 4];
//				bmp->palette [i * 3 + 1] = bmp->palette [i * 4 + 1];
//				bmp->palette [i * 3 + 2] = bmp->palette [i * 4 + 2];
//			}
//			bmp->pal_bpp = 3;
//		}
//	}
//
//	/* optimize colors with alpha entries (put those first), if necessary */
//
//	if (bmp->pal_bpp == 4) {
//		for (i = 0; i < bmp->pal_entries; i++) {
//			if (bmp->palette [i * 4 + 3] != 0xff)
//				total_alpha++;
//		}
//
//		if (total_alpha < bmp->pal_entries) {
//			j = 0;
//			for (i = total_alpha; i < bmp->pal_entries; i++) {
//				if (bmp->palette [i * 4 + 3] != 0xff)
//					j++;
//			}
//
//			if (j > 0) {
//				debug_log_puts ("Image has unoptimized transparency.");
//
//				/* reorder palette */
//
//				/* generate remap tables */
//				cur_id = 0; /* with alpha */
//				cur_id2 = total_alpha; /* without alpha */
//				for (i = 0; i < bmp->pal_entries; i++) {
//					if (bmp->palette [i * 4 + 3] != 0xff) {
//						color_remap [cur_id] = i;
//						color_remap2 [i] = cur_id;
//						cur_id++;
//					} else {
//						color_remap [cur_id2] = i;
//						color_remap2 [i] = cur_id2;
//						cur_id2++;
//					}
//				}
//
//				/* regenerate palette */
//				for (i = 0; i < used_colors; i++) {
//					for (j = 0; j < bmp->pal_bpp; j++) {
//						new_palette [i * bmp->pal_bpp + j] = bmp->palette [color_remap [i] * bmp->pal_bpp + j];
//					}
//				}
//				memcpy (bmp->palette, new_palette, sizeof (unsigned char) * bmp->pal_bpp * used_colors);
//
//				/* regenerate bitmap */
//				for (i = 0; i < rawsize; i++)
//					bmp->raster [i] = color_remap2 [bmp->raster [i]];
//			}
//
//			/* at this point, transparency is optimized regardless */
//			bmp->opt_pal_transp = total_alpha;
//		}
//	}
//
//	return 0;
//}
//
///* reduce palette color
//   if provided image has no palette (RGB etc), does nothing and returns.
//   returns: ==0 ok, !=0 error */
//static int reduce_palette_colors(raw_bitmap *bmp)
//{
//	int color_entry [256];
//	int color_remap [256]; /* data = old color number */
//	int color_remap2 [256]; /* data = new color number */
//	unsigned char new_palette [1024];
//	int rawsize = bmp->width * bmp->height;
//	int i, j;
//	int cur_id, cur_id2, used_colors = 0;
//	int useful_alpha = 0;
//	int total_alpha = 0;
//
//	/* is that really a image with palette? */
//	if ((bmp->pal_entries <= 0) || (bmp->raster == NULL))
//		return 1;
//
//	for (i = 0; i<bmp->pal_entries; i+=2)
//		new_palette[i<<1] = bmp->palette[i];
//	/* remove unnecessary palette entries */
//
//	memcpy (bmp->palette, new_palette, sizeof (unsigned char) * bmp->pal_bpp * used_colors);
//
//	/* regenerate bitmap */
//	for (i = 0; i < rawsize; i++) {
//		bmp->raster[i] = bmp->raster[i] << 1;
//	}
//	bmp->pal_entries = ( ( bmp->pal_entries + 1 ) << 1);
//
//	/* detect unecessary alpha in palette and remove it */
//
//	if (bmp->pal_bpp == 4) {
//		for (i = 0; i < bmp->pal_entries; i++) {
//			if (bmp->palette [i * 4 + 3] != (unsigned char) 0xff)
//				useful_alpha = 1;
//		}
//
//		if (useful_alpha == 0) {
//			debug_log_puts ("Image has unnecessary alpha in palette entries.");
//			for (i = 0; i < bmp->pal_entries; i++) {
//				bmp->palette [i * 3] = bmp->palette [i * 4];
//				bmp->palette [i * 3 + 1] = bmp->palette [i * 4 + 1];
//				bmp->palette [i * 3 + 2] = bmp->palette [i * 4 + 2];
//			}
//			bmp->pal_bpp = 3;
//		}
//	}
//
//	/* optimize colors with alpha entries (put those first), if necessary */
//
//	if (bmp->pal_bpp == 4) {
//		for (i = 0; i < bmp->pal_entries; i++) {
//			if (bmp->palette [i * 4 + 3] != 0xff)
//				total_alpha++;
//		}
//
//		if (total_alpha < bmp->pal_entries) {
//			j = 0;
//			for (i = total_alpha; i < bmp->pal_entries; i++) {
//				if (bmp->palette [i * 4 + 3] != 0xff)
//					j++;
//			}
//
//			if (j > 0) {
//				debug_log_puts ("Image has unoptimized transparency.");
//
//				/* reorder palette */
//
//				/* generate remap tables */
//				cur_id = 0; /* with alpha */
//				cur_id2 = total_alpha; /* without alpha */
//				for (i = 0; i < bmp->pal_entries; i++) {
//					if (bmp->palette [i * 4 + 3] != 0xff) {
//						color_remap [cur_id] = i;
//						color_remap2 [i] = cur_id;
//						cur_id++;
//					} else {
//						color_remap [cur_id2] = i;
//						color_remap2 [i] = cur_id2;
//						cur_id2++;
//					}
//				}
//
//				/* regenerate palette */
//				for (i = 0; i < used_colors; i++) {
//					for (j = 0; j < bmp->pal_bpp; j++) {
//						new_palette [i * bmp->pal_bpp + j] = bmp->palette [color_remap [i] * bmp->pal_bpp + j];
//					}
//				}
//				memcpy (bmp->palette, new_palette, sizeof (unsigned char) * bmp->pal_bpp * used_colors);
//
//				/* regenerate bitmap */
//				for (i = 0; i < rawsize; i++)
//					bmp->raster [i] = color_remap2 [bmp->raster [i]];
//			}
//
//			/* at this point, transparency is optimized regardless */
//			bmp->opt_pal_transp = total_alpha;
//		}
//	}
//
//	return 0;
//}

//
//int compress_google_map_png (http_headers *serv_hdr, http_headers *client_hdr, char *inbuf, ZP_DATASIZE_TYPE insize, char *outb, ZP_DATASIZE_TYPE *outl){
//	int st = IMG_RET_ERR_OTHER;
//	int pngstatus = IMG_RET_ERR_OTHER;
//	int jp2status = IMG_RET_ERR_OTHER;
//	int jpegstatus = IMG_RET_ERR_OTHER;
//	t_content_type outtype = OTHER_CONTENT;
//	int jpeg_q;
//	raw_bitmap *bmp = NULL;
//	long long int max_raw_size;
//	t_content_type detected_ct;
//	t_content_type source_type;
//	t_content_type target_lossy;
//	t_content_type target_lossless = IMG_PNG; /* only PNG is available */
//	int try_lossless = 1, try_lossy = 1;
//	int has_transparency = 0;
//	char *buf_lossy = NULL, *buf_lossless = NULL;
//	int buf_lossy_len, buf_lossless_len;
//	int max_outlen;
//	int lossy_status, lossless_status;
//	const int *j2bitlenYA, *j2bitlenRGBA, *j2bitlenYUVA, *j2csamplingYA, *j2csamplingRGBA, *j2csamplingYUVA;
//	int source_is_lossless = 0;	/* !=0 if source is gif or png */
//
//	// "rate" below: JP2 rate, the native compression setting of JP2
//	// ziproxy tries to emulate JPEG's quality setting to JP2, and this
//	// var represents the 'real thing' which is hidden from the user.
//	float rate = -1.0;
//	int jp2_q;
//
//	max_raw_size = insize * MaxUncompressedImageRatio;
//
//	debug_log_puts ("Starting image decompression...");
//
//	if (insize >= MIN_INSIZE_PNG)
//		st = png2bitmap (inbuf, insize, &bmp, max_raw_size);
//	else
//		st = IMG_RET_TOO_SMALL;
//	source_is_lossless = 1;
//
//	if (st != IMG_RET_OK) {
//		debug_log_puts ("Error while decompressing image.");
//		*outb = inbuf;
//		*outl = insize;
//		compress_image_freemem(source_type, bmp);
//		return st;
//	}
//	if (bmp->o_color_type == OCT_PALETTE) {
//		debug_log_printf ("Image parms (palette) -- w: %d, h: %d, " \
//			"palette with %d colors, pal_bpp: %d.\n", \
//			bmp->width, bmp->height, bmp->pal_entries, bmp->pal_bpp);
//	} else {
//		debug_log_printf ("Image parms (non-palette) -- w: %d, h: %d, bpp: %d\n", \
//			bmp->width, bmp->height, bmp->bpp);
//	}
//
//	optimize_palette (bmp);
//	reduce_palette_colors(bmp);
//	optimize_alpha_channel (bmp);
//
//	/*
//	 * STRATEGY DECISIONS
//	 */
//
//	debug_log_puts ("Deciding image compression strategy...");
//
//	/* does it have transparency? */
//	if (bmp->raster != NULL) {
//		/* palette image */
//		if ((bmp->pal_bpp == 2) || (bmp->pal_bpp == 4))
//			has_transparency = 1;
//	} else {
//		/* non-palette image */
//		if ((bmp->bpp == 2) || (bmp->bpp == 4))
//			has_transparency = 1;
//	}
//
//	/* which lossy format to use? */
//#ifdef JP2K
//	if (ProcessToJP2 && (! ForceOutputNoJP2) && \
//		((! JP2OutRequiresExpCap) || (JP2OutRequiresExpCap && (client_hdr != NULL && client_hdr->client_explicity_accepts_jp2)))) {
//		target_lossy = IMG_JP2K;
//	} else {
//		target_lossy = IMG_JPEG;
//	}
//#else
//	target_lossy = IMG_JPEG;
//#endif
//
//	/* is lossy suitable for this picture? */
//#ifdef JP2K
//	if (target_lossy == IMG_JP2K) {
//		jp2_q = getJP2ImageQuality (bmp->width, bmp->height);
//		if ((jp2_q == 0) || (insize < MIN_INSIZE_TO_JP2K))
//			try_lossy = 0;
//	}
//#endif
//	if (target_lossy == IMG_JPEG) {
//		jpeg_q = getImageQuality (bmp->width, bmp->height);
//		if ((jpeg_q == 0) || (insize < MIN_INSIZE_TO_JPEG)) {
//			try_lossy = 0;
//		} else if (has_transparency) {
//			if (AllowLookCh)
//				remove_alpha_channel (bmp);
//			else
//				try_lossy = 0;
//		}
//	}
//
//	/* compressed data may not be bigger than max_outlen */
//	max_outlen = insize - 1;
//
//#ifdef JP2K
//	/* should we convert from jp2k even if the final size is bigger? */
//	if ((source_type == IMG_JP2K) && (ForceOutputNoJP2)) {
//		// up to 100%+500bytes of uncompressed bitmap, otherwise it's an abnomaly
//		max_outlen = (bmp->width * bmp->height * bmp->bpp) + 500;
//	}
//#endif
//
//	/* let's try saving some CPU load:
//	   is it worth trying lossless compression? */
//	if ((try_lossless != 0) && (try_lossy != 0) && (source_is_lossless == 0)) {
//		try_lossless = 0;
//	}
//
//	/* no viable target? return */
//	if ((try_lossy == 0) && (try_lossless == 0)) {
//		debug_log_puts ("No viable image target (lossy or lossless).");
//#ifdef IMAGE_MEM_REDUCE
//		compress_image_freemem(source_type, bmp);
//#endif
//		return IMG_RET_NO_AVAIL_TARGET;
//	}
//
//	/*
//	 * END OF STRATEGY DECISIONS
//	 */
//
//	debug_log_puts ("Strategy defined. Continuing...");
//
//
//	if (try_lossy) {
//		buf_lossy_len = max_outlen;
//
//		/* for lossy, full RGB image is required */
//		if (bmp->bitmap == NULL)
//			depalettize (bmp);
//	}
//	if (try_lossless) {
//		/* bitmap2png requires a preallocated buffer */
//		buf_lossless = (char *) malloc (sizeof (char) * max_outlen);
//		buf_lossless_len = max_outlen;
//	}
//
//	if (ConvertToGrayscale && (bmp->bitmap != NULL)) {
//		debug_log_puts ("Converting image to grayscale...");
//		rgb2gray (bmp);
//	}
//
//#ifdef JP2K
//	if ((try_lossy) && (target_lossy == IMG_JP2K)) {
//		debug_log_puts ("Attempting JP2K compression...");
//
//		// get the components' bit depth specifically for this image (based on image dimensions)
//		j2bitlenYA = getJP2KBitLenYA (bmp->width, bmp->height);
//		j2bitlenRGBA = getJP2KBitLenRGBA (bmp->width, bmp->height);
//		j2bitlenYUVA = getJP2KBitLenYUVA (bmp->width, bmp->height);
//
//		// get the components' sampling (scaling) parameters specifically for this image (based on image dimensions)
//		j2csamplingYA = getJP2KCSamplingYA (bmp->width, bmp->height);
//		j2csamplingRGBA = getJP2KCSamplingRGBA (bmp->width, bmp->height);
//		j2csamplingYUVA = getJP2KCSamplingYUVA (bmp->width, bmp->height);
//
//		rate = estimate_jp2rate_from_quality (bmp, jp2_q, \
//			JP2Colorspace, j2bitlenYA, j2bitlenRGBA, j2bitlenYUVA, \
//			j2csamplingYA, j2csamplingRGBA, j2csamplingYUVA);
//
//		if (rate * (float) calculate_jp2_rawsize (bmp, JP2Colorspace, \
//			j2bitlenYA, j2bitlenRGBA, j2bitlenYUVA, j2csamplingYA, \
//			j2csamplingRGBA, j2csamplingYUVA, 0) <= (float) max_outlen) {
//
//			jp2status = bitmap2jp2 (bmp, rate, &buf_lossy, &buf_lossy_len, \
//				JP2Colorspace, j2bitlenYA, j2bitlenRGBA, \
//				j2bitlenYUVA, j2csamplingYA, j2csamplingRGBA, \
//				j2csamplingYUVA);
//		} else {
//			jp2status = IMG_RET_TOO_BIG;
//		}
//	} else {
//		jp2status = IMG_RET_ERR_OTHER;
//	}
//#endif
//
//	if ((try_lossy) && (target_lossy == IMG_JPEG)) {
//		debug_log_puts ("Attempting JPEG compression...");
//		jpegstatus = bitmap2jpg (bmp, jpeg_q, &buf_lossy, &buf_lossy_len);
//	}
//
//	/* try_lossless implies PNG */
//	if (try_lossless != 0) {
//		debug_log_puts ("Attempting PNG compression...");
//		pngstatus = bitmap2png (bmp, &buf_lossless, &buf_lossless_len);
//		debug_log_printf("the head of new png,%d %d %d %d\n",buf_lossless[0],buf_lossless[1],buf_lossless[2],buf_lossless[3]);
//	}
//
//	debug_log_printf ("Compression return codes -- JP2K:%d JPEG:%d PNG:%d\n", jp2status, jpegstatus, pngstatus);
//
//	lossless_status = pngstatus;
//	if (target_lossy == IMG_JPEG)
//		lossy_status = jpegstatus;
//	else
//		lossy_status = jp2status;
//
//	/* decide which compressed version to use, or none */
//	if ((lossless_status == IMG_RET_OK) && (lossy_status == IMG_RET_OK)) {
//		/* TODO: add some fuzzy logic here
//		  (smallest size is not always the best choice) */
//		if (buf_lossy_len < buf_lossless_len) {
//			outtype = target_lossy;
//		} else {
//			outtype = target_lossless;
//		}
//	} else if (lossless_status == IMG_RET_OK) {
//		outtype = target_lossless;
//	} else if (lossy_status == IMG_RET_OK) {
//		outtype = target_lossy;
//	} else {
//		outtype = OTHER_CONTENT;
//	}
//
//	/* select buffer and discard the other one (or both) */
//	if (outtype == target_lossy) {
//		*outb = buf_lossy;
//		*outl = buf_lossy_len;
//		if (buf_lossless != NULL)
//			free (buf_lossless);
//	} else if (outtype == target_lossless) {
//		*outb = buf_lossless;
//		*outl = buf_lossless_len;
//		if (buf_lossy != NULL)
//			free (buf_lossy);
//	} else {
//		*outb = inbuf;
//		*outl = insize;
//		if (buf_lossy != NULL)
//			free (buf_lossy);
//		if (buf_lossless != NULL)
//			free (buf_lossless);
//	}
//
//	//if (serv_hdr->where_content_type > 0){
//	if (serv_hdr != NULL && serv_hdr->where_content_type > 0){
//		if(outtype != OTHER_CONTENT)
//			switch(outtype){
//				case IMG_JP2K:
//					serv_hdr->hdr[serv_hdr->where_content_type] =
//						"Content-Type: image/jp2";
//					break;
//				case IMG_JPEG:
//					serv_hdr->hdr[serv_hdr->where_content_type] =
//						"Content-Type: image/jpeg";
//					break;
//				case IMG_PNG:
//					serv_hdr->hdr[serv_hdr->where_content_type] =
//						"Content-Type: image/png";
//					break;
//			}
//	}
//
//exit:
//
//#ifdef IMAGE_MEM_REDUCE
//	compress_image_freemem(source_type, bmp);
//#endif
//	return IMG_RET_OK;
//}

#ifdef TEST
int google_map_test() {
//	int compress_google_map_imageset(http_headers *serv_hdr, FILE* sockrfp, FILE* sess_wclient)
	ZP_DATASIZE_TYPE filesize = 0;
	char* inbuf = NULL;
	gmap_imageset_header ihdr;
	FILE* in = fopen("test/googlemap.g","r");
	FILE* out = fopen("test/googlemap.out","w");
	if (!in || !out) return 1;
	fseek(in,0,SEEK_END);
	filesize = ftell(in);
	fseek(in,0,SEEK_SET);
	inbuf = (char*)malloc(filesize);
	int ret = fread(inbuf,1024,filesize/1024 + 1,in);
	if ( gmap_compress_imageset(inbuf,filesize,&ihdr,NULL,NULL) == 1) {
		fwrite(inbuf,filesize,1,out);
		return 0;
	}

	if (ihdr.outbuf) {
		gmap_write_imageset(&ihdr,out);
		gmap_free(&ihdr);
	}

	return 0;

}
#endif

#endif /* GOOGLEMAP_C_ */
