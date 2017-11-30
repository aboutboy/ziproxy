/*
 * png_compressor.h
 *
 *  Created on: Jun 18, 2012
 *      Author: jiangxd
 */

#ifndef PNG_COMPRESSOR_H_
#define PNG_COMPRESSOR_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <inttypes.h>
#include <png.h>
#include "log.h"
#include "globaldefs.h"
#define PNG_READ_DITHER_SUPPORTED

#define COMP_OK 0
#define COMP_NOCOMP 1

typedef uint32_t color_freq_t;

typedef struct {
		char* buf;
		int size;
		int pos;
}IODesc;

typedef struct color_list_struct {
	png_color color;
	color_freq_t color_freq;
	struct color_list_struct* next;
} color_list;

typedef struct {
	png_color lb_vertice; // left bottom vertice
	png_color rt_vertice; // right top vertice
	color_list* colors;
	color_list* tail;
//	int num_colors;
} color_box;

typedef struct {
	char* raster;
	int bit_depth;
	png_uint_32 width;
	png_uint_32 height;
	png_structp png_ptr;
	png_infop info_ptr;
	int color_type;
	png_colorp palette;
	int pal_entries;
}PNGDesc;

#ifdef TEST
void print_colors(color_box* box);
#endif

extern void png_to_mem(png_structp png_ptr, png_bytep data, png_size_t length);

extern void mem_to_png(png_structp png_ptr, png_bytep data, png_size_t length);

extern void png_warn_still(png_structp png_ptr, png_const_charp msg);

extern void png_err_still(png_structp png_ptr, png_const_charp msg);

extern void alloc_colors(png_colorp colors, int num_colors, color_list** head,
		color_list** tail, const uint32_t* color_freq);

extern int compress_png(char *inbuf, ZP_DATASIZE_TYPE insize, char *outb,
		ZP_DATASIZE_TYPE *outl, png_colorp palette, unsigned int num_pal);

extern void quantize_colors_mc(color_box* boxes, int dest_colors);

#ifdef TEST
extern int compress_png_test();
#endif

#endif /* PNG_COMPRESSOR_H_ */
