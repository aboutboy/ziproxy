/*
* png_compressor.c
 *
 *  Created on: Jun 18, 2012
 *      Author: jiangxd
 */
#include <inttypes.h>
#include <png.h>
#include <assert.h>
#include <zlib.h>
#include "log.h"
#include "png_compressor.h"

#ifdef USER_SETTINGS
#include "user_settings.h"
#include "session.h"
#endif

#define MAX_COMPRESSED_SIZE 0x10000000  // 256MB

#ifdef USER_SETTINGS
static int level_colors[7][4] = {
		{4,8,16,32},
		{8,16,16,32},
		{8,16,32,64},
		{16,16,64,128},
		{16,32,64,128},
		{32,32,64,128},
		{32,64,128,256}
};
#endif

static inline int decide_compressed_colors(int colors) {
#ifdef USER_SETTINGS
	int* colors_matrix = level_colors[2];
	if (got_user_settings) {
		colors_matrix = level_colors[user_settings.image_quality];
	}
	if (colors <= 8) return 0;
	if (colors < 32) return colors_matrix[0];
	if (colors < 64) return colors_matrix[1];
	if (colors < 128) return colors_matrix[2];
	return colors_matrix[3];
#else
	if (colors <= 8) return 0;
	if (colors < 32) return 8;
	if (colors < 64) return 16;
	if (colors < 128) return 32;
	return 64;
#endif
}

static void png_flush_mem(png_structp png_ptr){};

static inline void query_color_frequency(PNGDesc* rd, color_freq_t color_freq[256]) {
	int64_t i;;
	for (i = (rd->width * rd->height)-1; i >= 0; i--) {
		color_freq[(unsigned char)rd->raster[i]] ++;
	}
}

void png_to_mem(png_structp png_ptr,
        png_bytep data, png_size_t length){
		IODesc *desc=(IODesc*)png_get_io_ptr(png_ptr);
	if(desc->pos + length > desc->size) {
		char buf[0x100];
		snprintf(buf,0x100,"Writing past output buffer:%ld,size:%d\n", (desc->pos + length), desc->size);
		error_log_printf(LOGMT_WARN,LOGSS_DAEMON,buf);
		png_error(png_ptr, buf);
	}

	memcpy(desc->buf + desc->pos, data ,length);
	desc->pos += length;
}

void mem_to_png(png_structp png_ptr, png_bytep data, png_size_t length)
{
	IODesc *desc = (IODesc*) png_get_io_ptr(png_ptr);

	if (desc->pos + length >= desc->size)
		png_error(png_ptr, "Reading past input buffer\n");

	memcpy(data, desc->buf + desc->pos, length);
	desc->pos += length;
}

void png_warn_still(png_structp png_ptr, png_const_charp msg){}

inline void png_err_still(png_structp png_ptr, png_const_charp msg)
{
	fprintf(stderr,"%s",msg);
	longjmp(png_jmpbuf(png_ptr), 5);
}
//
//#define free_and_return(val) \
//	if (raster) free(raster); \
//	if (new_palette) png_free(png_ptr, new_palette); \
//	if (new_raster) free(new_raster); \
//	if (row_pointers) free (row_pointers); \
//	png_destroy_read_struct (&png_ptr, &info_ptr, NULL); \
//	return val;
//
//static int gen_bit_depth(int palette_entries) {
//	if (palette_entries == 256) return 8;
//	if (palette_entries >= 16) return 4;
//	if (palette_entries >= 4) return 2;
//	return 1;
//}

//static char* create_new_raster(png_uint_32 width, png_uint_32 height, int bit_depth) {
//	uint64_t size = height * width;
//	switch(bit_depth) {
//	case 4:
//		size >>= 1;
//		break;
//	case 2:
//		size >>= 2;
//		break;
//	case 1:
//		size >>= 3;
//		break;
//	}
//	return (char*)malloc(size);
//}

/**
 * return ==COMP_OK ok, ==COMP_NOCOMP don't need compress >1, error
 * @param insize input buffer size
 * @param inbuf input buffer
 * @param read png descriptor
 */
int read_png(PNGDesc* rd, char *inbuf, ZP_DATASIZE_TYPE insize) {

	png_bytepp row_pointers = NULL;
	png_bytep onerow = NULL;

	if ((insize < 8) || png_sig_cmp (inbuf, (png_size_t) 0, 8)) {
		char hex[24];
		int i;
		for (i = 0; i < 8; i++) {
			snprintf(hex + i * 3,3, "%2x ", (unsigned char)inbuf[i]);
		}
		error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"insize:%d,buf:%s\n",insize,hex);
		return COMP_NOCOMP;
	}

	rd->png_ptr = png_create_read_struct (PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (rd->png_ptr == NULL) {
		return 2;
	}

	rd->info_ptr = png_create_info_struct (rd->png_ptr);
	if (rd->info_ptr == NULL) {
		return 3;
	}

	png_infop end_info = NULL;
	if (setjmp (png_jmpbuf(rd->png_ptr))) {
		return 4;
	}

	png_set_error_fn (rd->png_ptr, NULL, png_err_still, png_warn_still);

	IODesc desc;
	desc.buf = inbuf;
	desc.size = insize;
	desc.pos = 0;

	png_set_read_fn (rd->png_ptr, (voidp) &desc, mem_to_png);

	png_read_info (rd->png_ptr,rd->info_ptr);

	png_get_IHDR (rd->png_ptr, rd->info_ptr, &(rd->width), &(rd->height),
		&(rd->bit_depth), &(rd->color_type), NULL, NULL, NULL);
	if (rd->bit_depth == 16) {
		// strip to 8 bit depth
		png_set_strip_16 (rd->png_ptr);
		rd->bit_depth = 8;
	}

	uint64_t rawsize = rd->width * rd->height;

	/* too huge, unworkable */
	if ((rd->width > 0x7fffffff) || (rd->height > 0x7fffffff))
		return COMP_NOCOMP;
	if ( ((rawsize * rd->bit_depth) >> 3) > MAX_COMPRESSED_SIZE)
		return COMP_NOCOMP;

	/* using palette and using color */
	if ( (rd->color_type & PNG_COLOR_TYPE_PALETTE) != PNG_COLOR_TYPE_PALETTE ) {
		error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"bbb:%d\n",rd->color_type);
		return COMP_NOCOMP;
	}

	/* get alpha, if present */
	png_bytep trans;
	int num_trans;
	png_color_16p trans_values;
	if (!png_get_tRNS (rd->png_ptr, rd->info_ptr, &trans, &num_trans, &trans_values))
		num_trans = 0;

	if (png_get_PLTE (rd->png_ptr, rd->info_ptr, &rd->palette, &rd->pal_entries) != PNG_INFO_PLTE) return 7;

	if (rd->bit_depth < 8)
		png_set_packing (rd->png_ptr); /* force 1 byte per pixel */

	// in palette color 8 bit depth mode, every pixel has only one byte
	rd->raster = (unsigned char *) malloc (rawsize);
	if (!rd->raster) return 8;

	bzero(rd->raster, rawsize);

	int i;
	/* decompress bitmap to raw buffer */
	row_pointers = (png_bytepp) malloc (rd->height * sizeof (png_bytep));
	onerow = (png_bytep) rd->raster;
	for (i=0; i < rd->height; i++) {
		row_pointers [i] = onerow;
		onerow += rd->width; // in palette color 8 bit depth mode, every pixel has only one byte
	}
	png_read_image (rd->png_ptr, row_pointers);

	if (row_pointers) {
		free(row_pointers);
		row_pointers = NULL;
	}

	return 0;
}

/**
 * return ==COMP_OK ok, ==COMP_NOCOMP don't need compress >1, error
 * @param outl output length
 * @param outb output buffer
 * @param wrote png descriptor
 */
int write_png(PNGDesc* wd, char* outb, ZP_DATASIZE_TYPE *outl) {
	png_bytep onerow;
	IODesc desc;

	wd->png_ptr = png_create_write_struct
		(PNG_LIBPNG_VER_STRING, NULL,
		NULL, NULL);

	if (wd->png_ptr == NULL)
		return 2;

	wd->info_ptr = png_create_info_struct(wd->png_ptr);
	if (wd->info_ptr == NULL) {
		return 3;
	}

	if (setjmp(png_jmpbuf(wd->png_ptr))) {
		return 4;
	}

	png_set_error_fn(wd->png_ptr,NULL,
			png_err_still, png_warn_still);

	/* write */
	png_set_IHDR(wd->png_ptr, wd->info_ptr, wd->width, wd->height, wd->bit_depth,
			wd->color_type,PNG_INTERLACE_NONE,PNG_COMPRESSION_TYPE_DEFAULT,
			PNG_FILTER_TYPE_DEFAULT);

	png_set_PLTE (wd->png_ptr, wd->info_ptr, wd->palette, wd->pal_entries);

	png_set_packing(wd->png_ptr);
	png_set_compression_level(wd->png_ptr, Z_BEST_COMPRESSION);

	png_bytepp row_pointers = (png_bytepp)malloc(wd->height * sizeof(png_bytep));
	onerow = wd->raster;

	int i;
	for (i=0; i < wd->height; i++) {
		row_pointers[i] = onerow;
		onerow += wd->width;//* wd->bit_depth / 8;
	}

	png_set_rows(wd->png_ptr, wd->info_ptr, row_pointers);

	desc.buf = outb;
	desc.size = *outl;
	desc.pos = 0;
	png_set_write_fn (wd->png_ptr, (void*) &desc, png_to_mem, png_flush_mem);

	png_write_png (wd->png_ptr, wd->info_ptr,PNG_TRANSFORM_PACKING, NULL);
	*outl = desc.pos;
	if (row_pointers) {
		free(row_pointers);
		row_pointers = NULL;
	}
	return COMP_OK;
}

#ifdef TEST

static int get_box_colors(color_box* box) {
	color_list* c = box->colors;
	int n = 0;
	while (c) {
		n++;
		c = c->next;
	}
	return n;
}

void print_colors(color_box* box) {
	color_list* p = box->colors;
	printf("print colors\n");
	int num = 0;
	while (p) {
		printf("{%ud,%ud,%ud}\n",p->color.red,p->color.green,p->color.blue);
		p = p->next;
		num ++;
	}
	printf("print colors end, total %d colors\n",num);
}

void print_boxes(color_box* boxes, int n) {
	printf("n:%d\n",n);
	printf("boxes\n");
	int i;
	for (i = 0; i < n; i++) {
		printf("{%u,%u,%u} {%u,%u,%u} \n",
				boxes[i].lb_vertice.red,
				boxes[i].lb_vertice.green,
				boxes[i].lb_vertice.blue,
				boxes[i].rt_vertice.red,
				boxes[i].rt_vertice.green,
				boxes[i].rt_vertice.blue
				);
	}
//	printf("center nodes:\n");
//	for (i = 0; i < n; i++) {
//		printf("{%u,%u,%u},\n",
//				( boxes[i].lb_vertice.red + boxes[i].rt_vertice.red ) / 2,
//				( boxes[i].lb_vertice.green + boxes[i].rt_vertice.green ) / 2,
//				( boxes[i].lb_vertice.blue + boxes[i].rt_vertice.blue ) / 2
//				);
//	}
}
#endif

/**
 * create a color_list using 'colors' parameter, the list includes 2 pointers: 'head' and 'tail'
 */
void alloc_colors(png_colorp colors, int num_colors, color_list** head,
		color_list** tail, const color_freq_t* color_freq) {
	int i;
	*head = NULL;
	*tail = NULL;
	color_list** p = head;
	for (i=0;i<num_colors;i++) {
		*p = malloc(sizeof(color_list));
		(*p)->color = colors[i];
		if (color_freq)
			(*p)->color_freq = color_freq[i];
		*tail = *p;
		p = &((*p)->next);
	}
	*p = NULL;
}

static void shrink_box(color_box* box) {
	int i;
	box->lb_vertice = box->rt_vertice = box[0].colors->color;
	color_list* p = box->colors;
	while (p != NULL) {
		png_colorp c = &(p->color);
		if (c->red < box->lb_vertice.red)
			box->lb_vertice.red = c->red;
		if (c->blue < box->lb_vertice.blue)
			box->lb_vertice.blue = c->blue;
		if (c->green < box->lb_vertice.green)
			box->lb_vertice.green = c->green;

		if (c->red > box->rt_vertice.red)
			box->rt_vertice.red = c->red;
		if (c->blue > box->rt_vertice.blue)
			box->rt_vertice.blue = c->blue;
		if (c->green > box->rt_vertice.green)
			box->rt_vertice.green = c->green;

		p = p->next;
	}
}

static void cut_box(color_box* box, color_box* newbox) {
	int red_distance = box->rt_vertice.red - box->lb_vertice.red;
	int blue_distance = box->rt_vertice.blue - box->lb_vertice.blue;
	int green_distance = box->rt_vertice.green - box->lb_vertice.green;
	int i,j;
	int color_field = 0;
#define comp_color_field(f) \
	(f == 1? (p->color.red >= box->rt_vertice.red) : ( \
	f == 2? (p->color.green >= box->rt_vertice.green) : \
	p->color.blue >= box->rt_vertice.blue) \
	)

	bzero(newbox,sizeof(color_box));
	if (red_distance >= blue_distance && red_distance >= green_distance) {
		// cut along red axis
		newbox->lb_vertice.red = (box->rt_vertice.red + box->lb_vertice.red) / 2;
		newbox->rt_vertice.red = box->rt_vertice.red;
		box->rt_vertice.red = newbox->lb_vertice.red;

		newbox->lb_vertice.blue = box->lb_vertice.blue;
		newbox->lb_vertice.green = box->lb_vertice.green;
		newbox->rt_vertice.blue = box->rt_vertice.blue;
		newbox->rt_vertice.green = box->rt_vertice.green;
		color_field = 1;
	}

	else if (green_distance >= blue_distance && green_distance >= red_distance) {
		// cut along blue axis
		newbox->lb_vertice.green = (box->rt_vertice.green + box->lb_vertice.green)	/ 2;
		newbox->rt_vertice.green = box->rt_vertice.green;
		box->rt_vertice.green = newbox->lb_vertice.green;

		newbox->lb_vertice.red = box->lb_vertice.red;
		newbox->lb_vertice.blue = box->lb_vertice.blue;
		newbox->rt_vertice.red = box->rt_vertice.red;
		newbox->rt_vertice.blue = box->rt_vertice.blue;
		color_field = 2;
	}
	else if (blue_distance >= red_distance && blue_distance >= green_distance) {
		// cut along blue axis
		newbox->lb_vertice.blue = (box->rt_vertice.blue + box->lb_vertice.blue) / 2;
		newbox->rt_vertice.blue = box->rt_vertice.blue;
		box->rt_vertice.blue = newbox->lb_vertice.blue;

		newbox->lb_vertice.red = box->lb_vertice.red;
		newbox->lb_vertice.green = box->lb_vertice.green;
		newbox->rt_vertice.red = box->rt_vertice.red;
		newbox->rt_vertice.green = box->rt_vertice.green;
		color_field = 3;
	}

//#ifdef TEST
//	printf("cut %d side\n",color_field);
//#endif

	color_list* p = box->colors;
	color_list* prev = NULL;
	color_list* nprev = NULL;
	color_list* next = NULL;
	while (p) {
		next = p->next;
		if (comp_color_field(color_field)) {
			if (!newbox->colors) {
				newbox->colors = p;
				newbox->tail = newbox->colors;
			}
			else {
				nprev->next = p;
				newbox->tail = nprev;
			}
			if (prev) {
				prev->next = p->next;
			}
			else {
				box->colors = p->next;
			}
			p->next = NULL;
			nprev = p;
			box->tail = prev;
		}
		else {
			box->tail = p;
			prev = p;
		}
		p = next;
	}
}

static int get_large_side(color_box* box) {
	int red_distance = box->rt_vertice.red - box->lb_vertice.red;
	int blue_distance = box->rt_vertice.blue - box->lb_vertice.blue;
	int green_distance = box->rt_vertice.green - box->lb_vertice.green;
	int large_side = red_distance;
	if (large_side < blue_distance) large_side = blue_distance;
	if (large_side < green_distance) large_side = green_distance;
	return large_side;
}

static inline void get_center_color(color_box* box, png_color* color) {
	color->red = (box->lb_vertice.red + box->rt_vertice.red + 1) / 2;
	color->blue = (box->lb_vertice.blue + box->rt_vertice.blue + 1) / 2;
	color->green = (box->lb_vertice.green + box->rt_vertice.green + 1) / 2;
}

static void get_most_used_color(color_box* box, png_color* color) {
	color_list* most_used = box->colors;
	color_list* p = box->colors->next;
	while (p) {
		if (p->color_freq > most_used->color_freq)
			most_used = p;
		p = p->next;
	}
	*color = most_used->color;
}


static inline int color_in_box(const png_color* color, const color_box* box) {
	return (color->red >= box->lb_vertice.red
			&& color->red <= box->rt_vertice.red
			&& color->green >= box->lb_vertice.green
			&& color->green <= box->rt_vertice.green
			&& color->blue >= box->lb_vertice.blue
			&& color->blue <= box->rt_vertice.blue);
}

#define distance(a,b) ( (a) > (b) ? ((a)-(b)) : ((b)-(a)) )

/**
 * Using Median cut algorithm to reduce colors
 * @param dest_colors number of reduced colors
 * @param boxes There is must only 1 largest box
 */
void quantize_colors_mc(color_box* boxes, int dest_colors) {
	int num_boxes = 1;

	shrink_box(boxes);

	while (num_boxes < dest_colors) {
//#ifdef TEST
//		printf("\n");
//		print_boxes(boxes,num_boxes);
//#endif
		int large_side = 0;
		color_box* large_box = NULL;
		int i;
		assert(num_boxes < dest_colors);
		for (i = 0; i < num_boxes; i++) {
			int side = get_large_side(boxes + i);
			if (side > large_side) {
				large_side = side;
				large_box = boxes + i;
			}
		}
//		printf("large side:%d\n",large_side);
//		printf("cut %ldth box\n",large_box - boxes);
//		print_colors(large_box);
		cut_box(large_box, boxes + num_boxes);
//		print_colors(large_box);
		shrink_box(large_box);
		assert(num_boxes < dest_colors);
		shrink_box(boxes + num_boxes);
		num_boxes++;
	}

}

void reduce_using_existed_palette(PNGDesc* rd, PNGDesc* wd, png_colorp palette, int num_pal) {

	int i;
	unsigned char j;

	wd->palette = palette;
	wd->pal_entries = num_pal;

	uint64_t rawsize = wd->height * wd->width;
	unsigned char *map = (unsigned char*)malloc(rd->pal_entries);
	if (!map) return;

	// create map between 2 palettes
	uint32_t closest_distance = 0xFFFFFFFF;
	for (i = 0; i < rd->pal_entries; i++) {
		png_colorp color = rd->palette + i;
		unsigned char closest_index;
		for (j = 1; j < num_pal; j++) {
			png_colorp p = palette + j;
			uint32_t dist = distance(p->red,color->red) * distance(p->red,color->red)
					+ distance(p->green,color->green) * distance(p->green,color->green)
					+ distance(p->blue,color->blue) * distance(p->green,color->green);
			if (dist < closest_distance) {
				closest_distance = dist;
				closest_index = j;
			}
		}
		map[i] = closest_index;
//		printf("i:%u,%u\n",i,closest_index);
	}

	// update raster
	for (i = 0; i < rawsize; i++) {
		wd->raster[i] = map[rd->raster[i]];
//		if (rd->raster[i] >= rd->pal_entries)
//			printf("raster:%u\n",rd->raster[i]);
	}
	if (map) {
		free(map);
		map = NULL;
	}
}

/**
 * reduce colors using quantization algorithms
 */
void reduce_colors(PNGDesc* rd, PNGDesc* wd, int dest_colors) {
	assert(!wd->palette);
	assert(rd->pal_entries <= 256);
	assert(dest_colors <= 256);

	wd->pal_entries = dest_colors;
	color_box* boxes = malloc(dest_colors * sizeof(color_box));
	bzero(boxes,dest_colors * sizeof(color_box));

//	color_freq_t *color_freq = (color_freq_t*)malloc(rd->pal_entries * sizeof(color_freq_t));
	color_freq_t color_freq[256];
	bzero(color_freq,256 * sizeof(color_freq_t));
//	bzero(color_freq,rd->pal_entries * sizeof(color_freq_t));
	query_color_frequency(rd,color_freq);
	alloc_colors(rd->palette,rd->pal_entries,&(boxes[0].colors),&(boxes[0].tail),color_freq);
//	free(color_freq);

	// quantize
	quantize_colors_mc(boxes,dest_colors);

	// we get these colors, pack into wd
	wd->palette = (png_colorp)malloc(dest_colors * sizeof(png_color));

	int i;
	unsigned char j;

//	printf("generated colors:\n");
	for (i = 0; i < dest_colors; i++) {
		get_most_used_color(boxes + i,wd->palette + i);
//		printf("{%u,%u,%u}\n",wd->palette[i].red,wd->palette[i].green,wd->palette[i].blue);
//		printf("box {%ud,%ud,%ud} => {%ud,%ud,%ud}\n", boxes[i].lb_vertice.red,
//				boxes[i].lb_vertice.green, boxes[i].lb_vertice.blue,
//				boxes[i].rt_vertice.red,
//								boxes[i].rt_vertice.green, boxes[i].rt_vertice.blue
//				);
	}
	// remap new palette
	unsigned char* map = (unsigned char*)malloc(rd->pal_entries * sizeof (unsigned char));
	for (i = 0; i < rd->pal_entries; i++ ) {
		int found = 0;
		for (j = 0; j < dest_colors; j++) {
			if (color_in_box(rd->palette + i,boxes + j)) {
				map[i] = j;
				found = 1;
			}
		}
		if (!found) {
			map[i] = 0;
		}
	}

	// update raster
	for (i = 0; i < wd->height * wd->width; i++) {
		wd->raster[i] = map[rd->raster[i]];
	}

	if (map) {
		free(map);
		map = NULL;
	}

}


/**
 * return ==COMP_OK ok, ==COMP_NOCOMP don't need compress >1, error
 * @param palette fixed palette, set NULL if you want to use dynamic compressed palette
 * @param num_pal number of the fixed palette color entries
 */
int compress_png (char *inbuf, ZP_DATASIZE_TYPE insize, char *outb, ZP_DATASIZE_TYPE *outl, png_colorp palette, unsigned int num_pal)
{
	PNGDesc rd,wd;
	int retval;
	bzero(&rd,sizeof(PNGDesc));
	bzero(&wd,sizeof(PNGDesc));
	if ( (retval = read_png(&rd,inbuf,insize)) ) {
		if (rd.raster) {
			free(rd.raster);
			rd.raster = NULL;
		}
		if (rd.png_ptr || rd.info_ptr)
			png_destroy_read_struct (&rd.png_ptr, &rd.info_ptr, NULL);
		return retval;
	}
	int dest_colors = decide_compressed_colors(rd.pal_entries);
//	error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"reduced colors:%d,%d\n",rd.pal_entries,dest_colors);
#ifdef TEST
	printf("reduced colors:%d,%d\n",rd.pal_entries,dest_colors);
#endif
	*outl = insize;
	wd.bit_depth = 8;
	wd.color_type = rd.color_type;
	wd.height = rd.height;
	wd.width = rd.width;
	wd.info_ptr = NULL;
	wd.palette = NULL;
	wd.pal_entries = 0;
	wd.png_ptr = NULL;

	if (!dest_colors) {
		return COMP_NOCOMP;
//		wd.palette = rd.palette;
//		wd.pal_entries = rd.pal_entries;
//		wd.raster = rd.raster;
	}
	else {
		wd.raster = (char*) malloc(wd.height * wd.width); // * wd.bit_depth / 8);
		if (palette)
			reduce_using_existed_palette(&rd,&wd,palette,num_pal);
		else
			reduce_colors(&rd,&wd,dest_colors);
	}

	if ((retval = write_png(&wd, outb, outl))) {
		error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"write png error:%d\n",retval);
//		if (rd.raster) free(rd.raster);
//		if (wd.raster && wd.raster != rd.raster) free(wd.raster);
//		png_destroy_read_struct (&rd.png_ptr, &rd.info_ptr, NULL);
//		png_destroy_read_struct (&wd.png_ptr, &wd.info_ptr, NULL);
		return retval;
	}

//
//	if (rd.raster) free(rd.raster);
//	if (wd.raster && wd.raster != rd.raster) free(wd.raster);
//	png_destroy_read_struct (&rd.png_ptr, &rd.info_ptr, NULL);
//	png_destroy_read_struct (&wd.png_ptr, &wd.info_ptr, NULL);
	return COMP_OK;
}

#ifdef TEST
#include <errno.h>
#include <string.h>
#include "CUnit/Basic.h"
#define IMMUTABLE_PALETTE_SIZE 16
static png_color IMMUTABLE_PALETTE[] = {
		{63,47,63},
		{158,77,61},
		{63,78,158},
		{158,170,63},
		{158,181,158},
		{82,165,158},
		{158,63,159},
		{63,144,63},
		{223,63,52},
		{56,54,223},
		{223,183,63},
		{223,158,170},
		{158,181,223},
		{71,161,223},
		{223,116,149},
		{223,223,191}
};

int compress_png_test() {
	FILE *fp = fopen("test/apple.png","r");
	if (!fp) {
		fprintf(stderr,"cannot open file:%s",strerror(errno));
		return 1;
	}

	long size;
	ZP_DATASIZE_TYPE outsize;

	fseek(fp,0,SEEK_END);
	size = ftell(fp);
	fseek(fp,0,SEEK_SET);

	char* inbuf = malloc(size);
	fread(inbuf,size,1,fp);

	char* outbuf = (char*)malloc(size);
	int retval;
	if (!(retval = compress_png(inbuf,size,outbuf,&outsize,NULL,0))) {
		FILE* fwp = fopen("test/apple-pngcomp.png","w");
		if (fwp) {
			fwrite(outbuf,outsize,1,fwp);
			fclose(fwp);
		}
	}

	if (fp) fclose(fp);
	free(outbuf);
	return retval;
}

void shrink_and_cut_test() {
	png_color orgcolors[8] = {
			{165,191,221},
			{244,243,240},
			{229,221,206},
			{236,236,229},
			{232,229,217},
			{221,213,191},
			{255,255,255},
			{206,217,232}
	};

	color_box box;
	alloc_colors(orgcolors, 8, &(box.colors), &(box.tail),NULL);

	shrink_box(&box);

	CU_ASSERT(box.lb_vertice.red == (png_byte)165);
	CU_ASSERT(box.lb_vertice.blue == (png_byte)191);
	CU_ASSERT(box.rt_vertice.red == (png_byte)255);
	CU_ASSERT(box.rt_vertice.blue == (png_byte)255);

	color_box newbox;
	cut_box(&box,&newbox);
	CU_ASSERT((png_byte)210 == box.rt_vertice.red);
	CU_ASSERT((png_byte)210 == newbox.lb_vertice.red);
	CU_ASSERT((png_byte)191 == newbox.lb_vertice.blue);
	CU_ASSERT((png_byte)255 == newbox.rt_vertice.red);
	CU_ASSERT((png_byte)255 == newbox.rt_vertice.blue);

	int n = get_box_colors(&box);
	CU_ASSERT(2 == get_box_colors(&box));
	CU_ASSERT(6 == get_box_colors(&newbox));

	shrink_box(&newbox);
	CU_ASSERT((png_byte)221 == newbox.lb_vertice.red);
	CU_ASSERT((png_byte)213 == newbox.lb_vertice.green);
}

int png_compressor_runtests() {
	CU_pSuite pSuite = NULL;

	   /* initialize the CUnit test registry */
	   if (CUE_SUCCESS != CU_initialize_registry())
	      return CU_get_error();

	   /* add a suite to the registry */
	   pSuite = CU_add_suite("Suite_1", NULL, NULL);
	   if (NULL == pSuite) {
	      CU_cleanup_registry();
	      return CU_get_error();
	   }

	   /* add the tests to the suite */
	   if (! CU_add_test(pSuite, "test of cut_box()", shrink_and_cut_test) )
	   {
	      CU_cleanup_registry();
	      return CU_get_error();
	   }

	   /* Run all tests using the CUnit Basic interface */
	   CU_basic_set_mode(CU_BRM_VERBOSE);
	   CU_basic_run_tests();
	   CU_cleanup_registry();
	   return CU_get_error();
}
#endif
