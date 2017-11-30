/*
 * getcolor.c
 *
 *  Created on: Jun 27, 2012
 *      Author: jiangxd
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <png.h>
#include <dirent.h>
#include "../png_compressor.h"

typedef struct png_res_struct {
	png_structp png_ptr;
	png_infop info_ptr;
	png_colorp palette;
	int num_pal;
	struct png_res_struct *next;
} png_res;

//static png_colorp* colors = NULL;
static png_res* png_head = NULL;
static png_res* png_end = NULL;

static const char* ext_name(const char* filename) {
	const char* p = filename + strnlen(filename, 0x100) - 1;
	while (p > filename && p && *p != '.')
		p--;
	return p;
}

int read_from_png(char *inbuf, unsigned long insize) {

	png_structp png_ptr;
	png_infop info_ptr;
	png_uint_32 width,height;
	int bit_depth, color_type;
	png_colorp pal;

	if ((insize < 8) || png_sig_cmp (inbuf, (png_size_t) 0, 8)) {
		return 1;
	}

	png_ptr = png_create_read_struct (PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if (png_ptr == NULL) {
		return 2;
	}

	if (!png_end) {
		png_end = png_head = (png_res*)malloc(sizeof(png_res));
	}
	else {
		png_end->next = (png_res*)malloc(sizeof(png_res));
		png_end = png_end->next;
	}
	bzero(png_end,sizeof(png_res));
	png_end->png_ptr = png_ptr;

	info_ptr = png_create_info_struct (png_ptr);
	if (info_ptr == NULL) {
		return 3;
	}
	png_end->info_ptr = info_ptr;

	if (setjmp (png_jmpbuf(png_ptr))) {
		return 4;
	}

	png_set_error_fn (png_ptr, NULL, png_err_still, png_warn_still);

	IODesc desc;
	desc.buf = inbuf;
	desc.size = insize;
	desc.pos = 0;

	png_set_read_fn (png_ptr, (png_voidp) &desc, mem_to_png);

	png_read_info (png_ptr,info_ptr);

	png_get_IHDR (png_ptr, info_ptr, &width, &height,
		&bit_depth, &color_type, NULL, NULL, NULL);
	if (bit_depth == 16) {
		// strip to 8 bit depth
		png_set_strip_16 (png_ptr);
	}

	/* using palette and using color */
	if ( (color_type & PNG_COLOR_TYPE_PALETTE) != PNG_COLOR_TYPE_PALETTE ) {
		return 1;
	}

	if (png_get_PLTE(png_ptr, info_ptr, &(png_end->palette),
			&(png_end->num_pal)) != PNG_INFO_PLTE)
		return 7;

	return 0;
}

static int query_colors(const char* filename) {

	FILE* f = NULL;
	unsigned filesize = 0;
	int retval;

	f = fopen(filename,"r");
	if (!f) {
		fprintf(stderr,"open file failed:%s\n",filename);
		return 1;
	}

	char* inbuf = NULL;
	fseek(f,0,SEEK_END);
	filesize = ftell(f);
	fseek(f,0,SEEK_SET);
	inbuf = malloc(filesize);
	if (fread(inbuf,filesize,1,f) != 1) {
		fprintf(stderr,"read file failed:%s\n",filename);
		fclose(f);
		return 1;
	}

	if ( read_from_png(inbuf,filesize) ) {
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

int is_regular_file(const char* filepath) {
	struct stat fstat;
	stat(filepath,&fstat);
	return S_ISREG(fstat.st_mode);
}

int main(int argc, char** argv) {

	char* dirname = ".";
	DIR* dir = NULL;
	struct dirent* entry = NULL;
	char filepath[0x100];
	int dest_colors = 16;

	if (argc > 1)
		dirname = argv[1];
	if (argc > 2)
		dest_colors = atoi(argv[2]);

	dir = opendir(dirname);
	while ((entry = readdir(dir))) {
		snprintf(filepath,0x100,"%s/%s", dirname, entry->d_name);
		if (!is_regular_file(filepath)) continue;
		const char* ext = ext_name(entry->d_name);
		if (!strncmp(".png", ext, 4))
			query_colors(filepath);
	}

	color_box *boxes = (color_box*)malloc(sizeof(color_box) * dest_colors);
	bzero(boxes,dest_colors * sizeof(color_box));
	png_res* p = png_head;
	color_list* head = NULL;
	color_list* tail = NULL;
	while (p) {
		color_freq_t *color_freq = (uint32_t*)malloc(sizeof(color_freq_t));
		alloc_colors(p->palette,p->num_pal,&head,&tail,color_freq);
		free(color_freq);
		if (head && tail) {
			if (!boxes->colors) boxes->colors = head;
			else boxes->tail->next = head;
			boxes->tail = tail;
		}
		p = p->next;
	}

	quantize_colors_mc(boxes,dest_colors);
	print_boxes(boxes, dest_colors);

	p = png_head;
	png_res* next = NULL;
	while (p) {
		png_destroy_read_struct(&p->png_ptr, &p->info_ptr, NULL);
		next = p->next;
		free(p);
		p = next;
	}

	free(boxes);

	return 0;
}
