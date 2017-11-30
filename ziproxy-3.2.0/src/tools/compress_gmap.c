/*
 * compress_gmap.c
 *
 *  Created on: Jun 29, 2012
 *      Author: jiangxd
 */
#include <sys/time.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>
#include "session.h"
#include "globaldefs.h"
#include "log.h"
#include "image.h"
#include "googlemap.h"


int google_map_test(const char* infile, const char* outfile) {
//	int compress_google_map_imageset(http_headers *serv_hdr, FILE* sockrfp, FILE* sess_wclient)
	ZP_DATASIZE_TYPE filesize = 0;
	char* inbuf = NULL;
	gmap_imageset_header ihdr;
	FILE* in = fopen(infile,"r");
	FILE* out = fopen(outfile,"w");
	if (!in || !out) return 1;
	fseek(in,0,SEEK_END);
	filesize = ftell(in);
	fseek(in,0,SEEK_SET);
	inbuf = (char*)malloc(filesize);
	fread(inbuf,1024,filesize/1024 + 1,in);

	struct timeval tm;
	gettimeofday(&tm,NULL);

	if ( gmap_compress_imageset(inbuf,filesize,&ihdr,NULL,NULL) == 1) {
		fwrite(inbuf,filesize,1,out);
		return 0;
	}

	struct timeval end_tm;
	gettimeofday(&end_tm,NULL);
	time_t period = (end_tm.tv_sec - tm.tv_sec) * 1000 + ( (double)(end_tm.tv_usec - tm.tv_usec) ) / 1000;
	printf("time:%ldms\n",period);

	if (ihdr.outbuf) {
		gmap_write_imageset(&ihdr,out);
		free(ihdr.outbuf);
	}

	return 0;

}

int main(int argc, char** argv) {

	if (argc < 3) {
		printf("usage: compress_gmap infile\n");
		return 255;
	}

	return google_map_test(argv[1],argv[2]);
}
