/*
 * comppng.c
 *
 *  Created on: Jun 18, 2012
 *      Author: jiangxd
 */
#include <stdio.h>
#include <stdlib.h>
#include "../src/image.h"

//	int compress_image (http_headers *serv_hdr, http_headers *client_hdr, char *inbuf, ZP_DATASIZE_TYPE insize, char **outb, ZP_DATASIZE_TYPE *outl){

int main(int argc, char** argv) {

	FILE *fp = fopen("~/real.png","r");
	if (!fp) return 1;

	long size;
	ZP_DATASIZE_TYPE outsize;

	fseek(fp,0,SEEK_END);
	size = ftell(fp);
	fseek(fp,0,SEEK_SET);

	char* inbuf = malloc(size);
	fread(inbuf,size,1,fp);

	char* outbuf = NULL;
	if (compress_image(NULL,NULL,inbuf,size,&outbuf,&outsize) == IMG_RET_OK) {
		FILE* fwp = fopen("~/realcomp.png","w");
		if (fwp) {
			fwrite(outbuf,outsize,1,fwp);
			fclose(fwp);
		}
	}
	if (fp) fclose(fp);
}
