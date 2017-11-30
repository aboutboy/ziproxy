#include <stdio.h>
#include <stdlib.h>


/**
 * verify google map file structure
 */
int main(int argc, char** argv) {
	char* buf = NULL;
	long size = 0;
	unsigned char* readp = NULL;
	unsigned char* max = NULL;
	int imagelen = 0;
	int no =0;

	FILE* f = fopen(argv[1],"r");
	if (!f) return 1;
	fseek(f,0,SEEK_END);
	size = ftell(f);
	fseek(f,0,SEEK_SET);
	buf = (char*)malloc(size);
	if (!fread(buf,size,1,f)) return 2;
	
	readp = buf + 13;	
	max = readp + size;
	while (readp < max) {
		int len = (readp[10] << 8) + readp[11];
		printf("No. %d type:%u len:%d\n",no,readp[0],len);
/*
		if (readp[0] != 2) {
			fprintf(stderr,"no %d error:%u\n",no,readp[0]);
		}
*/
		imagelen = (readp[10] << 8) + readp[11];
		readp += 12 + imagelen;
		no++;
	}
	printf("total %d objects\n",no);
	
}
