#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

int writef(char* wp, long size, int no) {
	char fname[0x100];
	// write to file
	snprintf(fname,0x100,"%d.png",no);
	FILE* wf = fopen(fname,"w");
	if (!wf) return 3;
	if (!fwrite(wp,size,1,wf)) return 4;
	printf("wrote %d png\n", no);
	fclose(wf);
}

int split_file(const char* filename, int *no) {
	char* buf = NULL;
	FILE* f = fopen(filename,"r");
	if (!f) return 1;
	long size = 0;
	fseek(f,0,SEEK_END);
	size = ftell(f);
	fseek(f,0,SEEK_SET);
	buf = (char*)malloc(size);
	if (!fread(buf,size,1,f)) {
		return 2;
	}
	
	char* rp=buf, *wp = NULL;
	char* max = buf + size - 1;
	while (rp && rp < max && wp < max) {
		// find next PNG
		while (rp && rp < max && (unsigned char)(*rp) != 137) rp++;
		if (rp[1] != 'P' || rp[2] != 'N' || rp[3] != 'G') {
			rp++;
			continue;
		}
		if (wp) {
			if (writef(wp,rp-wp,*no)) return 3;
			(*no) ++;
		}
		wp = rp;
		rp++;
	} 
	if (wp) writef (wp, rp-wp, (*no)++);
	if (buf) free(buf);
	if (f) fclose(f);
}

#define USAGE() { \
	printf("Usage:\n  splitgmap mapfile\n  splitgmap -o dir\n"); \
}

int is_regular_file(const char* filepath) {
	struct stat fstat;
	stat(filepath,&fstat);
	return S_ISREG(fstat.st_mode);
}

int main(int argc, char** argv) {
	int no = 0;

	if (argc <= 1) {
		USAGE()
		return 255;
	}
	else if (argc == 2)
		return split_file(argv[1],&no);
	else if (argc > 2) {
		const char* dirname = argv[2];
		DIR* dir = opendir(dirname);
		struct dirent* entry = NULL;
		char filepath[0x100];
		while ( (entry = readdir(dir)) ) {
			snprintf(filepath,0x100,"%s/%s", dirname, entry->d_name);
			if (!is_regular_file(filepath)) continue;
//			if (entry->d_type != DT_REG) continue;
			if (strnlen(entry->d_name, 0x100) > 4
					&& !strncmp("http", entry->d_name, 4)) {
				split_file(filepath,&no);
			}
		}
		closedir(dir);
	}
}
