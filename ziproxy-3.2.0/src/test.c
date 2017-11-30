#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>

int main(int argc, char** argv) {
//	printf("%s\n",argv[0]);
//	printf("base:%s\n",dirname(argv[0]));
    char filepath[0x100];
    char* dir_name = dirname(argv[0]);
    if (dir_name) realpath(dir_name,filepath);

		strcpy(filepath + strnlen(filepath,0x100), "/ziproxy-killtimeout");
		printf("filepath:%s\n",filepath);
}
