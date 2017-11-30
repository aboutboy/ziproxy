#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <inttypes.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <libmemcached/memcached.h>


struct struct_mem_data{
	char key[128];	/* key	*/
	char value[1024];	/* value */
	char agent[2048];
	char cfpath[1024];/*config file path*/
	int time; /*out time */
	int debug;
	int read;
	int type;
} mem_data;

void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
        /* ecx is often an input as well as an output. */
        asm volatile("cpuid"
            : "=a" (*eax),
              "=b" (*ebx),
              "=c" (*ecx),
              "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

void get_cpuinfo(char *cpuinfo)
{
	unsigned eax, ebx, ecx, edx;
	int i=1;
	//char cpuinfo[33]={0};
//	for(i=0;i< 6;++i){
	  eax = i; /* processor info and feature bits */
	  native_cpuid(&eax, &ebx, &ecx, &edx);
	  snprintf(cpuinfo,34,"%08x%08x%08x%08x",eax,ebx,ecx,edx);
//	}
}

int data_to_md5 (char *data,unsigned char *md5res)
{
	unsigned int len = strlen (data);
	MD5_CTX context;
	unsigned char digest[16]={0};
	if(md5res!=NULL){
		MD5_Init(&context);
		MD5_Update(&context, (const unsigned char *) data, len);
		MD5_Final(digest, &context);
		memcpy(md5res,digest,16);
		return 0;
	}
	return -1;
}

int make_auth_key(const char*data,int alen,char *xres)
{
	int icount =0;
	char *pcount=NULL;
	char xbuff[513]={0};
	unsigned char md5age[17]={0};
	char hex[] = "0123456789abcdef";

	//最大长度 256个字符
	if(alen>256)
		alen=256;

	if(data!=NULL&&xres!=NULL){
		//转换16进制码
		for (icount = 0, pcount=xbuff; icount < alen; icount++) {
			*pcount++ = hex[data[icount] >> 4];
			*pcount++ = hex[data[icount] & 0xF];
		}
		//md5 16 to 32
		if(0 == data_to_md5(xbuff,md5age)){
			for (icount = 0, pcount=xres; icount < 16; icount++) {
				*pcount++ = hex[md5age[icount] >> 4];
				*pcount++ = hex[md5age[icount] & 0xF];
			}
		}else{
			memcpy(xres,xbuff,32);
		}
		return 0;
	}
	return -1;
}


static void process_command_line_arguments (int argc, char **argv)
{
	int option_index = 0;
	int iptn;
	struct option long_options[] =
	{
		{"key", 1, 0, 'k'},
		{"enable", 0, 0, 'e'},
		{"agent", 1, 0, 'a'},
		{"image", 0, 0, 'i'},
		{"value", 1, 0, 'v'},
		{"time", 1, 0, 't'},
		{"file", 1, 0, 'c'},
		{"debug", 0, 0, 'd'},
		{"help", 0, 0, 'h'},
		{"read", 0, 0, 'r'},
		{0, 0, 0, 0}
	};

	while ((iptn = getopt_long (argc, argv, "k:eia:dv:rht:c:", long_options, &option_index)) != EOF){
		switch(iptn){
			case 'k':
				strcpy(mem_data.key,optarg);
				break;
			case 'v':
				strcpy(mem_data.value,optarg);
				break;
			case 'a':
				strcpy(mem_data.agent,optarg);
				mem_data.type=1;
				break;
			case 'e':
				mem_data.type=0;
				break;
			case 'i':
				mem_data.type=2;
				break;
			case 't':
				mem_data.time=atoi(optarg);
				break;
			case 'c':
				strcpy(mem_data.cfpath,optarg);
				break;
			case 'd':
				mem_data.debug=1;
				break;
			case 'r':
				mem_data.read=1;
				break;
			case 'h':
				printf ("save to mem 1.0\n"
						"Copyright (c)2011-2012 Daniel Mealha Cabrita\n"
						"\n"
						"This program is free software; you can redistribute it and/or modify\n"
						"it under the terms of the GNU General Public License as published by\n"
						"the Free Software Foundation; either version 2 of the License, or\n"
						"(at your option) any later version.\n"
						"\n"
						"This program is distributed in the hope that it will be useful,\n"
						"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
						"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
						"GNU General Public License for more details.\n"
						"\n"
						"You should have received a copy of the GNU General Public License\n"
						"along with this program; if not, write to the Free Software\n"
						"Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111 USA\n"
						"\n\n"

						"Usage: savetomem [-k key] [-v value] [-t time] [-h] [-d]\n\n"
						"-d --debug \n\n"
						"-k <key>, --key head data.\n\n"
						"-e , --enable type data.\n\n"
						"-a <agent> or<agent and host> --agent host (data is hex string) \n\n"
						"-i , --qimage type data.\n\n"
						"-v <value>, --valeu data\n\n"
						"-t <time>, --out time.\n\n"
						"-c <file>, --config file path.\n\n"
						"-r , --read set value.\n\n"
						"-h, --help\n\tDisplay summarized help (this text).\n\n"
						"\n");
				exit (0);
				break;
			default:
				printf("Unrecognized option.\n");
				break;
		}
	}
}

static char* get_memserver_list(char *filepath)
{
	FILE *sl=NULL;
	char *listbuf=NULL;
	int filesize;
	size_t ret=0;
	if ((sl = fopen (filepath, "r")) != NULL){
				fseek (sl, 0, SEEK_END);
				filesize = ftell (sl);
				fseek (sl, 0, SEEK_SET);
				if ((listbuf = malloc (filesize + 1)) != NULL){
					ret=fread (listbuf, 1, filesize, sl);
				}
				fclose (sl);
			}
	return listbuf;
}


int main(int argc,char *argv[])
{
	char xres[33]={0};
	unsigned char md5res[17]={0};
	char *pvalue=NULL;
	size_t valuelen;
	char *serverlist=NULL;
	memcached_st memc;
	memcached_return_t rc;
	memcached_server_st *servers = NULL;
	uint32_t flags=0;
	int icount=0;

	memset(mem_data.key,0,128);
	memset(mem_data.value,0,1024);
	memset(mem_data.agent,0,2048);
	memset(mem_data.cfpath,0,1024);
	mem_data.debug=0;
	mem_data.read=0;
	mem_data.type=-1;

	process_command_line_arguments(argc,argv);

	if(strlen(mem_data.cfpath)>0){
		if(0==access(mem_data.cfpath,R_OK))
			serverlist=get_memserver_list(mem_data.cfpath);
	}else{
		if(0==access("list.conf",R_OK))
			serverlist=get_memserver_list("list.conf");
	}

	switch(mem_data.type){
		case 0:
			strcat(mem_data.key,"_flashapp_enable");
			break;
		case 1:
			if(0 == data_to_md5(mem_data.agent,md5res)){
				for(icount=0;icount<16;icount++){
					sprintf(xres,"%s%02x",xres,md5res[icount]);
					}
			}else{
				strncpy(xres,mem_data.agent,32);
			}
			strcat(mem_data.key,"_");
			strcat(mem_data.key,xres);
			break;
		case 2:
			strcat(mem_data.key,"_flashapp_qimage");
			break;
		default:
			printf("you put data type is invalidation , note  -i -a or - e not set !\n");
			goto free;
			break;
	}

	if(mem_data.debug){
		if(serverlist!=NULL)
			printf("memcached server list: %s \n",serverlist);
		printf("config path: %s \n",mem_data.cfpath);
		printf("key is: %s value is: %s time is: %d \n ",mem_data.key,mem_data.value,mem_data.time);
	}

	if(strlen(mem_data.key)>0){

		memcached_create(&memc);

		if(serverlist!=NULL)
			servers=memcached_servers_parse(serverlist);
		else
			servers=memcached_servers_parse("127.0.0.1:11211");

		rc = memcached_server_push(&memc, servers);
		if (rc != MEMCACHED_SUCCESS) {
				fprintf(stderr,"push server failed\n");
				goto free;
		}

		rc = memcached_behavior_set(&memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
		if (rc != MEMCACHED_SUCCESS) {
			fprintf(stderr,"set binary failed\n");
			goto free;
		}

		rc=memcached_behavior_set(&memc,MEMCACHED_BEHAVIOR_DISTRIBUTION,MEMCACHED_DISTRIBUTION_CONSISTENT);
		if (rc != MEMCACHED_SUCCESS)
		{
			fprintf(stderr,"set consis failed\n");
			goto free;
		}

		rc = memcached_behavior_set(&memc, MEMCACHED_BEHAVIOR_HASH, MEMCACHED_HASH_CRC);
		if (rc != MEMCACHED_SUCCESS) {
			fprintf(stderr,"set crc hash failed\n");
			goto free;
		}

		rc = memcached_behavior_set(&memc,MEMCACHED_BEHAVIOR_NUMBER_OF_REPLICAS,1);
		if (rc != MEMCACHED_SUCCESS) {
			fprintf(stderr,"set replication failed\n");
			goto free;
		}

		int keylen = strnlen(mem_data.key,128);

		if(1 == mem_data.read){
			printf(" read start get key:%s \n",mem_data.key);
			pvalue = memcached_get(&memc,mem_data.key,keylen,&valuelen,&flags,&rc);
			if (rc != MEMCACHED_SUCCESS){
					printf("read key:%s value:%s failed\n",mem_data.key,pvalue);
			}else{
					printf("get key:%s value:%s  %ld \n",mem_data.key,pvalue,valuelen);
			}
		}
		else{
			rc = memcached_set(&memc,mem_data.key,keylen,mem_data.value,strnlen(mem_data.value,1024),mem_data.time,0);
				if (rc != MEMCACHED_SUCCESS){
					printf("push key:%s value:%s failed\n",mem_data.key,mem_data.value);
				}
		}
	}
free:
	memcached_server_list_free(servers);
	memcached_free(&memc);
	if(serverlist){
		free(serverlist);
	}
	return 0;
}
