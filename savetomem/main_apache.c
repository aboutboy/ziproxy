#include <errno.h>
#include <stdio.h>
#include <getopt.h>
#include <inttypes.h>
#include <unistd.h>
#include "apr_md5.h"
#include "apr_memcache2.h"
#include "apr.h"
#include "apr_pools.h"

#define DECLINED -1
#define OK 0

//memcache 参数
const int kDefaultMcServerPort = 11211;
const int kDefaultMcServerMin = 0;
const int kDefaultMcServerSmax = 1;
const int kDefaultMcServerTtlUs = 600*1000*1000;

#define LOGE(...) do { fprintf(stderr,__VA_ARGS__); } while(0)
//#define LOGI(...) do { printf(__VA_ARGS__); } while(0)
#define LOGI(...) do {  } while(0)

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
	  LOGI("cpuinfo %s \r\n",cpuinfo);
//	}
}

int data_to_md5 (char *data,unsigned char *md5res)
{
	unsigned int len = strlen (data);
	apr_md5_ctx_t context;
	unsigned char digest[16]={0};
	if(md5res!=NULL){
		apr_md5_init(&context);
		apr_md5_update(&context, (const unsigned char *) data, len);
		apr_md5_final(digest, &context);
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
		LOGI("x: %s \r\n",xbuff);
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

/**
 *初始化memcached
 */
apr_status_t init_memcache(apr_pool_t *p,const char* hosts,apr_memcache2_t **mc)
{
	 apr_status_t rv;
	 int thread_limit = 1;
	 int nservers = 0;
	 char *host_list;
	 char *split;
	 char *tok;
	 int usnum=0;

	 //计算服务器数量
	 host_list = apr_pstrdup(p, hosts);
	 split = apr_strtok(host_list, ",", &tok);
	 while (split) {
	        nservers++;
	        split = apr_strtok(NULL,",", &tok);
	 }

	 rv=apr_memcache2_create(p, nservers, 0, mc);

	 if (rv == APR_SUCCESS && nservers > 0) {//添加服务器
		 	 host_list = apr_pstrdup(p, hosts);
			 split = apr_strtok(host_list, ",", &tok);
			 while (split) {
				 	 apr_memcache2_server_t *st=NULL;
				 	 apr_memcache2_stats_t *stats=NULL;
				     char *host_str=NULL;
				     char *scope_id=NULL;
				     apr_port_t port;
				     rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
				     if(rv!=APR_SUCCESS)
				    	 return DECLINED;
				     if (host_str == NULL)
				         return DECLINED;
				     if (port == 0) {
				         port = kDefaultMcServerPort;
				     }

				     rv = apr_memcache2_server_create(p,
				    		 host_str,port,
				    		 kDefaultMcServerMin,
				    		 kDefaultMcServerSmax,
				    		 thread_limit,
				    		 kDefaultMcServerTtlUs,
				    		 &st);
				     if(rv!=APR_SUCCESS){
				    	 LOGI("apr_memcache2_server_create  error! \n");
				    	 return DECLINED;
				     }
				     rv=apr_memcache2_add_server(*mc, st);
				     if(rv!=APR_SUCCESS)
				    	 return DECLINED;
				     rv=apr_memcache2_stats(st,p,&stats);
				     LOGI("apr_memcache2_stats is %d   %s  %d\n",rv,host_str,port);
				     if(rv==APR_SUCCESS){
				    	 usnum++;
				     }
			         split = apr_strtok(NULL,",", &tok);
			 }
			 if(usnum<=0){//没有可用的服务器
				 LOGI("usnum is zero \n");
				 return DECLINED;
			 }
	        return rv;
	    }

	return DECLINED;
}

/**
 *获取 memcached 健值
 */
apr_status_t memcache_get(apr_pool_t *p,apr_memcache2_t *mc,const char* key,char **data,apr_size_t *data_len)
{
	apr_status_t status = apr_memcache2_getp(mc, p,key, data, data_len, NULL);
	if (status == APR_SUCCESS) {
		return OK;
	}
	return DECLINED;
}

/**
 *写入 memcached 健值
 */
apr_status_t memcache_put(apr_memcache2_t *mc,const char* key,char *data,apr_size_t data_len,apr_uint32_t timeout)
{
	 apr_status_t status = apr_memcache2_set(mc,key,data, data_len,timeout, 0);
	   if (status == APR_SUCCESS) {
		   return OK;
	   }
	   //return DECLINED;
	   return status;
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
						"-a <agent>, --agent type  data.\n\n"
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

apr_status_t get_memserver_list(apr_pool_t *p,char *filepath,char **listbuf){

	apr_status_t rv;
	int xfer_flags = (APR_READ);
	apr_fileperms_t xfer_perms = APR_OS_DEFAULT;
	apr_file_t *fd=NULL;
	apr_size_t len=0;
	apr_finfo_t fi;

	rv = apr_file_open(&fd, filepath, xfer_flags, xfer_perms, p);
	LOGI("open file %s  %d\n",filepath,rv);
	if (rv != APR_SUCCESS) {
		return rv;
	}

	rv=apr_file_info_get(&fi, APR_FINFO_SIZE, fd);
	LOGI("get file size  %d  %d\n",fi.size,rv);
	if(fi.size > 0){
		len=fi.size-1;
		*listbuf=apr_pcalloc(p,len+1);
		rv=apr_file_read(fd, *listbuf, &len);
		LOGI("read file %d  %s  %d  \n",len,*listbuf,rv);
		if(rv != APR_SUCCESS){
		*listbuf=NULL;
		}
	}

	apr_file_close(fd);

	return rv;
}


int main(int argc,char *argv[])
{
	char xres[33]={0};
	unsigned char md5res[17]={0};
	char *data=NULL;
	apr_size_t len=0;
	char *serverlist=NULL;
	apr_memcache2_t *mc=NULL;
	apr_pool_t *mpool=NULL;
	apr_status_t ret=0;
	int icount=0;

	memset(mem_data.key,0,128);
	memset(mem_data.value,0,1024);
	memset(mem_data.agent,0,2048);
	memset(mem_data.cfpath,0,1024);
	mem_data.debug=0;
	mem_data.read=0;
	mem_data.type=-1;

	ret=apr_app_initialize(&argc, &argv, NULL);
	atexit(apr_terminate);
	if(ret!=APR_SUCCESS){
		LOGI("apr init error \n");
		goto free;
	}

	ret=apr_pool_create(&mpool, NULL);
	if(ret!=APR_SUCCESS){
		LOGI("apr pool create error \n");
		goto free;
	}

	process_command_line_arguments(argc,argv);

	if(strlen(mem_data.cfpath)>0){
		if(0==access(mem_data.cfpath,R_OK))
			get_memserver_list(mpool,mem_data.cfpath,&serverlist);
	}else{
		if(0==access("list.conf",R_OK))
			get_memserver_list(mpool,"list.conf",&serverlist);
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
		if(serverlist!=NULL)
			ret=init_memcache(mpool,serverlist,&mc);
		else
			ret=init_memcache(mpool,"127.0.0.1:11211",&mc);

		if(ret!=APR_SUCCESS){
			printf("open memcached error !  \n");
			goto free;
		}

		if(1 == mem_data.read){
			printf(" read start get key:%s \n",mem_data.key);
			ret=memcache_get(mpool,mc,mem_data.key,&data,&len);
			if (ret != APR_SUCCESS)
					printf("read key:%s value:%s failed\n",mem_data.key,data);
			else
					printf("get key:%s value:%s  %d \n",mem_data.key,data,len);
		}
		else{
			len=strnlen(mem_data.value,1024);
			ret=memcache_put(mc,mem_data.key,mem_data.value,len,mem_data.time);
			if (ret != APR_SUCCESS)
				printf("push key:%s value:%s failed\n",mem_data.key,mem_data.value);
		}
	}

free:
	if(mpool)
		apr_pool_destroy(mpool);

	return 0;
}
