/*
 * savetomem.c
 *
 *  Created on: Sep 7, 2012
 *      Author: Eric Jiang (jxd431@gmail.com)
 */
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <libmemcached/memcached.h>
#include <getopt.h>
#include "global.h"
#include "md5.h"
#include "md5func.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

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

static void sendtest()
{
	 int sockfd, portno, n;
	 struct sockaddr_in serv_addr;
	 char buffer[256]={0};
	 buffer[0]=22;
	 buffer[1]=3;
	 buffer[2]=1;
	 buffer[3]='\r';
	 buffer[4]='\n';

	 sockfd = socket(AF_INET, SOCK_STREAM, 0);

	 if(sockfd<0)
		 printf ("socket create error \n");

	 bzero((char *) &serv_addr, sizeof(serv_addr));
	 serv_addr.sin_family = AF_INET;
	 serv_addr.sin_addr.s_addr=inet_addr("192.168.11.154");
	 serv_addr.sin_port = htons(8000);

	 if(connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr))<0)
		 printf("connect error  \n");

	 n=write(sockfd,buffer,5);
	 printf("write %d\n",n);

	 n=read(sockfd,buffer,255);
	 printf("buffer%s\n",buffer);
	 close(sockfd);

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

static char* get_memserver_list(char *filepath){
	FILE *sl;
	char *listbuf=NULL;
	int filesize;
	if ((sl = fopen (filepath, "r")) != NULL){
				fseek (sl, 0, SEEK_END);
				filesize = ftell (sl);
				fseek (sl, 0, SEEK_SET);
				if ((listbuf = malloc (filesize + 1)) != NULL){
					fread (listbuf, 1, filesize, sl);
				}
				fclose (sl);
			}
	return listbuf;
}


int agent_to_md5 (const char *agent, char *md5res)
{
	MD5_CTX context;
	unsigned char digest[16];
	unsigned int len = strlen (agent);

	memset( digest, 0 , strlen(digest));
	MDInit (&context);
	MDUpdate (&context, agent, len);
	MDFinal (digest, &context);

	if(strlen(digest) >0){
		strcpy(md5res,digest);
		return 0;
	}
	return 1;
}


int main(int argc, char** argv)
{
	//test
	char *pvalue=NULL;
	uint32_t flags=0;
	size_t valuelen;
	//
	memcached_st memc;
	memcached_return_t rc;
	memcached_server_st *servers = NULL;
	pid_t pid;
	unsigned char md5res[17]={0};
	char xres[33]={0};
	char *serverlist=NULL;
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
		if(0 == agent_to_md5(mem_data.agent,md5res)){
		for(icount=0;icount<16;icount++){
			sprintf(xres,"%s%x",xres,md5res[icount]);
			}
		}else{
			//printf("make md5 key is failed! \n");
			//goto free;
			strncpy(xres,mem_data.agent,32);
		}
		//ƴװҪ���ҵ�key
		strcat(mem_data.key,"_");
		strcat(mem_data.key,xres);
		break;
	case 2:
		strcat(mem_data.key,"_flashapp_qimage");
		break;
	default:
		printf("you put data type is invalidation , note  -i -a or - e not set !\n");
		//sendtest();
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

	//servers = memcached_server_list_append(servers, "221.123.176.27", 11211, &rc);
		//servers = memcached_server_list_append(servers, "221.123.176.27", 11212, &rc);
		//servers = memcached_server_list_append(servers, "221.123.176.27", 11213, &rc);
		//servers = memcached_server_list_append(servers, "221.123.176.27", 11214, &rc);
		//servers = memcached_server_list_append(servers, "221.123.176.27", 11215, &rc);
	//"221.123.176.27:11211,221.123.176.27:11212,221.123.176.27:11213,221.123.176.27:11214,221.123.176.27:11215");
	if(serverlist!=NULL){
		servers=memcached_servers_parse(serverlist);
	}else{
		servers=memcached_servers_parse("127.0.0.1:11211");
	}

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
	//rc=memcached_behavior_set_distribution(&memc,MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA);
	rc=memcached_behavior_set(&memc,MEMCACHED_BEHAVIOR_DISTRIBUTION,MEMCACHED_DISTRIBUTION_CONSISTENT);
	if (rc != MEMCACHED_SUCCESS)
	{
		fprintf(stderr,"set consis failed\n");
		goto free;
	}
	//rc=memcached_behavior_set_distribution(&memc,MEMCACHED_KETAMA_COMPAT_LIBMEMCACHED); //MEMCACHED_DISTRIBUTION_CONSISTENT_KETAMA_SPY);

	rc = memcached_behavior_set(&memc, MEMCACHED_BEHAVIOR_HASH, MEMCACHED_HASH_CRC);//MEMCACHED_HASH_MD5);
	//rc = memcached_behavior_set(&memc, MEMCACHED_BEHAVIOR_KETAMA_HASH, MEMCACHED_HASH_CRC);
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
		if (rc != MEMCACHED_SUCCESS)
				printf("read key:%s value:%s failed\n",mem_data.key,pvalue);
		else
				printf("get key:%s value:%s  %d \n",mem_data.key,pvalue,valuelen);
	}
	else{
		rc = memcached_set(&memc,mem_data.key,keylen,mem_data.value,strnlen(mem_data.value,1024),mem_data.time,0);
			if (rc != MEMCACHED_SUCCESS)
				printf("push key:%s value:%s failed\n",mem_data.key,mem_data.value);
	}

free:
	memcached_server_list_free(servers);

	if(serverlist)
		free(serverlist);
/*
	pid = fork();
	if (pid == 0) {
		// child
	//Save data
	rc=memcached_set(&memc,key,key_length,value,value_length,0,0);
	if(rc==MEMCACHED_SUCCESS)
	{
		printf("Save data:%s sucessful!\n",value);
	}
	//Get data
	char* result = memcached_get(&memc,key,key_length,&value_length,&flags,&rc);
	if(rc == MEMCACHED_SUCCESS)
	{
		printf("Get data:%s sucessful!\n",result);
	}
	//Delete data
	rc=memcached_delete(&memc,key,key_length,0);
	if(rc==MEMCACHED_SUCCESS)
	{
		printf("Delete key:%s successfully\n",key);
	}
	memcached_server_list_free(servers);
	}
	else {
	memcached_server_list_free(servers)
	}

*/
	}
}
