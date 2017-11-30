/*
 * usettings_process.c
 *
 *  Created on: Jul 17, 2012
 *      Author: Eric Jiang (jxd431@gmail.com)
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef USER_SETTINGS
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <mysql/mysql.h>
#include <libmemcached/memcached.h>
#include <errno.h>
#include <assert.h>
#include <json/json.h>
#include "usettings_process.h"
#include "cfgfile.h"
#include "log.h"
#include "user_settings.h"
//for md5
#include "global.h"
#include "md5.h"
#include "md5func.h"

#define QUEUE_LEN 0x80
#define REFRESH_JSON_HOST 10   //10*30  all  time
#define SOCK_NAME "/tmp/ziproxy-user-server"

#define REQUEST_SIGNATURE_SIZE 4
unsigned char REQUEST_SIGNATURE[4] = {0x99,0x88,0xaa,0xbb};

#define US_NODATA 1
#define US_DBCONN_ERR 2
#define US_DBQRY_ERR 3

typedef struct {
	unsigned char signature[REQUEST_SIGNATURE_SIZE];
	uint32_t dip;
	uint16_t dport;
	bool usertype;//用户类型 默认 false  用 ip 和port  true  用guid 验证log
	char agent[64];//要验证的agent 长度 和log 日志里的长度要一直
	char host[64];//需要进一步验证host domain
	char guid[100];//用户名 用户唯一标志  ，和log 日志里的uname 长度一致
} us_request_t;

/* parent process variables */
/* server id array, used by parent process */
static pid_t* us_server_pids = NULL;

/* child process variables */
static memcached_st memc;
static int us_server_id; // work server id
static int us_listen_fd = 0;
static unsigned char notfound_rsp[3] = {1,0,0};
static int us_json_res=0;//time only for zidomain
static int us_timer_ic=0;//time 计数器
static int us_oldset_ch=1;// agent 的缓存判断
static clc_setting_t us_csetting;//服务器用户验证结果返回
static us_request_t us_req;//读取发送过来的验证数据
static char us_oldagent[1024]={0};//缓存旧agent

static void us_sigcatch (int sig)
{
	char sockpath[0x100];
	switch (sig) {
	case SIGTERM:
		close(us_listen_fd);
		snprintf(sockpath,0x100,"%s.%d",SSocketFile,us_server_id);
		unlink(sockpath);
		exit (100);
		break;
		//refresh json host and ip
	case SIGALRM:
		if(us_timer_ic>29){
			init_serverhost_list();
			us_timer_ic =1;
		}else{
			us_timer_ic++;
			us_oldset_ch=1;
		}
		us_json_res=1;
		break;
	default:
		break;
	}
}

static void save_user_settings_to_memcached(const user_settings_t* settings, unsigned short int dport, uint32_t dip) {
	char key[20];
	snprintf(key, 20, "%u:%u", dip, dport);
	uint16_t value_len;
	char* value = alloc_and_serial_user_settings(settings,&value_len);
	memcached_set(&memc,key,strnlen(key,20),value,value_len,MemcachedExpiredTime,0);
	free(value);
}

static int get_user_settings_from_db(user_settings_t* settings, uint16_t dport, uint32_t dip) {
	MYSQL mysql; //������ݿ����ӵľ�������ڼ������е�MySQL����
	MYSQL_RES *res = NULL; //��ѯ����ṹ����
//	MYSQL_FIELD *fd; //���ֶ���Ϣ�Ľṹ
	MYSQL_ROW row; //���һ�в�ѯ�����ַ�����
	char sql[100];
	int retval = 0;

	mysql_init(&mysql);
	if (!(mysql_real_connect(&mysql, MysqlHost, MysqlUser, MysqlPassword,
			MysqlDatabase, MysqlPort, NULL, 0))) {
		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"get_user_settings_from_db: %s\n",mysql_error(&mysql));
		retval = US_DBCONN_ERR;
		goto free;
	}
	snprintf(sql,100,"select `f_key`,`f_value` from user_settings where f_dport=%u and f_dip=%u",dport,dip);
	if (mysql_query(&mysql,sql)) {
		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"get_user_settings_from_db: %s\n",mysql_error(&mysql));
		retval = US_DBQRY_ERR;
		goto free;
	}

	if (!(res = mysql_store_result(&mysql))) {
		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"get_user_settings_from_db: %s\n",mysql_error(&mysql));
		retval = US_DBQRY_ERR;
		goto free;
	}

	int num_rows= mysql_num_rows(res);
//	error_log_printf(LOGMT_INFO,LOGSS_USSERVER,"num:%d\n",num_rows);
	if (!num_rows) {
		retval = US_NODATA;
		goto free;
	}
	while ( (row = mysql_fetch_row(res)) ) {
		if (!strncmp("da",row[0],2)) { // disabled_all
			settings->disable_all = (strncmp(row[1],"1",1) == 0);
		}
		else if (!strncmp("iq",row[0],2)) { // image_quality
			settings->image_quality = (image_quality_t)(row[1][0] - '0');
		}
		else { // 'du'
//			error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"parse user agents:%s\n",row[1]);
			user_agents_parse(&(settings->disabled_useragents),row[1],strnlen(row[1],MAX_USER_AGENTS_SIZE));
		}
	}

free:
	if (res)
		mysql_free_result(res);
	mysql_close(&mysql);
	return retval;;
}

/**
 * Must free return value if it is not NULL
 */
static char* get_settings_on_server(us_request_t* req, uint16_t* value_len) {
	char key[20];
	uint32_t flags;
	memcached_return_t rc;
	size_t valuelen;

	char str[0x1000];
	snprintf(key, 20, "%u:%u", req->dip, req->dport);

	// read 2 times to prevent connection disconnected
	int times = 0;
	char* value = NULL;
	rc = -1;
	while (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND && times < 2) {
		value = memcached_get(&memc,key,strnlen(key,20),&valuelen,&flags,&rc);
		if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND)
			error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
					"get_settings_on_server: memcached_get rc:%d, %s\n", rc,
					memcached_strerror(&memc, rc));
	}

	user_settings_t usettings;
	switch(rc) {
	case MEMCACHED_SUCCESS:
		*value_len = (uint16_t)valuelen; // max len not exceed 2 ^ 16
		return value;
	case MEMCACHED_NOTFOUND:
		user_settings_init(&usettings);
		if (get_user_settings_from_db(&usettings,req->dport,req->dip))
			return NULL;
		save_user_settings_to_memcached(&usettings,req->dport,req->dip);
		return alloc_and_serial_user_settings(&usettings,value_len);
	default:
		// TODO: check error type
		error_log_printf(LOGMT_ERROR,LOGSS_USSERVER,"get_settings_on_server: memcached get error:%d\n",rc);
		return NULL;
	}
}

/**
 * return ==0 success ==1 failure
 */
static int writebuf(int fd, const void* buf, size_t sz) {
	size_t writed_len = 0;
	ssize_t n = 0;
	while (writed_len < sz) {
		n = write(fd, buf + writed_len, sz - writed_len);
		if (n == -1) {
			error_log_printf(LOGMT_ERROR, LOGSS_USSERVER, "write buf failed:%s \n", strerror(errno));
			return 1;
		}
		writed_len += n;
	}
}

static void us_server() {
	int listen_fd,size;
	struct sockaddr_un un;
	if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		error_log_printf(LOGMT_FATALERROR,LOGSS_USSERVER,"create socket error:%s", strerror(errno));
		exit(1);
	}

	int so_val = 1;
    if ( setsockopt (listen_fd, SOL_SOCKET, SO_REUSEADDR, &so_val, sizeof (so_val)) == -1 ) {
		error_log_printf(LOGMT_FATALERROR, LOGSS_USSERVER,
				"Failed to set reuse.\n");
		exit(2);
    }

    /* fill in socket address structure */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	snprintf(un.sun_path, sizeof(un.sun_path), "%s.%d", SSocketFile, us_server_id);
	size = SUN_LEN(&un);
	if (bind(listen_fd, (struct sockaddr *)&un, size) < 0) {
		if (errno == EADDRINUSE) {
			// remove unix socket file and bind againt
			unlink(un.sun_path);
			if (bind(listen_fd, (struct sockaddr *)&un, size) < 0) {
				error_log_printf(LOGMT_FATALERROR, LOGSS_USSERVER,"bind '%s' error:%s",un.sun_path, strerror(errno));
				exit(3);
			}
		}
		else {
			error_log_printf(LOGMT_FATALERROR, LOGSS_USSERVER,"bind '%s' error:%s",un.sun_path, strerror(errno));
			exit(3);
		}
	}
	debug_log_puts("us_server: unix domain socket bound");

	if (listen(listen_fd, QUEUE_LEN) < 0) { /* tell kernel we're a server */
		close(listen_fd);
		exit(4);
	}

	us_listen_fd = listen_fd;

	int client_fd, len=sizeof(un);
	us_request_t req;
	while (1) {
		if ((client_fd = accept(listen_fd, (struct sockaddr *)&un, &len)) < 0) {
			error_log_printf(LOGMT_FATALERROR,LOGSS_USSERVER,"accept error:%s \n", strerror(errno));
			exit(255);
		}
		size = read(client_fd,&req,sizeof(us_request_t));
		if (size != sizeof(us_request_t)) {
			error_log_printf(LOGMT_ERROR,LOGSS_USSERVER,"read error size:%d\n", size);
			error_log_dumpbuf(LOGMT_ERROR,LOGSS_USSERVER,&req,size);
		}
		if ( memcmp(&(req.signature),REQUEST_SIGNATURE,REQUEST_SIGNATURE_SIZE) ) {
			error_log_puts(LOGMT_ERROR,LOGSS_USSERVER,"invalid signature");
			error_log_dumpbuf(LOGMT_ERROR,LOGSS_USSERVER,&(req.signature),REQUEST_SIGNATURE_SIZE);
			continue;
		}
		uint16_t valuelen;
		uint32_t flags;
		memcached_return_t rc;
		void* resp = NULL;
		char* value = get_settings_on_server(&req,&valuelen);
		if (value) {
			resp = (char*)malloc(valuelen + 1 + sizeof(uint16_t));
			*((char*)resp) = 0;
			// We use maximum length of 2 ^ 16
			*((uint16_t*)(resp+1)) = (uint16_t)valuelen;
			memcpy(resp +1 + sizeof(uint16_t),value,valuelen);
			writebuf(client_fd,resp,valuelen + 1 + sizeof(uint16_t));
		}
		else {
			writebuf(client_fd,notfound_rsp,sizeof(notfound_rsp));
    		debug_log_puts("us_server: write not found");
	    }

	}

}

/**
 * return buffer pointer on successfully; NULL if not found
 */
char* get_from_server(uint32_t dip, uint16_t dport, uint16_t* value_len) {
	int sockfd,size;
	struct sockaddr_un un;
	int server_id;
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		error_log_printf(LOGMT_FATALERROR,LOGSS_DAEMON,"create socket error:%s", strerror(errno));
		return NULL;
	}

	server_id = getpid() % NumOfUSProcesses;
	/* fill in socket address structure */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	snprintf(un.sun_path, sizeof(un.sun_path), "%s.%d", SSocketFile, server_id);
	size = SUN_LEN(&un);

//	error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"connect to server:%s\n", un.sun_path);
//
	if (connect(sockfd, (struct sockaddr *)&un, size) < 0) {
		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"connect error:%s  \n", strerror(errno));
		return NULL;
	}

	us_request_t req;
	memcpy(req.signature,REQUEST_SIGNATURE,REQUEST_SIGNATURE_SIZE);
	req.dip = dip;
	req.dport = dport;
	writebuf(sockfd,&req,sizeof(us_request_t));

	unsigned char buf[3];
	if (read(sockfd,buf,3) == -1) {
		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"read error:%s", strerror(errno));
		return NULL;
	}
	if (buf[0]) {
		// first byte being 1 indicates key not found
//		error_log_printf(LOGMT_WARN,LOGSS_DAEMON,"user settings not found:(%x:%x)\n",dip,dport);
		return NULL;
	}
	*value_len = *(uint16_t*)(buf+1);

	char* value = (char*)malloc(*value_len);

	int read_bytes = 0;
	int n;
	while (read_bytes < *value_len) {
		n = read(sockfd,value + read_bytes, *value_len - read_bytes);
		if (n == -1) {
			error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"read error:%s", strerror(errno));
			return NULL;
		}
		read_bytes += n;
	}
	close(sockfd);

	return value;
}

int init_memcached() {
    memcached_return_t rc;
    memcached_server_list_st servers = NULL;
    int retval = 0;

    memcached_create(&memc);

	servers=memcached_servers_parse(MemcachedServers);

	if(servers!=NULL){

		error_log_printf(LOGMT_INFO, LOGSS_USSERVER,"parse servers access : %s\n", MemcachedServers);
		 rc = memcached_server_push(&memc, servers);

		    if (rc != MEMCACHED_SUCCESS) {
		    	error_log_printf(LOGMT_INFO, LOGSS_USSERVER,"init_memcached: %s\n", memcached_strerror(&memc,rc));
		    	retval = 1;
		        goto free;
		    }

			rc = memcached_behavior_set(&memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
			if (rc != MEMCACHED_SUCCESS) {
				error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
						"init_memcached: set binary failed:%s\n",
						memcached_strerror(&memc, rc));
				exit(1);
			}
			else
				error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
						"init_memcached: server %d set binary protocol \n", us_server_id);

			rc = memcached_behavior_set(&memc,MEMCACHED_BEHAVIOR_DISTRIBUTION,MEMCACHED_DISTRIBUTION_CONSISTENT);
			if (rc != MEMCACHED_SUCCESS) {
					error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
							"init_memcached: set cnsis failed:%s\n",
							memcached_strerror(&memc, rc));
					exit(1);
				}
				else
					error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
							"init_memcached: server %d set distribution consistent \n", us_server_id);

			rc = memcached_behavior_set(&memc, MEMCACHED_BEHAVIOR_HASH, MEMCACHED_HASH_CRC);
				if (rc != MEMCACHED_SUCCESS) {
						error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
								"init_memcached: set crc_hash failed:%s\n",
								memcached_strerror(&memc, rc));
						exit(1);
					}
					else
						error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
								"init_memcached: server %d set  crc_hash\n", us_server_id);

		    rc = memcached_behavior_set(&memc,MEMCACHED_BEHAVIOR_NUMBER_OF_REPLICAS,MemcachedReplications);
		    if (rc != MEMCACHED_SUCCESS) {
				error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
						"init_memcached: set replicas failed:%s\n",
						memcached_strerror(&memc, rc));
		        retval = 3;
		        goto free;
		    }
			else
				error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
						"init_memcached: server %d set replications by %d\n",
						us_server_id, MemcachedReplications);

		free:
		    memcached_server_list_free(servers);
	}

    return retval;
}

void destroy_usprocess() {
	int i,status;
	if(us_server_pids==NULL)
		return;
	for (i=0;i<NumOfUSProcesses;i++) {
		if (us_server_pids[i]) {
			kill(us_server_pids[i],SIGTERM);
			waitpid(us_server_pids[i],&status,0);
		}
	}
	free(us_server_pids);
	us_server_pids = NULL;
}



//////////////////////////2012-09-04////////////////////////////

int get_hosts_fromjson(server_host_ip shp[],int imax,char * filepath){

	json_object *new_obj=NULL;
	json_object *val_obj=NULL,*val=NULL;
	array_list *new_list=NULL;
	struct lh_entry *entry =NULL;
	char *key=NULL;
	const char *chost=NULL;
	int icount=0;
	int ihas=0;

	int i=0;

	if(filepath){

		new_obj=json_object_from_file(filepath);

		if(new_obj){
		new_list=json_object_get_array(new_obj);//(struct json_object *)(json_object_get_object(new_obj)->head)->v);
		}
		for(i=0;i< array_list_length(new_list); i++){

			val_obj = (struct json_object *) array_list_get_idx(new_list, i);

			if(val_obj){
			 	 for (entry = json_object_get_object(val_obj)->head; entry; entry = entry->next) {
			                  	  key = (char *) entry->k;
			                  	  val = (struct json_object *) entry->v;

			                  	  if (strcmp(key, "domain") == 0) {
			                	  	  chost=json_object_get_string(val);
			                	  	  char *pt=strstr(chost,".flash");
			                	  	  int ifd=strlen(chost)-strlen(pt);
			                	  	  if(ifd>0){
			                		  	  strncpy(shp[icount].shost,chost,ifd);
			                		  	  ihas=1;
			                	  	  }
			                  	  }
			                  	  else if(strcmp(key, "ips") == 0){
			                	  	  strcpy(shp[icount].sip,json_object_get_string(val));
			                	  		ihas=1;
			                  	  }
			    			}

			 	 if(1==ihas){
				 	 debug_log_printf ("read content - %d  %s  %s \n", icount, shp[icount].shost, shp[icount].sip);
				 	 icount++;
				 	 ihas=0;
			 	 }
			}

			if(icount>=imax){
				break;
			}
		}
		if(new_obj){
			json_object_put(new_obj);
		}
	}

	if(icount>0)
		return 0;
	else
		return 1;
}

char* get_host_fromip(server_host_ip shp[],int imax,const char * ipbuf)
{
	int i=0;
	for(i=0;i<imax;i++){
		if(strstr(shp[i].sip,ipbuf)!=NULL){
			return shp[i].shost;
		}
	}
	return NULL;
}

static int get_value_from_mem(char *key,int len,char *value,int *value_len){
	uint32_t flags;
	memcached_return_t rc;
	size_t valuelen;
	int times = 0;
	char * pv=NULL;

	rc = -1;
	//while (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND && times < 2)
	{
		pv = memcached_get(&memc,key,strnlen(key,len),&valuelen,&flags,&rc);
		if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND)
				error_log_printf(LOGMT_INFO, LOGSS_USSERVER,
						"get_settings_on_server: memcached_get rc:%d, %s\n", rc,
						memcached_strerror(&memc, rc));
		}

		switch(rc) {
		case MEMCACHED_SUCCESS:
			*value_len = (uint16_t)valuelen; // max len not exceed 2 ^ 16
			//debug_log_printf ("the key:%s  value:%s valuelen:%d \n",key,pv,valuelen);
			if(valuelen>0&&pv!=NULL){
				strcpy(value,pv);
				free(pv);
				return 0;
			}else{
				return 1;
			}
		case MEMCACHED_NOTFOUND:
			return 1;
		default:
			// TODO: check error type
			error_log_printf(LOGMT_ERROR,LOGSS_USSERVER,"get_settings_on_server: memcached get error:%s  %d\n",key,rc);
			return 1;
		}
}


static int agent_to_md5 (const char *agent, char *md5res)
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

//生成验证的agent 和 host  的key
static int make_agent_key(char*agent,char*host,char *xres)
{
	int icount =0;
	char *pcount=NULL;
	char agentxbuf[513]={0};
	unsigned char md5age[17]={0};
	int alen=0;

	//转换16进制
	if(agent!=NULL){
		alen=strlen(agent);
		pcount=agent;
		for(icount=0;icount< alen;icount++){
			sprintf(agentxbuf,"%s%x",agentxbuf,(unsigned char)(*pcount));
			pcount++;
		}
	}
	//转换16进制
	if(host!=NULL){
		alen=strlen(host);
		pcount=host;
		for(icount=0;icount< alen;icount++){
			sprintf(agentxbuf,"%s%x",agentxbuf,(unsigned char)(*pcount));
			pcount++;
		}
	}

	//md5 16
	if(0 == agent_to_md5(agentxbuf,md5age)){
		for(icount=0;icount<16;icount++){
			sprintf(xres,"%s%x",xres,md5age[icount]);
		}
	}else{
		//md5 error
		//ires=1;
		strncpy(xres,agentxbuf,32);
	}

	debug_log_printf ("the agent before md5 key :%s  %s  %s\n",agentxbuf,agent,host);
	return 0;
}

//计算 获取用户设置
static int clc_settings_on_server(us_request_t* req,clc_setting_t* csetting) {
	char key[128];
	char *phost=NULL;
	char *pip=NULL;
	char value[3]={0};
	int  valuelen=0;
	int ires=0;
	int icount=0;
	int alllen=0;
	struct in_addr ir;

	char xres[33]={0};
	char gid[100]={0};
	char agentbuf[64]={0};
	char hostbuf[64]={0};
	uint16_t uport=0;
	bool isusedvpn=false;

	debug_log_printf ("the clc settings on server---- pid: %d  \n",getpid());

	//check user type  is used vpn
	isusedvpn=req->usertype;
	if(isusedvpn){
		strcpy(gid,req->guid);
	}else{
		ir.s_addr=htonl(req->dip);
		pip=inet_ntoa(ir);
		phost=get_host_from_ip(pip);
		if(phost==NULL){
			debug_log_printf ("the clc settings on server---- host no found %s  \n",pip);
			return 1;
		}
		uport=req->dport;
	}
	alllen=strlen(req->host);

	if(alllen>0){
		strcpy(hostbuf,req->host);
	}

	alllen=strlen(req->agent);
	if(alllen>0){
		strcpy(agentbuf,req->agent);
	}
	//check enable key
	//make all enable key
	if(isusedvpn){
		snprintf(key, 128, "%s_flashapp_enable",gid);
	}else{
		snprintf(key, 128, "%s_%u_flashapp_enable",phost, uport);
	}
	ires=get_value_from_mem(key,128,value,&valuelen);
	debug_log_printf ("the enable key is----  %s ires:%d value:%s\n", key,ires,value);
	if(0==ires){
		csetting->disable=setting_true;
	}else{
		ires=1;
	}
	//check agent key
	if(1==ires){
		if(alllen>0){
			//make agent 不能为空
			//make agent key
			make_agent_key(agentbuf,NULL,xres);
			if(isusedvpn){
				snprintf(key, 128, "%s_%s",gid,xres);
			}else{
				snprintf(key, 128, "%s_%u_%s",phost, uport,xres);
			}
			ires=get_value_from_mem(key,128,value,&valuelen);
			debug_log_printf ("the agent key is----  %s ires:%d value:%s \n", key,ires,value);

			if(0==ires){
				csetting->disable=setting_true;
			}else{
				alllen=strlen(hostbuf);
				//判断 agent 和 host
				if(alllen>0){
					memset(xres,0,33);
					make_agent_key(agentbuf,hostbuf,xres);
					if(isusedvpn){
						snprintf(key, 128, "%s_%s",gid,xres);
					}else{
						snprintf(key, 128, "%s_%u_%s",phost, uport,xres);
					}
					ires=get_value_from_mem(key,128,value,&valuelen);
					debug_log_printf ("the agent and domain key is----  %s ires:%d value:%s \n", key,ires,value);
					if(0==ires){
						csetting->disable=setting_true;
					}
				}
			}
		}else{
			debug_log_printf ("the agent key is NULL !!!\n");
		}
	}

	//check q image
	if(0!=ires){
		//图片质量
		if(isusedvpn){
			snprintf(key, 128, "%s_flashapp_qimage",gid);
		}else{
			snprintf(key, 128, "%s_%u_flashapp_qimage",phost, uport);
		}
		ires=get_value_from_mem(key,128,value,&valuelen);
		debug_log_printf ("the qimage key is----  %s res:%d value:%s \n", key,ires,value);
		if(0==ires){
			ires=atoi(value);
			if(ires>0&&ires<4){
				csetting->image_quality=ires;
			}
		}
	}
	return 0;
}

//计算获取结果服务器端
static void us_clc_server() {
	int listen_fd,size;
	struct sockaddr_un un;
	int clen=0;

	if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		error_log_printf(LOGMT_FATALERROR,LOGSS_USSERVER,"create socket error:%s\n", strerror(errno));
		exit(1);
	}

	int so_val = 1;
    if ( setsockopt (listen_fd, SOL_SOCKET, SO_REUSEADDR, &so_val, sizeof (so_val)) == -1 ) {
		error_log_printf(LOGMT_FATALERROR, LOGSS_USSERVER,
				"Failed to set reuse.\n");
		exit(2);
    }

    /* fill in socket address structure */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	snprintf(un.sun_path, sizeof(un.sun_path), "%s.%d", SSocketFile, us_server_id);
	size = SUN_LEN(&un);
	if (bind(listen_fd, (struct sockaddr *)&un, size) < 0) {
		if (errno == EADDRINUSE) {
			// remove unix socket file and bind againt
			unlink(un.sun_path);
			if (bind(listen_fd, (struct sockaddr *)&un, size) < 0) {
				error_log_printf(LOGMT_FATALERROR, LOGSS_USSERVER,"bind '%s' error:%s\n",un.sun_path, strerror(errno));
				exit(3);
			}
		}
		else {
			error_log_printf(LOGMT_FATALERROR, LOGSS_USSERVER,"bind '%s' error:%s\n",un.sun_path, strerror(errno));
			exit(3);
		}
	}


	if (listen(listen_fd, QUEUE_LEN) < 0) { /* tell kernel we're a server */
		exit(4);
	}

	us_listen_fd = listen_fd;

	int client_fd, len=sizeof(un);

	fd_set readfds,writefds;
	struct timeval tv;
	FD_ZERO(&readfds);
	FD_SET(listen_fd, &readfds);
	FD_ZERO(&writefds);
	FD_SET(listen_fd,&writefds);
	tv.tv_sec  = 1;
	tv.tv_usec = 0;

	debug_log_printf("us_server: unix domain socket bound path %s \n",un.sun_path);

	while (1) {

		if(us_json_res){//refresh zidomain  file by timer
			signal (SIGALRM, us_sigcatch);
			alarm (REFRESH_JSON_HOST);//10*30  seconds
			us_json_res=0;
		}

			if ((client_fd = accept(listen_fd, (struct sockaddr *)&un, &len)) < 0) {
						error_log_printf(LOGMT_FATALERROR,LOGSS_USSERVER,"accept error:%s\n", strerror(errno));
						exit(255);
					}

					int stats=1;
					/*
					stats=select(listen_fd+1, &readfds, &writefds, NULL, &tv);
					*/
					if(stats >0 ){
						/*
						debug_log_printf("us_server: stats++++++++++++NULLLLLLLLL  %d \n",stats);
					if(FD_ISSET(client_fd, &readfds)){
						//debug_log_printf("us_server: stats++++++++++++read  %d \n",stats);
					}

					if(FD_ISSET(listen_fd, &writefds)){
						debug_log_printf("us_server: stats++++++++++++write  %d \n",stats);
					}*/

					size = read(client_fd,&us_req,sizeof(us_request_t));
					if (size != sizeof(us_request_t)) {
						error_log_printf(LOGMT_ERROR,LOGSS_USSERVER,"read error size:%d\n", size);
						error_log_dumpbuf(LOGMT_ERROR,LOGSS_USSERVER,&us_req,size);
					}

					if ( memcmp(&(us_req.signature),REQUEST_SIGNATURE,REQUEST_SIGNATURE_SIZE) ) {
						error_log_puts(LOGMT_ERROR,LOGSS_USSERVER,"invalid signature");
						error_log_dumpbuf(LOGMT_ERROR,LOGSS_USSERVER,&(us_req.signature),REQUEST_SIGNATURE_SIZE);
						close(client_fd);
						continue;
					}

					/*//remove agent cache the resion is now check agent and host
					//check agent len
					clen=strlen(req.agent);
					if(clen>0){
						if((strcmp(us_oldagent,req.agent)!=0)||(1==us_oldset_ch)){
							clc_settings_init(&us_csetting);
							clc_settings_on_server(&req,&us_csetting);
							us_oldset_ch=0;
							if(clen<1024)
							strcpy(us_oldagent,req.agent);
						}else{
							debug_log_printf("us_server: not need to get setting from server  %s \n",req.agent);
						}
					}else{
						clc_settings_on_server(&req,&us_csetting);
						debug_log_printf("us_server: agent is null! \n");
					}
					*/

					clc_settings_init(&us_csetting);
					clc_settings_on_server(&us_req,&us_csetting);

					writebuf(client_fd,&us_csetting,sizeof(clc_setting_t));

					close(client_fd);
			}

	}

}

static void init_client_usres(us_request_t *req)
{
	if(req!=NULL)
	{
		memcpy(req->signature,REQUEST_SIGNATURE,REQUEST_SIGNATURE_SIZE);
		req->dip=0;
		req->dip=0;
		req->usertype=false;
		memset(req->agent,0,64);
		memset(req->host,0,64);
		memset(req->guid,0,100);
	}
}

//  server  get by clc
int get_from_clcserver(uint32_t dip, uint16_t dport,const void* agebuf ,const void * hostbuf,const void* gidbuf ,clc_setting_t* csetting) {
	int sockfd,size;
	struct sockaddr_un un;
	int server_id;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		error_log_printf(LOGMT_FATALERROR,LOGSS_DAEMON,"create socket error:%s", strerror(errno));
		return 1;
	}

	server_id = getpid() % NumOfUSProcesses;
	/* fill in socket address structure */
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	snprintf(un.sun_path, sizeof(un.sun_path), "%s.%d", SSocketFile, server_id);
	size = SUN_LEN(&un);

	debug_log_printf ("the get_from_clcserver---- pid: %d  socketpath: %s  \n",getpid(),un.sun_path );
//	error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"connect to server:%s\n", un.sun_path);
//
	if (connect(sockfd, (struct sockaddr *)&un, size) < 0) {
		error_log_printf(LOGMT_ERROR,LOGSS_DAEMON,"%s connect error:%s  \n", un.sun_path,strerror(errno));
		close(sockfd);
		return 1;
	}

	us_request_t req;
	init_client_usres(&req);
	if(gidbuf!=NULL){
		strncpy(req.guid,gidbuf,99);
		req.usertype=true;
	}else{
		req.dip = dip;
		req.dport = dport;
	}

	if(agebuf!=NULL)//agent is will not be null
		strncpy(req.agent,agebuf,63);

	if(hostbuf!=NULL)//agent is will not be null
			strncpy(req.host,hostbuf,63);

	writebuf(sockfd,&req,sizeof(us_request_t));

	size = read(sockfd,csetting,sizeof(clc_setting_t));
		if (size != sizeof(clc_setting_t)) {
			error_log_printf(LOGMT_ERROR,LOGSS_USSERVER,"client read error size:%d \n", size);
			error_log_dumpbuf(LOGMT_ERROR,LOGSS_USSERVER,csetting,size);
			close(sockfd);
			return 1;
		}
	close(sockfd);
	return 0;
}


int init_usprocess() {
	pid_t pid;

	//for squid
	if(SSocketFile==NULL){
		SSocketFile=strdup(SOCK_NAME);
	}

	if(SquidUsedIn==2)
		return 0;

	init_serverhost_list();
	int i;
	for (i = 0; i < NumOfUSProcesses; i++) {
fork_retry:
		switch(pid = fork())
		{
		case 0:
			/* CHILD */
			/* we don't want children using daemon's SIGTERM handler */
			signal (SIGTERM, us_sigcatch);
			signal (SIGALRM, us_sigcatch);
			alarm (REFRESH_JSON_HOST);

			us_server_id = i;
			if (init_memcached()) {
				error_log_printf(LOGMT_FATALERROR,LOGSS_CONFIG,"MemcachedServers config error: %s,:%d\n", MemcachedServers,getpid());
				return 12;
			}
			//��ֹ��killtimer ������ɱ��
			debug_log_set_pid_current();
			prctl(PR_SET_NAME, "ziproxy_us", NULL, NULL, NULL);
			//us_server();
			us_clc_server();

			break;
		case -1:
			/* ERROR */
			error_log_puts (LOGMT_ERROR, LOGSS_USSERVER, "Fork() failed, waiting then retrying...\n");

			/* collect terminated child procs */
			while (waitpid (-1, NULL, WNOHANG) > 0) {
				/* do nothing here */
			}

			/* sleep a bit, to avoid busy-looping the machine,
			   just in case this fork() failure is due
			   to something more serious */
			sleep (1);

			goto fork_retry;
			break;
		default:
			/* PARENT */
			error_log_printf(LOGMT_INFO,LOGSS_USSERVER,
					"init_usprocess: fork the us_server.%d process with pid %d\n",
					i, pid);
			if (!us_server_pids)
				us_server_pids = (pid_t*)malloc(NumOfUSProcesses * sizeof(pid_t));
			us_server_pids[i] = pid;
			break;
		}
	}
	return 0;
}


#ifdef TEST
#include "CUnit/Basic.h"

void user_settings_module_init_test() {
	init_memcached("localhost:11211, 221.123.176.27:11212");
}

void fault_tolerance_test() {
	init_memcached("localhost:11211, flashtest:11212");
	char key[] = "key00";
	char value[] = "value00";
	size_t valuelen;
	uint32_t flags;
	memcached_return_t rc;
	int i = 30;
	memcached_set(&memc,key,5,value,7,0,0);
	assert(7 == MEMCACHED_UNKNOWN_READ_FAILURE);
	assert(26 == MEMCACHED_ERRNO);
	while (i>=0) {
		sleep(1);
	    char* got_value = memcached_get(&memc,key,strnlen(key,20),&valuelen,&flags,&rc);
	    switch (rc) {
	    case MEMCACHED_SUCCESS:
	    	printf("got value:%s\n",got_value);
	    	break;
	    case MEMCACHED_NOTFOUND:
	    	puts("not found, reput\n");
	    	memcached_set(&memc,key,5,value,7,0,0);
	    	break;
	    default:
	    	printf("error:%d\n",rc);
	    	printf("error text:%s\n",strerror(errno));
	    	break;
	    }
		i--;
	}
}
//
//void get_user_settings_from_memcached_test() {
//	MysqlHost = "127.0.0.1";
//	MysqlPort = 3306;
//	MysqlUser = "root";
//	MysqlPassword = "123456";
//	MysqlDatabase = "flashapp";
//
//	init_memcached("127.0.0.1");
//
//	user_settings_t us;
//	user_settings_init(&us);
//	get_user_settings_from_db(&us,12081,1213486160);
//	save_user_settings_to_memcached(&us,12081,1213486160);
//
//    char buf[0x100];
//	printf("load settings:\n%s\n", user_settings_tostr(&us,buf,0x100) );
//
//	user_settings_init(&us);
//	get_user_settings_from_memcached(&us,12081,1213486160);
//	printf("load settings from memcached:\n%s\n",user_settings_tostr(&us,buf,0x100));
//
//}

void get_user_settings_from_db_test() {
	MysqlHost = "127.0.0.1";
	MysqlPort = 3306;
	MysqlUser = "root";
	MysqlPassword = "123456";
	MysqlDatabase = "flashapp";
	user_settings_t us;
	get_user_settings_from_db(&us,12081,1213486160);

	printf("disable all:%d\n",us.disable_all);
}

int usettings_process_test() {
	CU_pSuite pSuite = NULL;
	error_log_init(NULL);

	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	pSuite = CU_add_suite("Suite_1", NULL, NULL);
	if (NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	fault_tolerance_test();

//	user_settings_module_init_test();
//
//	get_user_settings_from_memcached_test();
//
//	/* add the tests to the suite */
//	if (!CU_add_test(pSuite, "test of parse_user_agents_test()", parse_user_agents_test)) {
//		CU_cleanup_registry();
//		return CU_get_error();
//	}
//
//	if (!CU_add_test(pSuite, "test of process_user_settings_test()", process_user_settings_test)) {
//		CU_cleanup_registry();
//		return CU_get_error();
//	}

	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}

#endif

#endif
