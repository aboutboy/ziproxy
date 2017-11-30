/*
 * user_settings.c
 *
 *  Created on: Jul 10, 2012
 *      Author: Eric Jiang (jxd431@gmail.com)
 */

#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <sys/un.h>
#include "log.h"
#include "cfgfile.h"
#include "http.h"
#include "user_settings.h"
#include "session.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef USER_SETTINGS

/**
 * 	if (i < 5000)
		imgcat = 0;
	else if ((i < 50000)|| (width < 150) || (height < 150))
		imgcat = 1;
	else if (i < 250000)
		imgcat = 2;
	else imgcat = 3;
 */

static int image_quality_map[][4] = {
		{20,20,20,20},
		{30,25,25,20},
		{60,50,50,40}
};

//
//static char* parse_value(char** start, char* end) {
//
//}
//
//int parse_settings_json(user_settings* settings, char* json_txt, int len) {
//	char* p = json_txt;
//	char* end = json_txt + len;
//	char* key;
//	char* value;
//	int state = 0; // 0: start, 1: key, 2:keyend, 3: value
//	while (*p && p <= end) {
//		if (state == 0 && *p == '"') {
//			state = 1;
//			key = p;
//		}
//		else if (state == 1 && *p == '"') {
//			*p = '\0';
//			state = 2;
//		}
//		else if (state == 2 && *p == ':') {
//			value = p;
//			state = 3;
//		}
//		else if (state == 3 && *p == ',') {
//			value = parse_value(&p,end);
//			if (!strncmp('da',key,2)) {
//				settings->disable_all = (value[0] == '1');
//			}
//			else if (!strncmp('iq',key,2)) {
//				settings->image_quality = value[0] - '0';
//			}
//			else if (!strncmp('du',key,2)) {
//
//			}
//			state = 1;
//		}
//		p++;
//	}
//}

void user_settings_init(user_settings_t* us) {
    bzero(us,sizeof(user_settings_t));
    us->image_quality = IQ_MID;
}

static const char* user_agents_get(const useragents_t *ua, int no) {
	if (no >= ua->offlen) return NULL;
	return ua->buf + ua->offsets[no];
}

const char* user_settings_tostr(const user_settings_t* us, char* str, int maxlen) {
	snprintf(str, maxlen,
			"{disabled_all:%d,image_quality:%d,user_agent_num:%d,user_agents:",
			us->disable_all, us->image_quality, us->disabled_useragents.offlen);
	char* p = str + strnlen(str,maxlen);
	int no = 0;
	while (no < us->disabled_useragents.offlen) {

		if (p - str >= maxlen) break;
		*p++ = '"';

		if (p - str >= maxlen) break;
		strcpy(p, user_agents_get(&(us->disabled_useragents),no++) );
		p = str + strnlen(str,maxlen);

		if (p - str >= maxlen) break;
		*p++ = '"';

		if (p - str >= maxlen) break;
		*p++ = ',';
	}
	if (p-str < maxlen) *p = '}';
	return str;
}

int user_agents_parse(useragents_t* user_agents, const char* str, int len) {
	char* value = NULL;
	int state = 0; // 0:out of user agent, 1:into user agent
	char* p = NULL;

	bzero(user_agents,sizeof(useragents_t));
	user_agents->buf = strndup(str,MAX_USER_AGENTS_SIZE);
	user_agents->buflen = len;
	p = user_agents->buf;
	char* end = p + len;

	int max_offsets = 16;
	user_agents->offsets = (uint16_t*)malloc(max_offsets * sizeof(uint16_t));
	while (p <= end) {
		if (state == 0) {
			if (*p == '"') {
				if ( user_agents->offlen >= max_offsets) {
					user_agents->offsets = (uint16_t*)realloc(user_agents->offsets, (max_offsets << 1) * sizeof(uint16_t));
				}
				user_agents->offsets[user_agents->offlen] = p + 1 - user_agents->buf;
				user_agents->offlen ++;
				state = 1;
			}
		}
		else {
			if (*p == '"') {
				*p = '\0';
				state = 0;
			}
		}
		p++;
	}
	return 0;
}

static void user_agents_free(useragents_t* user_agents) {
	if (user_agents->buf) free(user_agents->buf);
	if (user_agents->offsets) free(user_agents->offsets);
}

void user_settings_free(user_settings_t* user_settings) {
	user_agents_free(&(user_settings->disabled_useragents));
}

/**
 * return ==0 found key from memcached; !=0 not found or error
 */
int get_user_settings(user_settings_t* settings, unsigned short int dport, uint32_t dip) {

	int retval = 0;
	user_settings_init(settings);
	char key[20];
	snprintf(key, 20, "%d:%d", dip, dport);
	uint32_t flags;

	uint16_t valuelen = 0;
	char* value = get_from_server(dip,dport,&valuelen);
	if (!value) {
		error_log_printf(LOGMT_INFO,LOGSS_DAEMON,"memcached get null value(%x:%d)\n",dip,dport);
		return 2;
    }

	unserial_user_settings(settings,value,valuelen);

	char str[0x1000];
	error_log_printf(LOGMT_INFO, LOGSS_DAEMON, "Received user settings:\n%s(%x:%d)\n",
			user_settings_tostr(settings, str, 0x1000),dip,dport);
    free(value);

    return 0;
}

void unserial_user_settings(user_settings_t* settings, const char* value, uint16_t value_len) {

    const void* p = value;
	settings->disable_all = *((setting_bool*) p);
	p += sizeof(setting_bool);
	settings->image_quality = *((image_quality_t*) p);
    p += sizeof(image_quality_t);
	settings->disabled_useragents.buflen = *((uint16_t*) p);
    p+= sizeof(uint16_t);
	settings->disabled_useragents.offlen = *((uint16_t*) p);
    p += sizeof(uint16_t);

	settings->disabled_useragents.offsets = (uint16_t*)malloc(settings->disabled_useragents.offlen * sizeof(uint16_t));
	memcpy(settings->disabled_useragents.offsets,p,settings->disabled_useragents.offlen * sizeof(uint16_t));
    p += settings->disabled_useragents.offlen * sizeof(uint16_t);

	settings->disabled_useragents.buf = (char*)malloc(settings->disabled_useragents.buflen);
	memcpy(settings->disabled_useragents.buf,p,settings->disabled_useragents.buflen);
    p += settings->disabled_useragents.buflen;

	assert(p - (void*)value == value_len);

}

char* alloc_and_serial_user_settings(const user_settings_t* settings, uint16_t* value_len) {
	*value_len = sizeof(setting_bool) // disabled_all
			+ sizeof(image_quality_t) // image_quality
			+ sizeof(uint16_t) // useragent.buflen
			+ sizeof(uint16_t) // useragent.offlen
			+ settings->disabled_useragents.offlen * sizeof(uint16_t) // useragent.offsets
			+ settings->disabled_useragents.buflen; // useragent.buf
	void* value = malloc(*value_len);
	void* p = value;
	*((setting_bool*)p) = settings->disable_all;
	p += sizeof(setting_bool);
	*((image_quality_t*)p) = settings->image_quality;
	p += sizeof(image_quality_t);
	*((uint16_t*)p) = settings->disabled_useragents.buflen;
	p += sizeof(uint16_t);
	*((uint16_t*)p) = settings->disabled_useragents.offlen;
	p += sizeof(uint16_t);
	memcpy(p,settings->disabled_useragents.offsets,settings->disabled_useragents.offlen * sizeof(uint16_t));
	p += settings->disabled_useragents.offlen * sizeof(uint16_t);
	memcpy(p,settings->disabled_useragents.buf,settings->disabled_useragents.buflen);
	p += settings->disabled_useragents.buflen;

	assert( p - value == *value_len);

	return value;
}


///////////////////////2012-09-04///////////////////////////
char * get_host_from_ip(char *ipbuf){
	return get_host_fromip(server_hosts,MAX_SERVER_HOST_SIZE,ipbuf);
}

int init_serverhost_list() {
	int i;
	int ires=1;
	for (i = 0; i < MAX_SERVER_HOST_SIZE; i++) {
		memset(server_hosts[i].shost,0,256);
		memset(server_hosts[i].sip,0,512);
	}

	ires = get_hosts_fromjson(server_hosts,MAX_SERVER_HOST_SIZE,ServerIpListFileName);

	return ires;

}

void clc_settings_init(clc_setting_t* us) {
    bzero(us,sizeof(clc_setting_t));
    us->disable=setting_false;
    us->image_quality = ImageQualityDefaultSet[ImageQualityLevel];
}

//get result for server
int get_clc_settings(clc_setting_t* setting, unsigned short int dport,
		uint32_t dip,const void * agebuf,const void * hostbuf,const void *guidbuf)
{

	int ires=0;
	clc_settings_init(setting);

	//flash app  agent  pass through
	if(agebuf!=NULL){
		if(strstr(agebuf,"flashapp")!=NULL)
			return 0;
	}

	if(SquidUsedIn!=2)// for squid
	ires = get_from_clcserver(dip, dport, agebuf, hostbuf , guidbuf, setting);

	if (ires == 0) {
		return 1;
    }
    return 0;
}


#ifdef TEST
#include "CUnit/Basic.h"

void process_user_settings_test() {
	clc_setting_t us;
	http_headers hdr;
	us.disable = setting_false;
	us.image_quality = IQ_MID;
}

void parse_user_agents_test() {
	const char* str = "\"Mozilla\", \"IE\", \"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\"";
	int len = strlen(str);
	useragents_t ua;
	user_agents_parse(&ua,str,len);
	CU_ASSERT(ua.offsets != NULL);
	CU_ASSERT(ua.buf != NULL);
	CU_ASSERT(3 == ua.offlen);
	CU_ASSERT(len == ua.buflen);
	CU_ASSERT(ua.offsets[0] == 1);
	CU_ASSERT(ua.offsets[1] == 12);
	CU_ASSERT(strcmp("Mozilla",user_agents_get(&ua,0)) == 0);
	CU_ASSERT(strcmp("IE",user_agents_get(&ua,1)) == 0);
	CU_ASSERT(strcmp("Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",user_agents_get(&ua,2)) == 0);
	CU_ASSERT(user_agents_get(&ua,3) == NULL);
	user_agents_free(&ua);
}

int user_settings_test() {
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
