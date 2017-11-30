/*
 * user_settings.c
 *
 *  Created on: Jul 6, 2012
 *      Author: jiangxd
 */
#include <mysql/mysql.h>
#include "cfgfile.h"
#include "user_settings.h"

#ifdef USER_SETTINGS

typedef unsigned char setting_bool;
#define setting_false 0
#define setting_true 1

#define MAX_USER_AGENT_SIZE 64

typedef struct {
	/**
	 * every user_agent is a pointer in orgbuf
	 */
	const char** user_agents;
	/**
	 * number of user_agents
	 */
	uint32_t num;

	/**
	 * original buffer which includes user_agent seperated by ','
	 */
	const char* orgbuf;

	/**
	 * length of orgbuf
	 */
	uint32_t buflen;

} useragents;

typedef struct {

	setting_bool enabled;

	/**
	 * Disable all applications HTTP traffic
	 */
	setting_bool disable_all;

	/**
	 * Image quality for JPG (JPEG) compression.
	 * Image quality is specified in integers between 100 (best) and 0 (worst).
	 */
	int image_quality[4];

	/**
	 * disable traffic while got one of following user agents
	 */
	useragents *disabled_useragents;

} user_setting_item;

/**
 * Uses double buffer to avoid race condition
 */
struct {
	/**
	 * current items buffer
	 */
	user_setting_item* cur_items;
	int cur_items_num;

	/**
	 * 2nd items buffer , this maybe updating by read_user_settings
	 */
	user_setting_item* updating_items;
	int updating_items_num;

} user_settings_t;

static inline void user_settings_flip() {
	user_setting_item* tmp = user_settings_t.cur_items;
	user_settings_t.cur_items = user_settings_t.updating_items;
	user_settings_t.updating_items = tmp;

	int tmp_num = user_settings_t.cur_items_num;
	user_settings_t.updating_items_num = user_settings_t.cur_items_num;
	user_settings_t.cur_items_num = tmp_num;
}

static inline void user_setting_item_init(user_setting_item *settings) {
	settings->enabled = setting_false;
	settings->disable_all = setting_false;
	bzero(settings->image_quality,4*sizeof(int));
}

static inline void user_agents_init(useragents* set) {
	bzero(set,sizeof(useragents));
}

static useragents* user_agents_create(const char* user_agent_str, size_t sz) {
	if (sz <= 2 && (user_agent_str[0] != '"' || user_agent_str[sz-1] != '"')) return NULL;
	useragents* set = (useragents*)malloc(sz);
	set->orgbuf = strndup(user_agent_str,sz);
	// TODO: parsing user_agent_str
	return set;
}

static void user_agents_free(useragents** set) {
	free((*set)->orgbuf);
	free(*set);
	*set = NULL;
}

/**
 * return ==1 user_agent in set, ==0 user_agent not in set
 */
static inline int user_agents_include(const char* user_agent, useragents* set) {
	int i;
	for (i = 0; i < set->num; i++) {
		if (!strncmp(user_agent, set->user_agents[i]), MAX_USER_AGENT_SIZE)
			return 1;
	}
	return 0;
}

/**
 * Read user settings from database
 */
void read_user_settings() {
	static const char *sql = "select * from settings";
	MYSQL mysql;

	mysql_init(&mysql);
	mysql_real_connect(&mysql, MysqlHost, MysqlUser, MysqlPassword, MysqlDatabase, 3306, NULL, 0);

	mysql_query(&mysql, sql);

//	sql = "update t1 set name = 'java33' where id = 3;";
//	mysql_query(&mysql, sql);
	mysql_close(&mysql);
}

#endif /* USER_SETTINGS */
