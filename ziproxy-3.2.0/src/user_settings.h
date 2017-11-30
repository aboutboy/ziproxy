/*
 * user_settings.h
 *
 *  Created on: Jul 10, 2012
 *      Author: Eric Jiang (jxd431@gmail.com)
 */

#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http.h"

#ifdef USER_SETTINGS

typedef unsigned char setting_bool;
#define setting_false 0
#define setting_true 1

typedef enum _IMAGE_QUALITY_ {IQ_LOW,IQ_MID,IQ_HIGH,IQ_HIGH_1,IQ_HIGH_2,IQ_HIGH_3,IQ_LOSSLESS} IMAGE_QUALITY;
typedef unsigned char image_quality_t;
#define MAX_USER_AGENTS_SIZE 0x1000 // 4k
#define MAX_USER_AGENT_SIZE 80
#define MAX_SERVER_HOST_SIZE 256

typedef struct {
	/**
	 * buffer size
	 */
	uint16_t buflen;

	/**
	 * number of offsets
	 */
	uint16_t offlen;

	/**
	 * every element is a begin of user agent in 'buf'
	 */
	uint16_t *offsets;

	/**
	 * every user_agent is a pointer in orgbuf
	 */
	char* buf;

} useragents_t;

typedef struct {

	/**
	 * Disable all applications HTTP traffic
	 */
	setting_bool disable_all;

	/**
	 * Image quality for JPG (JPEG) compression.
	 * Image quality is specified in integers between 100 (best) and 0 (worst).
	 */
	image_quality_t image_quality;

	/**
	 * disable traffic while got one of following user agents
	 */
	useragents_t disabled_useragents;

} user_settings_t;


typedef struct {
	/**
	 * Disable one applications HTTP traffic
	 */
	setting_bool disable;

	/**
	 * Image quality for JPG (JPEG) compression.
	 * Image quality is specified in integers between 100 (best) and 0 (worst).
	 */
	image_quality_t image_quality;


} clc_setting_t;

typedef struct {
	//server host
	char shost[256];
	//server ip
	char sip[512];
}server_host_ip;

extern inline void user_settings_init(user_settings_t* us);

extern int init_memcached();

extern int get_user_settings(user_settings_t* settings, unsigned short int dport, uint32_t dip);

extern void user_settings_free(user_settings_t* user_settings);

extern char* alloc_and_serial_user_settings(const user_settings_t* settings, uint16_t* value_len);

extern void unserial_user_settings(user_settings_t* settings, const char* value, uint16_t value_len);

extern int user_agents_parse(useragents_t* user_agents, const char* str, int len);

extern const char* user_settings_tostr(const user_settings_t* us, char* str, int maxlen);

extern int get_clc_settings(clc_setting_t* setting, unsigned short int dport, uint32_t dip,const void * agebuf, const void * hostbuf, const void *guidbuf);

extern int init_serverhost_list();

extern char * get_host_from_ip(char *ipbuf);

extern int init_jsonprocess();

extern void destroy_jsonprocess();

#endif

#endif /* USER_SETTINGS_H_ */
