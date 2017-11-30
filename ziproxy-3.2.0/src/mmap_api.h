#ifndef  __MMAP_API_H_Djlskfj
#define  __MMAP_API_H_Djlskfj

#if (defined(WIN32) || defined(WIN64))

#else
	#define __int64  long long int
#endif

#if (defined(WIN32) || defined(WIN64))
	#ifdef __cplusplus
		#define __BEGIN_DECLS extern "C" {
		#define __END_DECLS	}
	#else
		#define __BEGIN_DECLS
		#define __END_DECLS
	#endif

#else
#include <sys/cdefs.h>
#endif

#include <memory.h>
#include <time.h>

__BEGIN_DECLS

#define MAX_MMAP_COOKIE_LEN 1024
#define MAX_MMAP_URL_LEN    2048 
#define MUTEX_IDNEX         0xFFFFFFFF 
#define INDEX_RANDOM        0xFFFFFFFE

#define MSG_QUEUE	0xFFFFFFFD 
extern int* MSG_QUEUE_ACTIVE;


// ���ر����ڹ����ڴ��е���ݽṹ
/*
typedef struct {	
	char cookie[MAX_MMAP_COOKIE_LEN];
	char visit_url[MAX_MMAP_URL_LEN];
	unsigned int update_time;
}MMAP_Item;
*/
typedef struct {	
	int msgid;
}MMAP_Item;

int  MMAP_Set(const int index, MMAP_Item* p_item);

int  MMAP_Get(const int index, MMAP_Item* p_item);

int MMAP_detache(void *p);

MMAP_Item*  MMAP_Get_Address(const int index);

#define PERM S_IRUSR|S_IWUSR
#define MSG_MAX_NUMS 2
#define MSG_PROJ_ID 'z'
#define MSG_TYPE 9876

extern int ACTIVE_MSG_ID;
extern char *MSG_KEY_FILES[2];

/*
mysql> desc accessLog;
+---------------+--------------+------+-----+---------+----------------+
| Field         | Type         | Null | Key | Default | Extra          |
+---------------+--------------+------+-----+---------+----------------+
| id            | int(11)      | NO   | PRI | NULL    | auto_increment | 
| accessTime    | datetime     | YES  | MUL | NULL    |                | 
| usec          | mediumtext   | YES  |     | NULL    |                | 
| username      | varchar(100) | YES  | MUL | NULL    |                | 
| ip            | varchar(64)  | YES  | MUL | NULL    |                | 
| proxytype     | varchar(20)  | YES  |     | NULL    |                | 
| orilength     | mediumtext   | YES  |     | NULL    |                | 
| ziplength     | mediumtext   | YES  |     | NULL    |                | 
| requestMethod | varchar(10)  | YES  |     | NULL    |                | 
| url           | varchar(512) | YES  |     | NULL    |                | 
| userAgent     | varchar(256) | YES  |     | NULL    |                | 
| appAgent      | varchar(64)  | YES  | MUL | NULL    |                | 
| cport         | int(6)       | YES  | MUL | NULL    |                | 
| dport         | int(6)       | YES  |     | NULL    |                | 
| dip           | varchar(64)  | YES  | MUL | NULL    |                | 
+---------------+--------------+------+-----+---------+----------------+
 */
typedef struct {
	int year;
	int month;
	int day;
	int accessTime;
	int usec;
	char username[100];
	char ip[64];
	char proxytype[20];
	unsigned int orilength;
	unsigned int ziplength;
	char requestMethod[10];
	char url[512];
#ifdef NEVER
	char refer[512];
#endif
	char userAgent[256];
	char appAgent[256];
	char realAgent[64];
	int cport;
	int dport;
	char dip[64];
} ACCESSLOG;

typedef struct {	
	long mtype;
	ACCESSLOG accesslog;
} MSG_Item;

int MSG_Init(const int index);
int MSG_Send(int index, MSG_Item* p_item, int len);
int MSG_Recv(int index, MSG_Item* p_item, int len);

__END_DECLS


#endif  /* __STAT_API_H_Included_aASDFbe3 */


