#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <syslog.h>
#include <linux/limits.h>

#define INIT_SOCKS_CAPACITY 1024
#define INIT_LISTEN_SOCKS_CAPACITY 8
#define INIT_SOCKINODE_ARRAY_CAPACITY 4
#define PROC_NAME "ziproxy"

typedef enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,    /* Now a valid state */
    TCP_MAX_STATES  /* Leave at the end! */
} TCP_STATE;

typedef struct _inode_socktcp {
	uint32_t inode_no;
	TCP_STATE state;
} tcpsock;

typedef struct _proc_sock {
	uint32_t *inodes;
	uint16_t size;
} proc_sock;

static FILE* logf = NULL;

static inline is_closing_tcp_sock_state(TCP_STATE state) {
	return ( (state >= TCP_FIN_WAIT1 && state <= TCP_LAST_ACK) || state == TCP_CLOSING);
}

static int is_pid_str(const char* dirname, pid_t* pid) {
	pid_t id = 0;
	while (dirname && *dirname) {
		if (*dirname < '0' || *dirname > '9') return 0;
		id = id * 10 + *dirname - '0';
		dirname++;
	}
	*pid = id;
	return 1;
}

static uint32_t ntoip(const char* hex) {
	uint32_t ip = 0;
	int bit = 0;
	while (*hex && hex) {
		ip += ((*hex > '9') ? (*hex - 'A' + 10) : (*hex - '0')) << (bit + 4);
		hex++;
		if (!*hex || !hex) break;
		ip += ((*hex > '9') ? (*hex - 'A' + 10) : (*hex - '0')) << bit;
		hex++;
		bit += 8;
	}
	return ip;
}

static uint32_t htou(const char* hex) {
	uint32_t u = 0;
	while (*hex && hex) {
		u = (u << 4) + ((*hex > '9') ? (*hex - 'A' + 10) : (*hex - '0'));
		hex++;
	}
	return u;
}

static const char* iptostr(uint32_t ip,char* str) {
	snprintf(str,15,"%d.%d.%d.%d", 
		(ip & 0xff000000 ) >> 24, 
		(ip & 0xff0000 ) >> 16, 
		(ip & 0xff00 ) >> 8, 
		(ip & 0xff ));
	return str;
}

static char msg[0x1000];
static void logtype(const char* type, const char* fmt, va_list ap) {
	time_t t_now = time(NULL);
	struct tm* t_info = localtime(&t_now);
	if (!t_info) return;
	vsnprintf(msg,0x100,fmt,ap);
	if (logf)
		fprintf(logf,"[%04d-%02d-%02d %02d:%02d:%02d] - %s: %s\n",
				t_info->tm_year + 1900, t_info->tm_mon + 1, t_info->tm_mday,
				t_info->tm_hour, t_info->tm_min, t_info->tm_sec, type, msg);
	else
		printf("[%04d-%02d-%02d %02d:%02d:%02d] - %s: %s\n",
				t_info->tm_year + 1900, t_info->tm_mon + 1, t_info->tm_mday,
				t_info->tm_hour, t_info->tm_min, t_info->tm_sec, type, msg);
	fflush(logf);
}

static void logerr(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logtype("ERROR",fmt,ap);
	va_end(ap);
}

static void loginfo(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	logtype("INFO",fmt,ap);
	va_end(ap);
}

//
//static pid_t* getpid_by_sockinode(uint32_t sock_inode_no, proc_sock* psocks, pid_t* pid) {
//	while (psocks) {
//		if (psocks->sock_inode_no == sock_inode_no) {
//			*pid = psocks->pid;
//			return pid;
//		}
//		psocks = psocks->next;
//	}
//	return NULL;
//}

static const char* get_cmdline_by_pid(pid_t pid, char* cmdline, uint32_t max_size) {
	char cmdlinepath[0x100];
	snprintf(cmdlinepath,0x100,"/proc/%d/cmdline",pid);
	int fd = open(cmdlinepath,O_RDONLY);
	if (fd == -1) {
		logerr("Error to open %s",cmdlinepath);
		return NULL;
	}
	if ( read(fd,cmdline,max_size) == -1) {
		logerr("Error to read from %s(%s)",cmdlinepath,strerror(errno));
		close(fd);
		return NULL;
	}
	close(fd);
	return cmdline;
}

static void quick_sort_tcp_sock(tcpsock* socks, uint32_t size) {
	if (size <= 1) return;

	int i = 0;
	int j = size -1;
	tcpsock tmp = socks[0];
	while (i < j) {
		while (i < j && socks[j].inode_no >= tmp.inode_no) j--;
		if (i < j) socks[i++] = socks[j];
		while (i < j && socks[i].inode_no <= tmp.inode_no) i++;
		if (i < j) socks[j--] = socks[i];
	}
	socks[i] = tmp;
	quick_sort_tcp_sock(socks, i);
	quick_sort_tcp_sock(socks + i + 1, size - i - 1);
}

static int in_socks(const tcpsock* socks, uint32_t size, uint32_t sock_inode) {
	int lind = 0;
	int rind = size - 1;

	while (lind <= rind) {
		int mid = (lind + rind) / 2;
		uint32_t inode_no = socks[mid].inode_no;
		if (sock_inode == inode_no) return 1;
		else if (sock_inode > inode_no)
			lind = mid + 1;
		else
			rind = mid-1;
	}
	return 0;
}

/**
 * assure socks pointer has enough space for storage
 */
static int inline assure_socks_size(tcpsock** socks, uint32_t* size, uint32_t* maxsize) {

	if (! (*socks) ) {
		*socks = (tcpsock*)malloc(sizeof(tcpsock) * (*maxsize) );
		if (!*socks) {
			logerr("Failed to malloc");
			return 1;
		}
	}

	if (*socks && (*size) == *maxsize) {
		(*maxsize) <<= 1;
		*socks = (tcpsock*)realloc(*socks, *maxsize * sizeof(tcpsock));
		if (!*socks) {
			logerr("Failed to realloc");
			return 1;
		}
	}

	return 0;
}

/**
 * Get tcp socket status from /proc/net/tcp
 * Return value is a array sorted by inode_no
 */
static int get_tcpsocks(uint32_t *closing_size, tcpsock** closing_socks, uint32_t *listen_size, tcpsock** listen_socks) {

	char ln[0x100];
	*closing_size = 0;
	uint32_t max_closing_size = INIT_SOCKS_CAPACITY;
	uint32_t max_listen_size = INIT_LISTEN_SOCKS_CAPACITY;

#ifdef PROFILE_TIME
	struct timeval begin,end;
	gettimeofday(&begin,NULL);
#endif

	FILE* f = fopen("/proc/net/tcp","r");
	if (!f) return 1;

	// ignore first line
	if (!fgets(ln,0x100,f)) return 1;

	while ( fgets(ln,0x100,f) ) {
		strtok(ln," "); // sl
		strtok(NULL," "); //local_address
		strtok(NULL," "); // rem_address
		char *statestr = strtok(NULL," "); // st

		TCP_STATE state = htou(statestr);
		tcpsock* tail = NULL;
		if (state == TCP_LISTEN) {
			if (assure_socks_size(listen_socks,listen_size,&max_listen_size))
				return 1;
			tail = *listen_socks + *listen_size;
			(*listen_size) ++;
		}
		else if (is_closing_tcp_sock_state(state)) {
			if (assure_socks_size(closing_socks,closing_size,&max_closing_size))
				return 1;
			tail = *closing_socks + *closing_size;
			(*closing_size) ++;
		}
		else
			continue;

		strtok(NULL, " "); // tx_queue, rx_queue
		strtok(NULL, " "); // tr, tm->when
		strtok(NULL, " "); // retrnsmt
		strtok(NULL, " "); // uid
		strtok(NULL, " "); // timeout
		char* inodestr = strtok(NULL," ");

		tail->state = state;
		tail->inode_no = atoi(inodestr);
	}
	fclose(f);

#ifdef PROFILE_TIME
	gettimeofday(&end,NULL);
	loginfo("[PROFILE] parse /proc/net/tcp spent %d ms",
			(end.tv_sec - begin.tv_sec) * 1000 + (end.tv_usec - begin.tv_usec) / 1000);

	gettimeofday(&begin,NULL);
#endif

	quick_sort_tcp_sock(*closing_socks,*closing_size);
	quick_sort_tcp_sock(*listen_socks,*listen_size);

#ifdef PROFILE_TIME
	gettimeofday(&end,NULL);
	loginfo("[PROFILE] quick_sort_tcp_sock %d items spent %d ms", *closing_size,
			(end.tv_sec - begin.tv_sec) * 1000 + (end.tv_usec - begin.tv_usec) / 1000);
#endif

}

static time_t get_boot_time() {
	FILE* f = fopen("/proc/stat", "r");
	if (!f) {
		logerr( "Failed to open /proc/stat(%s)", strerror(errno));
		return 0;
	}
	char ln[0x100];
	while (fgets(ln, 0x100, f)) {
		char* clmname = strtok(ln, " ");
		if (clmname && !strncmp(clmname, "btime", 5)) {
			char* btimestr = strtok(NULL, " ");
			return atol(btimestr);
		}
	}
	return 0;
}

static int get_proc_info(pid_t pid, time_t btime, char* name, uint16_t maxsize, unsigned long *running_seconds) {
	char fpath[0x100];
	snprintf(fpath,0x100,"/proc/%d/stat",pid);
	FILE* f= fopen(fpath,"r");
	if (!f) {
		// now the process exited
//		logerr("Failed to open %s(%s)",fpath,strerror(errno));
		return 1;
	}

	char state;
	char cmdname[0x100];
	int ppid, pgrp, session, tty_nr,tpgid;
	unsigned int flags;
	unsigned long minflt,cminflt,majflt,cmajflt,utime,stime;
	long cutime,cstime,priority,nice,num_threads,itrealvalue;
	long long unsigned starttime;

	int ret;
	if ( (ret = fscanf(f, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu",
			&pid,
			cmdname, &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
			&minflt, &cminflt, &majflt, &cmajflt, &utime, &stime ,
			&cutime,&cstime,&priority,&nice,&num_threads,&itrealvalue,
			&starttime
			))!= 22) {
		logerr("fscanf by %s failed:%d",fpath,ret);
		return 2;
	}
	*running_seconds = time(NULL) - starttime / sysconf(_SC_CLK_TCK) - btime;
	strncpy(name,cmdname + 1,strnlen(cmdname,0x100) - 1); // ignore 2 parentheses.
	name[strnlen(cmdname,0x100)-2] = 0;

	fclose(f);
	return 0;
}

//static inline destroy_proc_socks(proc_sock* psocks) {
//	if (psocks && psocks->inodes) {
//		free(psocks->inodes);
//		psocks->inodes = NULL;
//	}
//}

static void get_proc_socks(pid_t pid, proc_sock* psocks) {
	struct stat proc_sb;
	char procpath[0x100];
	assert(!psocks->inodes && !psocks->size);
	uint16_t max_size = INIT_SOCKINODE_ARRAY_CAPACITY;

	snprintf(procpath, 0x100, "/proc/%d/fd", pid);
	DIR* procdir = opendir(procpath);
	if (!procdir) {
		logerr( "Failed to open dir:%s(%s)", procpath,
				strerror(errno));
		return;
	}
	struct dirent* fileent;

	while ((fileent = readdir(procdir))) {

		if (!strcmp(fileent->d_name, ".") || !strcmp(fileent->d_name, ".."))
			continue;

		struct stat file_sb;
		char linkpath[0x100];
		snprintf(linkpath, 0x100, "%s/%s", procpath, fileent->d_name);

		if (stat(linkpath, &file_sb) < 0) // || !S_ISLNK(file_sb.st_mode))
			continue;

		char linkbuf[0x100];
		size_t link_sz = 0;
		if ((link_sz = readlink(linkpath, linkbuf, 0x100)) > 0) {
			if (link_sz <= 8)
				continue;
			if (strncmp(linkbuf, "socket:[", 8))
				continue;
			char* inode_str = linkbuf + 8;
			char* p = inode_str;
			while (p && *p) {
				if (*p == ']')
					*p = '\0';
				p++;
			}
			if (! (psocks->inodes))
				psocks->inodes = (uint32_t*)malloc(max_size * sizeof(uint32_t));
			if ( psocks->inodes && psocks->size == max_size) {
				max_size <<= 1;
				psocks->inodes = (uint32_t*)realloc(psocks->inodes, max_size * sizeof(uint32_t));
			}
			psocks->inodes[psocks->size ++] = (uint32_t) atol(inode_str);
		}
	}
	closedir(procdir);
}

/**
 * Get process by process name, live time and socket state
 */
void list_filtered_procs(const char* filtered_proc_name, unsigned long max_live_time ) {
	struct stat proc_sb;
	struct dirent* procent = NULL;
	char procpath[0x100];
	time_t btime = get_boot_time();
#ifdef PROFILE_TIME
	struct timeval begin,end;
	gettimeofday(&begin,NULL);
#endif
	tcpsock* closing_socks = NULL;
	tcpsock* listen_socks = NULL;
	uint32_t closing_socks_size = 0;
	uint32_t listen_socks_size = 0;
	get_tcpsocks(&closing_socks_size, &closing_socks, &listen_socks_size, &listen_socks);
#ifdef PROFILE_TIME
	gettimeofday(&end,NULL);
	loginfo("[PROFILE] get_closing_tcpsocks spent %d ms",
			(end.tv_sec - begin.tv_sec) * 1000 + (end.tv_usec - begin.tv_usec) / 1000);
#endif
//	int i;
//	for (i=0;i<closing_socks_size;i++) {
//		printf("state:%d, inode:%d\n",closing_socks[i].state,closing_socks[i].inode_no);
//	}

	DIR* rootdir = opendir("/proc");

	while ( (procent = readdir(rootdir)) ) {

		if (!stat(procent->d_name, &proc_sb) < 0 || !S_ISDIR(proc_sb.st_mode))
			continue;

		if (!strcmp(procent->d_name,".") || !strcmp(procent->d_name,".."))
			continue;

		pid_t pid;
		if (!is_pid_str(procent->d_name,&pid))
			continue;

		char proc_name[0x20];
		unsigned long runtime = 0; // in seconds
		if (get_proc_info(pid,btime,proc_name,0x20,&runtime)) {
			// now the process exited
//			logerr("Failed to get process name by pid:%d",pid);
			continue;
		}
		if (strncmp(proc_name,filtered_proc_name,0x20))
			continue;
		if (runtime < max_live_time) // smaller than 2 hour
			continue;

		proc_sock psocks;
		psocks.inodes = NULL;
		psocks.size = 0;
		get_proc_socks(pid,&psocks);
		if (!psocks.inodes) continue;

		int found_listen = 0;
		int i;
		int num_active_sock = 0;
		for (i=0;i<psocks.size; i++) {

			// if the process has one listen socket, Don't kill it.
			if (listen_socks && in_socks(listen_socks,listen_socks_size,psocks.inodes[i])) {
				found_listen = 1;
				break;
			}

			// count number of active sockets
			if (closing_socks && !in_socks(closing_socks,closing_socks_size,psocks.inodes[i]))
				num_active_sock ++;
		}

		// Don't kill listen sockets
		if (found_listen)
			continue;

		if (num_active_sock > 1)
			continue;

		/* Kill process */
		kill(pid,SIGKILL);
		loginfo("Kill process %d/%s with %d connections",pid,filtered_proc_name,num_active_sock);

		if (psocks.inodes)
			free(psocks.inodes);
//		destroy_proc_socks(&psocks);

	}

	closedir(rootdir);

	if (listen_socks)
		free(listen_socks);

	if (closing_socks)
		free(closing_socks);

}


static void sigcatch (int sig) {
	// term
	if (logf)
		fclose(logf);
	closelog();
	exit(0);
}

static print_usage() {
	fprintf(stderr,
			"usage: ziproxy-killtimeout [ -d interval timeout ]\n\tThe interval and timeout is both signed, 32 bit integer\n");
}

int main(int argc, char** argv) {
	if (argc >= 4 && !strncmp(argv[1],"-d",2)) {
		// daemon mode
		int interval = atoi(argv[2]);
		int timeout = atoi(argv[3]);
		time_t lasttime = time(NULL);
		if (interval <=0 || timeout <= 0) {
			print_usage();
			exit(255);
		}
		signal (SIGTERM, sigcatch);
		openlog("", LOG_NOWAIT, LOG_USER);
		if (argc >= 5) {
			logf = fopen(argv[4],"w");
			if (!logf) {
				syslog(0,"open '%s' error:%s\n",argv[4],strerror(errno));
			}
		}
		do {
			loginfo("%s","Start to run");
			list_filtered_procs("ziproxy",timeout);
			do {
				sleep(interval);
			} while (time(NULL) - lasttime < interval);
			lasttime = time(NULL);
		} while( 1 );
	}
	else if (argc > 1) {
		print_usage();
		exit(255);
	}
	else {
		// run once
		list_filtered_procs("ziproxy",60);
	}
}
