#if (defined(WIN32) || defined(WIN64))
#include <windows.h>
#define   G_PSZ_FILENAME       "C:\\MMSCAN.dat"
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <strings.h>
#include <sys/shm.h>
#include <errno.h>
#endif

#include "mmap_api.h"

// 共享内存的key

#if (defined(WIN32) || defined(WIN64))


struct MMAP_Handle{
	HANDLE hFile;
	HANDLE hFileMapping;
	struct MMAP_Item* p;
};

int MMAP_Init(struct MMAP_Handle* sh)
{
	// Open the file that we want to map.
	sh->hFile = CreateFile(G_PSZ_FILENAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
	   OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if(sh->hFile == NULL)
	{
//		printf("CreateFile fail!errorcode = %d\n", GetLastError());
		return -3;
	}
	
	// Create a file-mapping object for the file.
	sh->hFileMapping = CreateFileMapping(sh->hFile, NULL, PAGE_READWRITE,
	   0, MMAP_MEM_MAX_ITEM*sizeof(struct MMAP_Item), NULL);

	if(sh->hFileMapping == NULL)
	{
//		printf("CreateFileMapping fail!errorcode = %d\n", GetLastError());
		return -4;
	}
	
	// Map a copy-on-write view of the file; the system will commit
	// enough physical storage from the paging file to accommodate
	// the entire file. All pages in the view will initially have
	// PAGE_WRITECOPY access.
	sh->p = (struct MMAP_Item*) MapViewOfFile(sh->hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if(NULL == sh->p){
//		printf("MapViewOfFile fail! errorcode = %d\n", GetLastError());
		return -5;
	}

	return 0;

}

int MMAP_UnInit(struct MMAP_Handle* sh)
{
	// Because this byte is now in a PAGE_READWRITE page, the system
	// simply writes the byte to the page (backed by the paging file).
	
	// When finished using the file's mapped view, unmap it.
	// UnmapViewOfFile is discussed in the next section.
	if(NULL != sh->p)
		UnmapViewOfFile(sh->p);
	
	// The system decommits the physical storage from the paging file.
	// Any writes to the pages are lost.
	
	// Clean up after ourselves.
	if(NULL != sh->hFileMapping)
		CloseHandle(sh->hFileMapping);
	if(NULL != sh->hFile)
		CloseHandle(sh->hFile);	

	return 0;
}

int  MMAP_Set(const int index, struct MMAP_Item* p_item)
{
	struct MMAP_Handle sh;

	if ((index < 0) || (index >=MMAP_MEM_MAX_ITEM))
	{
		// 非法的统计id
		return -1;
	}


	MMAP_Init(&sh);

	if (NULL == sh.p){
		MMAP_UnInit(&sh);	
		return -2;
	}

	memcpy(&sh.p[index], p_item, sizeof(struct MMAP_Item));

	MMAP_UnInit(&sh);
	
	return 0;
}

int  MMAP_Get(const int index, struct MMAP_Item* p_item)
{
	struct MMAP_Handle sh;

	MMAP_Init(&sh);
	
	if (NULL == sh.p){
		MMAP_UnInit(&sh);	
		return -2;
	}

	memcpy(p_item, &sh.p[index], sizeof(struct MMAP_Item));

	MMAP_UnInit(&sh);

	return 0;
}

#else

int* MSG_QUEUE_ACTIVE;
char *MSG_KEY_FILES[2] =
        {
                "/usr/bin",
                "/bin"
        };

/* 取得共享内存大小
 */
int  get_shm_size(key_t key)
{
	struct shmid_ds stat_buf;

	int iShmID;

	iShmID = shmget(key, 0, 0);

	if (iShmID == -1) return -1;

	shmctl(iShmID, IPC_STAT, &stat_buf);

	return stat_buf.shm_segsz;

}

/* 删除共享内存
 */ 
int  remove_shm(key_t key)
{
	int iShmID;

	iShmID = shmget(key, 0, 0);

	if (iShmID == -1) return -1;
	return shmctl(iShmID, IPC_RMID, NULL);

}

/*  获取共享内存块指针
 */
void* get_shm(key_t key, ssize_t size)
{
	int iShmID, _size;
	int flag= 0666;
	void *ptr= NULL;


	_size = get_shm_size(key);
	if (_size == 0)
	{
		flag |= IPC_CREAT;
	}
	else if (_size != size) {
		remove_shm(key);
		flag |= IPC_CREAT;
	}

	iShmID = shmget(key, size, flag);
	if (iShmID == -1)
	{
		perror("create shm failed.");
		return NULL;
	}

	ptr = shmat(iShmID, NULL, 0);
	if (ptr == NULL) return NULL;

	if (flag & IPC_CREAT) {
		bzero(ptr, size);
	}
	return ptr;
}

/* 初始化统计接口
 */
struct MMAP_Item*  MMAP_Init(const int index)
{
	char* s_pStatMem= NULL;

	s_pStatMem= (char*)get_shm(index, sizeof(MMAP_Item));

	if (s_pStatMem == NULL) {
	   /* 获取共享内存失败 */
		return NULL;
	}
	
	return (struct MMAP_Item*)s_pStatMem;
}

int MMAP_detache(void *p)
{
	if (! p)
		return -1;

	shmdt(p);
}

int  MMAP_Set(const int index, MMAP_Item* p_item)
{
	struct MMAP_Item *p= MMAP_Init(index);

	if (p== NULL) return -2;

	memcpy(p, p_item, sizeof(MMAP_Item));
	
	return 0;
}

int  MMAP_Get(const int index, MMAP_Item* p_item)
{
	struct MMAP_Item *p= MMAP_Init(index);

	if (p== NULL) return -2;

	memcpy(p_item, p, sizeof(MMAP_Item));

	return 0;
}

MMAP_Item*  MMAP_Get_Address(const int index)
{
	return  MMAP_Init(index);
}

/*
 * get the msgid of the msg queue with index of idx
 * return value:
 * > 0: msgid on success
 * -1 : error happens
 */
int get_msg(int idx)
{
	key_t key;
	int msgid;

	if ( idx > MSG_MAX_NUMS - 1 || idx < 0)
	{
		perror("exceeeds the limit of num. of the msgque.");
		return -1;
	}
	
	if ( (key = ftok(MSG_KEY_FILES[idx], MSG_PROJ_ID)) == -1 )	
	{
		perror("create msg key failed.");
		return -1;
	}

	if( (msgid = msgget(key, PERM)) == -1 )
	{
		if (errno == ENOENT)
		{
			/* no msg queue available, need to create it */
			if( (msgid = msgget(key, PERM | IPC_CREAT | IPC_EXCL)) == -1 )
			{
				perror("create msg queue failed.");
				return -1;
			}
			else
				return msgid;
		}
		perror("create get msgid by msgget failed.");
		return -1;
	}
	else
		return msgid;
}

/* initialize the msgqueue
 * return value:
 * > 0 msgid on success
 * -1 on error
 */
int MSG_Init(const int index)
{
	int msgid = get_msg(index);

	if (msgid < 0)
	{
		return -1;
	}

	return msgid;
}

/* destory all the msgqueues
 * return value:
 * 0 on success
 * -1 on error
 */
int MSG_UnInit()
{
	int msgid;
	int index;

	for (index = 0; index < MSG_MAX_NUMS; index++)
	{
		msgid = get_msg(index);
		if (msgid > 0)
		{
			/* msgqueue exists */
			if ( msgctl(msgid, IPC_RMID, NULL) < 0 )
			{
				perror("msgctl with IPC_RMID failed");
				return -1;
			}
		}
	}

	return 0;
}

/* send the message to the msgque with msgid */
int MSG_Send(int index, MSG_Item* p_item, int len)
{
	int idx = index % MSG_MAX_NUMS;
	int msgid = get_msg(idx);
	/* If  IPC_NOWAIT  is specified in msgflg, then the
	   call instead fails with the error EAGAIN.
	 */
	int msgflg = 0;
	int rc;

	p_item->mtype = MSG_TYPE;

	rc = msgsnd(msgid, p_item, len, msgflg);
	if (rc < 0)
	{
		perror("msgsnd failed");
		return -1;
	}
	
	return 0;
}

/* recv the message from the msgque with msgid 
 * return value:
 * > 0: msg lengh got from the msgqueue
 * = 0: no more message in the msgqueue
 * < 0: error happens
 */
int MSG_Recv(int index, MSG_Item* p_item, int len)
{
	int idx = index % MSG_MAX_NUMS;
	int msgid = get_msg(idx);
	/* If  IPC_NOWAIT  is specified in msgflg, then the
	   call instead fails with the error EAGAIN.
	 */
	int msgflg = IPC_NOWAIT;
	int rc;

	rc = msgrcv(msgid, p_item, len, MSG_TYPE, msgflg);
	if (rc < 0)
	{
		if (errno == ENOMSG || errno == EAGAIN)
		{
			/* no more msg exits in the msg queue */
			return 0;
		}
		else
		{
			perror("msgrcv failed");
			return -1;
		}
	}
	
	return rc;
}

#endif
