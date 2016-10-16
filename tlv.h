
/***********************************************************
	Copyright (C), 1998-2013, Tenda Tech. Co., Ltd.
	FileName: 
	Description:
	Author: mojianwei
	Version : 1.0
	Date: 2016-5-5
	Function List:
	History:
	<author>   		<time>     <version >   <desc>
	mjw     		 2016-5-5   1.0        new
************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
struct Handler_entry{
	struct hlist_node hnode;
	int handling;
	int type;
	void (*handler)(int type, int data_len,  char *data);
};

typedef struct {
	char *buf;
	int offset;
	unsigned  short type;//explain by mojianwei :max is 2^16=65535, if you want to bigger, change type to  unsigned int 
	unsigned  short len;  
}Message;

#define FAIL 0
#define SUCC 1
#define TYPE1 1
#define TYPE2 2
#define TYPE3 3
#define TYPE4 4
#define UNKNOWN_TYPE 5
#define HASH_SIZE 64

struct msgHandlersHashTable{	
	struct hlist_head  table[HASH_SIZE];
	pthread_mutex_t lock;
};

typedef struct{
	int type;
	void (*handler)(int type, int data_len,  char *data);
}ElemMsgHandler;

#define __DEBUG__   
#ifdef __DEBUG__   
#define DEBUG(format,...) printf("Fun: %s, Line: %d: "format"\n",__FUNCTION__, __LINE__, ##__VA_ARGS__)   
#else   
#define DEBUG(format,...)   
#endif
void myAssertReport( const char *file_name, const char *function_name, unsigned int line_no ){
	printf( "\n[EXAM]Error  file_name: %s, function_name: %s, line %u\n"
		, file_name, function_name, line_no);
	abort();
}
#define myAssert(condition) \
do{\
	if(!condition)\
		myAssertReport(__FILE__, __FUNCTION__, __LINE__);\
}while(0)

extern void handle_type1 (int type, int data_len,  char *data);
extern void handle_type2 (int type, int data_len,  char *data);
extern void handle_type3 (int type, int data_len,  char *data);
extern int addElemMsg(Message *msg, int type, int len, void *data);
extern void handleElemMsg(int type, int data_len,  char *data);
extern int __handleMessage( char *recvbuf, int recvbuf_size, void (*handleElemMsg)(int type, int data_len,  char *data));
extern int handleMessage(Message *msg, void (*handleElemMsg)(int type, int data_len,  char *data));
extern int __regHandler(ElemMsgHandler msgHandler);
extern int regHandler(int type, void (*handler )(int type, int data_len,  char *data));
extern int __expandMessage(Message *msg, int data_len);
extern void MessageFree(Message *msg);
extern int msgStoreData(Message *msg, void *data, int data_len);

#define ADD_ELEM_MSG(msg, type, len, date)  do{\
											if(addElemMsg(msg, type, len, date) == FAIL){\
												printf("\n add elem msg fail: file=%s,function=%s,line=%d, type=%d\n", __FILE__, __FUNCTION__, __LINE__, type);\
											}\
										}while(0)
#define MSG_ENCAP_MSG(msg_to, type, msg_from)  do{\
													if(msgEncapMsg(msg_to, type, msg_from) == FAIL){\
														printf("\n add msgEncapMsg msg fail: file=%s,function=%s,line=%d, type=%d\n", __FILE__, __FUNCTION__, __LINE__, type);\
													}\
										}while(0)

//#define expandMessage(msg,len)	myAssert(SUCC == __expandMessage(msg,len))
#define expandMessage(msg,len)	do{\
								if(__expandMessage(msg, len) == FAIL)\
									return FAIL;\
								}while(0)
#define MessageMalloc(size)  malloc(size)
void MessageFree(Message *msg){
	myAssert(msg);
	if ( msg->buf){
		free(msg->buf);
		msg->buf = NULL;
	}
	return;
}
void initMsg(Message *msg){
	memset(msg, 0, sizeof(*msg));
	msg->buf = NULL;
}
inline int getMsgBufLen(Message *msg){
	return msg->offset;
}
inline int copyMsgBuf(void *dest, Message *msg){
	memcpy(dest, msg->buf, msg->offset);
}
