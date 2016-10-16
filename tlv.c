#include "tlv.h"

struct msgHandlersHashTable g_HandlersHash;
ElemMsgHandler  MsgHandlers[] = {
		{TYPE1, handle_type1},
		{TYPE2, handle_type2},
		{TYPE3, NULL},
};

int __expandMessage(Message *msg, int data_len){
	myAssert(msg);
	char *p = NULL;
	int size = msg->offset + sizeof(msg->type) + sizeof(msg->len) + data_len;
	p = (char *)MessageMalloc(size);
	if (!p){
		printf("===FUNC=%s err  data_len=%d, offset=%d, size=%d===\n",__FUNCTION__, data_len, msg->offset, size);
		return FAIL;
	}
	memset(p, 0, size);
	memcpy(p, msg->buf, msg->offset);
	MessageFree(msg);
	msg->buf = p;
	return SUCC;
}

void msgStroeType(Message *msg, int val){
	memcpy(&(msg->buf[msg->offset]), (char *)&val, sizeof(msg->type));
	(msg->offset) += sizeof(msg->type);
}
void msgStroeLen(Message *msg, int val){
	memcpy(&(msg->buf[msg->offset]), (char *)&val, sizeof(msg->len));
	(msg->offset) += sizeof(msg->len);
}
int msgStoreData(Message *msg, void *data, int data_len){
	memcpy(&(msg->buf[msg->offset]), (char *)data, data_len);
	(msg->offset) += data_len;
	return SUCC;
}

int addElemMsg(Message *msg, int type, int len, void *data){
	myAssert(msg);
	if (len < 0 || (!data && len))
		return FAIL;
	expandMessage(msg, len);
	msgStroeType(msg, type);
	msgStroeLen(msg, len);
	msgStoreData(msg, data, len);
	return SUCC;
}
int msgEncapMsg(Message *to, int type, Message *from){
	if(!to || !from){
		return FAIL;
	}
	return addElemMsg(to, type, from->offset, from->buf);
}
void parseMessage(Message *msg){
	myAssert(msg);
	memcpy(&msg->type, &(msg->buf[msg->offset]), sizeof(msg->type));
	(msg->offset) += sizeof(msg->type);
	
	memcpy(&msg->len, &(msg->buf[msg->offset]), sizeof(msg->len));
	(msg->offset) += sizeof(msg->len);
	return;
}
void showMsgData(Message *msg){
	printf("func=%s, this elem type=%d,len=%d,val=%.*s\n\n", __FUNCTION__, msg->type, msg->len, msg->len, &msg->buf[msg->offset]);
}

void handle_type1 (int type, int data_len,  char *data){
	DEBUG("type=%d,len=%d,val=%.*s", type,  data_len, data_len, data);
}
void handle_type2 (int type, int data_len,  char *data){
	DEBUG("type=%d,len=%d,val=%.*s", type,  data_len, data_len, data);
}
void handle_type3 (int type, int data_len,  char *data){
	DEBUG("type=%d,len=%d", type,  data_len);
	
	__handleMessage(data, data_len, NULL);
}
void handle_type4 (int type, int data_len,  char *data){
	DEBUG("type=%d,len=%d", type,  data_len);
	
	__handleMessage(data, data_len, handle_type3);
}
void initHandlersTable(struct msgHandlersHashTable *handlerHashTable){
	int i;
	for (i = 0; i < sizeof(handlerHashTable->table)/sizeof(handlerHashTable->table[0]); i++){
		INIT_HLIST_HEAD(&handlerHashTable->table[i]);		
	}
	pthread_mutex_init(&handlerHashTable->lock, NULL);
}

void handlerHashLock(){
	pthread_mutex_lock(&g_HandlersHash.lock);
}
void handlerHashUnlock(){
	pthread_mutex_unlock(&g_HandlersHash.lock);
}
struct hlist_head *getHashChain(int type){
	int hash_id = type & (HASH_SIZE-1);
	return &g_HandlersHash.table[hash_id];
}
void hlistAddHandler(struct Handler_entry *entry){
	struct hlist_head *chain = getHashChain(entry->type);
	hlist_add_head(&entry->hnode, chain);
}
void hlistDelHandler(struct Handler_entry *entry){
	hlist_del_init(&entry->hnode);
}

struct Handler_entry *findHandlerFromType(int type){
	struct hlist_node *pos, *next;
	struct Handler_entry *entry = NULL;
	struct hlist_head *chain = getHashChain(type);
	hlist_for_each_entry_safe(entry, pos, next, chain, hnode) {
		if (entry->type == type){			
			return entry;
		}
	}	
	return NULL;
}
int regHandler(int type, void (*handler )(int type, int data_len,  char *data)){
	ElemMsgHandler h;
	if (type < 0 || !handler)
		return FAIL;
	h.type = type;
	h.handler = handler;
	return __regHandler(h);
}
int __regHandler(ElemMsgHandler msgHandler){	
	struct Handler_entry *entry = NULL;
	handlerHashLock();
	entry = findHandlerFromType(msgHandler.type);
	if (entry){
		entry->handler = msgHandler.handler;
		handlerHashUnlock();
		return SUCC;
	}
	entry = (struct Handler_entry *)malloc(sizeof(struct Handler_entry));
	if (!entry)
		return FAIL;
	memset(entry, 0, sizeof(entry));
	entry->type = msgHandler.type;
	entry->handler = msgHandler.handler;
	hlistAddHandler(entry);
	handlerHashUnlock();
	return SUCC;
}

void unregHandler(int type){
	struct Handler_entry *entry = NULL;
	handlerHashLock();
	entry = findHandlerFromType(type);
	if (entry){
		hlistDelHandler(entry);
		if(!entry->handling)
			free(entry);
	}	
	handlerHashUnlock();
	return;
}

void registerHandlers(ElemMsgHandler *msgHandlers, int n){
	int i;
	for(i = 0; i < n; i++){
		if (msgHandlers[i].handler){
			__regHandler(msgHandlers[i]);
		}
	}
}

void handleElemMsg(int type, int data_len,  char *data){
	struct Handler_entry  *entry = NULL;
	handlerHashLock();
	entry = findHandlerFromType(type);
	if (!entry){
		handlerHashUnlock();
		DEBUG(" no handler: unrecognise this type %d, data_len=%d \n", type, data_len);
		return;
	}
	entry->handling = 1;
	handlerHashUnlock();
	if (entry->handler)
		entry->handler(type, data_len, data);
	handlerHashLock();
	entry->handling = 0;
	if (hlist_unhashed(&entry->hnode))
		free(entry);
	handlerHashUnlock();
}

int handleMessage(Message *msg, void (*handleElemMsg)(int type, int data_len,  char *data)){
	if (!msg){
		DEBUG();
		return FAIL;
	}
	return __handleMessage(msg->buf, msg->offset, handleElemMsg);
}

int __handleMessage( char *recvbuf, int recvbuf_size, void (*handleElemMsg)(int type, int data_len,  char *data)){
	DEBUG("recvbuf_size =%d", recvbuf_size);
	if (!recvbuf || !recvbuf_size)
		return FAIL;
	Message msg;
	memset(&msg, 0, sizeof(msg));
	msg.buf = recvbuf;
	msg.offset = 0;
	int size = recvbuf_size;
	while((size -= sizeof(msg.type)+sizeof(msg.len)) >= 0){
		parseMessage(&msg);
		if ((size -= msg.len) < 0){
			printf(" size %d, this elem type=%d,len=%d, offset =%d \n", size , msg.type, msg.len, msg.offset);
			return FAIL;
		}
		if (handleElemMsg)
			handleElemMsg(msg.type, msg.len, &msg.buf[msg.offset]);
		else{
			//如果在此增加消息处理函数,类型越多,代码会越冗长
			//最好是 处理函数采取注册方式加入
			switch (msg.type){
				case TYPE1:
					//TODO:
					DEBUG("   type %d ",msg.type);
					showMsgData(&msg); 
					break;
				case TYPE2:
					//TODO:
					DEBUG(" type %d ",msg.type);
					showMsgData(&msg); 
					break;				
				default:
					DEBUG("default: unrecognise this type %d \n",msg.type);
			}
		}
		msg.offset += msg.len;//jump data
	}
	return SUCC;
}

int main(){
	Message msg;
	Message msg_all;
	Message msg_all_all;
	memset(&msg, 0, sizeof(msg));
	memset(&msg_all, 0, sizeof(msg_all));
	memset(&msg_all_all, 0, sizeof(msg_all_all));
	DEBUG();
	initHandlersTable(&g_HandlersHash);
	registerHandlers(MsgHandlers, sizeof(MsgHandlers));
	//addElemMsg(&msg, TYPE1, 2, "abcd");	
	//addElemMsg(&msg, TYPE2, 3, "abcd");
	//addElemMsg(&msg, UNKNOWN_TYPE, 3, "abcd");
	ADD_ELEM_MSG(&msg, TYPE1, 2, "abcd");
	ADD_ELEM_MSG(&msg, TYPE2, 3, "abcd");
	ADD_ELEM_MSG(&msg, UNKNOWN_TYPE, 3, "abcd");
	
	//msgEncapMsg(&msg_all, TYPE3, &msg);
	MSG_ENCAP_MSG(&msg_all, TYPE3, &msg);
	//send msg to ap, and then  free msg
	
	regHandler(TYPE3, handle_type3);
	handleMessage(&msg_all, handleElemMsg);
	unregHandler(TYPE2);
	handleMessage(&msg, handleElemMsg);

	//msgEncapMsg(&msg_all_all, TYPE4, &msg_all);
	MSG_ENCAP_MSG(&msg_all_all, TYPE4, &msg_all);
	regHandler(TYPE4, handle_type4);
	handleMessage(&msg_all_all, handleElemMsg);

	MessageFree(&msg);
	MessageFree(&msg_all);
	MessageFree(&msg_all_all);
	return 1;
}
